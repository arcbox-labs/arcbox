//! Releasing what a computer holds: the three scopes a teardown comes in.
//!
//! Moved here from `sandbox::cleanup` by R3 PR-F1e, unchanged: these are the
//! bodies `Effect::SpawnRelease` names. `ReleaseScope::Runtime` is
//! [`release_runtime_resources`] (the failure path, and Stop, which keep the
//! record inspectable), `ReleaseScope::Full` is [`release_everything`] (a
//! removal, which also takes the retained pause state and the working
//! directory), and `ReleaseScope::KeepDisk` is the pause release next door in
//! [`super::pause`]. `sandbox::cleanup` still drives them until R3 PR-F2
//! flips the manager onto the actor.
//!
//! The ordering inside is load-bearing and shared by all three: the VMM must
//! be dead before the CoW teardown (`dmsetup remove` returns EBUSY while the
//! block device is open) and before the TAP goes (the ioctl fails while the
//! fd is held). Everything is `take()`n, so a release is idempotent and a
//! retry after a partial failure finishes the job — which is also what makes
//! preempting one safe.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arcbox_fc_driver::jail::chroot_root;
use arcbox_vm_driver::ShutdownMode;
use arcbox_vm_driver::net::GuestNetwork;

use crate::config::VmmConfig;
use crate::error::{Result, VmmError};
use crate::sandbox::{self, SandboxInstance};
use crate::snapshot_cow::CowManager;

/// Free every runtime resource a sandbox holds: the VMM process (SIGKILL +
/// bounded reap through the driver), the dm-snapshot CoW device, the TAP +
/// IP allocation, and the jailer chroot. Idempotent — every resource is
/// `take()`n, so calling this from both Stop and Remove is safe.
///
/// The ordering is load-bearing: the VMM must be dead before the CoW
/// teardown (`dmsetup remove` returns EBUSY while the block device is open)
/// and before TAP destruction (the ioctl fails while the fd is held).
pub async fn release_runtime_resources(
    id: &str,
    arc: &Arc<Mutex<SandboxInstance>>,
    network: &Arc<dyn GuestNetwork>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
) -> Result<()> {
    kill_sandbox_process(id, arc).await?;

    // Teardown dm-snapshot CoW device (must happen after the VMM exits
    // because it holds the block device open).
    {
        let cow_handle = arc.lock().unwrap().cow_handle.take();
        if let Some(handle) = cow_handle
            && let Err(error) = cow_manager.teardown_checked(&handle).await
        {
            arc.lock().unwrap().cow_handle = Some(handle);
            return Err(error.into());
        }
    }
    cow_manager.cleanup_setup_orphan(id).await?;

    // Release network resources (destroys TAP via ioctl).
    {
        let lease = arc.lock().unwrap().network.take();
        if let Some(lease) = lease
            && let Err(error) = network.quarantine(lease.clone()).await
        {
            arc.lock().unwrap().network = Some(lease);
            return Err(error.into());
        }
    }

    // Clean up the jailer chroot directory if applicable. A sandbox that
    // adopted a pre-warmed pool slot lives in the slot's chroot, so the
    // removal is keyed by the owning id, not the sandbox id.
    remove_jailer_chroot(id, arc, config).await
}

/// Remove the jailer chroot a sandbox actually lives in.
///
/// Keyed by the adopted pool slot id when the sandbox claimed a pre-warmed
/// slot (CORE-78), by the sandbox id otherwise. Shared with the pause path,
/// which releases the same chroot while keeping the disk.
pub async fn remove_jailer_chroot(
    id: &str,
    arc: &Arc<Mutex<SandboxInstance>>,
    config: &VmmConfig,
) -> Result<()> {
    let Some(ref jc) = config.firecracker.jailer else {
        return Ok(());
    };
    let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
    let chroot_owner = chroot_owner(id, arc);
    let chroot_dir = chroot_root(&config.firecracker.binary, base, &chroot_owner);
    // Remove {base}/{exec_name}/{id}/ (parent of "root/").
    if let Some(parent) = chroot_dir.parent()
        && let Err(e) = tokio::fs::remove_dir_all(parent).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmmError::Io(e));
    }
    Ok(())
}

/// Id the sandbox's jailer chroot and dm/CoW resources are named after.
pub fn chroot_owner(id: &str, arc: &Arc<Mutex<SandboxInstance>>) -> String {
    arc.lock()
        .unwrap()
        .pool_slot_id
        .clone()
        .unwrap_or_else(|| id.to_owned())
}

/// Kill the sandbox's VMM process and reap it: the driver's `discard`, a
/// SIGKILL plus a bounded wait for the reaper. Once the process is gone the
/// VM's handle only names a corpse — nothing dials, checkpoints or stops a
/// stopped, paused or failed sandbox — so it is dropped here too, the one
/// place both are let go.
///
/// A sandbox this process adopted rather than booted has no `PreparedVm` —
/// nothing hands the driver's grip on a *process* back across a restart — so
/// its VM is killed through the handle, which reaps as well. Without that
/// arm an adopted sandbox's Remove would report success while its VMM kept
/// running, and the dm device and TAP would then be torn out from under a
/// live guest.
///
/// Extracted so the pause path (which keeps the disk overlay) shares the exact
/// kill/reap discipline with full release. A failed reap (the driver's
/// bounded wait elapsed) restores whichever grip it took, and keeps the
/// handle, so a retry can finish the job. Idempotent — both are `take()`n,
/// and killing an exited VM just reports its status.
pub async fn kill_sandbox_process(id: &str, arc: &Arc<Mutex<SandboxInstance>>) -> Result<()> {
    let (prepared, handle) = {
        let mut inst = arc.lock().unwrap();
        let prepared = inst.prepared.take();
        // Only the adopted case needs the handle: while a `PreparedVm` is
        // present it owns the process, and discarding it is the whole kill.
        let handle = prepared.is_none().then(|| inst.handle.clone()).flatten();
        (prepared, handle)
    };
    // Kill and await the exit outside the lock; the driver bounds the wait so
    // cleanup proceeds (and reports) even if the process is stuck in
    // uninterruptible sleep after SIGKILL.
    if let Some(prepared) = prepared {
        if let Err(error) = prepared.discard().await {
            arc.lock().unwrap().prepared = Some(prepared);
            return Err(VmmError::Process(format!(
                "release the vmm of sandbox {id}: {error}"
            )));
        }
    } else if let Some(handle) = handle
        && let Err(error) = handle.shutdown(ShutdownMode::Kill).await
    {
        return Err(VmmError::Process(format!(
            "release the adopted vmm of sandbox {id}: {error}"
        )));
    }
    {
        let mut inst = arc.lock().unwrap();
        inst.handle = None;
        inst.net_identity = None;
    }
    Ok(())
}

/// Everything a removal frees, on top of the runtime: the retained pause
/// state a Stop-style release deliberately keeps (CORE-21) and the working
/// directory itself.
///
/// The pause artefacts are found by name rather than by record — a
/// checkpoint an interrupted pause committed to the catalog but never
/// recorded durably is exactly the one nobody else will ever collect.
pub async fn release_everything(
    id: &str,
    arc: &Arc<Mutex<SandboxInstance>>,
    network: &Arc<dyn GuestNetwork>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
    snapshots: &Arc<crate::snapshot::SnapshotCatalog>,
) -> Result<()> {
    release_runtime_resources(id, arc, network, config, cow_manager).await?;

    // Pause artifacts survive Stop-style release by design (CORE-21); Remove
    // is where they die: the retained disk overlay and the internal pause
    // checkpoint(s), including any leaked by an interrupted pause.
    cow_manager.remove_preserved_cow(id).await?;
    sandbox::pause::delete_pause_snapshots(snapshots, id)?;

    // Remove the sandbox working directory (sockets, logs, state journal).
    let vm_dir = PathBuf::from(&config.firecracker.data_dir)
        .join("sandboxes")
        .join(id);
    if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmmError::Io(e));
    }
    Ok(())
}
