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

use arcbox_vm_driver::ShutdownMode;
use arcbox_vm_driver::net::GuestNetwork;

use crate::config::RuntimeConfig;
use crate::error::{ComputerError, Result};
use crate::lifecycle::runtime::ComputerRuntime;
use crate::sandbox;
use crate::snapshot_cow::CowManager;

/// Free every runtime resource a sandbox holds: the VMM process (SIGKILL +
/// bounded reap through the driver, which takes the area the VM's files
/// were staged into with it), the dm-snapshot CoW device, and the TAP + IP
/// allocation. Idempotent — every resource is `take()`n, so calling this
/// from both Stop and Remove is safe.
///
/// The ordering is load-bearing: the VMM must be dead before the CoW
/// teardown (`dmsetup remove` returns EBUSY while the block device is open)
/// and before TAP destruction (the ioctl fails while the fd is held).
pub async fn release_runtime_resources(
    id: &str,
    arc: &Arc<Mutex<ComputerRuntime>>,
    network: &Arc<dyn GuestNetwork>,
    cow_manager: &Arc<CowManager>,
) -> Result<()> {
    kill_computer_process(id, arc).await?;

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
    let lease = arc.lock().unwrap().network.take();
    if let Some(lease) = lease
        && let Err(error) = network.quarantine(lease.clone()).await
    {
        arc.lock().unwrap().network = Some(lease);
        return Err(error.into());
    }
    Ok(())
}

/// Id this computer's dm/CoW resources are named after.
///
/// A computer that adopted a pre-warmed pool slot (CORE-78) runs on the
/// slot's resources, so they are named after the slot and not after it.
pub fn resource_owner(id: &str, arc: &Arc<Mutex<ComputerRuntime>>) -> String {
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
/// **The driver takes the VM's staging area with the kill**, so anything
/// that has to outlive the VM leaves through `Staging::unstage_disk`
/// before this is called — which is what the pause release does with a
/// copy-mode rootfs.
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
pub async fn kill_computer_process(id: &str, arc: &Arc<Mutex<ComputerRuntime>>) -> Result<()> {
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
            return Err(ComputerError::Process(format!(
                "release the vmm of sandbox {id}: {error}"
            )));
        }
    } else if let Some(handle) = handle
        && let Err(error) = handle.shutdown(ShutdownMode::Kill).await
    {
        return Err(ComputerError::Process(format!(
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
    arc: &Arc<Mutex<ComputerRuntime>>,
    network: &Arc<dyn GuestNetwork>,
    config: &Arc<RuntimeConfig>,
    cow_manager: &Arc<CowManager>,
    snapshots: &Arc<crate::snapshot::SnapshotCatalog>,
) -> Result<()> {
    release_runtime_resources(id, arc, network, cow_manager).await?;

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
        return Err(ComputerError::Io(e));
    }
    Ok(())
}
