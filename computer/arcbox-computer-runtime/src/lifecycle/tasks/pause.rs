//! The pause release: freeing a checkpointed computer's runtime while its
//! disk survives.
//!
//! Moved here from `sandbox::pause` by R3 PR-F1d, unchanged: this is the body
//! `Effect::SpawnRelease { KeepDisk }` names. `sandbox::pause` still drives
//! it until R3 PR-F2 flips the manager onto the actor.
//!
//! The ordering mirrors a full release and is load-bearing for the same
//! reasons: the VMM must be dead before the dm detach (EBUSY) and before the
//! TAP goes. What differs is the disk — the overlay is detached with its COW
//! file kept, or, in copy mode, the staged rootfs is parked in `vm_dir`
//! before the chroot is removed — and the renaming that leaves every
//! retained resource keyed by the computer's own id.

use std::sync::{Arc, Mutex};

use arcbox_fc_driver::jail::{chroot_root, move_file};
use arcbox_vm_driver::net::GuestNetwork;

use crate::config::{JailerConfig, VmmConfig};
use crate::error::{Result, VmmError};
use crate::sandbox::pause::PAUSED_ROOTFS_FILE;
use crate::sandbox::{self, SandboxId, SandboxInstance};
use crate::snapshot_cow::CowManager;

/// Free the VM, network, and chroot of a checkpointed sandbox while
/// keeping its disk.
///
/// Ordering is load-bearing, mirroring full release: the VMM must be
/// dead before the dm detach (EBUSY) and TAP destruction. The network
/// allocation is quarantined — the daemon completes host-side forwarding
/// cleanup through the same durable ticket flow Stop uses.
///
/// A sandbox that adopted a pre-warmed slot (CORE-78) is released out of
/// the *slot's* chroot and its slot-keyed overlay is renamed onto the
/// sandbox-id path, so `Paused` is always reached with every retained
/// resource keyed by the sandbox id.
#[allow(
    clippy::too_many_arguments,
    reason = "the pause release spans the resource set its computer owns"
)]
pub async fn release_for_pause(
    id: &SandboxId,
    arc: &Arc<Mutex<SandboxInstance>>,
    jailer: &JailerConfig,
    config: &VmmConfig,
    cow_manager: &CowManager,
    network: &dyn GuestNetwork,
) -> Result<()> {
    sandbox::cleanup::kill_sandbox_process(id, arc).await?;
    let owner = sandbox::cleanup::chroot_owner(id, arc);

    // Disk: detach the overlay but keep its COW file; the copy-mode
    // fallback parks the staged rootfs (the sandbox's actual disk) in
    // vm_dir before the chroot is removed.
    let cow_handle = arc.lock().unwrap().cow_handle.take();
    if let Some(handle) = cow_handle {
        if let Err(error) = cow_manager.detach_keep_cow(&handle).await {
            arc.lock().unwrap().cow_handle = Some(handle);
            return Err(error.into());
        }
        // A slot-keyed overlay must become sandbox-keyed: resume's
        // `reattach`, the restart sweep's keep-list, and `Remove` all
        // look the file up by sandbox id.
        let retained = sandbox::preserved_cow_file(config, id);
        let detached = sandbox::preserved_cow_file(config, &owner);
        if detached != retained && detached.exists() {
            tokio::fs::rename(&detached, &retained)
                .await
                .map_err(VmmError::Io)?;
        }
    } else {
        let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        let staged = chroot_root(&config.firecracker.binary, base, &owner).join("rootfs.ext4");
        if staged.exists() {
            let vm_dir = arc.lock().unwrap().vm_dir.clone();
            move_file(&staged, &vm_dir.join(PAUSED_ROOTFS_FILE))
                .await
                .map_err(VmmError::Io)?;
        }
    }

    {
        let lease = arc.lock().unwrap().network.take();
        if let Some(lease) = lease
            && let Err(error) = network.quarantine(lease.clone()).await
        {
            arc.lock().unwrap().network = Some(lease);
            return Err(error.into());
        }
    }

    sandbox::cleanup::remove_jailer_chroot(id, arc, config).await?;
    // Nothing slot-keyed survives this point.
    arc.lock().unwrap().pool_slot_id = None;
    Ok(())
}
