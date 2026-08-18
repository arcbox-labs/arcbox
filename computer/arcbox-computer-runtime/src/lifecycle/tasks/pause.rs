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
//! file kept, or, in copy mode, the staged rootfs is taken back out of the
//! VM's area and parked in `vm_dir` — and the renaming that leaves every
//! retained resource keyed by the computer's own id.
//!
//! **The copy-mode disk comes out of the VM's area before the VMM is
//! killed.** In copy mode the staged rootfs *is* the paused computer's
//! disk, and it lives wherever the driver put it — an area a kill is
//! entitled to take with it, and one nothing here can name. So the disk is
//! taken back out through the port first, while the grip that staged it is
//! still held; only then is the VMM discarded. The other order reports a
//! successful pause and leaves the resume that follows with no disk, which
//! is why it is stated here rather than left to the reader of two
//! statements twenty lines apart.
//!
//! The guest is quiesced by the checkpoint that precedes this, which is
//! what makes taking its disk out safe while its VMM is still up.

use std::sync::{Arc, Mutex};

use arcbox_vm_driver::net::GuestNetwork;

use crate::config::VmmConfig;
use crate::error::{Result, VmmError};
use crate::lifecycle::runtime::ComputerRuntime;
use crate::sandbox::pause::PAUSED_ROOTFS_FILE;
use crate::sandbox::{self, ROOTFS_DISK_ID, SandboxId};
use crate::snapshot_cow::CowManager;

/// Free the VM and the network of a checkpointed sandbox while keeping its
/// disk.
///
/// Ordering is load-bearing, mirroring full release: the VMM must be
/// dead before the dm detach (EBUSY) and TAP destruction — and, ahead of
/// both, a copy-mode disk must leave the VM's area before the kill that
/// may take that area with it. The network allocation is quarantined —
/// the daemon completes host-side forwarding cleanup through the same
/// durable ticket flow Stop uses.
///
/// A sandbox that adopted a pre-warmed slot (CORE-78) has its slot-keyed
/// overlay renamed onto the sandbox-id path, so `Paused` is always reached
/// with every retained resource keyed by the sandbox id.
pub async fn release_for_pause(
    id: &SandboxId,
    arc: &Arc<Mutex<ComputerRuntime>>,
    config: &VmmConfig,
    cow_manager: &CowManager,
    network: &dyn GuestNetwork,
) -> Result<()> {
    // Copy mode: the staged rootfs IS this computer's disk. Take it out of
    // the VM's area first — the guest is quiesced, the grip that staged it
    // is still held, and after the kill neither is true.
    let (prepared, in_copy_mode, vm_dir) = {
        let computer = arc.lock().unwrap();
        (
            computer.prepared.clone(),
            computer.cow_handle.is_none(),
            computer.vm_dir.clone(),
        )
    };
    if in_copy_mode {
        let prepared = prepared.ok_or_else(|| {
            // A computer this process adopted rather than booted (CORE-135)
            // holds no prepared VM, so nothing here can reach into the area
            // its disk sits in. Refusing before the checkpoint's guest is
            // killed leaves the disk where it is and the pause retryable;
            // the routes an adopted computer is missing arrive with R3
            // PR-G3.
            VmmError::Unavailable(format!(
                "computer {id} runs on a copied rootfs and was adopted after an agent \
                 restart, so its disk cannot be taken out of the vm it was staged into; \
                 it can be stopped or removed, but not paused"
            ))
        })?;
        // Nothing taken out is a refusal, not a skip: in copy mode the
        // VM's area is where this computer's only writable disk lives, so
        // `false` means there is no disk to pause. Discarding anyway would
        // commit `Paused` with neither a preserved overlay nor a parked
        // rootfs — the exact state resume refuses to start from, reached
        // after the disk is already unrecoverable.
        if !sandbox::staging_capability(&*prepared)
            .unstage_disk(ROOTFS_DISK_ID, &vm_dir.join(PAUSED_ROOTFS_FILE))
            .await?
        {
            return Err(VmmError::Snapshot(format!(
                "computer {id} runs on a copied rootfs but its vm has no disk staged to take \
                 out; pausing it would leave nothing to resume from"
            )));
        }
    }

    super::release::kill_sandbox_process(id, arc).await?;
    let owner = super::release::resource_owner(id, arc);

    // Disk: detach the overlay but keep its COW file.
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

    // Nothing slot-keyed survives this point: the slot's VM is gone with
    // the area it ran in, and its overlay was renamed above.
    arc.lock().unwrap().pool_slot_id = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use arcbox_vm_driver::testkit::{FakeDriver, FakeNetwork};
    use arcbox_vm_driver::{DiskSource, IsolationSpec, PreparedVm, VmDriver as _, VmId};

    use super::*;
    use crate::sandbox::SandboxSpec;
    use crate::snapshot_cow::CowOptions;

    /// A copy-mode computer — no overlay, its disk staged into its VM's
    /// area — with `staged` written there under the root disk's id when
    /// asked for.
    async fn copy_mode_computer(
        data_dir: &std::path::Path,
        driver: &FakeDriver,
        staged: Option<&[u8]>,
    ) -> (Arc<Mutex<ComputerRuntime>>, Arc<dyn PreparedVm>, PathBuf) {
        let vm_dir = data_dir.join("sandboxes/job");
        std::fs::create_dir_all(&vm_dir).unwrap();
        let prepared: Arc<dyn PreparedVm> = Arc::from(
            driver
                .prepare()
                .unwrap()
                .prepare(&VmId::new("job").unwrap(), &IsolationSpec::None, &vm_dir)
                .await
                .unwrap(),
        );
        if let Some(bytes) = staged {
            let source = data_dir.join("template.ext4");
            std::fs::write(&source, bytes).unwrap();
            prepared
                .staging()
                .unwrap()
                .stage_disk(ROOTFS_DISK_ID, DiskSource::Image(&source))
                .await
                .unwrap();
        }
        let mut computer = ComputerRuntime::new(
            "job".to_owned(),
            SandboxSpec::default(),
            None,
            vm_dir.clone(),
        );
        computer.prepared = Some(Arc::clone(&prepared));
        (Arc::new(Mutex::new(computer)), prepared, vm_dir)
    }

    fn config(data_dir: &std::path::Path) -> VmmConfig {
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
        config
    }

    /// A copy-mode computer's disk comes out of the VM's area and lands
    /// where resume looks for it, and the VM is released.
    ///
    /// That the take-out *precedes* the discard is not observable through
    /// the fake, whose staging area survives one; the ordering is held by
    /// the comment at the site and proven by the `sandbox` e2e, where the
    /// area really does go with the kill.
    #[tokio::test]
    async fn the_copy_mode_disk_is_parked_before_the_vm_is_discarded() {
        let data_dir = tempfile::tempdir().unwrap();
        let driver = FakeDriver::new();
        let (computer, prepared, vm_dir) =
            copy_mode_computer(data_dir.path(), &driver, Some(b"the guest's disk")).await;
        let config = config(data_dir.path());
        let cow = CowManager::new(CowOptions::new(&config.firecracker.data_dir)).unwrap();

        release_for_pause(
            &"job".to_owned(),
            &computer,
            &config,
            &cow,
            &FakeNetwork::new(),
        )
        .await
        .expect("a copy-mode pause parks the disk and releases the vm");

        assert_eq!(
            std::fs::read(vm_dir.join(PAUSED_ROOTFS_FILE)).unwrap(),
            b"the guest's disk"
        );
        assert!(
            !prepared.alive(),
            "the vm is discarded after the disk is out"
        );
    }

    /// Nothing to take out is a refusal, not a skip: continuing would
    /// discard the VM, take its area with it, and record `Paused` for a
    /// computer with no disk to resume from.
    #[tokio::test]
    async fn a_copy_mode_pause_with_no_staged_disk_is_refused_before_the_kill() {
        let data_dir = tempfile::tempdir().unwrap();
        let driver = FakeDriver::new();
        let (computer, prepared, vm_dir) = copy_mode_computer(data_dir.path(), &driver, None).await;
        let config = config(data_dir.path());
        let cow = CowManager::new(CowOptions::new(&config.firecracker.data_dir)).unwrap();

        let refused = release_for_pause(
            &"job".to_owned(),
            &computer,
            &config,
            &cow,
            &FakeNetwork::new(),
        )
        .await;

        match refused {
            Err(VmmError::Snapshot(message)) => {
                assert!(message.contains("nothing to resume from"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(prepared.alive(), "the vm is left running for a retry");
        assert!(!vm_dir.join(PAUSED_ROOTFS_FILE).exists());
    }
}
