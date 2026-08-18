//! The resume sub-task: rebuilding a paused computer's runtime from its own
//! checkpoint.
//!
//! Moved here from `sandbox::pause` by R3 PR-F1d, unchanged: this is the body
//! `Effect::SpawnResume` names. `sandbox::pause` still drives it until R3
//! PR-F2 flips the manager onto the actor.
//!
//! A failed resume is two-valued, and that is the whole reason the unwind
//! below reports back: when every re-created resource was released again the
//! retained pause state is intact and the computer parks back at `Paused`;
//! when it was not, recording `Paused` would tell a restart sweep that a
//! half-allocated computer is cleanly resumable.

use std::path::Path;
use std::sync::Arc;

use arcbox_fc_driver::jail::{
    chroot_root, link_or_copy_for_jailer, move_file, stage_kernel_for_jailer,
    stage_rootfs_device_for_jailer,
};
use arcbox_vm_driver::net::{GuestNetwork, NetworkLease};
use arcbox_vm_driver::{IsolationSpec, NicSpec, PreparedVm, VmDriver, VmHandle, VmId};
use tracing::warn;

use crate::agent::{ClockSync, GuestAgentFactory};
use crate::config::{JailerConfig, VmmConfig};
use crate::error::{Result, VmmError};
use crate::sandbox::pause::{PAUSED_ROOTFS_FILE, ResumeFailure, ResumedRuntime};
use crate::sandbox::reconcile::JournaledLease;
use crate::sandbox::spec::restore_spec;
use crate::sandbox::{self, SandboxId};
use crate::snapshot::SnapshotMeta;
use crate::snapshot_cow::{CowHandle, CowManager};

/// Re-create the runtime of a paused sandbox from its checkpoint.
///
/// On failure every re-created resource is unwound (the VMM killed,
/// overlay detached with its COW kept, copy-mode rootfs parked again,
/// fresh network quarantined, chroot and journal removed) so the caller
/// can park the sandbox back at `Paused`.
#[allow(
    clippy::too_many_arguments,
    reason = "the resume spans the resource set its computer owns"
)]
pub async fn restore_paused(
    id: &SandboxId,
    jailer: &JailerConfig,
    snap_meta: &SnapshotMeta,
    vm_dir: &Path,
    networked: bool,
    config: &VmmConfig,
    cow_manager: &CowManager,
    driver: &dyn VmDriver,
    network: &dyn GuestNetwork,
    agents: &dyn GuestAgentFactory,
) -> std::result::Result<ResumedRuntime, ResumeFailure> {
    let fc_cfg = &config.firecracker;
    let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
    let cr = chroot_root(&fc_cfg.binary, base, id);
    let uid = jailer.uid;
    let gid = jailer.gid;

    // Incrementally-owned resources for the unwind. The lease is held
    // apart from the NIC because it is owed to the pool from `reserve`
    // on, and the journal write between the two can fail — an unwind
    // that only knew about activated leases would strand that address.
    let mut lease: Option<NetworkLease> = None;
    let mut nic: Option<NicSpec> = None;
    let mut prepared: Option<Arc<dyn PreparedVm>> = None;
    let mut cow_handle: Option<CowHandle> = None;

    let attempt: Result<ResumedRuntime> = async {
        // Reserve network metadata, journal it, then materialize the
        // TAP — the same order boot and restore use, so a crash never
        // leaves an unowned interface.
        if networked {
            lease = Some(
                network
                    .reserve(&VmId::new(id.as_str())?, sandbox::sandbox_network_policy())
                    .await?,
            );
        }
        let ip_address = lease
            .as_ref()
            .map(|lease| lease.ip.to_string())
            .unwrap_or_default();
        let journal = |pid: Option<i32>, cow: Option<&CowHandle>, net: Option<&NetworkLease>| {
            // The lease attaches the way the snapshot says, exactly as
            // the `activate` below does — the same expression, so the
            // journal and the datapath cannot disagree.
            let net =
                net.map(|lease| JournaledLease::from_snapshot(lease, snap_meta.net_invariant));
            sandbox::reconcile::SandboxStateRecord::new(id, pid, net, cow, config, None)
                .and_then(|record| sandbox::reconcile::write_state_record(vm_dir, &record))
        };
        journal(None, None, lease.as_ref())?;
        if let Some(lease) = &lease {
            // The resumed guest keeps the addressing its pause checkpoint
            // baked, exactly as Restore does: an invariant guest pairs
            // with an invariant TAP (host-side NAT, no guest work), a
            // legacy one with the legacy TAP shape plus the reconfig RPC
            // below (CORE-81).
            nic = Some(
                network
                    .activate(lease, sandbox::attach_mode(snap_meta.net_invariant))
                    .await?,
            );
        }

        // Fresh chroot + VMM process, prepared through the driver.
        let spawned: Arc<dyn PreparedVm> = Arc::from(
            sandbox::prepare_capability(driver)
                .prepare(&VmId::new(id)?, &IsolationSpec::try_from(jailer)?, vm_dir)
                .await?,
        );
        let pid = sandbox::journaled_pid(&*spawned);
        prepared = Some(spawned);
        journal(pid, None, lease.as_ref())?;

        // Stage kernel + the retained disk + snapshot files.
        if let Some(kernel) = snap_meta.kernel_path.as_deref() {
            stage_kernel_for_jailer(&cr, kernel, uid, gid).await?;
        }
        let preserved_cow = sandbox::preserved_cow_file(config, id);
        if preserved_cow.exists() {
            let rootfs = snap_meta.rootfs_path.as_deref().ok_or_else(|| {
                VmmError::Snapshot(format!(
                    "pause checkpoint for {id} records no rootfs template"
                ))
            })?;
            let handle = cow_manager.reattach(id, rootfs).await?;
            journal(pid, Some(&handle), lease.as_ref())?;
            stage_rootfs_device_for_jailer(&cr, &handle.dm_device, uid, gid).await?;
            cow_handle = Some(handle);
        } else {
            let parked = vm_dir.join(PAUSED_ROOTFS_FILE);
            if !parked.exists() {
                return Err(VmmError::Snapshot(format!(
                    "paused sandbox {id} has neither a preserved overlay nor a parked rootfs"
                )));
            }
            let staged = cr.join("rootfs.ext4");
            move_file(&parked, &staged).await.map_err(VmmError::Io)?;
            nix::unistd::chown(
                &staged,
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(gid)),
            )
            .map_err(|e| VmmError::Process(format!("chown parked rootfs: {e}")))?;
        }

        let snap_in_chroot = cr.join("snapshots").join(&snap_meta.id);
        std::fs::create_dir_all(&snap_in_chroot).map_err(VmmError::Io)?;
        nix::unistd::chown(
            &snap_in_chroot,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
        .map_err(|e| VmmError::Process(format!("chown snap dir: {e}")))?;
        link_or_copy_for_jailer(
            &snap_meta.vmstate_path,
            &snap_in_chroot.join("vmstate"),
            uid,
            gid,
        )
        .await?;
        if let Some(ref mem) = snap_meta.mem_path
            && mem.exists()
        {
            link_or_copy_for_jailer(mem, &snap_in_chroot.join("mem"), uid, gid).await?;
        }

        // Load the snapshot on the prepared VMM: the retained disk in
        // this jail, eth0 retargeted onto the fresh TAP.
        let image = sandbox::checkpoint_image(snap_in_chroot, &snap_meta.format);
        let restore = restore_spec(id, &cr, nic.clone(), IsolationSpec::try_from(jailer)?)?;
        let handle: Arc<dyn VmHandle> = Arc::from(
            prepared
                .as_ref()
                .expect("prepared set above")
                .restore(&image, restore)
                .await?,
        );
        // What the guest holds on its interface once this resume has
        // configured it, read under the mode its snapshot was addressed
        // in. Derived once — the agent and the reconfig RPC below must
        // not disagree. An invariant guest already holds it; a legacy
        // one still carries its origin's address until that RPC lands,
        // and this host cannot name that, so its agent is told nothing
        // about reaching it by address in the meantime.
        let identity = lease
            .as_ref()
            .map(|lease| network.identity(lease, sandbox::attach_mode(snap_meta.net_invariant)));
        let settled_on_load = snap_meta.net_invariant.then(|| identity.clone()).flatten();
        let agent = agents.connect(Arc::clone(&handle), settled_on_load.as_ref())?;

        // Clock sync is DETACHED, mirroring restore and cold boot
        // (CORE-80): the guest wall clock froze at pause time, but
        // vm-agent re-syncs itself from ptp_kvm on every accepted exec
        // connection, so correct time no longer depends on this RPC.
        // Awaiting it would put the post-resume vsock connect settle back
        // on the resume critical path.
        {
            let id = id.clone();
            let agent = Arc::clone(&agent);
            tokio::spawn(async move {
                match tokio::time::timeout(std::time::Duration::from_secs(10), agent.sync_clock())
                    .await
                {
                    Ok(Ok(ClockSync::Synced)) => {}
                    Ok(Ok(ClockSync::AgentError(code))) => {
                        warn!(sandbox_id = %id, code, "agent could not set the clock after resume");
                    }
                    Ok(Err(e)) => warn!(sandbox_id = %id, "clock sync after resume failed: {e}"),
                    Err(_) => warn!(sandbox_id = %id, "clock sync after resume timed out"),
                }
            });
        }

        // Re-address the guest only when its snapshot is legacy-addressed.
        // An invariant guest (CORE-81) already holds the fixed link-local
        // identity and its resolv.conf already points at the fixed
        // gateway; the fresh TAP carries the new pool IP host-side, so
        // resume awaits nothing here.
        if let Some(identity) = &identity
            && !snap_meta.net_invariant
        {
            let cmd = crate::boot_proto::NetReconfigCommand {
                ip: sandbox::ipv4(identity.ip)?,
                netmask: sandbox::netmask(identity.prefix_len),
                gateway: sandbox::ipv4(identity.gateway)?,
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                agent.reconfigure_network(&cmd),
            )
            .await
            .map_err(|_| VmmError::Vsock("net reconfig after resume timed out".into()))
            .and_then(|r| r)?;
        }

        journal(pid, cow_handle.as_ref(), lease.as_ref())?;
        Ok(ResumedRuntime {
            prepared: prepared.take().expect("prepared set above"),
            handle,
            net_identity: identity,
            network: lease.take(),
            cow_handle: cow_handle.take(),
            ip_address,
        })
    }
    .await;

    match attempt {
        Ok(resumed) => Ok(resumed),
        Err(error) => {
            let unwound = unwind_resume(
                id,
                vm_dir,
                jailer,
                config,
                cow_manager,
                network,
                prepared,
                cow_handle,
                lease,
            )
            .await;
            Err(ResumeFailure { error, unwound })
        }
    }
}

/// Best-effort release of everything a failed resume re-created,
/// restoring the on-disk shape of a cleanly paused sandbox.
///
/// Returns true when the sandbox can safely go back to `Paused`.
#[allow(
    clippy::too_many_arguments,
    reason = "the unwind spans everything the failed resume re-created"
)]
async fn unwind_resume(
    id: &SandboxId,
    vm_dir: &Path,
    jailer: &JailerConfig,
    config: &VmmConfig,
    cow_manager: &CowManager,
    network: &dyn GuestNetwork,
    prepared: Option<Arc<dyn PreparedVm>>,
    cow_handle: Option<CowHandle>,
    net_lease: Option<NetworkLease>,
) -> bool {
    let mut clean = true;

    if let Some(prepared) = prepared {
        // SIGKILL plus the driver's bounded wait for the reaper.
        if let Err(error) = prepared.discard().await {
            warn!(sandbox_id = %id, error = %error, "resume unwind: the vmm did not exit");
            clean = false;
        }
    }

    if let Some(handle) = cow_handle
        && let Err(error) = cow_manager.detach_keep_cow(&handle).await
    {
        warn!(sandbox_id = %id, error = %error, "resume unwind: overlay detach failed");
        clean = false;
    }

    // Copy-mode fallback: park the staged rootfs back in vm_dir so the
    // retained disk state survives the chroot removal below. The order is
    // load-bearing in the same way the pause release's is — the staged
    // rootfs *is* the paused computer's disk and it lives inside the jail,
    // so a chroot removed before this point turns the `exists()` guard
    // false, the move is skipped, and the computer is left unresumable.
    let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
    let cr = chroot_root(&config.firecracker.binary, base, id);
    let staged = cr.join("rootfs.ext4");
    if !sandbox::preserved_cow_file(config, id).exists() && staged.exists() {
        if let Err(error) = move_file(&staged, &vm_dir.join(PAUSED_ROOTFS_FILE)).await {
            warn!(sandbox_id = %id, error = %error, "resume unwind: parking rootfs failed");
            clean = false;
        }
    }

    if let Some(lease) = net_lease
        && let Err(error) = network.quarantine(lease).await
    {
        warn!(sandbox_id = %id, error = %error, "resume unwind: network quarantine failed");
        clean = false;
    }

    if let Some(parent) = cr.parent()
        && let Err(error) = tokio::fs::remove_dir_all(parent).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(sandbox_id = %id, error = %error, "resume unwind: chroot removal failed");
        clean = false;
    }

    if clean && let Err(error) = sandbox::reconcile::clear_state_record(vm_dir) {
        warn!(sandbox_id = %id, error = %error, "resume unwind: journal removal failed");
        clean = false;
    }
    clean
}
