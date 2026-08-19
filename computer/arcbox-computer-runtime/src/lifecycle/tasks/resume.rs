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

use arcbox_vm_driver::net::{GuestNetwork, NetworkLease};
use arcbox_vm_driver::{DiskSource, IsolationSpec, NicSpec, PreparedVm, VmDriver, VmHandle, VmId};
use tracing::warn;

use crate::agent::{ClockSync, GuestAgentFactory};
use crate::config::{JailerConfig, RuntimeConfig};
use crate::error::{ComputerError, Result};
use crate::sandbox::pause::{PAUSED_ROOTFS_FILE, ResumeFailure, ResumedRuntime};
use crate::sandbox::reconcile::JournaledLease;
use crate::sandbox::spec::restore_spec;
use crate::sandbox::{self, ComputerId, ROOTFS_DISK_ID};
use crate::snapshot::SnapshotMeta;
use crate::snapshot_cow::{CowHandle, CowManager};

/// Re-create the runtime of a paused sandbox from its checkpoint.
///
/// On failure every re-created resource is unwound (a copy-mode rootfs
/// parked again, the VMM killed — which takes the area it ran in — the
/// overlay detached with its COW kept, the fresh network quarantined, the
/// journal removed) so the caller can park the sandbox back at `Paused`.
#[allow(
    clippy::too_many_arguments,
    reason = "the resume spans the resource set its computer owns"
)]
pub async fn restore_paused(
    id: &ComputerId,
    jailer: &JailerConfig,
    snap_meta: &SnapshotMeta,
    vm_dir: &Path,
    networked: bool,
    config: &RuntimeConfig,
    cow_manager: &CowManager,
    driver: &dyn VmDriver,
    network: &dyn GuestNetwork,
    agents: &dyn GuestAgentFactory,
) -> std::result::Result<ResumedRuntime, ResumeFailure> {
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
        let journal = |pid: Option<i32>, cow: Option<&CowHandle>, net: Option<&NetworkLease>| {
            // The lease attaches the way the snapshot says, exactly as
            // the `activate` below does — the same expression, so the
            // journal and the datapath cannot disagree.
            let net =
                net.map(|lease| JournaledLease::from_snapshot(lease, snap_meta.net_invariant));
            sandbox::reconcile::ComputerStateRecord::new(id, pid, net, cow, config, None)
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

        // A fresh VMM, prepared through the driver.
        let spawned: Arc<dyn PreparedVm> = Arc::from(
            sandbox::prepare_capability(driver)
                .prepare(&VmId::new(id)?, &IsolationSpec::try_from(jailer)?, vm_dir)
                .await?,
        );
        let pid = sandbox::journaled_pid(&*spawned);
        let staging = sandbox::staging_capability(spawned.staging());
        prepared = Some(Arc::clone(&spawned));
        journal(pid, None, lease.as_ref())?;

        // Bring the kernel, the retained disk and the checkpoint into the
        // area the fresh VMM reads from.
        if let Some(kernel) = snap_meta.kernel_path.as_deref() {
            staging.stage_kernel(Path::new(kernel)).await?;
        }
        let preserved_cow = sandbox::preserved_cow_file(config, id);
        let rootfs = if preserved_cow.exists() {
            let template = snap_meta.rootfs_path.as_deref().ok_or_else(|| {
                ComputerError::Snapshot(format!(
                    "pause checkpoint for {id} records no rootfs template"
                ))
            })?;
            let handle = cow_manager.reattach(id, template).await?;
            journal(pid, Some(&handle), lease.as_ref())?;
            let staged = staging
                .stage_disk(
                    ROOTFS_DISK_ID,
                    DiskSource::Device(Path::new(&handle.dm_device)),
                )
                .await?;
            cow_handle = Some(handle);
            staged
        } else {
            // The copy-mode disk the pause parked outside: handed over, so
            // it is moved back in rather than duplicated — it is the size
            // of a guest rootfs, and nothing else holds a copy of it.
            let parked = vm_dir.join(PAUSED_ROOTFS_FILE);
            if !parked.exists() {
                return Err(ComputerError::Snapshot(format!(
                    "paused sandbox {id} has neither a preserved overlay nor a parked rootfs"
                )));
            }
            staging
                .stage_disk(ROOTFS_DISK_ID, DiskSource::Handover(&parked))
                .await?
        };
        let image = staging
            .stage_checkpoint(&sandbox::catalogued_checkpoint(snap_meta)?)
            .await?;

        // Load the snapshot on the prepared VMM: the retained disk where
        // staging put it, eth0 retargeted onto the fresh TAP.
        let restore = restore_spec(id, rootfs, nic.clone(), IsolationSpec::try_from(jailer)?)?;
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
                        warn!(computer_id = %id, code, "agent could not set the clock after resume");
                    }
                    Ok(Err(e)) => warn!(computer_id = %id, "clock sync after resume failed: {e}"),
                    Err(_) => warn!(computer_id = %id, "clock sync after resume timed out"),
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
            .map_err(|_| ComputerError::Vsock("net reconfig after resume timed out".into()))
            .and_then(|r| r)?;
        }

        journal(pid, cow_handle.as_ref(), lease.as_ref())?;
        Ok(ResumedRuntime {
            prepared: prepared.take().expect("prepared set above"),
            handle,
            net_identity: identity,
            network: lease.take(),
            cow_handle: cow_handle.take(),
        })
    }
    .await;

    match attempt {
        Ok(resumed) => Ok(resumed),
        Err(error) => {
            let unwound = unwind_resume(
                id,
                vm_dir,
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

/// Take a copy-mode rootfs back out of the VM's area and park it in
/// `vm_dir`, restoring what a clean pause leaves behind.
///
/// This runs before the discard, for the same reason the pause release's
/// does: the staged rootfs *is* the paused computer's disk, it sits in an
/// area the discard is entitled to take with it, and only the grip being
/// discarded can reach in there. Nothing is writing it — a resume that got
/// as far as a running guest dropped that handle on its way out, and a
/// dropped handle SIGKILLs.
///
/// `false` when the disk could not be parked, which is what stops the
/// computer being recorded as cleanly `Paused`. Unlike the pause release,
/// *nothing staged* is a normal outcome here and not a refusal: a resume
/// that failed before it handed the parked disk over never moved it, so
/// the file is still sitting in `vm_dir` where a clean pause left it.
async fn park_copy_mode_rootfs(
    id: &ComputerId,
    vm_dir: &Path,
    config: &RuntimeConfig,
    prepared: Option<&Arc<dyn PreparedVm>>,
) -> bool {
    let Some(prepared) = prepared else {
        return true;
    };
    if sandbox::preserved_cow_file(config, id).exists() {
        return true;
    }
    match sandbox::staging_capability(prepared.staging())
        .unstage_disk(ROOTFS_DISK_ID, &vm_dir.join(PAUSED_ROOTFS_FILE))
        .await
    {
        Ok(_) => true,
        Err(error) => {
            warn!(computer_id = %id, error = %error, "resume unwind: parking rootfs failed");
            false
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
    id: &ComputerId,
    vm_dir: &Path,
    config: &RuntimeConfig,
    cow_manager: &CowManager,
    network: &dyn GuestNetwork,
    prepared: Option<Arc<dyn PreparedVm>>,
    cow_handle: Option<CowHandle>,
    net_lease: Option<NetworkLease>,
) -> bool {
    let mut clean = park_copy_mode_rootfs(id, vm_dir, config, prepared.as_ref()).await;

    if let Some(prepared) = prepared {
        // SIGKILL plus the driver's bounded wait for the reaper.
        if let Err(error) = prepared.discard().await {
            warn!(computer_id = %id, error = %error, "resume unwind: the vmm did not exit");
            clean = false;
        }
    }

    if let Some(handle) = cow_handle
        && let Err(error) = cow_manager.detach_keep_cow(&handle).await
    {
        warn!(computer_id = %id, error = %error, "resume unwind: overlay detach failed");
        clean = false;
    }

    if let Some(lease) = net_lease
        && let Err(error) = network.quarantine(lease).await
    {
        warn!(computer_id = %id, error = %error, "resume unwind: network quarantine failed");
        clean = false;
    }

    if clean && let Err(error) = sandbox::reconcile::clear_state_record(vm_dir) {
        warn!(computer_id = %id, error = %error, "resume unwind: journal removal failed");
        clean = false;
    }
    clean
}
