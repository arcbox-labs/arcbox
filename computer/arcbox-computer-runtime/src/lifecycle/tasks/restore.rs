//! The restore flow's sub-task: bringing a checkpointed computer back up.
//!
//! Moved here from `sandbox::checkpoint` by R3 PR-F1c, unchanged: this is the
//! body `Effect::SpawnRestore` names — claim a pre-warmed slot or prepare and
//! stage a fresh one, load the image, re-address the guest, journal what it
//! now owns. Everything around it stays with the manager: the durable intent,
//! the id reservation, the atomic `ReadyWithOutcome` commit, and the rollback
//! that unwinds a failure. `sandbox::checkpoint::restore_from_snapshot` is
//! still the caller until R3 PR-F2 flips the manager onto the actor.
//!
//! Two orderings inside are load-bearing and commented at their sites: the
//! clock sync stays **detached** (awaiting it measured +57 ms on the restore
//! hot path, CORE-80), and the claimed slot's journal is cleared only *after*
//! the adopting computer's own journal is durable — the other order leaves a
//! crash window with no journal at all, and the slot-keyed VMM, chroot and
//! CoW invisible to reconciliation.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use arcbox_fc_driver::jail::{
    SnapshotFiles, chroot_root, stage_kernel_for_jailer, stage_snapshot_files,
};
use arcbox_vm_driver::net::{GuestNetwork, NetworkIdentity, NetworkLease};
use arcbox_vm_driver::{
    CheckpointImage, IsolationSpec, NicSpec, PreparedVm, VmDriver, VmHandle, VmId,
};
use tracing::warn;

use crate::agent::{ClockSync, GuestAgent, GuestAgentFactory};
use crate::config::{JailerConfig, VmmConfig};
use crate::error::{Result, VmmError};
use crate::lifecycle::runtime::ComputerRuntime;
use crate::sandbox;
use crate::sandbox::boot::{StageError, stage_rootfs_cow_or_copy};
use crate::sandbox::pool::PreparedSlot;
use crate::sandbox::reconcile::JournaledLease;
use crate::snapshot::SnapshotMeta;
use crate::snapshot_cow::{CowHandle, CowManager};

/// What the restore sub-task needs that its computer already has.
pub struct RestoreVm<'a> {
    /// The id being restored *into* — not the checkpoint's own.
    pub new_id: &'a str,
    pub snap_meta: &'a SnapshotMeta,
    pub lease: Option<&'a NetworkLease>,
    /// The interface activating that lease produced, if any.
    pub nic: Option<NicSpec>,
    /// The addressing the snapshot baked, read from the snapshot rather than
    /// from a constant: every journal this restore writes and the TAP it
    /// attaches to must agree with it.
    pub net_invariant: bool,
    pub vm_dir: &'a Path,
    pub jailer: &'a JailerConfig,
    /// The reserved instance: a claimed pool slot is recorded on it before
    /// anything else, because failure cleanup and the startup sweep key the
    /// chroot and dm/CoW teardown on that id.
    pub instance: &'a Arc<Mutex<ComputerRuntime>>,
    /// A pre-warmed slot this restore adopted (CORE-78), when the pool had
    /// one for this checkpoint.
    pub claimed: Option<PreparedSlot>,
    pub config: &'a VmmConfig,
    pub cow_manager: &'a CowManager,
    pub driver: &'a dyn VmDriver,
    pub network: &'a dyn GuestNetwork,
    pub agents: &'a dyn GuestAgentFactory,
}

/// A restored VM, with everything the computer must now own.
pub struct RestoredVm {
    pub prepared: Arc<dyn PreparedVm>,
    pub handle: Arc<dyn VmHandle>,
    pub agent: Arc<dyn GuestAgent>,
    /// What the guest holds on its interface, read under the mode its
    /// snapshot was addressed in.
    pub identity: Option<NetworkIdentity>,
    pub cow_handle: Option<CowHandle>,
    /// Whether a pre-warmed slot served this restore.
    pub pool_hit: bool,
    pub timings: RestoreTimings,
}

/// Phase clocks for the completion log: restore latency is a product metric
/// (CORE-75) and the breakdown is what makes a regression attributable. A
/// pool hit pre-executed the spawn and staging phases, so those two collapse
/// and the log reports them honestly as ~0 rather than faking them.
pub struct RestoreTimings {
    pub prepared: Instant,
    pub staged: Instant,
    pub loaded: Instant,
    pub guest_cfg: Instant,
}

/// A restore that failed before its commit, carrying whatever it had already
/// acquired so the caller can unwind it (`rollback_restore`).
pub struct RestoreFailure {
    pub error: VmmError,
    pub prepared: Option<Arc<dyn PreparedVm>>,
    pub cow_handle: Option<CowHandle>,
}

/// Restore the VM: claim or prepare, stage, load, configure the guest, and
/// journal what the computer now owns.
///
/// Every failure returns [`RestoreFailure`] rather than unwinding here: a
/// pre-commit restore failure is rolled back by force-removing the whole
/// reservation, which is the caller's transaction to end.
pub async fn restore_vm(inputs: RestoreVm<'_>) -> std::result::Result<RestoredVm, RestoreFailure> {
    let RestoreVm {
        new_id,
        snap_meta,
        lease,
        nic,
        net_invariant,
        vm_dir,
        jailer,
        instance,
        claimed,
        config,
        cow_manager,
        driver,
        network,
        agents,
    } = inputs;

    let fc_cfg = &config.firecracker;

    // Track resources that need cleanup if anything between this point
    // and the final instance registration fails:
    //
    // - `pending_cow`: a CowHandle has no Drop impl, so a `?` propagating
    //   the error would silently leak the dm device + loop + COW file.
    // On success, the CoW handle is moved onto the ComputerRuntime.
    let mut pending_cow: Option<CowHandle> = None;

    // CORE-78: a pre-warmed slot has already executed the spawn and
    // staging blocks below; claiming one leaves LoadSnapshot + guest
    // reconfiguration as the only restore work. From the claim on, the
    // slot's resources are owned by this restore and unwind through
    // rollback_restore like freshly created ones.
    let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
    let pool_hit = claimed.is_some();
    // The id the jail is keyed by (the slot's for a pool hit), which is
    // also the id the driver prepared the VMM under.
    let (prepared, resource_owner, chroot, staged_checkpoint, t_prepared, t_staged) =
        if let Some(slot) = claimed {
            // Record the adopting sandbox's slot id first: failure cleanup
            // and crash reconciliation key the chroot and dm/CoW teardown
            // on it (see release_runtime_resources / sweep_orphans).
            instance.lock().unwrap().pool_slot_id = Some(slot.slot_id.clone());
            let handover = sandbox::reconcile::SandboxStateRecord::new(
                new_id,
                sandbox::journaled_pid(&*slot.prepared),
                lease
                    .as_ref()
                    .map(|lease| JournaledLease::from_snapshot(lease, net_invariant)),
                slot.cow_handle.as_ref(),
                config,
                None,
            )
            .map(|record| record.with_pool_slot(Some(&slot.slot_id)))
            .and_then(|record| sandbox::reconcile::write_state_record(vm_dir, &record));
            let PreparedSlot {
                slot_id,
                prepared: slot_prepared,
                cow_handle,
                image,
                vm_dir: slot_vm_dir,
            } = slot;
            pending_cow = cow_handle;
            match handover {
                Ok(()) => {
                    // Only now is the slot's own journal superseded: the
                    // adopted record is durable under the sandbox id. The
                    // crash window where both journals exist is safe — the
                    // startup sweep is idempotent over already-released
                    // resources. Clearing BEFORE the adopted write is
                    // confirmed would open the opposite window: a crash
                    // with NEITHER journal, leaving the slot-keyed FC,
                    // chroot, and CoW invisible to reconciliation.
                    if let Err(error) = sandbox::reconcile::clear_state_record(&slot_vm_dir) {
                        warn!(
                            sandbox_id = %new_id,
                            slot_id = %slot_id,
                            error = %error,
                            "claimed slot journal not cleared; the startup sweep will reconcile it"
                        );
                    } else if let Err(error) = tokio::fs::remove_dir_all(&slot_vm_dir).await
                        && error.kind() != std::io::ErrorKind::NotFound
                    {
                        warn!(
                            sandbox_id = %new_id,
                            slot_id = %slot_id,
                            error = %error,
                            "claimed slot runtime dir not removed"
                        );
                    }
                }
                Err(error) => {
                    // Keep the slot journal: it is the only durable record
                    // of the slot-keyed resources if this rollback gets
                    // interrupted.
                    return Err(RestoreFailure {
                        error,
                        prepared: Some(slot_prepared),
                        cow_handle: pending_cow,
                    });
                }
            }
            // Both phases were pre-executed by the slot; the timestamps
            // collapse so the completion log reports them honestly as ~0.
            let t_claimed = std::time::Instant::now();
            let chroot = chroot_root(&fc_cfg.binary, base, &slot_id);
            (slot_prepared, slot_id, chroot, image, t_claimed, t_claimed)
        } else {
            // Each jailer restore owns a distinct chroot; the driver's
            // prepared VMM spawns into it.
            let cr = chroot_root(&fc_cfg.binary, base, new_id);
            let spawned: Result<Arc<dyn PreparedVm>> = async {
                let prepared = sandbox::prepare_capability(driver)
                    .prepare(
                        &VmId::new(new_id)?,
                        &IsolationSpec::try_from(jailer)?,
                        vm_dir,
                    )
                    .await?;
                Ok(Arc::from(prepared))
            }
            .await;
            let spawned_prepared = match spawned {
                Ok(spawned) => spawned,
                Err(error) => {
                    return Err(RestoreFailure {
                        error,
                        prepared: None,
                        cow_handle: None,
                    });
                }
            };

            let pid = sandbox::journaled_pid(&*spawned_prepared);
            let journal = |cow: Option<&CowHandle>| {
                sandbox::reconcile::SandboxStateRecord::new(
                    new_id,
                    pid,
                    lease
                        .as_ref()
                        .map(|lease| JournaledLease::from_snapshot(lease, net_invariant)),
                    cow,
                    config,
                    None,
                )
                .and_then(|record| sandbox::reconcile::write_state_record(vm_dir, &record))
            };
            if let Err(error) = journal(None) {
                return Err(RestoreFailure {
                    error,
                    prepared: Some(Arc::clone(&spawned_prepared)),
                    cow_handle: None,
                });
            }

            let t_prepared = std::time::Instant::now();

            // In jailer mode the restored FC process also runs inside a
            // chroot and cannot access the catalog's host-absolute paths.
            // Stage the snapshot files into the new sandbox's chroot and use
            // chroot-relative paths.
            let setup_result: Result<CheckpointImage> = async {
                let jc = jailer;

                // Stage kernel (always hard-linked or copied, ~16MB).
                if let Some(k) = snap_meta.kernel_path.as_deref() {
                    stage_kernel_for_jailer(&cr, k, jc.uid, jc.gid).await?;
                }

                // Stage rootfs: dm-snapshot + mknod with full-copy fallback,
                // mirroring the boot path so restored sandboxes get the same
                // CoW semantics (block-level template sharing, sparse COW).
                if let Some(r) = snap_meta.rootfs_path.as_deref() {
                    match stage_rootfs_cow_or_copy(
                        cow_manager,
                        &cr,
                        new_id,
                        r,
                        jc.uid,
                        jc.gid,
                        &journal,
                    )
                    .await
                    {
                        Ok(cow) => pending_cow = cow,
                        Err(StageError { error, cow_handle }) => {
                            pending_cow = cow_handle;
                            return Err(error);
                        }
                    }
                }

                // Stage vmstate + mem into the chroot. Both are read-only to
                // FC (mem is mapped MAP_PRIVATE on load), so the root jailer
                // hard-links them instead of copying — the mem file is the
                // sandbox's full memory size (CORE-75).
                let files = SnapshotFiles {
                    id: &snap_meta.id,
                    vmstate: &snap_meta.vmstate_path,
                    mem: snap_meta.mem_path.as_deref(),
                };
                stage_snapshot_files(&cr, &files, jc.uid, jc.gid).await?;
                Ok(sandbox::checkpoint_image(
                    cr.join("snapshots").join(&snap_meta.id),
                    &snap_meta.format,
                ))
            }
            .await;

            let image = match setup_result {
                Ok(image) => image,
                Err(error) => {
                    return Err(RestoreFailure {
                        error,
                        prepared: Some(Arc::clone(&spawned_prepared)),
                        cow_handle: pending_cow,
                    });
                }
            };
            (
                spawned_prepared,
                new_id.to_owned(),
                cr,
                image,
                t_prepared,
                std::time::Instant::now(),
            )
        };

    // What the guest holds on its interface once this restore has
    // configured it, read under the mode its snapshot was addressed in.
    // Derived once — the agent and the re-address RPC must not disagree.
    let identity = lease
        .as_ref()
        .map(|lease| network.identity(lease, sandbox::attach_mode(snap_meta.net_invariant)));
    // An invariant guest already holds it, so its agent can be told
    // straight away. A legacy one still carries its origin's address
    // until the RPC below lands, and this host cannot name that — so
    // nothing is told how to reach it by address in the meantime.
    let settled_on_load = snap_meta.net_invariant.then(|| identity.clone()).flatten();

    // Load the image on the prepared VMM: the disk is the rootfs staged
    // into the owner's jail, eth0 lands on the fresh TAP.
    let loaded: Result<(Arc<dyn VmHandle>, Arc<dyn GuestAgent>)> = async {
        let restore = sandbox::spec::restore_spec(
            &resource_owner,
            &chroot,
            nic.clone(),
            IsolationSpec::try_from(jailer)?,
        )?;
        let handle: Arc<dyn VmHandle> =
            Arc::from(prepared.restore(&staged_checkpoint, restore).await?);
        let agent = agents.connect(Arc::clone(&handle), settled_on_load.as_ref())?;
        Ok((handle, agent))
    }
    .await;
    let (handle, agent) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            return Err(RestoreFailure {
                error,
                prepared: Some(prepared),
                cow_handle: pending_cow,
            });
        }
    };

    let t_loaded = std::time::Instant::now();

    // Clock sync after restore is DETACHED, mirroring the cold-boot path
    // (boot.rs): vm-agent re-syncs itself from ptp_kvm (/dev/ptp0) on
    // every accepted exec connection, so correct wall time no longer
    // depends on this RPC. It stays as belt-and-braces while ptp proves
    // itself in production, with the same 10 s cap and warn-only
    // semantics it always had — but awaiting it cost ~57 ms (mostly the
    // post-resume vsock connect settle), the dominant remainder of the
    // restore RPC (CORE-80).
    {
        let id = new_id.to_owned();
        let agent = Arc::clone(&agent);
        tokio::spawn(async move {
            match tokio::time::timeout(std::time::Duration::from_secs(10), agent.sync_clock()).await
            {
                Ok(Ok(ClockSync::Synced)) => {}
                Ok(Ok(ClockSync::AgentError(code))) => {
                    warn!(sandbox_id = %id, code, "agent could not set the clock after restore");
                }
                Ok(Err(e)) => warn!(sandbox_id = %id, "clock sync after restore failed: {e}"),
                Err(_) => warn!(sandbox_id = %id, "clock sync after restore timed out"),
            }
        });
    }

    // Re-address the guest to the fresh allocation. The restored kernel
    // still carries the origin's `ip=` boot configuration, so without
    // this the clone would squat the origin's IP on its new TAP and
    // never own the address its DNAT/expose mappings target. Unlike the
    // clock, a fresh-network restore without a working network is the
    // silent breakage `network_override` exists to prevent — fail the
    // restore rather than hand back a half-networked sandbox.
    let net_reconfig = async {
        // Invariant-addressed snapshot: the guest already holds the fixed
        // link-local identity and its resolv.conf already points at the
        // fixed gateway; the fresh TAP carries the new pool IP host-side.
        // Zero guest-side work (CORE-81). Legacy snapshots (flag absent /
        // false) keep the reconfig RPC below.
        if snap_meta.net_invariant {
            return Ok(());
        }
        let Some(identity) = identity.as_ref() else {
            return Ok(());
        };
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
        .map_err(|_| VmmError::Vsock("net reconfig after restore timed out".into()))
        .and_then(|r| r)
    };

    // The reconfig RPC is the only guest configuration still awaited —
    // and only by legacy snapshots; invariant snapshots return
    // immediately above. A legacy guest holds the pool address only
    // once it returns, so that is where its agent learns the identity.
    let configured = net_reconfig.await.and_then(|()| {
        if snap_meta.net_invariant {
            Ok(Arc::clone(&agent))
        } else {
            agents.connect(Arc::clone(&handle), identity.as_ref())
        }
    });
    let agent = match configured {
        Ok(agent) => agent,
        Err(error) => {
            return Err(RestoreFailure {
                error,
                prepared: Some(Arc::clone(&prepared)),
                cow_handle: pending_cow,
            });
        }
    };

    let t_guest_cfg = std::time::Instant::now();

    // Persist cleanup metadata before handing runtime resources to the
    // instance. A failed durable write aborts and unwinds every resource.
    let adopted_slot = instance.lock().unwrap().pool_slot_id.clone();
    let final_journal = sandbox::reconcile::SandboxStateRecord::new(
        new_id,
        sandbox::journaled_pid(&*prepared),
        lease
            .as_ref()
            .map(|lease| JournaledLease::from_snapshot(lease, net_invariant)),
        pending_cow.as_ref(),
        config,
        None,
    )
    .map(|record| record.with_pool_slot(adopted_slot.as_deref()))
    .and_then(|record| sandbox::reconcile::write_state_record(vm_dir, &record));
    if let Err(error) = final_journal {
        return Err(RestoreFailure {
            error,
            prepared: Some(Arc::clone(&prepared)),
            cow_handle: pending_cow,
        });
    }

    Ok(RestoredVm {
        prepared,
        handle,
        agent,
        identity,
        cow_handle: pending_cow,
        pool_hit,
        timings: RestoreTimings {
            prepared: t_prepared,
            staged: t_staged,
            loaded: t_loaded,
            guest_cfg: t_guest_cfg,
        },
    })
}
