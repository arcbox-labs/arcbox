//! The two restores: bringing a checkpointed computer up under a new id, and
//! bringing a paused one back in place.
//!
//! Both hand back an agent and leave every resource they acquired on the
//! computer. Neither ends its own transaction: a restore that fails is
//! force-removed by the machine (the id and its request key must be free
//! again so a warm create can fall back to a cold boot), and a resume that
//! fails parks back at `Paused` — or, when it could not unwind, fails, which
//! is what [`TaskFailure::stranded`] says.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};

use super::{ComputerFlows, Launch, RestoreLaunch, warm_create};
use crate::agent::GuestAgent;
use crate::error::VmmError;
use crate::lifecycle::event::RestoreOrigin;
use crate::lifecycle::tasks::restore::{RestoreTimings, RestoreVm, RestoredVm, restore_vm};
use crate::lifecycle::tasks::resume::restore_paused;
use crate::lifecycle::tasks::{TaskFailure, TaskResult};
use crate::sandbox::reconcile::{JournaledLease, SandboxStateRecord, write_state_record};
use crate::sandbox::record::SandboxProvisionOutcome;
use crate::sandbox::{journaled_api_socket, journaled_pid, pool};

impl ComputerFlows {
    /// The restore proper: claim a pre-warmed slot or prepare and stage a
    /// fresh one, load the image, re-address the guest, journal what the
    /// computer now owns.
    pub(super) async fn restore_vm(
        &self,
        origin: RestoreOrigin,
    ) -> TaskResult<(Arc<dyn GuestAgent>, SandboxProvisionOutcome)> {
        let Launch::Restore(launch) = self.take_launch() else {
            return Err(self.wrong_launch("restore"));
        };
        let RestoreLaunch {
            snapshot_id,
            snap_meta,
            lease,
            nic,
            started,
        } = *launch;
        let services = &self.services;
        let ip_address = lease
            .as_ref()
            .map(|lease| lease.ip.to_string())
            .unwrap_or_default();
        let vm_dir = self.computer.lock().unwrap().vm_dir.clone();
        let Some(jailer) = services.config.firecracker.jailer.clone() else {
            return Err(TaskFailure::recoverable(VmmError::Config(
                "checkpoint restore requires jailer isolation; direct mode embeds shared origin \
                 paths"
                    .into(),
            )));
        };

        let claimed = pool::claim_restore_slot(&services.pool, &services.cow_manager, &snapshot_id);
        let restored = restore_vm(RestoreVm {
            new_id: &self.id,
            snap_meta: &snap_meta,
            lease: lease.as_ref(),
            nic,
            net_invariant: snap_meta.net_invariant,
            vm_dir: &vm_dir,
            jailer: &jailer,
            instance: &self.computer,
            claimed,
            config: &services.config,
            cow_manager: &services.cow_manager,
            driver: &*services.driver,
            network: &*services.network,
            agents: &*services.agents,
        })
        .await;

        let RestoredVm {
            prepared,
            handle,
            agent,
            identity,
            cow_handle,
            pool_hit,
            timings,
        } = match restored {
            Ok(restored) => restored,
            // `rollback_restore`'s first half: journal what the failed
            // restore is still holding, then hand it to the computer so the
            // force-remove the machine drives can reclaim it. The journal is
            // what a crash *during* that teardown would be reconciled from,
            // so it is written before anything is torn down.
            Err(failure) => {
                let pool_slot_id = self.computer.lock().unwrap().pool_slot_id.clone();
                let journal = SandboxStateRecord::new(
                    &self.id,
                    failure.prepared.as_deref().and_then(journaled_pid),
                    lease
                        .as_ref()
                        .map(|lease| JournaledLease::from_snapshot(lease, snap_meta.net_invariant)),
                    failure.cow_handle.as_ref(),
                    &services.config,
                    None,
                )
                .map(|record| {
                    record
                        .with_api_socket(failure.prepared.as_deref().and_then(journaled_api_socket))
                        .with_pool_slot(pool_slot_id.as_deref())
                })
                .and_then(|record| write_state_record(&vm_dir, &record));
                if let Err(error) = journal {
                    warn!(sandbox_id = %self.id, %error, "the failed restore's journal was not written");
                }
                let mut computer = self.computer.lock().unwrap();
                computer.prepared = failure.prepared;
                computer.network = lease;
                computer.cow_handle = failure.cow_handle;
                computer.net_invariant = snap_meta.net_invariant;
                return Err(TaskFailure::recoverable(failure.error));
            }
        };

        {
            let mut computer = self.computer.lock().unwrap();
            computer.network = lease;
            computer.prepared = Some(prepared);
            computer.handle = Some(handle);
            computer.net_identity = identity;
            computer.cow_handle = cow_handle;
            computer.net_invariant = snap_meta.net_invariant;
            computer.ready_at = Some(Utc::now());
        }

        let RestoreTimings {
            prepared: t_prepared,
            staged: t_staged,
            loaded: t_loaded,
            guest_cfg: t_guest_cfg,
        } = timings;
        // On a pool hit, spawn_ms covers records + network + the claim itself
        // (the phases that still ran) and stage_ms is genuinely 0 — the log
        // never fakes the pre-executed phases. guest_cfg_ms bills only what
        // stayed awaited (the legacy net-reconfig RPC): invariant snapshots
        // await nothing and honestly read ~0, since the detached clock sync
        // is not restore latency.
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        info!(
            sandbox_id = %self.id,
            snapshot_id = %snapshot_id,
            pool_hit,
            warm_create = warm_create(origin),
            spawn_ms = ms(t_prepared.duration_since(started)),
            stage_ms = ms(t_staged.duration_since(t_prepared)),
            load_ms = ms(t_loaded.duration_since(t_staged)),
            guest_cfg_ms = ms(t_guest_cfg.duration_since(t_loaded)),
            total_ms = ms(started.elapsed()),
            "computer restored from checkpoint"
        );

        // Populate/refill the pool for this snapshot in the background: the
        // successful restore is what makes it eligible for pooling.
        pool::spawn_pool_refill(
            &services.pool,
            &services.driver,
            &services.config,
            &services.cow_manager,
            &services.snapshots,
            &snapshot_id,
        );

        Ok((agent, SandboxProvisionOutcome { ip_address }))
    }

    /// Bring a paused computer back in place, onto a fresh network.
    pub(super) async fn resume_vm(&self) -> TaskResult<Arc<dyn GuestAgent>> {
        let (snapshot_id, vm_dir, networked) = {
            let computer = self.computer.lock().unwrap();
            (
                computer.pause_snapshot_id.clone(),
                computer.vm_dir.clone(),
                computer.spec.network.mode != "none",
            )
        };
        let recoverable = TaskFailure::recoverable;
        let snapshot_id = snapshot_id.ok_or_else(|| {
            recoverable(VmmError::Snapshot(format!(
                "paused computer {} has no pause checkpoint recorded",
                self.id
            )))
        })?;
        let services = &self.services;
        let jailer = services.config.firecracker.jailer.clone().ok_or_else(|| {
            recoverable(VmmError::Config(
                "computer resume requires jailer isolation".into(),
            ))
        })?;
        let snap_meta = services
            .snapshots
            .find_by_id(&snapshot_id)
            .map_err(|error| recoverable(error.into()))?;

        let started = std::time::Instant::now();
        let resumed = restore_paused(
            &self.id,
            &jailer,
            &snap_meta,
            &vm_dir,
            networked,
            &services.config,
            &services.cow_manager,
            &*services.driver,
            &*services.network,
            &*services.agents,
        )
        .await
        .map_err(|failure| {
            if failure.unwound {
                TaskFailure::recoverable(failure.error)
            } else {
                TaskFailure::stranded(failure.error)
            }
        })?;

        {
            let mut computer = self.computer.lock().unwrap();
            computer.prepared = Some(resumed.prepared);
            computer.handle = Some(resumed.handle);
            computer.net_identity = resumed.net_identity;
            computer.network = resumed.network;
            computer.cow_handle = resumed.cow_handle;
            // Re-establish the guest's addressing mode from the checkpoint,
            // exactly as Restore does: a paused computer rebuilt by the
            // restart sweep has no live runtime to inherit it from, and a
            // later Checkpoint must record the guest's actual addressing
            // (CORE-81).
            computer.net_invariant = snap_meta.net_invariant;
            computer.paused_at = None;
            computer.pause_snapshot_id = None;
            computer.ready_at = Some(Utc::now());
        }

        // The checkpoint matched the disk *at pause time*; the computer will
        // now diverge, so it must not be restorable again. Deletion also
        // frees the memory-sized image.
        if let Err(error) = services.snapshots.delete_by_id(&snapshot_id) {
            warn!(
                sandbox_id = %self.id,
                snapshot_id = %snapshot_id,
                %error,
                "resumed, but deleting the pause checkpoint failed"
            );
        }
        info!(
            sandbox_id = %self.id,
            total_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "computer resumed from pause checkpoint"
        );
        let agent = self.agent().map_err(TaskFailure::recoverable)?;
        Ok(agent)
    }
}
