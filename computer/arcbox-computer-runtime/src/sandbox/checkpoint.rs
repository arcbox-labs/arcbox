use super::reconcile::JournaledLease;
use super::record::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::types::action;
use super::*;

// The restore proper lives with the machine that names it
// (`Effect::SpawnRestore`); this module still drives it until R3 PR-F2 flips
// the manager onto the actor.
use crate::lifecycle::tasks::checkpoint::{CheckpointFailure, CheckpointRequest, checkpoint_impl};
use crate::lifecycle::tasks::restore::{
    RestoreFailure, RestoreTimings, RestoreVm, RestoredVm, restore_vm,
};

/// The image format the reference driver writes, for tests that seed the
/// catalog by hand. Production never names it: [`checkpoint_impl`] records
/// whatever format the driver's `CheckpointImage` reports, and a restore
/// hands that back to the driver, which refuses any other.
#[cfg(test)]
pub(super) const CHECKPOINT_FORMAT: &str = arcbox_fc_driver::CHECKPOINT_FORMAT;

/// Parameters for the internal restore path
/// ([`SandboxManager::restore_from_snapshot`]), shared by the Restore RPC
/// and internal callers.
pub(super) struct RestoreRequest {
    /// Source checkpoint id.
    pub(super) snapshot_id: String,
    /// Assign a fresh TAP + IP to the restored sandbox.
    pub(super) network_override: bool,
    /// Spec journaled with the provision intent and installed on the
    /// instance. Restore consumes its identity fields (`id`, `labels`,
    /// `ttl_seconds`) — plus, on the warm-create origin, the initial
    /// workload fields; the boot-recipe fields are ignored — the snapshot
    /// carries the boot state.
    pub(super) spec: SandboxSpec,
    /// Which API surface this restore serves; decides the event contract.
    pub(super) origin: RestoreOrigin,
}

/// Which caller a restore serves.
pub(super) enum RestoreOrigin {
    /// The Restore RPC: the sandbox announces itself with READY alone.
    Restore,
    /// The warm-create reroute (CORE-77): watchers must see the Create
    /// contract — CREATED then READY — and the spec's initial `cmd` runs
    /// after Ready exactly as a cold boot would run it.
    WarmCreate,
}

impl SandboxManager {
    /// Rootfs images that existing snapshots or catalog templates need to
    /// stay restorable/bootable.
    ///
    /// Exposed so whoever owns the converted-rootfs cache can pin them; see
    /// [`SnapshotCatalog::referenced_rootfs_paths`] and
    /// [`TemplateCatalog::rootfs_paths`](crate::template_catalog::TemplateCatalog::rootfs_paths).
    /// The union matters: a non-prewarmed template pins no snapshot, so
    /// without the catalog half a vm-agent update plus a create for the same
    /// docker layer would sweep the template's ext4 as superseded.
    pub fn pinned_rootfs_paths(&self) -> Result<std::collections::BTreeSet<PathBuf>> {
        let mut pinned = self.snapshots.referenced_rootfs_paths()?;
        pinned.extend(self.templates.rootfs_paths()?);
        Ok(pinned)
    }

    /// Checkpoint a `Ready` sandbox into the snapshot catalog.
    pub async fn checkpoint_sandbox(
        &self,
        sandbox_id: &SandboxId,
        name: String,
        labels: HashMap<String, String>,
    ) -> Result<CheckpointInfo> {
        self.check_reconcile()?;
        // The pause machinery owns this name: Remove deletes every snapshot
        // carrying it, so a user checkpoint must not squat on it (CORE-21).
        if name == super::pause::PAUSE_SNAPSHOT_NAME {
            return Err(VmmError::Config(format!(
                "checkpoint name {:?} is reserved for sandbox pause",
                super::pause::PAUSE_SNAPSHOT_NAME
            )));
        }
        // The warm-create cache (CORE-77) trusts its label as the lookup
        // key; a caller must not be able to plant one.
        super::warm::reject_reserved_labels(&labels)?;
        match checkpoint_impl(
            &self.instances,
            &self.snapshots,
            sandbox_id,
            CheckpointRequest {
                name,
                labels,
                expected_state: SandboxState::Ready,
                resume_after: true,
            },
        )
        .await
        {
            Ok(info) => Ok(info),
            Err(CheckpointFailure::Recoverable(error)) => Err(error),
            // A guest the driver could not resume is unusable: fail the
            // sandbox the way a failed boot does rather than leave it Ready
            // with every dial waiting out the budget.
            Err(CheckpointFailure::Frozen(error)) => {
                self.fail_frozen_sandbox(sandbox_id, &error).await;
                Err(error)
            }
        }
    }

    /// Fail a sandbox whose guest is frozen with no way back (see
    /// [`CheckpointFailure::Frozen`]): kill and reap the VMM, release its
    /// runtime resources, record and publish `Failed`.
    async fn fail_frozen_sandbox(&self, id: &SandboxId, error: &VmmError) {
        let Some((generation, vm_dir)) = self.instances.read().unwrap().get(id).map(|arc| {
            let inst = arc.lock().unwrap();
            (inst.record_generation, inst.vm_dir.clone())
        }) else {
            return;
        };
        super::boot::fail_live_sandbox(
            id,
            generation,
            &error.to_string(),
            &vm_dir,
            &self.instances,
            &self.network,
            &self.config,
            &self.cow_manager,
            &self.records,
            &self.events_tx,
        )
        .await;
        error!(sandbox_id = %id, error = %error, "checkpoint left the guest frozen; sandbox failed");
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "restore rollback owns every partially acquired resource"
    )]
    async fn rollback_restore(
        &self,
        id: &str,
        reservation: IdReservation,
        error: VmmError,
        prepared: Option<Arc<dyn PreparedVm>>,
        network: Option<NetworkLease>,
        net_invariant: bool,
        cow_handle: Option<CowHandle>,
    ) -> VmmError {
        let arc = reservation.instance();
        let (vm_dir, pool_slot_id) = {
            let inst = arc.lock().unwrap();
            (inst.vm_dir.clone(), inst.pool_slot_id.clone())
        };
        let journal_error = super::reconcile::SandboxStateRecord::new(
            id,
            prepared.as_deref().and_then(super::journaled_pid),
            network
                .as_ref()
                .map(|lease| JournaledLease::from_snapshot(lease, net_invariant)),
            cow_handle.as_ref(),
            &self.config,
            None,
        )
        .map(|record| record.with_pool_slot(pool_slot_id.as_deref()))
        .and_then(|record| super::reconcile::write_state_record(&vm_dir, &record))
        .err();
        {
            let mut inst = arc.lock().unwrap();
            inst.state = SandboxState::Failed;
            inst.error = Some(error.to_string());
            inst.prepared = prepared;
            inst.network = network;
            inst.cow_handle = cow_handle;
        }
        reservation.commit();

        let cleanup_error = super::cleanup::remove_sandbox_impl(
            id,
            true,
            &arc,
            &self.instances,
            &self.network,
            &self.events_tx,
            &self.config,
            &self.cow_manager,
            &self.records,
            &self.snapshots,
        )
        .await
        .err();
        match (journal_error, cleanup_error) {
            (None, None) => error,
            (journal, cleanup) => VmmError::Unavailable(format!(
                "{error}; restore rollback incomplete{}{}",
                journal
                    .map(|journal| format!("; journal: {journal}"))
                    .unwrap_or_default(),
                cleanup
                    .map(|cleanup| format!("; cleanup: {cleanup}"))
                    .unwrap_or_default()
            )),
        }
    }

    /// Restore a new sandbox from a previously created checkpoint.
    ///
    /// The restored sandbox starts in `Ready` state immediately.
    ///
    /// Returns `(sandbox_id, ip_address)`.
    pub async fn restore_sandbox(&self, spec: RestoreSandboxSpec) -> Result<(SandboxId, String)> {
        self.restore_sandbox_keyed(spec, &Uuid::new_v4().to_string())
            .await
    }

    /// Restore with a stable request key for durable replay.
    pub async fn restore_sandbox_keyed(
        &self,
        spec: RestoreSandboxSpec,
        restore_key: &str,
    ) -> Result<(SandboxId, String)> {
        let RestoreSandboxSpec {
            id,
            snapshot_id,
            labels,
            network_override,
            ttl_seconds,
        } = spec;
        self.restore_from_snapshot(
            RestoreRequest {
                snapshot_id,
                network_override,
                spec: SandboxSpec {
                    id,
                    labels,
                    ttl_seconds,
                    ..Default::default()
                },
                origin: RestoreOrigin::Restore,
            },
            restore_key,
        )
        .await
    }

    /// Internal restore path shared by the Restore RPC and internal callers.
    pub(super) async fn restore_from_snapshot(
        &self,
        request: RestoreRequest,
        restore_key: &str,
    ) -> Result<(SandboxId, String)> {
        // Gate on the startup sweep before touching per-id resources (see
        // create_sandbox / await_reconcile).
        self.await_reconcile().await?;

        let caller_supplied_id = request.spec.id.as_ref().is_some_and(|id| !id.is_empty());
        let new_id = request
            .spec
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        super::validate_new_sandbox_id(&new_id, &self.config)?;
        // The snapshot id is caller-supplied and flows into snapshot dir paths
        // (create_dir_all / copy / remove_dir_all) — validate it too, or a
        // `../` id would traverse out of the snapshots directory.
        super::validate_id("snapshot id", &request.snapshot_id)?;

        // Phase clocks for the completion log: restore latency is a product
        // metric (CORE-75) and the breakdown is what makes a regression
        // attributable.
        let restore_started = std::time::Instant::now();

        if caller_supplied_id
            && let Some(outcome) = self.records.replay_provision(&new_id, restore_key)?
        {
            return Ok((new_id, outcome.ip_address));
        }

        // Resolve read-only prerequisites before claiming durable ownership.
        // Once the intent exists, every failure goes through rollback.
        let snap_meta = self.snapshots.find_by_id(&request.snapshot_id)?;
        // A pause checkpoint pairs with its sandbox's retained disk overlay;
        // cloning it with a fresh overlay would silently discard that disk
        // state. Resume is the only consumer (CORE-21).
        if snap_meta.name.as_deref() == Some(super::pause::PAUSE_SNAPSHOT_NAME) {
            return Err(VmmError::WrongState {
                id: request.snapshot_id.clone(),
                expected: "a user checkpoint".into(),
                actual: "the internal pause checkpoint of a paused sandbox".into(),
            });
        }
        let jailer = self.config.firecracker.jailer.as_ref().ok_or_else(|| {
            VmmError::Config(
                "checkpoint restore requires jailer isolation; direct mode embeds shared origin paths"
                    .into(),
            )
        })?;

        // Reserve the id atomically so a concurrent restore/create of the same
        // id fails fast with AlreadyExists instead of both proceeding to set up
        // the deterministic per-id CoW/dm/TAP resources and corrupting each
        // other (see reserve_id). Unwound on every error path via Drop.
        let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
            .join("sandboxes")
            .join(&new_id);
        let mut restore_spec = request.spec.clone();
        restore_spec.id = Some(new_id.clone());
        let reservation = super::reserve_id(
            &self.instances,
            &new_id,
            SandboxInstance::new(new_id.clone(), restore_spec.clone(), None, vm_dir.clone()),
        )?;
        let record = match self
            .records
            .provision_intent(&new_id, restore_key, restore_spec)?
        {
            ProvisionIntent::Created(record) | ProvisionIntent::Resume(record) => record,
            ProvisionIntent::Replay(record) => {
                let outcome = record
                    .provision_outcome
                    .ok_or_else(|| VmmError::WrongState {
                        id: new_id.clone(),
                        expected: "a persisted restore outcome".into(),
                        actual: "none".into(),
                    })?;
                return Ok((new_id, outcome.ip_address));
            }
            ProvisionIntent::Blocked(_) => return Err(VmmError::AlreadyExists(new_id)),
        };
        let generation = record.generation;
        // Kept out of the instance for the warm-create origin's initial
        // workload; the durable copy is redacted once the record leaves the
        // provisioning phases.
        let effective_spec = record.effective_spec.clone();
        {
            let arc = reservation.instance();
            let mut instance = arc.lock().unwrap();
            instance.record_generation = Some(generation);
            instance.labels.clone_from(&record.effective_spec.labels);
            instance.spec = record.effective_spec;
            instance.created_at = record.created_at;
            instance.ttl_deadline = record.ttl_deadline;
        }

        // Reserve network metadata, journal it, then materialize the TAP. This
        // mirrors Create so an agent crash never leaves an unowned interface.
        let lease = if request.network_override {
            match self
                .network
                .reserve(
                    &VmId::new(new_id.as_str())?,
                    super::sandbox_network_policy(),
                )
                .await
            {
                Ok(lease) => Some(lease),
                Err(error) => {
                    let abort = self.records.abort_provision(&new_id, generation)?;
                    if let Some(durability_error) = abort.durability_error {
                        return Err(VmmError::Unavailable(format!(
                            "{error}; restore rollback is visible, but durability is unconfirmed: {durability_error}"
                        )));
                    }
                    return Err(error.into());
                }
            }
        } else {
            None
        };
        let ip_address = lease
            .as_ref()
            .map(|lease| lease.ip.to_string())
            .unwrap_or_default();
        // Every journal this restore writes records the lease the way the
        // `activate` below attaches it: from the snapshot's own flag, never
        // from a constant. One binding so the two cannot drift.
        let net_invariant = snap_meta.net_invariant;
        // The NIC is tracked apart from the lease: the lease is owed back
        // to the pool from `reserve` on, so the rollback below must see one
        // whose TAP a failed journal write meant was never built.
        let mut nic: Option<NicSpec> = None;
        let setup = async {
            super::reconcile::create_runtime_dir(&vm_dir)?;
            let cleanup_record = super::reconcile::SandboxStateRecord::new(
                &new_id,
                None,
                lease
                    .as_ref()
                    .map(|lease| JournaledLease::from_snapshot(lease, net_invariant)),
                None,
                &self.config,
                None,
            )?;
            super::reconcile::write_state_record(&vm_dir, &cleanup_record)?;
            if let Some(lease) = &lease {
                // The restored guest keeps the addressing its snapshot baked:
                // invariant snapshots pair with an invariant TAP (host-side
                // NAT, no guest work); legacy snapshots keep the legacy TAP
                // shape and are re-addressed over the reconfig RPC below.
                nic = Some(
                    self.network
                        .activate(lease, super::attach_mode(snap_meta.net_invariant))
                        .await?,
                );
            }
            Ok::<_, VmmError>(())
        }
        .await;
        if let Err(error) = setup {
            return Err(self
                .rollback_restore(
                    &new_id,
                    reservation,
                    error,
                    None,
                    lease,
                    snap_meta.net_invariant,
                    None,
                )
                .await);
        }
        // The restore proper (`Effect::SpawnRestore`), which unwinds through
        // the rollback below rather than in place: the id and its request key
        // must be free again for a retry, and a warm create must be able to
        // fall back to a cold boot.
        let claimed = self.claim_restore_slot(&request.snapshot_id);
        let restored = restore_vm(RestoreVm {
            new_id: &new_id,
            snap_meta: &snap_meta,
            lease: lease.as_ref(),
            nic,
            net_invariant,
            vm_dir: &vm_dir,
            jailer,
            instance: &reservation.instance(),
            claimed,
            config: &self.config,
            cow_manager: &self.cow_manager,
            driver: &*self.driver,
            network: &*self.network,
            agents: &*self.agent,
        })
        .await;
        let RestoredVm {
            prepared,
            handle,
            agent,
            identity,
            cow_handle: mut pending_cow,
            pool_hit,
            timings,
        } = match restored {
            Ok(restored) => restored,
            Err(RestoreFailure {
                error,
                prepared,
                cow_handle,
            }) => {
                return Err(self
                    .rollback_restore(
                        &new_id,
                        reservation,
                        error,
                        prepared,
                        lease.clone(),
                        snap_meta.net_invariant,
                        cow_handle,
                    )
                    .await);
            }
        };
        let RestoreTimings {
            prepared: t_prepared,
            staged: t_staged,
            loaded: t_loaded,
            guest_cfg: t_guest_cfg,
        } = timings;

        let outcome = SandboxProvisionOutcome {
            ip_address: ip_address.clone(),
        };
        let ready_commit = match self.records.transition(
            &new_id,
            generation,
            SandboxTransition::ReadyWithOutcome(outcome),
        ) {
            Ok(commit) => commit,
            Err(error) => {
                return Err(self
                    .rollback_restore(
                        &new_id,
                        reservation,
                        error,
                        Some(Arc::clone(&prepared)),
                        lease.clone(),
                        snap_meta.net_invariant,
                        pending_cow,
                    )
                    .await);
            }
        };

        let warm_create = matches!(request.origin, RestoreOrigin::WarmCreate);

        // Populate the reserved instance in place, then commit the reservation
        // so it survives (the placeholder inserted by reserve_id is otherwise
        // removed on drop). All resources are now tracked on the instance and
        // torn down via remove_sandbox_impl.
        let arc = reservation.instance();
        {
            let mut inst = arc.lock().unwrap();
            inst.network.clone_from(&lease);
            inst.prepared = Some(prepared);
            inst.handle = Some(handle);
            inst.net_identity.clone_from(&identity);
            inst.cow_handle = pending_cow.take();
            inst.net_invariant = snap_meta.net_invariant;
            // A warm create that owes the spec's initial cmd stays
            // `Starting` so the workload slot is reserved for that cmd —
            // an Inspect-polling client must not see Ready here and steal
            // it with an exec (the cold-boot tail has the same guard).
            inst.state = if warm_create && !effective_spec.cmd.is_empty() {
                SandboxState::Starting
            } else {
                SandboxState::Ready
            };
            inst.ready_at = Some(Utc::now());
        }
        reservation.commit();

        if warm_create {
            // The Create event contract: watchers see CREATED then READY for
            // this id in that order, exactly as a cold boot emits them.
            let _ = self
                .events_tx
                .send(SandboxEvent::new(&new_id, action::CREATED));
        }

        // Initial cmd + ready probe on a warm create (CORE-107): READY
        // carries the same promise as a probed cold boot. The cmd starts
        // first through the reserved Initial claim (it is the only listener
        // source); a prewarmed snapshot's listener lives in the memory
        // image, so the port form passes near-instantly there. Unlike the
        // cold-boot path, this runs POST-commit — the cmd needs the
        // populated instance, and the restore transaction's rollback
        // machinery ends at reservation.commit — so a probe failure is
        // unwound with the post-commit verb (force remove), and the
        // caller's create falls back to a cold boot that probes from
        // scratch — when the teardown succeeded; a failed teardown leaves
        // the record Removing, which blocks the same-id retry until startup
        // reconcile clears it (the warn below carries the id). A crash
        // mid-probe leaves a durable Ready record whose FC process is dead;
        // startup reconcile normalizes it, and the create RPC never
        // returned, so no client ever saw an unprobed READY.
        let cmd_started = if warm_create && !effective_spec.cmd.is_empty() {
            super::boot::run_initial_cmd(
                &new_id,
                effective_spec.clone(),
                agent.as_ref(),
                &self.instances,
                &self.events_tx,
            )
            .await
        } else {
            false
        };
        if warm_create
            && let Some(probe) = effective_spec.ready_probe.clone()
            && let Err(probe_error) = super::boot::run_ready_probe(&probe, agent.as_ref()).await
        {
            let message = format!("ready probe failed after restore: {probe_error}");
            if let Err(remove_error) = self.remove_sandbox(&new_id, true).await {
                warn!(
                    sandbox_id = %new_id,
                    error = %remove_error,
                    "failed to tear down the probe-failed restore"
                );
            }
            return Err(VmmError::FailedPrecondition(message));
        }
        let _ = self
            .events_tx
            .send(SandboxEvent::new(&new_id, action::READY));

        // Arm the TTL expiry timer if a deadline was set — identity-guarded
        // so a stale timer can't remove a same-id sandbox re-created after
        // this one (see expire_sandbox), re-armable via SetLifecycle.
        self.arm_ttl_timer(&new_id);

        // On a pool hit, spawn_ms covers records + network + the claim
        // itself (the phases that still ran) and stage_ms is genuinely 0 —
        // the log never fakes the pre-executed phases. guest_cfg_ms bills
        // only what stayed awaited (the legacy net-reconfig RPC): invariant
        // snapshots await nothing and honestly read ~0, since the detached
        // clock sync is not restore latency.
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        info!(
            sandbox_id = %new_id,
            snapshot_id = %request.snapshot_id,
            pool_hit,
            warm_create,
            spawn_ms = ms(t_prepared.duration_since(restore_started)),
            stage_ms = ms(t_staged.duration_since(t_prepared)),
            load_ms = ms(t_loaded.duration_since(t_staged)),
            guest_cfg_ms = ms(t_guest_cfg.duration_since(t_loaded)),
            total_ms = ms(restore_started.elapsed()),
            "sandbox restored from checkpoint"
        );

        // Populate/refill the pool for this snapshot in the background:
        // the successful restore is what makes it eligible for pooling.
        self.spawn_pool_refill(&request.snapshot_id);

        // A failed initial start released the claim (the sandbox is Ready);
        // give the cmd its one ordinary post-READY attempt, exactly as the
        // cold-boot tail does. Kept off the timing log above — the workload
        // is the user's, not restore's.
        if warm_create && !cmd_started && !effective_spec.cmd.is_empty() {
            let _ = super::boot::run_initial_cmd(
                &new_id,
                effective_spec,
                agent.as_ref(),
                &self.instances,
                &self.events_tx,
            )
            .await;
        }

        if let Some(error) = ready_commit.durability_error {
            return Err(VmmError::AckUnconfirmed {
                id: new_id,
                detail: error,
            });
        }
        Ok((new_id, ip_address))
    }

    /// List checkpoints, optionally filtered by origin sandbox ID.
    ///
    /// Internal pause checkpoints are hidden: they are lifecycle state, not
    /// user-owned snapshots, and deleting one would strand a paused sandbox.
    /// Template-owned snapshots (CORE-107) are hidden for the same reason —
    /// they surface via `TemplateService.Get/List`, not as user checkpoints.
    pub fn list_checkpoints(&self, sandbox_id: Option<&str>) -> Result<Vec<CheckpointSummary>> {
        let infos = match sandbox_id {
            Some(sid) => self.snapshots.list(sid)?,
            None => self.snapshots.list_all()?,
        };
        Ok(infos
            .into_iter()
            .filter(|s| s.name.as_deref() != Some(super::pause::PAUSE_SNAPSHOT_NAME))
            .filter(|s| {
                !s.labels
                    .contains_key(crate::template_catalog::TEMPLATE_LABEL)
            })
            .map(|s| CheckpointSummary {
                id: s.id,
                sandbox_id: s.vm_id,
                name: s.name.unwrap_or_default(),
                labels: s.labels,
                snapshot_dir: s
                    .vmstate_path
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                created_at: s.created_at.to_rfc3339(),
            })
            .collect())
    }

    /// Delete a checkpoint by its ID, tearing down any pre-warmed restore
    /// slots staged from it first.
    ///
    /// Internal pause checkpoints are refused — deleting one would strand
    /// its paused sandbox; they die with the sandbox via `Remove`.
    /// Template-owned snapshots (CORE-107) are refused while the catalog
    /// still references them — they are reclaimed through template deletion.
    /// A labeled snapshot no record references (orphaned by a failed
    /// post-commit cleanup) is deliberately deletable: this is the operator's
    /// only recovery path, since `list_checkpoints` hides it and
    /// `delete_template` answers `TemplateNotFound`.
    pub async fn delete_checkpoint(&self, snapshot_id: &str) -> Result<()> {
        let meta = self.snapshots.find_by_id(snapshot_id)?;
        if meta.name.as_deref() == Some(super::pause::PAUSE_SNAPSHOT_NAME) {
            return Err(VmmError::WrongState {
                id: snapshot_id.to_owned(),
                expected: "a user checkpoint".into(),
                actual: "the internal pause checkpoint of a paused sandbox".into(),
            });
        }
        // Fail closed on a catalog scan error: never delete what an
        // unreadable catalog might still reference.
        if let Some(owner) = meta.labels.get(crate::template_catalog::TEMPLATE_LABEL)
            && self.templates.references_snapshot(snapshot_id)?
        {
            return Err(VmmError::FailedPrecondition(format!(
                "snapshot {snapshot_id} is owned by template {owner}; delete the template instead"
            )));
        }
        self.drain_pool(Some(snapshot_id)).await;
        self.snapshots.delete_by_id(snapshot_id).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{
        FrozenOnCheckpoint, assert_failed_and_released, expect_err, fake_manager, live_sandbox,
        live_sandbox_with,
    };
    use super::super::types::action;
    use super::*;

    /// A capture that fails and leaves the guest running (here: the fake's
    /// capture succeeds, the catalog commit fails, the fake resumed) is an
    /// error the caller can retry: the sandbox stays Ready with everything
    /// it holds.
    #[tokio::test]
    async fn a_recoverable_checkpoint_failure_leaves_the_sandbox_ready() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, driver, probe) = fake_manager(dir.path()).await;
        let (instance, handle) = live_sandbox(&manager, &driver, "keeps").await;

        expect_err(
            manager
                .checkpoint_sandbox(&"keeps".to_owned(), "user".into(), HashMap::new())
                .await,
            "a checkpoint whose commit fails",
        );

        let inst = instance.lock().unwrap();
        assert_eq!(inst.state, SandboxState::Ready);
        assert!(inst.prepared.is_some() && inst.handle.is_some());
        assert!(inst.cow_handle.is_some());
        assert!(
            inst.network.is_some(),
            "the lease survives a failed capture"
        );
        assert_eq!(handle.state(), arcbox_vm_driver::VmState::Running);
        assert_eq!(probe.teardown_count(), 0);
    }

    /// A capture whose guest stayed frozen — the driver's own resume failed
    /// — has no way back: the Checkpoint RPC fails the sandbox the way a
    /// failed boot does instead of leaving it Ready with a guest that never
    /// runs again.
    #[tokio::test]
    async fn a_checkpoint_that_leaves_the_guest_frozen_fails_and_releases_the_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, driver, probe) = fake_manager(dir.path()).await;
        let (instance, handle) =
            live_sandbox_with(&manager, &driver, "frozen", FrozenOnCheckpoint::over).await;
        let mut events = manager.subscribe_events();

        let error = expect_err(
            manager
                .checkpoint_sandbox(&"frozen".to_owned(), "user".into(), HashMap::new())
                .await,
            "a checkpoint that froze the guest",
        );
        assert!(
            error.to_string().contains("could not be resumed"),
            "the driver's error is the reported one: {error}"
        );

        assert_failed_and_released(&manager, &instance, &probe, "frozen").await;
        assert!(
            matches!(handle.state(), arcbox_vm_driver::VmState::Exited(_)),
            "the frozen guest is killed: {}",
            handle.state()
        );
        let mut actions = Vec::new();
        while let Ok(event) = events.try_recv() {
            actions.push(event.action);
        }
        assert_eq!(actions, [action::FAILED]);
    }
}
