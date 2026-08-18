use super::reconcile::JournaledLease;
use super::record::{ProvisionIntent, SandboxProvisionOutcome};
use super::*;
use crate::lifecycle::tasks::CaptureSpec;

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
        self.mailbox(sandbox_id)?
            .ask(sandbox_id, |reply| Command::Checkpoint {
                spec: CaptureSpec { name, labels },
                reply,
            })
            .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "restore rollback owns every partially acquired resource"
    )]
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
        if self.config.firecracker.jailer.is_none() {
            return Err(VmmError::Config(
                "checkpoint restore requires jailer isolation; direct mode embeds shared origin \
                 paths"
                    .into(),
            ));
        }

        // Claim the id atomically so a concurrent restore/create of the same
        // id fails fast with AlreadyExists instead of both proceeding to set up
        // the deterministic per-id CoW/dm/TAP resources and corrupting each
        // other (see reserve_actor). Unwound on every error path via Drop.
        let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
            .join("sandboxes")
            .join(&new_id);
        let mut restore_spec = request.spec.clone();
        restore_spec.id = Some(new_id.clone());
        let reservation = super::reserve_actor(
            &self.computers,
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
        let deadlines = Deadlines {
            ttl: record.ttl_deadline,
            idle_timeout_seconds: record.effective_spec.idle_timeout_seconds,
            on_idle: record.effective_spec.on_idle,
        };
        {
            let mut computer = reservation.runtime().lock().unwrap();
            computer.record_generation = Some(generation);
            computer.labels.clone_from(&record.effective_spec.labels);
            // The effective spec carries the warm-create origin's initial
            // workload; the durable copy is redacted once the record leaves
            // the provisioning phases, so the gate reads it from here.
            computer.spec = record.effective_spec;
            computer.created_at = record.created_at;
            computer.ttl_deadline = record.ttl_deadline;
        }

        // Reserve network metadata, journal it, then materialize the TAP. This
        // mirrors Create so an agent crash never leaves an unowned interface.
        let lease = if request.network_override {
            match self
                .services
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
                    self.services
                        .network
                        .activate(lease, super::attach_mode(snap_meta.net_invariant))
                        .await?,
                );
            }
            Ok::<_, VmmError>(())
        }
        .await;
        if let Err(error) = setup {
            // Nothing has been handed to a computer yet: the claim's drop
            // frees the id, and the rollback here is the caller's own — the
            // same shape a create's pre-actor setup failure takes.
            let abort = self.records.abort_provision(&new_id, generation);
            let mut unwound = Vec::new();
            if let Some(reserved) = lease
                && let Err(release_error) = self.services.network.release(reserved).await
            {
                unwound.push(format!("network: {release_error}"));
            }
            if let Err(abort_error) = abort {
                unwound.push(format!("record: {abort_error}"));
            }
            if unwound.is_empty() {
                return Err(error);
            }
            return Err(VmmError::Unavailable(format!(
                "{error}; restore rollback incomplete: {}",
                unwound.join("; ")
            )));
        }

        // The actor takes it from here: the restore proper, the atomic
        // `ReadyWithOutcome` commit, the CREATED event a warm create owes,
        // the gate and READY. A failure before the commit is unwound by the
        // machine's own force-remove — the id and its request key must be
        // free again for a retry, and a warm create must be able to fall
        // back to a cold boot.
        let (services, timers_enabled) = self.spawn_context();
        let mailbox = reservation.spawn(super::ActorSpawn {
            services,
            timers_enabled,
            generation: Some(generation),
            deadlines,
            launch: Launch::Restore(Box::new(RestoreLaunch {
                snapshot_id: request.snapshot_id.clone(),
                snap_meta,
                lease,
                nic,
                started: restore_started,
            })),
            seeded: Seeded::Fresh,
        });
        let outcome = SandboxProvisionOutcome {
            ip_address: ip_address.clone(),
        };
        // A restore's caller waits for READY: that is what makes the sandbox
        // usable, and what a warm create's own caller was promised.
        let restored = mailbox
            .ask(&new_id, |reply| Command::Provision {
                provision: Provision::Restore {
                    origin: request.origin,
                },
                outcome,
                reply,
            })
            .await;
        match restored {
            Ok(()) => Ok((new_id, ip_address)),
            Err(error) => Err(error),
        }
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
