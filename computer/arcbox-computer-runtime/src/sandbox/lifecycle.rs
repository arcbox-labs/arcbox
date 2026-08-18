use super::reconcile::JournaledLease;
use super::record::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::*;
use crate::lifecycle::actor::ComputerSnapshot;
use crate::sandbox::record::PersistPhase;

/// Whether a create may restore from warm sources and publish into the
/// warm-cache LRU. [`Disabled`](Self::Disabled) exists for the prewarm
/// builder (CORE-107), whose boot must be a plain cold boot.
pub(super) enum WarmPolicy {
    Auto,
    Disabled,
}

impl SandboxManager {
    /// Replay a durable Create outcome without resolving its template again.
    pub async fn replay_sandbox_create(
        &self,
        id: &str,
        request_key: &str,
    ) -> Result<Option<(SandboxId, String)>> {
        self.await_reconcile().await?;
        self.records
            .replay_provision(id, request_key)
            .map(|outcome| outcome.map(|outcome| (id.to_owned(), outcome.ip_address)))
    }

    pub async fn create_sandbox(&self, spec: SandboxSpec) -> Result<(SandboxId, String)> {
        self.create_sandbox_keyed(spec, &Uuid::new_v4().to_string())
            .await
    }

    /// Create a sandbox with a stable key for durable request replay.
    pub async fn create_sandbox_keyed(
        &self,
        spec: SandboxSpec,
        request_key: &str,
    ) -> Result<(SandboxId, String)> {
        self.create_sandbox_inner(spec, request_key, WarmPolicy::Auto)
            .await
    }

    /// Bounded wait for the host to finalize a just-removed same-id
    /// sandbox's network cleanup, so a cold-boot fallback can re-reserve.
    ///
    /// A failed warm restore unwinds with an internal force remove, which
    /// quarantines the id's network until the host completes the cleanup
    /// ticket — delivered over the always-open `WatchSandboxCleanup` stream
    /// (terminal events prompt it; a 1 s rescan backstops), so this
    /// normally resolves within a second or two. On expiry the fallback
    /// proceeds anyway and `reserve` surfaces the honest UNAVAILABLE.
    async fn await_network_release(&self, id: &SandboxId) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match self.reconcile_network().pending_cleanups().await {
                Ok(pending) if !pending.iter().any(|(vm, _)| vm.as_str() == id) => return,
                Ok(_) => {}
                Err(error) => {
                    // The ledger is what the wait is about, so an unreadable
                    // one is not something to spin on: fall through and let
                    // `reserve` report it.
                    warn!(sandbox_id = %id, %error, "network cleanup ledger is unreadable");
                    return;
                }
            }
            if std::time::Instant::now() > deadline {
                warn!(
                    sandbox_id = %id,
                    "network cleanup still awaiting host finalization; cold boot will report it"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// [`Self::create_sandbox_keyed`] with explicit warm behaviour: the
    /// prewarm builder (CORE-107) passes [`WarmPolicy::Disabled`] so its own
    /// boot neither restores from a warm source nor publishes into the
    /// warm-cache LRU (which would burn one of the `MAX_WARM_KEYS` slots on
    /// a duplicate full-memory snapshot).
    pub(super) async fn create_sandbox_inner(
        &self,
        mut spec: SandboxSpec,
        request_key: &str,
        warm_policy: WarmPolicy,
    ) -> Result<(SandboxId, String)> {
        // Do not allocate any per-id resources until the startup orphan sweep
        // has run — otherwise a re-created same-id sandbox races it.
        self.await_reconcile().await?;

        // Whether the caller pinned its own boot recipe. Captured before the
        // defaults fill — a custom kernel or cmdline is never warm-created.
        let caller_supplied_boot = !spec.kernel.is_empty() || !spec.boot_args.is_empty();

        // Apply daemon defaults for fields not supplied by the caller.
        let defaults = &self.config.defaults;
        if spec.kernel.is_empty() {
            spec.kernel.clone_from(&defaults.kernel);
        }
        if spec.rootfs.is_empty() {
            spec.rootfs.clone_from(&defaults.rootfs);
        }
        if spec.boot_args.is_empty() {
            spec.boot_args.clone_from(&defaults.boot_args);
        }
        if spec.vcpus == 0 {
            spec.vcpus = defaults.vcpus as u32;
        }
        if spec.memory_mib == 0 {
            spec.memory_mib = defaults.memory_mib;
        }
        if spec.network.mode.is_empty() {
            spec.network.mode = "tap".into();
        }

        let id = spec
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Restrict caller-supplied ids to a safe charset (path components,
        // jailer --id, dm/TAP names). Auto-generated UUIDs pass unchanged.
        super::validate_new_sandbox_id(&id, &self.config)?;
        spec.id = Some(id.clone());

        // Template warm-restore (CORE-107): a catalog template carrying a
        // pre-warmed snapshot restores it directly — the sub-second start the
        // template was built for. Same restore path as the warm cache below
        // (`WarmCreate` origin delivers the CREATED→READY event contract and
        // runs the effective spec's cmd after Ready; the checkpoint was taken
        // idle and cmd-less, so defaults-vs-checkpoint divergence resolves to
        // the spec). A geometry mismatch — the caller overrode `limits` —
        // makes the snapshot unusable and cold-boots from the template
        // rootfs, correct per the wholesale-replace contract. Unlike the
        // warm cache, a kernel bump does NOT invalidate a template snapshot:
        // a published template pins its artifacts, and the restore resurrects
        // the kernel it was built with.
        if matches!(warm_policy, WarmPolicy::Auto)
            && let Some(warm) = spec.template_warm.clone()
            && super::templates::template_restore_eligible(
                &self.config,
                &spec,
                caller_supplied_boot,
                &warm,
            )
        {
            info!(
                sandbox_id = %id,
                snapshot_id = %warm.snapshot_id,
                "template create: restoring the template's pre-warmed snapshot"
            );
            let mut warm_spec = spec.clone();
            warm_spec.id = Some(id.clone());
            match self
                .restore_from_snapshot(
                    super::checkpoint::RestoreRequest {
                        snapshot_id: warm.snapshot_id.clone(),
                        network_override: true,
                        spec: warm_spec,
                        origin: RestoreOrigin::WarmCreate,
                    },
                    request_key,
                )
                .await
            {
                Ok(result) => return Ok(result),
                // Post-commit ambiguity: the sandbox is running under this
                // id — cold-booting would recreate a live sandbox.
                Err(error @ VmmError::AckUnconfirmed { .. }) => return Err(error),
                Err(error) => {
                    warn!(
                        sandbox_id = %id,
                        snapshot_id = %warm.snapshot_id,
                        %error,
                        "template warm restore failed; cold-booting from the template rootfs"
                    );
                    self.await_network_release(&id).await;
                }
            }
        }

        // Warm create (CORE-77): a Create whose boot shape matches a cached
        // template snapshot restores instead of cold-booting. Decided before
        // any resource allocation — the restore path owns its own id
        // reservation, durable intent, and fresh network identity
        // (`network_override`, free with net-invariant snapshots). On a miss
        // the boot task publishes the snapshot once the guest is Ready.
        let mut warm_publish = None;
        if matches!(warm_policy, WarmPolicy::Auto)
            && super::warm::warm_eligible(&self.config, &spec, caller_supplied_boot)
        {
            match super::warm::derive_warm_key(&spec) {
                Ok(key) => match super::warm::find_warm_snapshot(&self.snapshots, &key) {
                    Ok(Some(snapshot_id)) => {
                        self.warm.touch(&key);
                        info!(
                            sandbox_id = %id,
                            snapshot_id,
                            "warm create: restoring cached template snapshot"
                        );
                        // The cache entry can die between this lookup and the
                        // restore: a concurrent publish of another key evicts
                        // by LRU and deletes the snapshot. That is a cache
                        // miss arriving late, not a create failure — fall
                        // through to the cold boot (which republishes) rather
                        // than surfacing a snapshot-not-found to the caller.
                        //
                        // The failure class decides the fallback, carried
                        // in the error itself: `AckUnconfirmed` is the one
                        // post-commit failure — the sandbox is running and
                        // READY under this id — so cold-booting there would
                        // recreate a live (or, if the client already acted
                        // on READY and deleted it, just-deleted) sandbox.
                        // Every other failure unwound its claim pre-commit
                        // and cold-boots safely. The restore is pinned to
                        // this create's id so both outcomes concern the id
                        // the caller asked for.
                        let mut warm_spec = spec.clone();
                        warm_spec.id = Some(id.clone());
                        match self
                            .restore_from_snapshot(
                                super::checkpoint::RestoreRequest {
                                    snapshot_id: snapshot_id.clone(),
                                    network_override: true,
                                    spec: warm_spec,
                                    origin: RestoreOrigin::WarmCreate,
                                },
                                request_key,
                            )
                            .await
                        {
                            Ok(result) => return Ok(result),
                            Err(error @ VmmError::AckUnconfirmed { .. }) => {
                                return Err(error);
                            }
                            Err(error) => {
                                warn!(
                                    sandbox_id = %id,
                                    snapshot_id,
                                    %error,
                                    "warm restore failed; cold-booting instead"
                                );
                                self.await_network_release(&id).await;
                                warm_publish = Some(super::warm::WarmPublishTicket {
                                    key,
                                    cache: Arc::clone(&self.warm),
                                    snapshots: Arc::clone(&self.snapshots),
                                    pool: Arc::clone(&self.pool),
                                });
                            }
                        }
                    }
                    Ok(None) => {
                        warm_publish = Some(super::warm::WarmPublishTicket {
                            key,
                            cache: Arc::clone(&self.warm),
                            snapshots: Arc::clone(&self.snapshots),
                            pool: Arc::clone(&self.pool),
                        });
                    }
                    Err(error) => {
                        // The publish path would scan the same catalog, so a
                        // failed lookup cold-boots without cache interaction.
                        warn!(sandbox_id = %id, %error, "warm snapshot lookup failed; cold-booting");
                    }
                },
                Err(error) => {
                    debug!(sandbox_id = %id, %error, "rootfs fingerprint failed; skipping warm create");
                }
            }
        }

        let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
            .join("sandboxes")
            .join(&id);

        // Create and Restore claim the in-memory namespace in the same order,
        // before either consults durable ownership.
        let reservation = super::reserve_actor(
            &self.computers,
            &id,
            ComputerRuntime::new(id.clone(), spec.clone(), None, vm_dir.clone()),
        )?;

        // This durable boundary still precedes every external side effect.
        let record = match self.records.provision_intent(&id, request_key, spec)? {
            ProvisionIntent::Created(record) | ProvisionIntent::Resume(record) => record,
            ProvisionIntent::Replay(record) => {
                let outcome = record
                    .provision_outcome
                    .ok_or_else(|| VmmError::WrongState {
                        id: id.clone(),
                        expected: "a persisted create outcome".into(),
                        actual: "none".into(),
                    })?;
                return Ok((id, outcome.ip_address));
            }
            ProvisionIntent::Blocked(_) => return Err(VmmError::AlreadyExists(id)),
        };
        let generation = record.generation;
        let deadlines = Deadlines {
            // Computed by the durable record so a same-key create retry keeps
            // the original cap instead of re-deriving it from a later "now".
            ttl: record.ttl_deadline,
            idle_timeout_seconds: record.effective_spec.idle_timeout_seconds,
            on_idle: record.effective_spec.on_idle,
        };
        let spec = record.effective_spec;
        let arc = Arc::clone(reservation.runtime());
        {
            let mut creating = arc.lock().unwrap();
            creating.record_generation = Some(generation);
            creating.labels.clone_from(&spec.labels);
            creating.spec.clone_from(&spec);
            creating.ttl_deadline = deadlines.ttl;
        }
        // No lock is held across the awaits below: nothing can tear this
        // computer down while it is being built, because its actor is the
        // only thing that could and it has not been asked to do anything yet.

        // Reserve the IP without touching the host, durably journal it, then
        // materialize the TAP. No external resource exists before its cleanup
        // metadata does.
        // Tracked apart from the NIC on purpose: the lease exists from
        // `reserve` on, and the rollback below must hand back one whose TAP
        // was never built — a journal write between the two can fail.
        let mut lease: Option<NetworkLease> = None;
        let mut nic: Option<NicSpec> = None;
        // Whether this boot bakes the fixed invariant identity into the
        // guest's command line (see do_boot); false when the caller brought
        // their own `ip=`. Independent of the mode the host side is attached
        // in, which is `Invariant` either way.
        let invariant_identity = !spec.boot_args.contains("ip=");
        let setup = async {
            if spec.network.mode != "none" {
                lease = Some(
                    self.services
                        .network
                        .reserve(&VmId::new(&id)?, super::sandbox_network_policy())
                        .await?,
                );
            }
            let ip_address = lease
                .as_ref()
                .map(|lease| lease.ip.to_string())
                .unwrap_or_default();

            super::reconcile::create_runtime_dir(&vm_dir)?;
            let cleanup_record = super::reconcile::SandboxStateRecord::new(
                &id,
                None,
                lease
                    .as_ref()
                    .map(|lease| JournaledLease::cold_boot(lease, invariant_identity)),
                None,
                &self.config,
                None,
            )?;
            super::reconcile::write_state_record(&vm_dir, &cleanup_record)?;
            if let Some(lease) = &lease {
                nic = Some(
                    self.services
                        .network
                        .activate(lease, AttachMode::Invariant)
                        .await?,
                );
            }

            Ok::<_, VmmError>(ip_address)
        }
        .await;

        let ip_address = match setup {
            Ok(result) => result,
            Err(error) => {
                // The reply frame carries the only other copy of this error;
                // log it here so a create that dies between the network
                // activation and the Starting journal commit is attributable
                // from the guest log alone (CORE-82).
                warn!(sandbox_id = %id, error = %error, "sandbox create setup failed; rolling back");
                let mut rollback_errors = Vec::new();
                let mut network_cleanup_failed = false;
                if let Some(reserved) = lease.clone()
                    && let Err(release_error) = self.services.network.release(reserved).await
                {
                    network_cleanup_failed = true;
                    rollback_errors.push(format!("network: {release_error}"));
                }
                if !network_cleanup_failed
                    && let Err(remove_error) = std::fs::remove_dir_all(&vm_dir)
                    && remove_error.kind() != std::io::ErrorKind::NotFound
                {
                    rollback_errors.push(format!("directory {}: {remove_error}", vm_dir.display()));
                }
                if !rollback_errors.is_empty() {
                    {
                        let mut creating = arc.lock().unwrap();
                        creating.network = lease;
                        creating.state = SandboxState::Failed;
                        creating.error = Some(error.to_string());
                    }
                    let record_error = self
                        .records
                        .transition(
                            &id,
                            generation,
                            SandboxTransition::Failed(error.to_string()),
                        )
                        .err()
                        .map(|record_error| format!("record: {record_error}"));
                    if let Some(record_error) = record_error {
                        rollback_errors.push(record_error);
                    }
                    // Kept, in the phase the record was just left in: the
                    // computer is inspectable and removable, and its actor is
                    // what a later Remove reaches to release whatever the
                    // rollback could not.
                    let (services, timers_enabled) = self.spawn_context();
                    reservation.spawn(super::ActorSpawn {
                        services,
                        timers_enabled,
                        generation: Some(generation),
                        deadlines,
                        launch: Launch::Reinstated,
                        seeded: Seeded::Recovered(PersistPhase::Failed),
                    });
                    let rollback = rollback_errors.join("; ");
                    error!(
                        sandbox_id = %id,
                        error = %error,
                        rollback = %rollback,
                        "sandbox create rollback incomplete; instance left Failed"
                    );
                    return Err(VmmError::Other(format!(
                        "{error}; sandbox rollback is incomplete: {rollback}"
                    )));
                }
                let abort = self.records.abort_provision(&id, generation)?;
                if let Some(durability_error) = abort.durability_error {
                    return Err(VmmError::Unavailable(format!(
                        "{error}; create rollback is visible, but durability is unconfirmed: {durability_error}"
                    )));
                }
                return Err(error);
            }
        };

        // Populate the claimed computer.
        // What the guest is told over its NIC is the network's answer for
        // the mode it was activated in, not a constant of any one adapter.
        let attachment = lease.clone().zip(nic).map(|(lease, nic)| {
            let identity = self
                .services
                .network
                .identity(&lease, AttachMode::Invariant);
            NetworkAttachment {
                lease,
                nic,
                identity,
                invariant_identity,
            }
        });
        {
            let mut creating = arc.lock().unwrap();
            creating.network = lease;
            // The boot bakes the invariant `ip=` identity unless the caller
            // supplied an explicit ip= (see do_boot); record which one this
            // guest runs so checkpoints carry the right restore contract.
            creating.net_invariant = creating.network.is_some() && invariant_identity;
        }

        // The actor takes it from here: the `Starting` write, the CREATED
        // event, the TTL arm and the boot task are all effects of the
        // provision, in that order.
        let (services, timers_enabled) = self.spawn_context();
        let warm = warm_publish.is_some();
        let mailbox = reservation.spawn(super::ActorSpawn {
            services,
            timers_enabled,
            generation: Some(generation),
            deadlines,
            launch: Launch::Boot(Box::new(BootLaunch {
                attachment,
                warm_publish,
            })),
            seeded: Seeded::Fresh,
        });
        let outcome = SandboxProvisionOutcome {
            ip_address: ip_address.clone(),
        };
        // `AckUnconfirmed` says the `Starting` write is visible but not
        // proven durable — the boot is under way and the caller decides. Any
        // other error means the write was refused, so nothing was recorded
        // and no boot started; the computer failed itself, releasing what
        // this create had allocated, and keeps its `Failed` record rather
        // than freeing the id — the disposition a rollback that cannot
        // finish leaves behind.
        mailbox
            .ask(&id, |reply| Command::Provision {
                provision: Provision::Boot { warm },
                outcome,
                reply,
            })
            .await?;
        info!(sandbox_id = %id, "sandbox create requested (async boot started)");
        Ok((id, ip_address))
    }

    /// Stop a sandbox gracefully.
    ///
    /// Waits up to `timeout_seconds` (default 30 s) for an active workload
    /// to exit, asks the guest to shut down (Ctrl+Alt+Del reboots the guest,
    /// which exits the VMM), and the driver SIGKILLs the VMM only if it
    /// outlives the remaining budget. All runtime resources (TAP + IP,
    /// dm-snapshot CoW, jailer chroot) are released on `Stopped`; only the
    /// inspectable record and the log directory survive until `Remove`.
    pub async fn stop_sandbox(&self, id: &SandboxId, timeout_seconds: u32) -> Result<()> {
        self.await_reconcile().await?;
        let budget = Duration::from_secs(u64::from(if timeout_seconds > 0 {
            timeout_seconds
        } else {
            30
        }));
        self.mailbox(id)?
            .ask(id, |reply| Command::Stop { budget, reply })
            .await
    }

    /// Give up ownership of every live VM without stopping it, so this
    /// process can exit and the next one adopt them.
    ///
    /// The composer calls this on graceful shutdown. Without it a clean exit
    /// unwinds into the driver handle's `Drop`, which kills — so the startup
    /// sweep's adoption would only ever fire after a crash, never after the
    /// binary upgrade or redeploy it mainly exists for.
    ///
    /// Best-effort per sandbox: one VM that refuses to be handed over must
    /// not cost the others theirs, so failures are collected and reported
    /// together. A driver without `Detach` runs its VMs in-process and has
    /// nothing to hand over — the same reasoning the sweep applies to
    /// `Adopt`. The `PreparedVm` a booted sandbox also holds needs no such
    /// step: it kills on drop only while it is still unconsumed.
    pub async fn detach_all(&self) -> Result<()> {
        let live: Vec<(SandboxId, Arc<dyn VmHandle>)> = self
            .computers
            .read()
            .unwrap()
            .iter()
            .filter_map(|(id, computer)| {
                let handle = computer.snapshot.borrow().handle.clone();
                handle.map(|handle| (id.clone(), handle))
            })
            .collect();

        let mut failures = Vec::new();
        for (id, handle) in live {
            let Some(detach) = handle.detach() else {
                continue;
            };
            match detach.detach().await {
                Ok(_) => info!(sandbox_id = %id, "handed the sandbox's vm to the next process"),
                Err(error) => failures.push(format!("{id}: {error}")),
            }
        }
        if failures.is_empty() {
            return Ok(());
        }
        Err(VmmError::Unavailable(format!(
            "some sandboxes could not be handed over and will be killed on exit: {}",
            failures.join("; ")
        )))
    }

    /// Forcibly destroy a sandbox and release all resources immediately.
    pub async fn remove_sandbox(&self, id: &SandboxId, force: bool) -> Result<()> {
        self.await_reconcile().await?;
        let mailbox = match self.mailbox(id) {
            Ok(mailbox) => mailbox,
            // No computer under this id. It may still own a durable record —
            // an intent nobody acknowledged, or a tombstone a previous
            // removal did not finish — and the claim is what serializes this
            // against a create of the same id arriving now.
            Err(VmmError::NotFound(_)) => {
                let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
                    .join("sandboxes")
                    .join(id);
                match super::reserve_actor(
                    &self.computers,
                    id,
                    ComputerRuntime::new(
                        id.clone(),
                        SandboxSpec {
                            id: Some(id.clone()),
                            ..Default::default()
                        },
                        None,
                        vm_dir,
                    ),
                ) {
                    Ok(_reservation) => {
                        let commit = self.records.cancel_pending_or_missing(id)?;
                        if let Some(error) = commit.durability_error {
                            return Err(VmmError::Unavailable(format!(
                                "sandbox {id} removal is visible, but durability is unconfirmed: {error}"
                            )));
                        }
                        info!(sandbox_id = %id, "sandbox already removed");
                        return Ok(());
                    }
                    // A create won the race for the id; remove what it made.
                    Err(VmmError::AlreadyExists(_)) => self.mailbox(id)?,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        mailbox
            .ask(id, |reply| Command::Remove { force, reply })
            .await?;
        info!(sandbox_id = %id, "sandbox removed");
        Ok(())
    }

    /// Files a checkpoint occupies on disk, for storage accounting.
    ///
    /// Empty when the id is unknown — a paused sandbox whose checkpoint went
    /// missing reports the disk overlay alone rather than failing the read.
    fn checkpoint_paths(&self, snapshot_id: &str) -> Vec<PathBuf> {
        self.snapshots
            .find_by_id(snapshot_id)
            .map(|meta| {
                std::iter::once(meta.vmstate_path)
                    .chain(meta.mem_path)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return the current state and metadata of a sandbox.
    pub fn inspect_sandbox(&self, id: &SandboxId) -> Result<SandboxInfo> {
        let snapshot = self.snapshot(id)?;
        // Size the retained artifacts after the read: the sizing stats files
        // and scans the catalog, and the snapshot is a borrow of a `watch`
        // the actor writes.
        let artifacts = (snapshot.state == SandboxState::Paused)
            .then(|| super::pause::paused_artifacts(&self.config, id, &snapshot));
        let mut info = snapshot_to_info(id, &snapshot);
        if let Some(artifacts) = artifacts {
            info.storage_bytes = artifacts.storage_bytes(|id| self.checkpoint_paths(id));
        }
        Ok(info)
    }

    /// List sandboxes, optionally filtered by state string and/or labels.
    pub fn list_sandboxes(
        &self,
        state_filter: Option<&str>,
        label_filter: &HashMap<String, String>,
    ) -> Result<Vec<SandboxSummary>> {
        self.check_reconcile()?;
        // Snapshot every computer's read view under the map read guard. No
        // per-computer lock is taken at all, so the "never hold the map lock
        // while holding an instance lock" discipline this fold used to need
        // has nothing left to violate.
        let computers: Vec<(SandboxId, ComputerSnapshot)> = self
            .computers
            .read()
            .unwrap()
            .iter()
            .map(|(id, computer)| (id.clone(), computer.snapshot.borrow().clone()))
            .collect();
        // The second pass pays one catalog listing for the whole response
        // instead of one per paused sandbox.
        let mut summaries: Vec<(SandboxSummary, Option<super::pause::PausedArtifacts>)> = computers
            .iter()
            .filter_map(|(id, snapshot)| {
                if let Some(sf) = state_filter
                    && !sf.is_empty()
                    && snapshot.state.to_string() != sf
                {
                    return None;
                }
                // Label filter: all supplied key-value pairs must match.
                for (k, v) in label_filter {
                    if snapshot.labels.get(k).map(String::as_str) != Some(v.as_str()) {
                        return None;
                    }
                }
                let summary = SandboxSummary {
                    id: id.clone(),
                    state: snapshot.state,
                    labels: snapshot.labels.clone(),
                    ip_address: snapshot
                        .lease
                        .as_ref()
                        .map(|lease| lease.ip.to_string())
                        .unwrap_or_default(),
                    created_at: snapshot.created_at,
                    paused_at: snapshot.paused_at,
                    storage_bytes: 0,
                };
                let artifacts = (snapshot.state == SandboxState::Paused)
                    .then(|| super::pause::paused_artifacts(&self.config, id, snapshot));
                Some((summary, artifacts))
            })
            .collect();

        if summaries.iter().any(|(_, artifacts)| artifacts.is_some()) {
            let catalog = self.snapshots.list_all().unwrap_or_default();
            for (summary, artifacts) in &mut summaries {
                if let Some(artifacts) = artifacts {
                    summary.storage_bytes = artifacts.storage_bytes(|id| {
                        catalog
                            .iter()
                            .find(|info| info.id == id)
                            .map(snapshot_files)
                            .unwrap_or_default()
                    });
                }
            }
        }
        Ok(summaries.into_iter().map(|(summary, _)| summary).collect())
    }

    /// Subscribe to sandbox lifecycle events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SandboxEvent> {
        self.events_tx.subscribe()
    }

    /// Verify the computer is `Ready` and return the agent inside it.
    ///
    /// A paused computer answers [`VmmError::Paused`], not `WrongState`, so
    /// the daemon can resume it transparently and retry (CORE-21).
    pub(super) fn require_ready_agent(&self, id: &SandboxId) -> Result<Arc<dyn GuestAgent>> {
        self.agent_in(id, &[SandboxState::Ready], "Ready")
    }

    /// Verify the computer is alive (Ready or Running) and return the agent
    /// inside it. Unlike [`Self::require_ready_agent`], an in-flight workload
    /// does not block the operation — file I/O works alongside Run/Exec.
    /// Paused states map to [`VmmError::Paused`] for the daemon's transparent
    /// resume, as above.
    pub(super) fn require_alive_agent(&self, id: &SandboxId) -> Result<Arc<dyn GuestAgent>> {
        self.agent_in(
            id,
            &[SandboxState::Ready, SandboxState::Running],
            "Ready or Running",
        )
    }

    /// The agent reaching this computer's guest, if it is in one of `allowed`.
    ///
    /// The whole data plane's entry point, and the reason the agent rides the
    /// read snapshot (§B.6 of the R3 plan): one borrow of a `watch`, no
    /// mailbox round-trip and no lock a lifecycle transition also needs, so
    /// an exec costs a clone of an `Arc` rather than a scheduling hop.
    fn agent_in(
        &self,
        id: &SandboxId,
        allowed: &[SandboxState],
        expected: &str,
    ) -> Result<Arc<dyn GuestAgent>> {
        let snapshot = self.snapshot(id)?;
        if !allowed.contains(&snapshot.state) {
            return Err(match snapshot.state {
                SandboxState::Pausing | SandboxState::Paused => VmmError::Paused(id.clone()),
                state => VmmError::WrongState {
                    id: id.clone(),
                    expected: expected.to_owned(),
                    actual: state.to_string(),
                },
            });
        }
        snapshot
            .agent
            .ok_or_else(|| VmmError::Vsock(format!("sandbox {id} has no running vm to reach")))
    }
}

/// A computer's read snapshot as `Inspect` reports it.
fn snapshot_to_info(id: &SandboxId, snapshot: &ComputerSnapshot) -> SandboxInfo {
    SandboxInfo {
        id: id.clone(),
        state: snapshot.state,
        labels: snapshot.labels.clone(),
        vcpus: snapshot.vcpus,
        memory_mib: snapshot.memory_mib,
        network: snapshot.lease.as_ref().map(|lease| SandboxNetworkInfo {
            ip_address: lease.ip.to_string(),
            gateway: lease.gateway.to_string(),
        }),
        created_at: snapshot.created_at,
        ready_at: snapshot.ready_at,
        last_exited_at: snapshot.last_exited_at,
        last_exit_status: snapshot.last_exit_status,
        error: snapshot.error.clone(),
        paused_at: snapshot.paused_at,
        // Filled by the caller for paused computers (it owns the paths).
        storage_bytes: 0,
        ttl_deadline: snapshot.deadlines.ttl,
        idle_timeout_seconds: snapshot.deadlines.idle_timeout_seconds,
        on_idle: snapshot.deadlines.on_idle,
    }
}

/// Files a listed checkpoint occupies on disk, for storage accounting.
///
/// The listing counterpart of [`SandboxManager::checkpoint_paths`]: it reads
/// an already-loaded [`SnapshotInfo`] so a multi-sandbox response pays one
/// catalog scan rather than one per paused sandbox.
fn snapshot_files(info: &crate::snapshot::SnapshotInfo) -> Vec<PathBuf> {
    std::iter::once(info.vmstate_path.clone())
        .chain(info.mem_path.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::agent::FakeAgentFactory;

    /// A factory whose guests announce nothing needs no `vsock_listen` from
    /// the driver: what the readiness gate costs is the agent port's answer.
    #[test]
    fn a_probing_agent_does_not_require_a_listening_driver() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = dir.path().to_string_lossy().into_owned();
        let driver = arcbox_vm_driver::testkit::FakeDriver::builder()
            .capabilities(arcbox_vm_driver::DriverCapabilities {
                vsock_listen: false,
                ..arcbox_vm_driver::testkit::FakeDriver::new().capabilities()
            })
            .build();
        SandboxManager::with_environment(
            config,
            SandboxEnvironment {
                driver: Some(Arc::new(driver)),
                network: Some(Arc::new(
                    arcbox_vm_driver::testkit::FakeNetwork::with_startup_cleanup("test-boot"),
                )),
                agent: Some(Arc::new(FakeAgentFactory::new())),
                ..SandboxEnvironment::default()
            },
        )
        .expect("a probing agent asks the driver for no listener");
    }
}
