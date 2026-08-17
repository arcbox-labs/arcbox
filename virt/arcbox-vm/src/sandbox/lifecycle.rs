use super::boot::boot_sandbox;
use super::cleanup::{inst_to_info, remove_sandbox_impl};
use super::persistence::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::types::{SandboxBootTask, action};
use super::*;
use arcbox_vm_driver::ShutdownMode;

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
        while self.network.quarantine_pending(id) {
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
                        origin: super::checkpoint::RestoreOrigin::WarmCreate,
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
                                    origin: super::checkpoint::RestoreOrigin::WarmCreate,
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
        let reservation = super::reserve_id(
            &self.instances,
            &id,
            SandboxInstance::new(id.clone(), spec.clone(), None, vm_dir.clone()),
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
        let ttl_deadline = record.ttl_deadline;
        let spec = record.effective_spec;
        let arc = reservation.instance();
        let mut creating_instance = arc.lock().unwrap();
        creating_instance.record_generation = Some(generation);
        creating_instance.labels.clone_from(&spec.labels);
        creating_instance.spec.clone_from(&spec);
        // Computed by the durable record so a same-key create retry keeps
        // the original cap instead of re-deriving it from a later "now".
        creating_instance.ttl_deadline = ttl_deadline;

        // Reserve the IP without touching the host, durably journal it, then
        // materialize the TAP. No external resource exists before its cleanup
        // metadata does.
        let mut net_alloc = None;
        let setup = (|| -> Result<(String, Option<String>)> {
            if spec.network.mode != "none" {
                net_alloc = Some(self.network.reserve(&id)?);
            }
            let ip_address = net_alloc
                .as_ref()
                .map(|net| net.ip_address.to_string())
                .unwrap_or_default();

            super::reconcile::create_runtime_dir(&vm_dir)?;
            let cleanup_record = super::reconcile::SandboxStateRecord::new(
                &id,
                None,
                net_alloc.as_ref(),
                None,
                self.config.firecracker.jailer.is_some(),
                None,
            );
            super::reconcile::write_state_record(&vm_dir, &cleanup_record)?;
            if let Some(net) = &net_alloc {
                self.network
                    .activate(net, crate::network::TapMode::Invariant)?;
            }

            let outcome = SandboxProvisionOutcome {
                ip_address: ip_address.clone(),
            };
            let commit =
                self.records
                    .transition(&id, generation, SandboxTransition::Starting(outcome))?;
            Ok((ip_address, commit.durability_error))
        })();

        let (ip_address, starting_durability_error) = match setup {
            Ok(result) => result,
            Err(error) => {
                // The reply frame carries the only other copy of this error;
                // log it here so a create that dies between the network
                // activation and the Starting journal commit is attributable
                // from the guest log alone (CORE-82).
                warn!(sandbox_id = %id, error = %error, "sandbox create setup failed; rolling back");
                let mut rollback_errors = Vec::new();
                let mut network_cleanup_failed = false;
                if let Some(net) = &net_alloc
                    && let Err(release_error) = self.network.release_checked(net)
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
                    creating_instance.network.clone_from(&net_alloc);
                    creating_instance.state = SandboxState::Failed;
                    creating_instance.error = Some(error.to_string());
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
                    drop(creating_instance);
                    reservation.commit();
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

        // Populate the reserved instance.
        creating_instance.network.clone_from(&net_alloc);
        // The boot bakes the invariant `ip=` identity unless the caller
        // supplied an explicit ip= (see do_boot); record which one this guest
        // runs so checkpoints carry the right restore contract.
        creating_instance.net_invariant =
            creating_instance.network.is_some() && !spec.boot_args.contains("ip=");

        // Retain the boot task so force/TTL removal can cancel and join it
        // before deleting the crash-recovery journal.
        {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let driver = Arc::clone(&self.driver);
            let config = Arc::clone(&self.config);
            let events_tx = self.events_tx.clone();
            let cow_manager = Arc::clone(&self.cow_manager);
            let records = Arc::clone(&self.records);
            let id_clone = id.clone();
            let net_alloc_clone = net_alloc;
            let (resource_handoff_tx, resource_handoff) = tokio::sync::oneshot::channel();
            let handle = tokio::spawn(async move {
                boot_sandbox(
                    id_clone,
                    spec,
                    net_alloc_clone,
                    vm_dir,
                    instances,
                    network,
                    driver,
                    config,
                    events_tx,
                    cow_manager,
                    records,
                    generation,
                    warm_publish,
                    resource_handoff_tx,
                )
                .await;
            });
            creating_instance.boot_task = Some(SandboxBootTask {
                resource_handoff: Some(resource_handoff),
                handle,
            });
        }
        drop(creating_instance);
        reservation.commit();

        // Publish only after removal can observe and join the boot task.
        let _ = self.events_tx.send(SandboxEvent::new(&id, action::CREATED));

        // Arm the TTL expiry timer if a deadline was set (re-armable via
        // SetLifecycle, CORE-60).
        self.arm_ttl_timer(&id);

        info!(sandbox_id = %id, "sandbox create requested (async boot started)");
        if let Some(error) = starting_durability_error {
            return Err(VmmError::AckUnconfirmed { id, detail: error });
        }
        Ok((id, ip_address))
    }

    /// Stop a sandbox gracefully.
    ///
    /// Waits up to `timeout_seconds` (default 30 s) for an active workload
    /// to exit, asks the guest to shut down (Ctrl+Alt+Del reboots the guest,
    /// which exits Firecracker), and SIGKILLs Firecracker only if it
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
        let deadline = tokio::time::Instant::now() + budget;

        let instance = self.get_instance(id)?;
        let cleanup_lock = instance.lock().unwrap().cleanup_lock.clone();
        let _cleanup_guard = cleanup_lock.lock().await;
        super::ensure_current_instance(&self.instances, id, &instance)?;
        let already_stopped = {
            let inst = instance.lock().unwrap();
            (inst.state == SandboxState::Stopped)
                .then(|| (inst.record_generation, inst.vm_dir.clone()))
        };
        if let Some((generation, vm_dir)) = already_stopped {
            if let Some(generation) = generation {
                self.records
                    .transition(id, generation, SandboxTransition::Stopped)?
                    .confirmed("sandbox stop retry")?;
            }
            super::reconcile::clear_state_record(&vm_dir)?;
            return Ok(());
        }
        let (was_running, handle, record_generation, last_exited_at) = {
            let mut inst = instance.lock().unwrap();
            match inst.state {
                SandboxState::Ready | SandboxState::Running | SandboxState::Stopping => {}
                s => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "Ready, Running, or Stopping".into(),
                        actual: s.to_string(),
                    });
                }
            }
            let was_running = inst.state == SandboxState::Running;
            let captured = (
                was_running,
                inst.handle.clone(),
                inst.record_generation,
                inst.last_exited_at,
            );
            if let Some(generation) = inst.record_generation {
                let commit =
                    self.records
                        .transition(id, generation, SandboxTransition::Stopping)?;
                if let Some(error) = commit.durability_error {
                    warn!(
                        sandbox_id = %id,
                        error,
                        "stopping transition is visible but durability is unconfirmed"
                    );
                }
            }
            inst.state = SandboxState::Stopping;
            captured
        };

        let _ = self.events_tx.send(SandboxEvent::new(id, action::STOPPING));

        // Drain: give an active workload the budget to finish. The run/exec
        // watcher records last_exited_at when the exit chunk arrives, so poll
        // for that signal without relinquishing the Stopping state.
        if was_running {
            while tokio::time::Instant::now() < deadline {
                if instance.lock().unwrap().last_exited_at != last_exited_at {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        // Ask the guest to shut down and wait for it within the remaining
        // budget; the driver kills the VMM at the deadline (and reports a
        // reap that timed out — the handle stays on the instance for a
        // retry). A VM that never came up has no handle to ask.
        if let Some(handle) = handle {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or(Duration::from_secs(1))
                .max(Duration::from_secs(1));
            handle
                .shutdown(ShutdownMode::Graceful { timeout: remaining })
                .await
                .map_err(|error| VmmError::Process(format!("shut down sandbox {id}: {error}")))?;
        }

        // Release the VMM (already exited, or never booted), TAP/IP, CoW
        // device, and chroot; the record itself stays inspectable until Remove.
        let stop_commit = {
            super::cleanup::release_runtime_resources(
                id,
                &instance,
                &self.network,
                &self.config,
                &self.cow_manager,
            )
            .await?;
            let commit = record_generation
                .map(|generation| {
                    self.records
                        .transition(id, generation, SandboxTransition::Stopped)
                })
                .transpose()?;
            let mut inst = instance.lock().unwrap();
            inst.state = SandboxState::Stopped;
            if commit
                .as_ref()
                .is_none_or(|commit| commit.durability_error.is_none())
            {
                // Every reconcilable resource is gone and Stopped is durable.
                super::reconcile::clear_state_record(&inst.vm_dir)?;
            }
            commit
        };

        let _ = self.events_tx.send(SandboxEvent::new(id, action::STOPPED));
        info!(sandbox_id = %id, "sandbox stopped");
        stop_commit
            .map(|commit| commit.confirmed("sandbox stop"))
            .transpose()?;
        Ok(())
    }

    /// Forcibly destroy a sandbox and release all resources immediately.
    pub async fn remove_sandbox(&self, id: &SandboxId, force: bool) -> Result<()> {
        self.await_reconcile().await?;
        let expected = match self.get_instance(id) {
            Ok(expected) => expected,
            Err(VmmError::NotFound(_)) => {
                let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
                    .join("sandboxes")
                    .join(id);
                match super::reserve_id(
                    &self.instances,
                    id,
                    SandboxInstance::new(
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
                    Err(VmmError::AlreadyExists(_)) => self.get_instance(id)?,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };

        remove_sandbox_impl(
            id,
            force,
            &expected,
            &self.instances,
            &self.network,
            &self.events_tx,
            &self.config,
            &self.cow_manager,
            &self.records,
            &self.snapshots,
        )
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
        let instance = self.get_instance(id)?;
        // Locate the retained artifacts under the lock; size them after it
        // is dropped — the sizing stats files and scans the catalog, and
        // holding the instance lock across that blocks every lifecycle
        // transition on this sandbox.
        let (mut info, artifacts) = {
            let inst = instance.lock().unwrap();
            let artifacts =
                (inst.state == SandboxState::Paused).then(|| self.paused_artifacts(&inst));
            (inst_to_info(&inst), artifacts)
        };
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
        // Snapshot the Arcs under the map read guard, then release it before
        // locking any instance. The manager's discipline is "never hold the
        // instances map lock while holding an instance lock"; taking both here
        // (as before) is the one place that could deadlock a future writer that
        // locks in the opposite order.
        let instances: Vec<_> = self.instances.read().unwrap().values().cloned().collect();
        // Two passes on purpose. Under the instance lock, only field reads:
        // sizing a paused sandbox's retained state stats files and scans the
        // snapshot catalog, so doing it here would put blocking I/O on the
        // async executor while holding a lock every lifecycle transition
        // needs. The second pass pays one catalog listing for the whole
        // response instead of one per paused sandbox.
        let mut summaries: Vec<(SandboxSummary, Option<super::pause::PausedArtifacts>)> = instances
            .iter()
            .filter_map(|arc| {
                let inst = arc.lock().unwrap();
                // State filter.
                if let Some(sf) = state_filter
                    && !sf.is_empty()
                    && inst.state.to_string() != sf
                {
                    return None;
                }
                // Label filter: all supplied key-value pairs must match.
                for (k, v) in label_filter {
                    if inst.labels.get(k).map(String::as_str) != Some(v.as_str()) {
                        return None;
                    }
                }
                let summary = SandboxSummary {
                    id: inst.id.clone(),
                    state: inst.state,
                    labels: inst.labels.clone(),
                    ip_address: inst
                        .network
                        .as_ref()
                        .map(|n| n.ip_address.to_string())
                        .unwrap_or_default(),
                    created_at: inst.created_at,
                    paused_at: inst.paused_at,
                    storage_bytes: 0,
                };
                let artifacts =
                    (inst.state == SandboxState::Paused).then(|| self.paused_artifacts(&inst));
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

    pub(super) fn get_instance(&self, id: &SandboxId) -> Result<Arc<Mutex<SandboxInstance>>> {
        self.check_reconcile()?;
        self.instances
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| VmmError::NotFound(id.clone()))
    }

    /// Verify the sandbox is `Ready` and return the vsock capability that
    /// reaches its guest agent.
    ///
    /// A paused sandbox answers [`VmmError::Paused`], not `WrongState`, so
    /// the daemon can resume it transparently and retry (CORE-21).
    pub(super) fn require_ready_vsock(
        &self,
        id: &SandboxId,
    ) -> Result<Arc<dyn arcbox_vm_driver::Vsock>> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        match inst.state {
            SandboxState::Ready => {}
            SandboxState::Pausing | SandboxState::Paused => {
                return Err(VmmError::Paused(id.clone()));
            }
            s => {
                return Err(VmmError::WrongState {
                    id: id.clone(),
                    expected: "Ready".into(),
                    actual: s.to_string(),
                });
            }
        }
        guest_vsock(id, &inst)
    }

    /// Verify the sandbox is alive (Ready or Running) and return the vsock
    /// capability that reaches its guest agent. Unlike
    /// [`Self::require_ready_vsock`], an in-flight workload does not block
    /// the operation — file I/O works alongside Run/Exec. Paused states map
    /// to [`VmmError::Paused`] for the daemon's transparent resume, as above.
    pub(super) fn require_alive_vsock(
        &self,
        id: &SandboxId,
    ) -> Result<Arc<dyn arcbox_vm_driver::Vsock>> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        match inst.state {
            SandboxState::Ready | SandboxState::Running => {}
            SandboxState::Pausing | SandboxState::Paused => {
                return Err(VmmError::Paused(id.clone()));
            }
            s => {
                return Err(VmmError::WrongState {
                    id: id.clone(),
                    expected: "Ready or Running".into(),
                    actual: s.to_string(),
                });
            }
        }
        guest_vsock(id, &inst)
    }
}

/// The vsock capability reaching `inst`'s guest agent, once a boot or
/// restore has handed one over.
fn guest_vsock(id: &SandboxId, inst: &SandboxInstance) -> Result<Arc<dyn arcbox_vm_driver::Vsock>> {
    inst.vsock_uds_path
        .clone()
        .map(|path| Arc::new(vsock::UdsVsock(path)) as Arc<dyn arcbox_vm_driver::Vsock>)
        .ok_or_else(|| VmmError::Vsock(format!("sandbox {id} has no vsock configured")))
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
