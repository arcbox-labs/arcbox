use super::boot::{
    StageError, chroot_root, stage_kernel_for_jailer, stage_rootfs_cow_or_copy,
    stage_snapshot_files,
};
use super::persistence::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::pool::PreparedSlot;
use super::types::action;
use super::*;

/// Move a file even when source and destination sit on different mounts.
///
/// The jailer chroot is its own vfsmount (bind + pivot_root), so a plain
/// `rename(2)` out of it fails with `EXDEV` regardless of the underlying
/// filesystem; fall back to copy + remove in that case.
pub(super) async fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match tokio::fs::rename(from, to).await {
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            tokio::fs::copy(from, to).await?;
            // fsync the destination before removing the source: a crash between
            // the copy and the remove must not leave a zero-length/partial
            // snapshot file registered in the catalog.
            tokio::fs::File::open(to).await?.sync_all().await?;
            tokio::fs::remove_file(from).await
        }
        other => other,
    }
}

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

/// What a single [`checkpoint_impl`] call should capture, and how it should
/// leave the guest.
pub(super) struct CheckpointRequest {
    /// Catalog name recorded on the committed snapshot.
    pub(super) name: String,
    /// Catalog labels recorded on the committed snapshot.
    pub(super) labels: HashMap<String, String>,
    /// State the instance must be in. The Checkpoint RPC and the warm-create
    /// publisher require `Ready`; pause has already claimed the instance and
    /// moved it to `Pausing` (CORE-21).
    pub(super) expected_state: SandboxState,
    /// Resume the guest once the snapshot files are written.
    ///
    /// False only for pause, whose whole point is that the guest must never
    /// run past the memory image — any progress after it would diverge from
    /// the retained disk overlay. The caller then owns the resume-on-error.
    pub(super) resume_after: bool,
}

/// Pause a sandbox, capture a full snapshot into the catalog, and (unless
/// the request opts out) resume it.
///
/// Free-standing (rather than a method) so the boot task can publish warm
/// snapshots (CORE-77) through the exact code path the Checkpoint RPC uses,
/// and so pause (CORE-21) inherits the same chroot-owner and addressing-mode
/// handling instead of re-deriving it.
pub(super) async fn checkpoint_impl(
    instances: &super::InstanceMap,
    snapshots: &SnapshotCatalog,
    config: &VmmConfig,
    sandbox_id: &SandboxId,
    request: CheckpointRequest,
) -> Result<CheckpointInfo> {
    let CheckpointRequest {
        name,
        labels,
        expected_state,
        resume_after,
    } = request;
    // Verify state and capture the kernel/rootfs paths for jailer
    // re-staging, the id the sandbox's chroot is actually keyed by
    // — a sandbox restored from a pre-warmed pool slot lives in the
    // slot's chroot, and FC resolves snapshot paths inside it — plus
    // the guest's network addressing mode and the VM API handle.
    let (kernel_path, rootfs_path, chroot_owner, net_invariant, geometry, vm) = {
        let instance = instances
            .read()
            .unwrap()
            .get(sandbox_id)
            .cloned()
            .ok_or_else(|| VmmError::NotFound(sandbox_id.clone()))?;
        let inst = instance.lock().unwrap();
        if inst.state != expected_state {
            return Err(VmmError::WrongState {
                id: sandbox_id.clone(),
                expected: expected_state.to_string(),
                actual: inst.state.to_string(),
            });
        }
        let vm = inst
            .vm
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| VmmError::WrongState {
                id: sandbox_id.clone(),
                expected: format!("{expected_state} (VM handle available)"),
                actual: inst.state.to_string(),
            })?;
        // Only needed for jailer mode; safe to capture regardless.
        (
            inst.spec.kernel.clone(),
            inst.spec.rootfs.clone(),
            inst.pool_slot_id
                .clone()
                .unwrap_or_else(|| sandbox_id.clone()),
            inst.net_invariant,
            crate::snapshot::SnapshotGeometry {
                vcpus: inst.spec.vcpus,
                memory_mib: inst.spec.memory_mib,
            },
            vm,
        )
    };

    // Staging directory outside the catalog: the snapshot becomes visible
    // only on commit, and dropping `pending` on any error below takes the
    // directory and whatever partial vmstate/mem it holds with it.
    let pending = snapshots.begin(sandbox_id)?;
    let snapshot_id = pending.id().to_owned();
    let staging_dir = pending.dir();

    // Pause before snapshotting.
    vm.pause().await.map_err(VmmError::from)?;

    // Everything between pause and resume is fallible (chroot dir setup,
    // chown, the snapshot RPC). Run it in a block whose result is handled
    // only AFTER the resume — a bare `?` here previously left the guest
    // paused forever, wedging every later RPC. Returns the chroot snapshot
    // dir (jailer mode) to move afterward.
    //
    // In jailer mode FC runs inside a chroot and can only write to paths
    // within it, so the snapshot is written to a chroot-local dir and moved
    // into staging after resume.
    let paused: Result<Option<PathBuf>> = async {
        let (fc_vmstate_path, fc_mem_path, chroot_snap_dir_opt) =
            if let Some(ref jc) = config.firecracker.jailer {
                let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
                let cr = chroot_root(&config.firecracker.binary, base, &chroot_owner);
                let chroot_snap = cr.join("snapshots").join(&snapshot_id);
                std::fs::create_dir_all(&chroot_snap).map_err(VmmError::Io)?;
                // Firecracker runs as jc.uid/jc.gid; chown the directory so
                // it can create the snapshot files.
                let uid = nix::unistd::Uid::from_raw(jc.uid);
                let gid = nix::unistd::Gid::from_raw(jc.gid);
                nix::unistd::chown(&chroot_snap, Some(uid), Some(gid))
                    .map_err(|e| VmmError::Process(format!("chown snapshot dir: {e}")))?;
                // Paths as seen by Firecracker inside the chroot.
                let fc_vmstate = format!("/snapshots/{snapshot_id}/vmstate");
                let fc_mem = format!("/snapshots/{snapshot_id}/mem");
                (fc_vmstate, fc_mem, Some(chroot_snap))
            } else {
                (
                    staging_dir.join("vmstate").to_str().unwrap().to_owned(),
                    staging_dir.join("mem").to_str().unwrap().to_owned(),
                    None,
                )
            };

        vm.create_snapshot(&fc_vmstate_path, &fc_mem_path)
            .await
            .map_err(VmmError::from)?;
        Ok(chroot_snap_dir_opt)
    }
    .await;

    // Always resume, regardless of how the paused section fared — unless the
    // caller owns the resume decision (pause).
    if resume_after {
        let _ = vm.resume().await;
    }

    let chroot_snap_dir_opt = paused?;

    // If jailer mode, move snapshot files from the chroot into staging. The
    // guest is either resumed (and the files complete, FC having flushed
    // them before returning) or deliberately left paused, so in both cases
    // nothing is still writing to them.
    if let Some(chroot_snap) = chroot_snap_dir_opt {
        move_file(&chroot_snap.join("vmstate"), &staging_dir.join("vmstate"))
            .await
            .map_err(VmmError::Io)?;
        if chroot_snap.join("mem").exists() {
            move_file(&chroot_snap.join("mem"), &staging_dir.join("mem"))
                .await
                .map_err(VmmError::Io)?;
        }
        let _ = tokio::fs::remove_dir_all(&chroot_snap).await;
    }

    // Store kernel/rootfs template paths so restore can re-derive them.
    // Jailer mode needs them for chroot staging; direct mode needs the
    // rootfs path to set up a fresh dm-snapshot and retarget the
    // vmstate-recorded symlink.
    let meta = pending.commit(SnapshotDraft {
        name: Some(name),
        labels,
        snapshot_type: crate::config::SnapshotType::Full,
        parent_id: None,
        kernel_path: Some(kernel_path),
        rootfs_path: Some(rootfs_path),
        net_invariant,
        geometry: Some(geometry),
    })?;

    let snap_dir_path = meta
        .vmstate_path
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    info!(sandbox_id, snapshot_id = %meta.id, "sandbox checkpointed");
    Ok(CheckpointInfo {
        snapshot_id: meta.id,
        snapshot_dir: snap_dir_path,
        created_at: meta.created_at.to_rfc3339(),
    })
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
        checkpoint_impl(
            &self.instances,
            &self.snapshots,
            &self.config,
            sandbox_id,
            CheckpointRequest {
                name,
                labels,
                expected_state: SandboxState::Ready,
                resume_after: true,
            },
        )
        .await
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
        process: Option<fc_sdk::FirecrackerProcess>,
        network: Option<NetworkAllocation>,
        cow_handle: Option<CowHandle>,
    ) -> VmmError {
        let arc = reservation.instance();
        let (vm_dir, pool_slot_id) = {
            let inst = arc.lock().unwrap();
            (inst.vm_dir.clone(), inst.pool_slot_id.clone())
        };
        #[allow(
            clippy::cast_possible_wrap,
            reason = "Firecracker pid fits platform pid_t"
        )]
        let state_record = super::reconcile::SandboxStateRecord::new(
            id,
            process
                .as_ref()
                .and_then(fc_sdk::FirecrackerProcess::pid)
                .map(|pid| pid as i32),
            network.as_ref(),
            cow_handle.as_ref(),
            self.config.firecracker.jailer.is_some(),
            None,
        )
        .with_pool_slot(pool_slot_id.as_deref());
        let journal_error = super::reconcile::write_state_record(&vm_dir, &state_record).err();
        {
            let mut inst = arc.lock().unwrap();
            inst.state = SandboxState::Failed;
            inst.error = Some(error.to_string());
            inst.process = process;
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

        super::validate_id("sandbox id", &new_id)?;
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
        let net_alloc = if request.network_override {
            match self.network.reserve(&new_id) {
                Ok(allocation) => Some(allocation),
                Err(error) => {
                    let abort = self.records.abort_provision(&new_id, generation)?;
                    if let Some(durability_error) = abort.durability_error {
                        return Err(VmmError::Unavailable(format!(
                            "{error}; restore rollback is visible, but durability is unconfirmed: {durability_error}"
                        )));
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        let ip_address = net_alloc
            .as_ref()
            .map(|n| n.ip_address.to_string())
            .unwrap_or_default();
        let setup = (|| -> Result<()> {
            super::reconcile::create_runtime_dir(&vm_dir)?;
            let cleanup_record = super::reconcile::SandboxStateRecord::new(
                &new_id,
                None,
                net_alloc.as_ref(),
                None,
                self.config.firecracker.jailer.is_some(),
                None,
            );
            super::reconcile::write_state_record(&vm_dir, &cleanup_record)?;
            if let Some(network) = &net_alloc {
                // The restored guest keeps the addressing its snapshot baked:
                // invariant snapshots pair with an invariant TAP (host-side
                // NAT, no guest work); legacy snapshots keep the legacy TAP
                // shape and are re-addressed over the reconfig RPC below.
                let mode = if snap_meta.net_invariant {
                    crate::network::TapMode::Invariant
                } else {
                    crate::network::TapMode::LegacySnapshot
                };
                self.network.activate(network, mode)?;
            }
            Ok(())
        })();
        if let Err(error) = setup {
            return Err(self
                .rollback_restore(&new_id, reservation, error, None, net_alloc, None)
                .await);
        }
        let fc_cfg = &self.config.firecracker;

        // Track resources that need cleanup if anything between this point
        // and the final instance registration fails:
        //
        // - `pending_cow`: a CowHandle has no Drop impl, so a `?` propagating
        //   the error would silently leak the dm device + loop + COW file.
        // On success, the CoW handle is moved onto the SandboxInstance.
        let mut pending_cow: Option<CowHandle> = None;

        // CORE-78: a pre-warmed slot has already executed the spawn and
        // staging blocks below; claiming one leaves LoadSnapshot + guest
        // reconfiguration as the only restore work. From the claim on, the
        // slot's resources are owned by this restore and unwind through
        // rollback_restore like freshly created ones.
        let claimed = self.claim_restore_slot(&request.snapshot_id);
        let pool_hit = claimed.is_some();
        let (process, actual_vsock_path, effective_vmstate, effective_mem, t_spawned, t_staged) =
            if let Some(slot) = claimed {
                // Record the adopting sandbox's slot id first: failure cleanup
                // and crash reconciliation key the chroot and dm/CoW teardown
                // on it (see release_runtime_resources / sweep_orphans).
                reservation.instance().lock().unwrap().pool_slot_id = Some(slot.slot_id.clone());
                #[allow(
                    clippy::cast_possible_wrap,
                    reason = "Firecracker pid fits platform pid_t"
                )]
                let adopted_record = super::reconcile::SandboxStateRecord::new(
                    &new_id,
                    slot.process.pid().map(|pid| pid as i32),
                    net_alloc.as_ref(),
                    slot.cow_handle.as_ref(),
                    true,
                    None,
                )
                .with_pool_slot(Some(&slot.slot_id));
                let handover = super::reconcile::write_state_record(&vm_dir, &adopted_record);
                let PreparedSlot {
                    slot_id,
                    process: slot_process,
                    cow_handle,
                    vmstate_path,
                    mem_path,
                    vsock_path,
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
                        if let Err(error) = super::reconcile::clear_state_record(&slot_vm_dir) {
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
                        return Err(self
                            .rollback_restore(
                                &new_id,
                                reservation,
                                error,
                                Some(slot_process),
                                net_alloc,
                                pending_cow,
                            )
                            .await);
                    }
                }
                // Both phases were pre-executed by the slot; the timestamps
                // collapse so the completion log reports them honestly as ~0.
                let t_claimed = std::time::Instant::now();
                (
                    slot_process,
                    vsock_path,
                    vmstate_path,
                    mem_path,
                    t_claimed,
                    t_claimed,
                )
            } else {
                // Determine the actual host-side vsock UDS path FC will bind to
                // on restore and ensure the socket path is clear before spawning.
                //
                // Each jailer restore owns a distinct chroot and vsock path.
                let spawned: Result<(fc_sdk::FirecrackerProcess, PathBuf)> = async {
                    let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
                    let cr = chroot_root(&fc_cfg.binary, base, &new_id);
                    // Ensure the `run/` directory exists inside the new chroot so
                    // FC can create the vsock socket there on restore.
                    let run_dir = cr.join("run");
                    std::fs::create_dir_all(&run_dir).map_err(VmmError::Io)?;
                    let vsock_path = cr.join("run/firecracker.vsock");
                    let _ = std::fs::remove_file(&vsock_path);

                    let proc = spawn_jailer(jailer, fc_cfg, &new_id).await?;
                    Ok((proc, vsock_path))
                }
                .await;
                let (spawned_process, vsock_path) = match spawned {
                    Ok(spawned) => spawned,
                    Err(error) => {
                        return Err(self
                            .rollback_restore(&new_id, reservation, error, None, net_alloc, None)
                            .await);
                    }
                };

                #[allow(
                    clippy::cast_possible_wrap,
                    reason = "Firecracker pid fits platform pid_t"
                )]
                let pid = spawned_process.pid().map(|pid| pid as i32);
                let journal = |cow: Option<&CowHandle>| {
                    super::reconcile::write_state_record(
                        &vm_dir,
                        &super::reconcile::SandboxStateRecord::new(
                            &new_id,
                            pid,
                            net_alloc.as_ref(),
                            cow,
                            true,
                            None,
                        ),
                    )
                };
                if let Err(error) = journal(None) {
                    return Err(self
                        .rollback_restore(
                            &new_id,
                            reservation,
                            error,
                            Some(spawned_process),
                            net_alloc,
                            None,
                        )
                        .await);
                }

                let t_spawned = std::time::Instant::now();

                // In jailer mode the restored FC process also runs inside a
                // chroot and cannot access the catalog's host-absolute paths.
                // Stage the snapshot files into the new sandbox's chroot and use
                // chroot-relative paths.
                let setup_result: Result<(String, Option<String>)> = async {
                    let jc = jailer;
                    let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
                    let cr = chroot_root(&fc_cfg.binary, base, &new_id);

                    // Stage kernel (always hard-linked or copied, ~16MB).
                    if let Some(k) = snap_meta.kernel_path.as_deref() {
                        stage_kernel_for_jailer(&cr, k, jc.uid, jc.gid).await?;
                    }

                    // Stage rootfs: dm-snapshot + mknod with full-copy fallback,
                    // mirroring the boot path so restored sandboxes get the same
                    // CoW semantics (block-level template sharing, sparse COW).
                    if let Some(r) = snap_meta.rootfs_path.as_deref() {
                        match stage_rootfs_cow_or_copy(
                            &self.cow_manager,
                            &cr,
                            &new_id,
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
                    stage_snapshot_files(&cr, &snap_meta, jc.uid, jc.gid).await
                }
                .await;

                let (effective_vmstate, effective_mem) = match setup_result {
                    Ok(staged) => staged,
                    Err(error) => {
                        return Err(self
                            .rollback_restore(
                                &new_id,
                                reservation,
                                error,
                                Some(spawned_process),
                                net_alloc,
                                pending_cow,
                            )
                            .await);
                    }
                };
                (
                    spawned_process,
                    vsock_path,
                    effective_vmstate,
                    effective_mem,
                    t_spawned,
                    std::time::Instant::now(),
                )
            };

        // Build the restore parameters.
        let mut load_params = fc_sdk::types::SnapshotLoadParams {
            snapshot_path: effective_vmstate,
            mem_file_path: effective_mem,
            mem_backend: None,
            enable_diff_snapshots: None,
            track_dirty_pages: None,
            resume_vm: Some(true),
            network_overrides: vec![],
        };

        if let Some(ref net) = net_alloc {
            load_params.network_overrides = vec![fc_sdk::types::NetworkOverride {
                iface_id: "eth0".into(),
                host_dev_name: net.tap_name.clone(),
            }];
        }

        // In jailer mode, the actual socket path is inside the chroot; use the
        // path reported by the process handle instead of vm_dir's socket_path.
        let effective_socket = process.socket_path().to_owned();
        let vm = match fc_sdk::restore(effective_socket.to_str().unwrap(), load_params).await {
            Ok(v) => Arc::new(v),
            Err(e) => {
                return Err(self
                    .rollback_restore(
                        &new_id,
                        reservation,
                        VmmError::from(e),
                        Some(process),
                        net_alloc,
                        pending_cow,
                    )
                    .await);
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
            let id = new_id.clone();
            let vsock_path = actual_vsock_path.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    vsock::sync_clock(&vsock_path),
                )
                .await
                {
                    Ok(Ok(vsock::ClockSync::Synced)) => {}
                    Ok(Ok(vsock::ClockSync::AgentError(code))) => {
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
            let Some(ref net) = net_alloc else {
                return Ok(());
            };
            // Invariant-addressed snapshot: the guest already holds the fixed
            // link-local identity and its resolv.conf already points at the
            // fixed gateway; the fresh TAP carries the new pool IP host-side.
            // Zero guest-side work (CORE-81). Legacy snapshots (flag absent /
            // false) keep the reconfig RPC below.
            if snap_meta.net_invariant {
                return Ok(());
            }
            let cmd = crate::boot_proto::NetReconfigCommand {
                ip: net.ip_address,
                netmask: net.netmask(),
                gateway: net.gateway,
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                vsock::reconfigure_network(&actual_vsock_path, &cmd),
            )
            .await
            .map_err(|_| VmmError::Vsock("net reconfig after restore timed out".into()))
            .and_then(|r| r)
        };

        // The reconfig RPC is the only guest configuration still awaited —
        // and only by legacy snapshots; invariant snapshots return
        // immediately above.
        if let Err(error) = net_reconfig.await {
            return Err(self
                .rollback_restore(
                    &new_id,
                    reservation,
                    error,
                    Some(process),
                    net_alloc,
                    pending_cow,
                )
                .await);
        }

        let t_guest_cfg = std::time::Instant::now();

        // Persist cleanup metadata before handing runtime resources to the
        // instance. A failed durable write aborts and unwinds every resource.
        let adopted_slot = reservation.instance().lock().unwrap().pool_slot_id.clone();
        #[allow(
            clippy::cast_possible_wrap,
            reason = "Firecracker pid fits platform pid_t"
        )]
        let state_record = super::reconcile::SandboxStateRecord::new(
            &new_id,
            process.pid().map(|pid| pid as i32),
            net_alloc.as_ref(),
            pending_cow.as_ref(),
            true,
            None,
        )
        .with_pool_slot(adopted_slot.as_deref());
        if let Err(error) = super::reconcile::write_state_record(&vm_dir, &state_record) {
            return Err(self
                .rollback_restore(
                    &new_id,
                    reservation,
                    error,
                    Some(process),
                    net_alloc,
                    pending_cow,
                )
                .await);
        }

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
                        Some(process),
                        net_alloc,
                        pending_cow,
                    )
                    .await);
            }
        };

        // Populate the reserved instance in place, then commit the reservation
        // so it survives (the placeholder inserted by reserve_id is otherwise
        // removed on drop). All resources are now tracked on the instance and
        // torn down via remove_sandbox_impl.
        let arc = reservation.instance();
        {
            let mut inst = arc.lock().unwrap();
            inst.network.clone_from(&net_alloc);
            inst.process = Some(process);
            inst.vm = Some(vm);
            inst.vsock_uds_path = Some(actual_vsock_path.clone());
            inst.cow_handle = pending_cow.take();
            inst.net_invariant = snap_meta.net_invariant;
            inst.state = SandboxState::Ready;
            inst.ready_at = Some(Utc::now());
        }
        reservation.commit();

        let warm_create = matches!(request.origin, RestoreOrigin::WarmCreate);
        if warm_create {
            // The Create event contract: watchers see CREATED then READY for
            // this id in that order, exactly as a cold boot emits them.
            let _ = self
                .events_tx
                .send(SandboxEvent::new(&new_id, action::CREATED));
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
            spawn_ms = ms(t_spawned.duration_since(restore_started)),
            stage_ms = ms(t_staged.duration_since(t_spawned)),
            load_ms = ms(t_loaded.duration_since(t_staged)),
            guest_cfg_ms = ms(t_guest_cfg.duration_since(t_loaded)),
            total_ms = ms(restore_started.elapsed()),
            "sandbox restored from checkpoint"
        );

        // Populate/refill the pool for this snapshot in the background:
        // the successful restore is what makes it eligible for pooling.
        self.spawn_pool_refill(&request.snapshot_id);

        // A warm create still owes the Create contract's initial workload:
        // run it through the same path as a cold boot, after Ready. Kept off
        // the timing log above — the workload is the user's, not restore's.
        if warm_create && !effective_spec.cmd.is_empty() {
            super::boot::run_initial_cmd(
                &new_id,
                effective_spec,
                &actual_vsock_path,
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
        self.snapshots.delete_by_id(snapshot_id)
    }
}
