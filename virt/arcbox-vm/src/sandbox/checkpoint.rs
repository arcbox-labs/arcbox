use super::boot::{
    chroot_root, stage_kernel_for_jailer, stage_rootfs_copy_for_jailer,
    stage_rootfs_device_for_jailer,
};
use super::persistence::{ProvisionIntent, SandboxProvisionOutcome, SandboxTransition};
use super::types::action;
use super::*;

/// Move a file even when source and destination sit on different mounts.
///
/// The jailer chroot is its own vfsmount (bind + pivot_root), so a plain
/// `rename(2)` out of it fails with `EXDEV` regardless of the underlying
/// filesystem; fall back to copy + remove in that case.
async fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
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

impl SandboxManager {
    /// Rootfs images that existing snapshots need to stay restorable.
    ///
    /// Exposed so whoever owns the converted-rootfs cache can pin them; see
    /// [`SnapshotCatalog::referenced_rootfs_paths`].
    pub fn pinned_rootfs_paths(&self) -> Result<std::collections::BTreeSet<PathBuf>> {
        self.snapshots.referenced_rootfs_paths()
    }

    pub async fn checkpoint_sandbox(
        &self,
        sandbox_id: &SandboxId,
        name: String,
        labels: HashMap<String, String>,
    ) -> Result<CheckpointInfo> {
        // Verify state and capture the kernel/rootfs paths for jailer re-staging.
        let (kernel_path, rootfs_path) = {
            let instance = self.get_instance(sandbox_id)?;
            let inst = instance.lock().unwrap();
            if inst.state != SandboxState::Ready {
                return Err(VmmError::WrongState {
                    id: sandbox_id.clone(),
                    expected: "Ready".into(),
                    actual: inst.state.to_string(),
                });
            }
            // Only needed for jailer mode; safe to capture regardless.
            (inst.spec.kernel.clone(), inst.spec.rootfs.clone())
        };

        let vm = self.get_vm_handle(sandbox_id)?;

        // Staging directory outside the catalog: the snapshot becomes visible
        // only on commit, and dropping `pending` on any error below takes the
        // directory and whatever partial vmstate/mem it holds with it.
        let pending = self.snapshots.begin(sandbox_id)?;
        let snapshot_id = pending.id().to_owned();
        let staging_dir = pending.dir();

        // Pause before snapshotting.
        vm.pause().await.map_err(VmmError::from)?;

        // Everything between pause and resume is fallible (chroot dir setup,
        // chown, the snapshot RPC). Run it in a block whose result is handled
        // only AFTER an unconditional resume — a bare `?` here previously left
        // the guest paused forever, wedging every later RPC. Returns the chroot
        // snapshot dir (jailer mode) to move afterward.
        //
        // In jailer mode FC runs inside a chroot and can only write to paths
        // within it, so the snapshot is written to a chroot-local dir and moved
        // into staging after resume.
        let paused: Result<Option<PathBuf>> = async {
            let (fc_vmstate_path, fc_mem_path, chroot_snap_dir_opt) =
                if let Some(ref jc) = self.config.firecracker.jailer {
                    let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
                    let cr = chroot_root(&self.config.firecracker.binary, base, sandbox_id);
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

        // Always resume, regardless of how the paused section fared.
        let _ = vm.resume().await;

        let chroot_snap_dir_opt = paused?;

        // If jailer mode, move snapshot files from the chroot into staging.
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
        let vm_dir = arc.lock().unwrap().vm_dir.clone();
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
        );
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
        // Gate on the startup sweep before touching per-id resources (see
        // create_sandbox / await_reconcile).
        self.await_reconcile().await?;

        let caller_supplied_id = spec.id.as_ref().is_some_and(|id| !id.is_empty());
        let new_id = spec
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        super::validate_id("sandbox id", &new_id)?;
        // The snapshot id is caller-supplied and flows into snapshot dir paths
        // (create_dir_all / copy / remove_dir_all) — validate it too, or a
        // `../` id would traverse out of the snapshots directory.
        super::validate_id("snapshot id", &spec.snapshot_id)?;

        if caller_supplied_id
            && let Some(outcome) = self.records.replay_provision(&new_id, restore_key)?
        {
            return Ok((new_id, outcome.ip_address));
        }

        // Resolve read-only prerequisites before claiming durable ownership.
        // Once the intent exists, every failure goes through rollback.
        let snap_meta = self.snapshots.find_by_id(&spec.snapshot_id)?;
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
        let restore_spec = SandboxSpec {
            id: Some(new_id.clone()),
            labels: spec.labels.clone(),
            ttl_seconds: spec.ttl_seconds,
            ..Default::default()
        };
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
        {
            let arc = reservation.instance();
            let mut instance = arc.lock().unwrap();
            instance.record_generation = Some(generation);
            instance.labels.clone_from(&record.effective_spec.labels);
            instance.spec = record.effective_spec;
            instance.created_at = record.created_at;
        }

        // Reserve network metadata, journal it, then materialize the TAP. This
        // mirrors Create so an agent crash never leaves an unowned interface.
        let net_alloc = if spec.network_override {
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
                self.network.activate(network)?;
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

        // Determine the actual host-side vsock UDS path FC will bind to on restore
        // and ensure the socket path is clear before spawning.
        //
        // Each jailer restore owns a distinct chroot and vsock path.
        let spawned: Result<(fc_sdk::FirecrackerProcess, PathBuf)> = async {
            let base = jailer.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, &new_id);
            // Ensure the `run/` directory exists inside the new chroot so FC can
            // create the vsock socket there on restore.
            let run_dir = cr.join("run");
            std::fs::create_dir_all(&run_dir).map_err(VmmError::Io)?;
            let vsock_path = cr.join("run/firecracker.vsock");
            let _ = std::fs::remove_file(&vsock_path);

            let proc = spawn_jailer(jailer, fc_cfg, &new_id).await?;
            Ok((proc, vsock_path))
        }
        .await;
        let (process, actual_vsock_path) = match spawned {
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
        let spawned_record = super::reconcile::SandboxStateRecord::new(
            &new_id,
            process.pid().map(|pid| pid as i32),
            net_alloc.as_ref(),
            None,
            self.config.firecracker.jailer.is_some(),
            None,
        );
        if let Err(error) = super::reconcile::write_state_record(&vm_dir, &spawned_record) {
            return Err(self
                .rollback_restore(&new_id, reservation, error, Some(process), net_alloc, None)
                .await);
        }

        // In jailer mode the restored FC process also runs inside a chroot and
        // cannot access the catalog's host-absolute paths.  Copy the snapshot
        // files into the new sandbox's chroot and use chroot-relative paths.
        let setup_result: Result<(String, Option<String>)> = async {
            let jc = jailer;
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, &new_id);
            let snap_in_chroot = cr.join("snapshots").join(&spec.snapshot_id);
            std::fs::create_dir_all(&snap_in_chroot).map_err(VmmError::Io)?;
            let uid = nix::unistd::Uid::from_raw(jc.uid);
            let gid = nix::unistd::Gid::from_raw(jc.gid);
            nix::unistd::chown(&snap_in_chroot, Some(uid), Some(gid))
                .map_err(|e| VmmError::Process(format!("chown snap dir: {e}")))?;

            // Stage kernel (always copied, ~16MB).
            if let Some(k) = snap_meta.kernel_path.as_deref() {
                stage_kernel_for_jailer(&cr, k, jc.uid, jc.gid).await?;
            }

            // Stage rootfs: try dm-snapshot + mknod, fall back to full copy.
            // Mirrors the boot path so restored sandboxes get the same CoW
            // semantics (block-level sharing of the template, sparse COW).
            if let Some(r) = snap_meta.rootfs_path.as_deref() {
                match self.cow_manager.setup(&new_id, r).await {
                    Ok(handle) => {
                        pending_cow = Some(handle);
                        #[allow(
                            clippy::cast_possible_wrap,
                            reason = "Firecracker pid fits platform pid_t"
                        )]
                        let record = super::reconcile::SandboxStateRecord::new(
                            &new_id,
                            process.pid().map(|pid| pid as i32),
                            net_alloc.as_ref(),
                            pending_cow.as_ref(),
                            true,
                            None,
                        );
                        super::reconcile::write_state_record(&vm_dir, &record)?;
                        match stage_rootfs_device_for_jailer(
                            &cr,
                            &pending_cow.as_ref().unwrap().dm_device,
                            jc.uid,
                            jc.gid,
                        )
                        .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                debug!(
                                    sandbox_id = %new_id,
                                    error = %e,
                                    "mknod failed on restore, falling back to rootfs copy"
                                );
                                self.cow_manager
                                    .teardown_checked(pending_cow.as_ref().unwrap())
                                    .await?;
                                pending_cow = None;
                                #[allow(
                                    clippy::cast_possible_wrap,
                                    reason = "Firecracker pid fits platform pid_t"
                                )]
                                let record = super::reconcile::SandboxStateRecord::new(
                                    &new_id,
                                    process.pid().map(|pid| pid as i32),
                                    net_alloc.as_ref(),
                                    None,
                                    true,
                                    None,
                                );
                                super::reconcile::write_state_record(&vm_dir, &record)?;
                                stage_rootfs_copy_for_jailer(&cr, r, jc.uid, jc.gid).await?;
                            }
                        }
                    }
                    Err(e) => {
                        if matches!(e, VmmError::Unavailable(_)) {
                            return Err(e);
                        }
                        debug!(
                            sandbox_id = %new_id,
                            error = %e,
                            "dm-snapshot unavailable on restore, copying rootfs"
                        );
                        stage_rootfs_copy_for_jailer(&cr, r, jc.uid, jc.gid).await?;
                    }
                }
            }

            // Copy vmstate into chroot.
            let dst_vmstate = snap_in_chroot.join("vmstate");
            tokio::fs::copy(&snap_meta.vmstate_path, &dst_vmstate)
                .await
                .map_err(VmmError::Io)?;
            nix::unistd::chown(&dst_vmstate, Some(uid), Some(gid))
                .map_err(|e| VmmError::Process(format!("chown vmstate: {e}")))?;

            let effective_mem = if let Some(ref mf) = snap_meta.mem_path
                && mf.exists()
            {
                let dst_mem = snap_in_chroot.join("mem");
                tokio::fs::copy(mf, &dst_mem).await.map_err(VmmError::Io)?;
                nix::unistd::chown(&dst_mem, Some(uid), Some(gid))
                    .map_err(|e| VmmError::Process(format!("chown mem: {e}")))?;
                Some(format!("/snapshots/{}/mem", spec.snapshot_id))
            } else {
                None
            };

            Ok((
                format!("/snapshots/{}/vmstate", spec.snapshot_id),
                effective_mem,
            ))
        }
        .await;

        let (effective_vmstate, effective_mem) = match setup_result {
            Ok(x) => x,
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

        // Synchronise the guest clock to the host after restore.  The sandbox
        // clock is frozen at snapshot creation time; correct it before any
        // workload runs.  A failure here is non-fatal — the sandbox is still
        // usable, just with a potentially stale clock.
        //
        // Use a short timeout so clock sync never dominates restore latency.
        // sync_clock itself has a 5s read timeout, but connect_to_agent can
        // retry for up to AGENT_READY_TIMEOUT (30s).  Cap the whole operation.
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            vsock::sync_clock(&actual_vsock_path),
        )
        .await
        {
            Ok(Err(e)) => warn!(sandbox_id = %new_id, "clock sync after restore failed: {e}"),
            Err(_) => warn!(sandbox_id = %new_id, "clock sync after restore timed out"),
            Ok(Ok(())) => {}
        }

        // Re-address the guest to the fresh allocation. The restored kernel
        // still carries the origin's `ip=` boot configuration, so without
        // this the clone would squat the origin's IP on its new TAP and
        // never own the address its DNAT/expose mappings target. Unlike the
        // clock, a fresh-network restore without a working network is the
        // silent breakage `network_override` exists to prevent — fail the
        // restore rather than hand back a half-networked sandbox.
        if let Some(ref net) = net_alloc {
            let cmd = crate::boot_proto::NetReconfigCommand {
                ip: net.ip_address,
                netmask: net.netmask(),
                gateway: net.gateway,
            };
            let reconfig = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                vsock::reconfigure_network(&actual_vsock_path, &cmd),
            )
            .await
            .map_err(|_| VmmError::Vsock("net reconfig after restore timed out".into()))
            .and_then(|r| r);
            if let Err(error) = reconfig {
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
        }

        // Persist cleanup metadata before handing runtime resources to the
        // instance. A failed durable write aborts and unwinds every resource.
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
        );
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
            inst.vsock_uds_path = Some(actual_vsock_path);
            inst.cow_handle = pending_cow.take();
            inst.state = SandboxState::Ready;
            inst.ready_at = Some(Utc::now());
        }
        reservation.commit();
        let ttl_armed_for = Arc::downgrade(&arc);

        let _ = self
            .events_tx
            .send(SandboxEvent::new(&new_id, action::READY));

        // TTL expiry task — identity-guarded so a stale timer can't remove a
        // same-id sandbox re-created after this one (see expire_sandbox).
        if spec.ttl_seconds > 0 {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let events_tx = self.events_tx.clone();
            let config2 = Arc::clone(&self.config);
            let cow2 = Arc::clone(&self.cow_manager);
            let records = Arc::clone(&self.records);
            let id2 = new_id.clone();
            let ttl = spec.ttl_seconds;
            let armed_for = ttl_armed_for;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl as u64)).await;
                super::cleanup::expire_sandbox(
                    &id2,
                    Some(generation),
                    &armed_for,
                    &instances,
                    &network,
                    &events_tx,
                    &config2,
                    &cow2,
                    &records,
                )
                .await;
            });
        }

        info!(
            sandbox_id = %new_id,
            snapshot_id = %spec.snapshot_id,
            "sandbox restored from checkpoint"
        );
        if let Some(error) = ready_commit.durability_error {
            return Err(VmmError::Unavailable(format!(
                "sandbox {new_id} was restored, but ACK durability is unconfirmed: {error}"
            )));
        }
        Ok((new_id, ip_address))
    }

    /// List checkpoints, optionally filtered by origin sandbox ID.
    pub fn list_checkpoints(&self, sandbox_id: Option<&str>) -> Result<Vec<CheckpointSummary>> {
        let infos = match sandbox_id {
            Some(sid) => self.snapshots.list(sid)?,
            None => self.snapshots.list_all()?,
        };
        Ok(infos
            .into_iter()
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

    /// Delete a checkpoint by its ID.
    pub fn delete_checkpoint(&self, snapshot_id: &str) -> Result<()> {
        self.snapshots.delete_by_id(snapshot_id)
    }
}
