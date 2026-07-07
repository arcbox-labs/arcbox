use super::boot::{
    chroot_root, cleanup_pending_restore, create_rootfs_symlink, kill_and_reap_fc,
    stage_kernel_for_jailer, stage_rootfs_copy_for_jailer, stage_rootfs_device_for_jailer,
};
use super::cleanup::remove_sandbox_impl;
use super::*;

impl SandboxManager {
    pub async fn checkpoint_sandbox(
        &self,
        sandbox_id: &SandboxId,
        name: String,
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

        // Pause before snapshotting.
        vm.pause().await.map_err(VmmError::from)?;

        let snapshot_id = Uuid::new_v4().to_string();

        // In jailer mode FC runs inside a chroot and can only write to paths
        // within that chroot.  We create a temporary snapshot directory inside
        // the chroot, pass the chroot-relative paths to FC, then move the
        // resulting files to the standard catalog location on the host.
        let (fc_vmstate_path, fc_mem_path, chroot_snap_dir_opt) =
            if let Some(ref jc) = self.config.firecracker.jailer {
                let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
                let cr = chroot_root(&self.config.firecracker.binary, base, sandbox_id);
                let chroot_snap = cr.join("snapshots").join(&snapshot_id);
                std::fs::create_dir_all(&chroot_snap).map_err(VmmError::Io)?;
                // Firecracker runs as jc.uid/jc.gid; chown the directory so it
                // can create the snapshot files.
                let uid = nix::unistd::Uid::from_raw(jc.uid);
                let gid = nix::unistd::Gid::from_raw(jc.gid);
                nix::unistd::chown(&chroot_snap, Some(uid), Some(gid))
                    .map_err(|e| VmmError::Process(format!("chown snapshot dir: {e}")))?;
                // Paths as seen by Firecracker inside the chroot.
                let fc_vmstate = format!("/snapshots/{snapshot_id}/vmstate");
                let fc_mem = format!("/snapshots/{snapshot_id}/mem");
                (fc_vmstate, fc_mem, Some(chroot_snap))
            } else {
                let snap_dir = self.snapshots.prepare_dir(sandbox_id, &snapshot_id)?;
                (
                    snap_dir.join("vmstate").to_str().unwrap().to_owned(),
                    snap_dir.join("mem").to_str().unwrap().to_owned(),
                    None,
                )
            };

        let snap_result = vm.create_snapshot(&fc_vmstate_path, &fc_mem_path).await;

        // Always resume regardless of snapshot success.
        let _ = vm.resume().await;

        snap_result.map_err(VmmError::from)?;

        // If jailer mode, move snapshot files from chroot to the catalog dir.
        let (vmstate_path, mem_path) = if let Some(chroot_snap) = chroot_snap_dir_opt {
            let catalog_dir = self.snapshots.prepare_dir(sandbox_id, &snapshot_id)?;
            let dst_vmstate = catalog_dir.join("vmstate");
            let dst_mem = catalog_dir.join("mem");
            tokio::fs::rename(chroot_snap.join("vmstate"), &dst_vmstate)
                .await
                .map_err(VmmError::Io)?;
            if chroot_snap.join("mem").exists() {
                tokio::fs::rename(chroot_snap.join("mem"), &dst_mem)
                    .await
                    .map_err(VmmError::Io)?;
            }
            let _ = tokio::fs::remove_dir_all(&chroot_snap).await;
            (dst_vmstate, dst_mem)
        } else {
            let snap_dir = self.snapshots.prepare_dir(sandbox_id, &snapshot_id)?;
            (snap_dir.join("vmstate"), snap_dir.join("mem"))
        };

        // Store kernel/rootfs template paths so restore can re-derive them.
        // Jailer mode needs them for chroot staging; direct mode needs the
        // rootfs path to set up a fresh dm-snapshot and retarget the
        // vmstate-recorded symlink.
        let meta = self.snapshots.register(
            sandbox_id,
            Some(name),
            crate::config::SnapshotType::Full,
            vmstate_path,
            Some(mem_path),
            None,
            Some(kernel_path),
            Some(rootfs_path),
        )?;

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

    /// Restore a new sandbox from a previously created checkpoint.
    ///
    /// The restored sandbox starts in `Ready` state immediately.
    ///
    /// Returns `(sandbox_id, ip_address)`.
    pub async fn restore_sandbox(&self, spec: RestoreSandboxSpec) -> Result<(SandboxId, String)> {
        let new_id = spec
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        if new_id.contains('/')
            || new_id.contains('\\')
            || new_id.contains('\0')
            || new_id == "."
            || new_id == ".."
        {
            return Err(VmmError::Config(format!(
                "invalid sandbox ID: {new_id:?} (must not contain path separators)"
            )));
        }

        // Uniqueness check.
        {
            let instances = self.instances.read().unwrap();
            if instances.contains_key(&new_id) {
                return Err(VmmError::AlreadyExists(new_id.clone()));
            }
        }

        // Allocate network if requested.
        let net_alloc = if spec.network_override {
            Some(self.network.allocate(&new_id)?)
        } else {
            None
        };

        let ip_address = net_alloc
            .as_ref()
            .map(|n| n.ip_address.to_string())
            .unwrap_or_default();

        // Create working directory.
        let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
            .join("sandboxes")
            .join(&new_id);
        std::fs::create_dir_all(&vm_dir).map_err(VmmError::Io)?;
        let socket_path = vm_dir.join("firecracker.sock");

        // Locate checkpoint on disk.
        let snap_meta = self.snapshots.find_by_id(&spec.snapshot_id)?;
        let vmstate_str = snap_meta.vmstate_path.to_str().unwrap().to_owned();
        let mem_file = snap_meta.mem_path.as_ref().and_then(|p| {
            if p.exists() {
                Some(p.to_str().unwrap().to_owned())
            } else {
                None
            }
        });

        let fc_cfg = &self.config.firecracker;

        // Track resources that need cleanup if anything between this point
        // and the final instance registration fails:
        //
        // - `pending_cow`: a CowHandle has no Drop impl, so a `?` propagating
        //   the error would silently leak the dm device + loop + COW file.
        // - `pending_origin_dir` (direct mode only): we recreate the original
        //   sandbox's vm_dir so the vmstate-recorded symlink + vsock paths
        //   resolve.  Set as soon as the dir is created so any later failure
        //   (CoW setup, fc_sdk::restore) cleans it up, not only the CoW Ok
        //   branch.
        //
        // On success, both are moved onto the SandboxInstance.
        let mut pending_cow: Option<CowHandle> = None;
        let mut pending_origin_dir: Option<PathBuf> = None;

        // Determine the actual host-side vsock UDS path FC will bind to on restore
        // and ensure the socket path is clear before spawning.
        //
        // - Jailer mode: each sandbox has its own chroot; FC sees `/run/firecracker.vsock`
        //   which maps to `{chroot_root}/run/firecracker.vsock` on the host. No conflict
        //   between sandboxes — we just ensure the `run/` directory exists.
        // - Direct mode: the vmstate stores the ABSOLUTE host path from the original
        //   sandbox. We must recreate that directory and delete any stale socket so FC
        //   can bind successfully.
        let (mut process, actual_vsock_path) = if let Some(ref jc) = fc_cfg.jailer {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, &new_id);
            // Ensure the `run/` directory exists inside the new chroot so FC can
            // create the vsock socket there on restore.
            let run_dir = cr.join("run");
            std::fs::create_dir_all(&run_dir).map_err(VmmError::Io)?;
            let vsock_path = cr.join("run/firecracker.vsock");
            let _ = std::fs::remove_file(&vsock_path);

            let proc = spawn_jailer(jc, fc_cfg, &new_id).await?;
            (proc, vsock_path)
        } else {
            // Direct mode: the vmstate embeds the original sandbox's full vsock
            // path.  Firecracker cannot override this on restore, so we must
            // reuse the original directory.  This means concurrent restores from
            // the same checkpoint (or restoring while the source sandbox is
            // still running) will conflict on the vsock socket.
            let original_vm_dir = PathBuf::from(&fc_cfg.data_dir)
                .join("sandboxes")
                .join(&snap_meta.vm_id);
            let original_vsock_path = original_vm_dir.join("firecracker.vsock");

            // Guard: if the vsock socket is already in use (source sandbox or
            // another restore is still running), reject early.
            if original_vsock_path.exists() {
                // Check if the socket is live by attempting a non-blocking connect.
                if std::os::unix::net::UnixStream::connect(&original_vsock_path).is_ok() {
                    return Err(VmmError::Vsock(format!(
                        "vsock path {} is already in use by another sandbox; \
                         direct-mode restore does not support concurrent restores \
                         from the same checkpoint",
                        original_vsock_path.display(),
                    )));
                }
                // Stale socket file — safe to remove.
                let _ = std::fs::remove_file(&original_vsock_path);
            }

            if let Err(e) = std::fs::create_dir_all(&original_vm_dir)
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(VmmError::Io(e));
            }
            // Track the dir for cleanup — any failure past this point (FC spawn,
            // CoW setup, fc_sdk::restore) must remove it, not only the CoW Ok
            // branch.
            pending_origin_dir = Some(original_vm_dir.clone());

            // Pre-create log/metrics files — Firecracker requires them to
            // exist at startup (same as the boot path in do_boot).
            let log_path = vm_dir.join("firecracker.log");
            let metrics_path = vm_dir.join("firecracker.metrics");
            std::fs::File::create(&log_path).map_err(VmmError::Io)?;
            std::fs::File::create(&metrics_path).map_err(VmmError::Io)?;
            let proc =
                spawn_direct(fc_cfg, &new_id, &socket_path, &log_path, &metrics_path).await?;
            (proc, original_vsock_path)
        };

        // In jailer mode the restored FC process also runs inside a chroot and
        // cannot access the catalog's host-absolute paths.  Copy the snapshot
        // files into the new sandbox's chroot and use chroot-relative paths.
        let setup_result: Result<(String, Option<String>)> = async {
            if let Some(ref jc) = fc_cfg.jailer {
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
                            match stage_rootfs_device_for_jailer(
                                &cr,
                                &handle.dm_device,
                                jc.uid,
                                jc.gid,
                            )
                            .await
                            {
                                Ok(_) => pending_cow = Some(handle),
                                Err(e) => {
                                    debug!(
                                        sandbox_id = %new_id,
                                        error = %e,
                                        "mknod failed on restore, falling back to rootfs copy"
                                    );
                                    self.cow_manager.teardown(&handle).await;
                                    stage_rootfs_copy_for_jailer(&cr, r, jc.uid, jc.gid).await?;
                                }
                            }
                        }
                        Err(e) => {
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
            } else {
                // Direct mode: set up a fresh dm-snapshot for the restored sandbox
                // and retarget the vmstate-recorded `{original_vm_dir}/rootfs.link`
                // at the new device.  FC reopens the symlink path on restore.
                //
                // Unlike boot, direct-mode restore has no usable fallback:  the
                // vmstate-recorded path is the symlink, so the only way for FC to
                // open the rootfs is for that symlink to exist.  If dm-snapshot
                // isn't available we fail explicitly rather than silently letting
                // `fc_sdk::restore` fault on a missing file.
                let rootfs = snap_meta.rootfs_path.as_deref().ok_or_else(|| {
                    VmmError::Config(
                        "snapshot has no rootfs_path; cannot restore in direct mode".into(),
                    )
                })?;
                let handle = self.cow_manager.setup(&new_id, rootfs).await.map_err(|e| {
                    VmmError::DeviceMapper(format!(
                        "dm-snapshot setup failed during direct-mode restore: {e}"
                    ))
                })?;
                let original_vm_dir = PathBuf::from(&fc_cfg.data_dir)
                    .join("sandboxes")
                    .join(&snap_meta.vm_id);
                if let Err(e) = create_rootfs_symlink(&original_vm_dir, &handle.dm_device) {
                    self.cow_manager.teardown(&handle).await;
                    return Err(e);
                }
                pending_cow = Some(handle);

                Ok((vmstate_str, mem_file))
            }
        }
        .await;

        let (effective_vmstate, effective_mem) = match setup_result {
            Ok(x) => x,
            Err(e) => {
                // FC was spawned but hasn't yet been told to load the vmstate,
                // so it shouldn't have the dm device open.  Kill it anyway
                // before teardown so the cleanup is unconditionally safe.
                kill_and_reap_fc(&mut process).await;
                cleanup_pending_restore(
                    &self.cow_manager,
                    pending_cow,
                    pending_origin_dir.as_deref(),
                )
                .await;
                return Err(e);
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
                // FC has likely opened the dm-snapshot block device by now
                // (vmstate load reopens all recorded drives).  Kill and wait
                // before teardown so `dmsetup remove` doesn't hit EBUSY.
                kill_and_reap_fc(&mut process).await;
                cleanup_pending_restore(
                    &self.cow_manager,
                    pending_cow.take(),
                    pending_origin_dir.as_deref(),
                )
                .await;
                return Err(VmmError::from(e));
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

        // Build and register the new sandbox instance.
        let restore_spec = SandboxSpec {
            id: Some(new_id.clone()),
            labels: spec.labels,
            ttl_seconds: spec.ttl_seconds,
            ..Default::default()
        };
        let mut instance =
            SandboxInstance::new(new_id.clone(), restore_spec, net_alloc.clone(), vm_dir);
        instance.process = Some(process);
        instance.vm = Some(vm);
        instance.vsock_uds_path = Some(actual_vsock_path);
        // Hand off pending resources to the instance — they're now tracked
        // for teardown via `remove_sandbox_impl` and won't leak.
        instance.cow_handle = pending_cow.take();
        instance.restore_origin_dir = pending_origin_dir.take();
        instance.state = SandboxState::Ready;
        instance.ready_at = Some(Utc::now());

        // Persist the crash-recovery record for the restored sandbox.
        #[allow(
            clippy::cast_possible_wrap,
            reason = "Firecracker pid fits platform pid_t"
        )]
        let record = super::reconcile::SandboxStateRecord::new(
            &new_id,
            instance
                .process
                .as_ref()
                .and_then(|p| p.pid())
                .map(|p| p as i32),
            instance.network.as_ref(),
            instance.cow_handle.as_ref(),
            self.config.firecracker.jailer.is_some(),
            instance.restore_origin_dir.as_deref(),
        );
        super::reconcile::write_state_record(&instance.vm_dir, &record);

        {
            let mut instances = self.instances.write().unwrap();
            instances.insert(new_id.clone(), Arc::new(Mutex::new(instance)));
        }

        let _ = self.events_tx.send(SandboxEvent::new(&new_id, "ready"));

        // TTL expiry task.
        if spec.ttl_seconds > 0 {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let events_tx = self.events_tx.clone();
            let config2 = Arc::clone(&self.config);
            let cow2 = Arc::clone(&self.cow_manager);
            let id2 = new_id.clone();
            let ttl = spec.ttl_seconds;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl as u64)).await;
                remove_sandbox_impl(
                    &id2, true, &instances, &network, &events_tx, &config2, &cow2,
                )
                .await;
            });
        }

        info!(
            sandbox_id = %new_id,
            snapshot_id = %spec.snapshot_id,
            "sandbox restored from checkpoint"
        );
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
                labels: HashMap::new(),
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
