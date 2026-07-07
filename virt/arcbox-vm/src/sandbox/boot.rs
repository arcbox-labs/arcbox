use super::*;

#[allow(
    clippy::too_many_arguments,
    reason = "boot task captures manager state"
)]
pub(super) async fn boot_sandbox(
    id: SandboxId,
    spec: SandboxSpec,
    net_alloc: Option<NetworkAllocation>,
    vm_dir: PathBuf,
    instances: Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: Arc<NetworkManager>,
    config: Arc<VmmConfig>,
    events_tx: broadcast::Sender<SandboxEvent>,
    cow_manager: Arc<CowManager>,
) {
    match do_boot(
        &id,
        &spec,
        net_alloc.as_ref(),
        &vm_dir,
        &config,
        &cow_manager,
    )
    .await
    {
        Ok((process, vm, vsock_uds_path, cow_handle)) => {
            let ready_at = Utc::now();

            // Persist the crash-recovery record before handing resources to
            // the instance, so an agent restart can reconcile them.
            #[allow(
                clippy::cast_possible_wrap,
                reason = "Firecracker pid fits platform pid_t"
            )]
            let record = super::reconcile::SandboxStateRecord::new(
                &id,
                process.pid().map(|p| p as i32),
                net_alloc.as_ref(),
                cow_handle.as_ref(),
                config.firecracker.jailer.is_some(),
                None,
            );
            super::reconcile::write_state_record(&vm_dir, &record);

            let value = instances.read().unwrap().get(&id).cloned();
            if let Some(arc) = value {
                let mut inst = arc.lock().unwrap();
                // If stop was requested while booting, do not transition to Ready.
                if inst.state == SandboxState::Stopping || inst.state == SandboxState::Stopped {
                    info!(sandbox_id = %id, "sandbox boot completed but stop was requested; staying stopped");
                    return;
                }
                inst.process = Some(process);
                inst.vm = Some(vm);
                inst.vsock_uds_path = Some(vsock_uds_path.clone());
                inst.cow_handle = cow_handle;
                inst.state = SandboxState::Ready;
                inst.ready_at = Some(ready_at);
            }
            let _ = events_tx.send(SandboxEvent::new(&id, "ready"));
            info!(sandbox_id = %id, "sandbox booted and ready");

            // Launch the initial workload, if the spec carries one. The
            // sandbox stays alive when it exits (Running → Ready + "idle"),
            // exactly like an explicit Run. A start failure is logged and
            // leaves the sandbox Ready — the caller can still Run/Exec.
            if !spec.cmd.is_empty() {
                run_initial_cmd(&id, spec, &vsock_uds_path, &instances, &events_tx).await;
            }
        }
        Err(e) => {
            let value = instances.read().unwrap().get(&id).cloned();
            if let Some(arc) = value {
                let mut inst = arc.lock().unwrap();
                inst.state = SandboxState::Failed;
                inst.error = Some(e.to_string());
            }
            // Release network on boot failure.
            if let Some(ref net) = net_alloc {
                network.release(net);
            }
            let _ =
                events_tx.send(SandboxEvent::new(&id, "failed").with_attr("error", &e.to_string()));
            error!(sandbox_id = %id, error = %e, "sandbox boot failed");
        }
    }
}

/// Start the initial `cmd` from the creation spec and drain its output.
///
/// Uses the same workload path as `Run` (`start_run_workload`), so state
/// transitions and events are identical; the output itself has no consumer
/// and is discarded chunk by chunk to keep the exit handler flowing.
async fn run_initial_cmd(
    id: &SandboxId,
    spec: SandboxSpec,
    vsock_uds_path: &Path,
    instances: &super::InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) {
    let start = StartCommand {
        cmd: spec.cmd,
        env: spec.env,
        working_dir: spec.working_dir,
        user: spec.user,
        tty: false,
        tty_width: 80,
        tty_height: 24,
        timeout_seconds: 0,
    };
    match super::workload::start_run_workload(id, vsock_uds_path, start, instances, events_tx).await
    {
        Ok(mut rx) => {
            info!(sandbox_id = %id, "initial cmd started");
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
        }
        Err(e) => {
            warn!(sandbox_id = %id, error = %e, "initial cmd failed to start; sandbox stays ready");
        }
    }
}

/// Compute the host-side absolute path to the jailer chroot root directory.
///
/// Returns `{chroot_base_dir}/{fc_binary_filename}/{id}/root`.
pub(super) fn chroot_root(fc_binary: &str, chroot_base_dir: &str, id: &str) -> PathBuf {
    let exec_name = Path::new(fc_binary)
        .file_name()
        .expect("fc_binary must have a filename")
        .to_string_lossy();
    PathBuf::from(chroot_base_dir)
        .join(exec_name.as_ref())
        .join(id)
        .join("root")
}

/// Copy kernel into the jailer chroot and set ownership.
///
/// Returns the chroot-relative kernel path (e.g. `"/vmlinux"`).
pub(super) async fn stage_kernel_for_jailer(
    chroot_root: &Path,
    kernel_src: &str,
    uid: u32,
    gid: u32,
) -> Result<String> {
    tokio::fs::create_dir_all(chroot_root)
        .await
        .map_err(VmmError::Io)?;
    let kernel_dst = chroot_root.join("vmlinux");
    tokio::fs::copy(kernel_src, &kernel_dst)
        .await
        .map_err(VmmError::Io)?;
    chown(
        &kernel_dst,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|e| VmmError::Process(format!("chown kernel: {e}")))?;
    Ok("/vmlinux".to_string())
}

/// Copy rootfs into the jailer chroot and set ownership.
///
/// Returns the chroot-relative rootfs path (e.g. `"/rootfs.ext4"`).
pub(super) async fn stage_rootfs_copy_for_jailer(
    chroot_root: &Path,
    rootfs_src: &str,
    uid: u32,
    gid: u32,
) -> Result<String> {
    tokio::fs::create_dir_all(chroot_root)
        .await
        .map_err(VmmError::Io)?;
    let rootfs_dst = chroot_root.join("rootfs.ext4");
    // Remove any stale entry — a previous crash or a failed mknod-then-chown
    // fallback may have left a block device node here, in which case
    // `tokio::fs::copy` would write into the device instead of replacing it.
    if let Err(e) = tokio::fs::remove_file(&rootfs_dst).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmmError::Io(e));
    }
    tokio::fs::copy(rootfs_src, &rootfs_dst)
        .await
        .map_err(VmmError::Io)?;
    chown(
        &rootfs_dst,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|e| VmmError::Process(format!("chown rootfs: {e}")))?;
    Ok("/rootfs.ext4".to_string())
}

/// Create a block device node in the jailer chroot pointing to a dm device.
///
/// Returns the chroot-relative rootfs path (`"/rootfs.ext4"`).
pub(super) async fn stage_rootfs_device_for_jailer(
    chroot_root: &Path,
    dm_device: &str,
    uid: u32,
    gid: u32,
) -> Result<String> {
    tokio::fs::create_dir_all(chroot_root)
        .await
        .map_err(VmmError::Io)?;
    let (major, minor) = crate::snapshot_cow::device_major_minor(dm_device).await?;
    let node_path = chroot_root.join("rootfs.ext4");
    // Remove any leftover entry from a previous crash so mknod can succeed
    // (and so we never end up writing into a stale device node).
    if let Err(e) = tokio::fs::remove_file(&node_path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmmError::Io(e));
    }
    crate::snapshot_cow::mknod_blkdev(&node_path, major, minor).await?;
    chown(
        &node_path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|e| VmmError::Process(format!("chown rootfs device: {e}")))?;
    Ok("/rootfs.ext4".to_string())
}

/// Create a stable `{vm_dir}/rootfs.link` symlink pointing at the dm-snapshot
/// device.  Returns the symlink path as a string for Firecracker to use as the
/// rootfs.  The vmstate records this path verbatim, so on restore we can
/// retarget the symlink at a freshly-created dm-snapshot without FC noticing.
///
/// Removes any stale symlink first so a previous crash doesn't cause EEXIST.
pub(super) fn create_rootfs_symlink(vm_dir: &Path, dm_device: &str) -> Result<String> {
    let link_path = vm_dir.join("rootfs.link");
    let _ = std::fs::remove_file(&link_path);
    std::os::unix::fs::symlink(dm_device, &link_path).map_err(VmmError::Io)?;
    link_path
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| VmmError::Config(format!("non-UTF-8 path: {}", link_path.display())))
}

/// Release dm-snapshot + recreated origin directory after a failed restore.
///
/// `CowHandle` has no Drop impl, so dropping it would leak the dm device,
/// loop device, and sparse COW file.  This must be called on every error
/// path between `cow_manager.setup` and the point where the handle is
/// handed off to the SandboxInstance.
pub(super) async fn cleanup_pending_restore(
    cow_manager: &CowManager,
    cow: Option<CowHandle>,
    origin_dir: Option<&Path>,
) {
    if let Some(handle) = cow {
        cow_manager.teardown(&handle).await;
    }
    if let Some(dir) = origin_dir
        && let Err(e) = tokio::fs::remove_dir_all(dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(dir = %dir.display(), err = %e, "failed to clean up restore origin dir");
    }
}

/// SIGKILL Firecracker and wait for it to exit (bounded timeout).
///
/// Required before `cow_manager.teardown` on any failure path where FC may
/// have opened the dm-snapshot block device: `dmsetup remove` returns EBUSY
/// while a process still holds the device, leaking the dm device + loop +
/// sparse COW file.  `FirecrackerProcess::drop` sends SIGKILL but never
/// reaps, so by the time teardown runs FC may still be alive.
pub(super) async fn kill_and_reap_fc(process: &mut fc_sdk::FirecrackerProcess) {
    if let Some(pid) = process.pid()
        && pid > 0
    {
        let _ = nix::sys::signal::kill(
            #[allow(
                clippy::cast_possible_wrap,
                reason = "Firecracker pid fits platform pid_t"
            )]
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), process.wait()).await;
}

/// Perform the actual Firecracker boot: spawn process, configure, start VM.
///
/// Returns `(FirecrackerProcess, Arc<Vm>, vsock_uds_path, Option<CowHandle>)`
/// on success.  The `CowHandle` is `Some` whenever dm-snapshot CoW is
/// active — both direct mode and jailer mode (when the snapshot device
/// node is successfully created inside the chroot).
#[allow(
    clippy::type_complexity,
    reason = "boot returns coupled Firecracker resources"
)]
async fn do_boot(
    id: &str,
    spec: &SandboxSpec,
    net_alloc: Option<&NetworkAllocation>,
    vm_dir: &Path,
    config: &VmmConfig,
    cow_manager: &CowManager,
) -> Result<(
    fc_sdk::FirecrackerProcess,
    Arc<fc_sdk::Vm>,
    PathBuf,
    Option<CowHandle>,
)> {
    let log_path = vm_dir.join("firecracker.log");
    let metrics_path = vm_dir.join("firecracker.metrics");
    // socket_path is used only for the direct (non-jailer) mode spawn.
    let socket_path = vm_dir.join("firecracker.sock");

    let fc_cfg = &config.firecracker;

    // Some Firecracker builds expect log/metrics targets to pre-exist when
    // --log-path/--metrics-path are provided. Pre-create both files to avoid
    // startup failures with ENOENT across version variants.
    if fc_cfg.jailer.is_none() {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(VmmError::Io)?;
        }
        std::fs::File::create(&log_path).map_err(VmmError::Io)?;
        std::fs::File::create(&metrics_path).map_err(VmmError::Io)?;
    }

    // Spawn the Firecracker process (direct or via Jailer).
    let mut process = if let Some(ref jc) = fc_cfg.jailer {
        spawn_jailer(jc, fc_cfg, id).await?
    } else {
        spawn_direct(fc_cfg, id, &socket_path, &log_path, &metrics_path).await?
    };

    // Determine kernel, rootfs, and vsock paths.
    //
    // In jailer mode the files must exist inside the chroot, and paths passed
    // to the FC API are relative to the chroot root.  In direct mode the
    // host-absolute paths from the spec are used as-is.
    let (kernel_path, rootfs_path, vsock_fc_path, vsock_host_path, cow_handle) =
        if let Some(ref jc) = fc_cfg.jailer {
            // Jailer mode: stage kernel + rootfs into chroot.
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, id);

            // Kernel is always copied (small, ~16MB).
            let k = stage_kernel_for_jailer(&cr, &spec.kernel, jc.uid, jc.gid).await?;

            // Rootfs: try dm-snapshot + mknod, fall back to full copy.
            let (r, cow) = match cow_manager.setup(id, &spec.rootfs).await {
                Ok(handle) => {
                    match stage_rootfs_device_for_jailer(&cr, &handle.dm_device, jc.uid, jc.gid)
                        .await
                    {
                        Ok(path) => (path, Some(handle)),
                        Err(e) => {
                            debug!(
                                sandbox_id = %id,
                                error = %e,
                                "mknod failed, falling back to rootfs copy"
                            );
                            cow_manager.teardown(&handle).await;
                            let path =
                                stage_rootfs_copy_for_jailer(&cr, &spec.rootfs, jc.uid, jc.gid)
                                    .await?;
                            (path, None)
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        sandbox_id = %id,
                        error = %e,
                        "dm-snapshot unavailable, copying rootfs into chroot"
                    );
                    let path =
                        stage_rootfs_copy_for_jailer(&cr, &spec.rootfs, jc.uid, jc.gid).await?;
                    (path, None)
                }
            };

            let vsock_host = cr.join("run/firecracker.vsock");
            (k, r, "/run/firecracker.vsock".to_string(), vsock_host, cow)
        } else {
            // Direct mode: try dm-snapshot CoW, fall back to using rootfs directly.
            // When CoW is active, create a stable `{vm_dir}/rootfs.link` symlink
            // pointing at the dm device.  Firecracker records the symlink path
            // (not the ephemeral dm device name) in the vmstate, so a restored
            // sandbox can recreate a new dm-snapshot and retarget the symlink
            // transparently.
            let (rootfs, cow) = match cow_manager.setup(id, &spec.rootfs).await {
                Ok(handle) => match create_rootfs_symlink(vm_dir, &handle.dm_device) {
                    Ok(link) => (link, Some(handle)),
                    Err(e) => {
                        cow_manager.teardown(&handle).await;
                        return Err(e);
                    }
                },
                Err(e) => {
                    debug!(
                        sandbox_id = %id,
                        error = %e,
                        "dm-snapshot unavailable, using rootfs directly"
                    );
                    (spec.rootfs.clone(), None)
                }
            };
            let vsock_path = vm_dir.join("firecracker.vsock");
            (
                spec.kernel.clone(),
                rootfs,
                vsock_path.to_str().unwrap().to_owned(),
                vsock_path,
                cow,
            )
        };

    // Configure and boot the VM.
    let vcpu_count = NonZeroU64::new(spec.vcpus.max(1) as u64)
        .ok_or_else(|| VmmError::Config("vcpus must be > 0".into()))?;

    // Append static IP configuration to boot args so the kernel configures
    // eth0 before init runs.  The guest-side vm-agent parses this back via
    // `KernelIpParam::from_str` to derive the DNS nameserver.
    let boot_args = if let Some(net) = net_alloc {
        if spec.boot_args.contains("ip=") {
            spec.boot_args.clone()
        } else {
            let ip_param = KernelIpParam {
                client: net.ip_address,
                gateway: net.gateway,
                netmask: net.netmask(),
            };
            format!("{} {ip_param}", spec.boot_args)
        }
    } else {
        spec.boot_args.clone()
    };

    let mut builder = VmBuilder::new(process.socket_path())
        .boot_source(BootSource {
            kernel_image_path: kernel_path,
            boot_args: Some(boot_args),
            initrd_path: None,
        })
        .machine_config(fc_sdk::types::MachineConfiguration {
            vcpu_count,
            #[allow(
                clippy::cast_possible_wrap,
                reason = "memory MiB value fits Firecracker API i64"
            )]
            mem_size_mib: spec.memory_mib as i64,
            smt: false,
            // Enable dirty-page tracking so checkpointing is always available.
            track_dirty_pages: true,
            cpu_template: None,
            huge_pages: None,
        })
        .drive(Drive {
            drive_id: "rootfs".into(),
            path_on_host: Some(rootfs_path),
            is_root_device: true,
            is_read_only: Some(false),
            partuuid: None,
            cache_type: fc_sdk::types::DriveCacheType::Unsafe,
            rate_limiter: None,
            io_engine: fc_sdk::types::DriveIoEngine::Sync,
            socket: None,
        });

    if let Some(net) = net_alloc {
        builder = builder.network_interface(NetworkInterface {
            iface_id: "eth0".into(),
            guest_mac: Some(net.mac_address.clone()),
            host_dev_name: net.tap_name.clone(),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
    }

    // Configure vsock device so the guest agent can receive connections.
    // vsock_fc_path is the path FC uses inside its own filesystem view;
    // vsock_host_path is the host-absolute path used to connect from the host.
    builder = builder.vsock(Vsock {
        // CID 3 is the conventional guest CID; each Firecracker process is
        // isolated so the same CID is safe across concurrent sandboxes.
        guest_cid: 3,
        uds_path: vsock_fc_path,
        vsock_id: None,
    });

    let vm = match builder.start().await {
        Ok(v) => Arc::new(v),
        Err(e) => {
            // Clean up dm-snapshot if boot fails after setup.
            if let Some(ref handle) = cow_handle {
                // FC has likely opened the dm-snapshot block device by this
                // point.  Kill and wait before teardown so `dmsetup remove`
                // doesn't hit EBUSY and leak the dm/loop/COW resources.
                kill_and_reap_fc(&mut process).await;
                cow_manager.teardown(handle).await;
                // The rootfs.link symlink now points at a torn-down device.
                // Remove it so subsequent retries see a clean slate.  Only
                // applies to direct mode — jailer mode uses a chroot-internal
                // device node which is removed when the chroot is destroyed.
                if fc_cfg.jailer.is_none() {
                    let _ = std::fs::remove_file(vm_dir.join("rootfs.link"));
                }
            }
            return Err(VmmError::from(e));
        }
    };
    Ok((process, vm, vsock_host_path, cow_handle))
}
