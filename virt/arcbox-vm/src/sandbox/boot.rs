use super::persistence::{SandboxRecordStore, SandboxTransition};
use super::types::action;
use super::*;

type BootOutput = (Arc<fc_sdk::Vm>, PathBuf, vsock::ReadyListener);

/// How long the readiness gate waits for vm-agent's dial-out (the guest
/// connect to [`vsock::READY_PORT`]) before the boot is declared failed.
/// Covers guest kernel boot plus agent startup.
const AGENT_GATE_TIMEOUT: Duration = Duration::from_secs(35);

/// Cap on the non-gating cold-boot clock sync: `sync_clock`'s internal
/// connect loop can retry for up to 30 s, pointlessly long for an agent
/// that has already dialed out. Mirrors the restore path's cap.
const CLOCK_SYNC_TIMEOUT: Duration = Duration::from_secs(10);

struct BootFailure {
    error: VmmError,
    process: Option<fc_sdk::FirecrackerProcess>,
    cow_handle: Option<CowHandle>,
}

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
    records: Arc<SandboxRecordStore>,
    generation: Uuid,
    resource_handoff: tokio::sync::oneshot::Sender<()>,
) {
    match do_boot(
        &id,
        &spec,
        net_alloc.as_ref(),
        &vm_dir,
        &config,
        &cow_manager,
        &instances,
        generation,
        resource_handoff,
    )
    .await
    {
        Ok((vm, vsock_uds_path, ready_listener)) => {
            let current = instances.read().unwrap().get(&id).cloned();
            let is_current_generation = current
                .as_ref()
                .is_some_and(|arc| arc.lock().unwrap().record_generation == Some(generation));
            if !is_current_generation {
                info!(sandbox_id = %id, "stale sandbox boot completed");
                return;
            }

            // READY promises "accepting executions", but InstanceStart returns
            // while the guest kernel is still booting and vm-agent is not yet
            // listening. The gate is an event, not a poll: once its exec and
            // file listeners are up, vm-agent dials host port READY_PORT, and
            // the accept on the listener do_boot pre-bound IS the signal.
            //
            // Compat: an OLD vm-agent (no dial-out) under this host would sit
            // out the full gate timeout — but the template freshness keys
            // (the vm-agent binary among them) rebuild the default template
            // and re-inject it into docker templates automatically, so a
            // guest always carries the agent from the same build as its host.
            let agent_ready = match tokio::time::timeout(AGENT_GATE_TIMEOUT, ready_listener.wait())
                .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(VmmError::Vsock(format!("agent readiness gate: {error}"))),
                Err(_) => Err(VmmError::Vsock(format!(
                    "agent readiness gate: vm-agent did not dial the ready port within {}s",
                    AGENT_GATE_TIMEOUT.as_secs()
                ))),
            };
            // The socket file is per-boot; the gate has consumed its one event.
            drop(ready_listener);
            if let Err(gate_error) = agent_ready {
                let message = gate_error.to_string();
                fail_started_boot(
                    &id,
                    generation,
                    &message,
                    &vm_dir,
                    &instances,
                    &network,
                    &config,
                    &cow_manager,
                    &records,
                    &events_tx,
                )
                .await;
                error!(sandbox_id = %id, error = %gate_error, "sandbox agent readiness gate failed");
                return;
            }

            // The guest clock still needs setting on cold boot (no RTC — the
            // guest wakes at the kernel default epoch), but it must not delay
            // readiness either: the agent is already accepting executions, so
            // a slow or retrying sync holding the Ready publication back
            // would recreate the latency this gate exists to remove. Fire it
            // detached; any failure is a warn, mirroring the restore path.
            // Belt-and-braces alongside vm-agent's ptp_kvm self-sync;
            // retires once ptp is proven in production.
            {
                let id = id.clone();
                let vsock_uds_path = vsock_uds_path.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        CLOCK_SYNC_TIMEOUT,
                        vsock::sync_clock(&vsock_uds_path),
                    )
                    .await
                    {
                        Ok(Ok(vsock::ClockSync::Synced)) => {}
                        Ok(Ok(vsock::ClockSync::AgentError(code))) => {
                            warn!(
                                sandbox_id = %id, code,
                                "agent could not set the clock; continuing with a possibly skewed clock"
                            );
                        }
                        Ok(Err(error)) => {
                            warn!(sandbox_id = %id, %error, "cold-boot clock sync failed; continuing");
                        }
                        Err(_) => {
                            warn!(sandbox_id = %id, "cold-boot clock sync timed out; continuing");
                        }
                    }
                });
            }

            let ready_at = Utc::now();

            // do_boot persisted every cleanup resource before completing the
            // handoff, so only the lifecycle phase remains to make Ready.
            let durable_ready =
                records
                    .transition(&id, generation, SandboxTransition::Ready)
                    .and_then(|commit| match commit.durability_error {
                        Some(error) => Err(VmmError::Unavailable(format!(
                            "sandbox {id} ready state is visible, but durability is unconfirmed: {error}"
                        ))),
                        None => Ok(()),
                    });
            if let Err(record_error) = durable_ready {
                let message = format!("failed to persist ready state: {record_error}");
                fail_started_boot(
                    &id,
                    generation,
                    &message,
                    &vm_dir,
                    &instances,
                    &network,
                    &config,
                    &cow_manager,
                    &records,
                    &events_tx,
                )
                .await;
                error!(sandbox_id = %id, error = %record_error, "sandbox ready state was not durable");
                return;
            }

            // Hand the post-boot API objects to the instance. Every cleanup
            // resource was transferred before configuration could be aborted.
            let mut vm = Some(vm);
            let accepted = {
                let map = instances.read().unwrap();
                match map.get(&id) {
                    Some(arc) => {
                        let mut inst = arc.lock().unwrap();
                        if inst.record_generation != Some(generation)
                            || matches!(inst.state, SandboxState::Stopping | SandboxState::Stopped)
                        {
                            false
                        } else {
                            inst.vm = vm.take();
                            inst.vsock_uds_path = Some(vsock_uds_path.clone());
                            inst.state = SandboxState::Ready;
                            inst.ready_at = Some(ready_at);
                            true
                        }
                    }
                    None => false,
                }
            };

            if !accepted {
                info!(sandbox_id = %id, "sandbox removed/stopped during boot");
                return;
            }

            let _ = events_tx.send(SandboxEvent::new(&id, action::READY));
            info!(sandbox_id = %id, "sandbox booted and ready");

            // Launch the initial workload, if the spec carries one. The
            // sandbox stays alive when it exits (Running → Ready + "idle"),
            // exactly like an explicit Run. A start failure is logged and
            // leaves the sandbox Ready — the caller can still Run/Exec.
            if !spec.cmd.is_empty() {
                run_initial_cmd(&id, spec, &vsock_uds_path, &instances, &events_tx).await;
            }
        }
        Err(mut failure) => {
            let message = failure.error.to_string();
            let value = instances.read().unwrap().get(&id).cloned();
            let cleanup_lock = value
                .as_ref()
                .map(|arc| arc.lock().unwrap().cleanup_lock.clone());
            let _cleanup_guard = match cleanup_lock.as_ref() {
                Some(lock) => Some(lock.lock().await),
                None => None,
            };
            let mut updated_current = false;
            let mut record_error = None;
            let mut failure_record_visible = false;
            if let Some(ref arc) = value {
                let mut inst = arc.lock().unwrap();
                if can_mark_boot_failed(&inst, generation) {
                    (failure_record_visible, record_error) =
                        persist_boot_failure(&records, &id, generation, &message);
                    inst.state = SandboxState::Failed;
                    inst.error = Some(message.clone());
                    if let Some(process) = failure.process.take() {
                        inst.process = Some(process);
                    }
                    if let Some(cow_handle) = failure.cow_handle.take() {
                        inst.cow_handle = Some(cow_handle);
                    }
                    updated_current = true;
                }
            }
            let cleanup_complete = if updated_current {
                match super::cleanup::release_runtime_resources(
                    &id,
                    value.as_ref().unwrap(),
                    &network,
                    &config,
                    &cow_manager,
                )
                .await
                {
                    Ok(()) => true,
                    Err(error) => {
                        error!(sandbox_id = %id, error = %error, "boot failure cleanup incomplete");
                        false
                    }
                }
            } else if let Some(process) = failure.process.take() {
                match tear_down_orphaned_boot(process, failure.cow_handle.take(), &cow_manager)
                    .await
                {
                    Ok(()) => true,
                    Err(error) => {
                        error!(sandbox_id = %id, error = %error, "stale boot failure cleanup incomplete");
                        false
                    }
                }
            } else if let Some(handle) = failure.cow_handle.take() {
                match cow_manager.teardown_checked(&handle).await {
                    Ok(()) => true,
                    Err(error) => {
                        error!(sandbox_id = %id, error = %error, "stale boot CoW cleanup incomplete");
                        false
                    }
                }
            } else {
                true
            };
            if failure_record_visible && cleanup_complete {
                if let Err(error) = super::reconcile::clear_state_record(&vm_dir) {
                    error!(sandbox_id = %id, error = %error, "stale boot journal cleanup is not durable");
                }
            }
            if updated_current {
                let _ = events_tx
                    .send(SandboxEvent::new(&id, action::FAILED).with_attr("error", &message));
            }
            if let Some(record_error) = record_error {
                error!(
                    sandbox_id = %id,
                    error = %record_error,
                    "failed to persist sandbox boot failure"
                );
            }
            error!(sandbox_id = %id, error = %failure.error, "sandbox boot failed");
        }
    }
}

fn can_mark_boot_failed(inst: &SandboxInstance, generation: Uuid) -> bool {
    inst.record_generation == Some(generation)
        && !matches!(inst.state, SandboxState::Stopping | SandboxState::Stopped)
}

fn persist_boot_failure(
    records: &SandboxRecordStore,
    id: &str,
    generation: Uuid,
    message: &str,
) -> (bool, Option<String>) {
    match records.transition(
        id,
        generation,
        SandboxTransition::Failed(message.to_owned()),
    ) {
        Ok(commit) => match commit.durability_error {
            Some(error) => (false, Some(error)),
            None => (true, None),
        },
        Err(error) => (false, Some(error.to_string())),
    }
}

/// Fail a boot whose VM process already started and whose cleanup resources
/// were all transferred to the instance: persist the failure, flip the
/// instance to `Failed`, release runtime resources, clear the boot journal,
/// and broadcast the FAILED event. Shared by the agent-readiness gate and the
/// durable-Ready persistence check; each caller logs its own context line.
#[allow(
    clippy::too_many_arguments,
    reason = "failure handling spans the boot task's captured manager state"
)]
async fn fail_started_boot(
    id: &SandboxId,
    generation: Uuid,
    message: &str,
    vm_dir: &Path,
    instances: &super::InstanceMap,
    network: &Arc<NetworkManager>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
    records: &SandboxRecordStore,
    events_tx: &broadcast::Sender<SandboxEvent>,
) {
    let value = instances.read().unwrap().get(id).cloned();
    let cleanup_lock = value
        .as_ref()
        .map(|arc| arc.lock().unwrap().cleanup_lock.clone());
    let _cleanup_guard = match cleanup_lock.as_ref() {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let mut updated_current = false;
    let mut failure_record_error = None;
    let mut failure_record_visible = false;
    if let Some(ref arc) = value {
        let mut inst = arc.lock().unwrap();
        if can_mark_boot_failed(&inst, generation) {
            (failure_record_visible, failure_record_error) =
                persist_boot_failure(records, id, generation, message);
            inst.state = SandboxState::Failed;
            inst.error = Some(message.to_owned());
            updated_current = true;
        }
    }
    let cleanup_complete = if updated_current {
        match super::cleanup::release_runtime_resources(
            id,
            value.as_ref().unwrap(),
            network,
            config,
            cow_manager,
        )
        .await
        {
            Ok(()) => true,
            Err(error) => {
                error!(sandbox_id = %id, error = %error, "boot failure cleanup incomplete");
                false
            }
        }
    } else {
        false
    };
    if failure_record_visible && cleanup_complete {
        if let Err(error) = super::reconcile::clear_state_record(vm_dir) {
            error!(sandbox_id = %id, error = %error, "boot failure journal cleanup is not durable");
        }
    }
    if updated_current {
        let _ = events_tx.send(SandboxEvent::new(id, action::FAILED).with_attr("error", message));
    }
    if let Some(error) = failure_record_error {
        error!(sandbox_id = %id, error, "failed to persist sandbox boot failure");
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

/// Stage a read-only file into a jailer chroot: hard-link when possible,
/// copy otherwise.
///
/// A hard link shares the inode with the source, so it is only safe for
/// files FC never writes — the kernel image, a snapshot vmstate, and a
/// snapshot mem file (mapped MAP_PRIVATE on load). Do NOT use it for the
/// rootfs copy fallback: FC writes guest blocks into that file. Linking is
/// also reserved for the root jailer (uid/gid 0), because chown on a link
/// would mutate the shared source inode; a non-root jailer gets a private
/// copy with its own ownership.
pub(super) async fn link_or_copy_for_jailer(
    src: &Path,
    dst: &Path,
    uid: u32,
    gid: u32,
) -> Result<()> {
    // Remove a stale entry first: hard_link fails on an existing dst, and a
    // leftover from a previous run must not survive by accident.
    if let Err(e) = tokio::fs::remove_file(dst).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(VmmError::Io(e));
    }
    if uid == 0 && gid == 0 {
        match tokio::fs::hard_link(src, dst).await {
            Ok(()) => return Ok(()),
            // Cross-device (EXDEV) or filesystem quirk. warn, not debug: the
            // copy fallback silently forfeits the restore fast path, and at
            // default log levels a misplaced chroot base would only ever be
            // rediscovered by re-measuring.
            Err(e) => {
                warn!(src = %src.display(), dst = %dst.display(), error = %e,
                    "hard link failed; falling back to copy");
            }
        }
    }
    tokio::fs::copy(src, dst).await.map_err(VmmError::Io)?;
    chown(dst, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|e| VmmError::Process(format!("chown {}: {e}", dst.display())))?;
    Ok(())
}

/// Stage the kernel into the jailer chroot (link or copy).
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
    link_or_copy_for_jailer(Path::new(kernel_src), &kernel_dst, uid, gid).await?;
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

/// A failed restore-staging step, carrying whichever CoW resources were
/// acquired before the failure so the caller can roll them back.
pub(super) struct StageError {
    pub error: VmmError,
    pub cow_handle: Option<CowHandle>,
}

/// Stage a snapshot's rootfs into a jailer chroot: dm-snapshot + mknod
/// when device-mapper is available, full copy otherwise.
///
/// `owner_id` keys the dm/CoW resource names (the sandbox id, or a pool
/// slot id for pre-warmed slots). `journal` persists the caller's crash
/// record whenever CoW resources appear or disappear, so reconciliation
/// can always identify them. Returns the CoW handle when the dm path was
/// taken; the staged rootfs is `/rootfs.ext4` inside the chroot either way.
pub(super) async fn stage_rootfs_cow_or_copy(
    cow_manager: &CowManager,
    chroot: &Path,
    owner_id: &str,
    rootfs: &str,
    uid: u32,
    gid: u32,
    journal: &(dyn Fn(Option<&CowHandle>) -> Result<()> + Sync),
) -> std::result::Result<Option<CowHandle>, StageError> {
    let fail = |error: VmmError, cow_handle: Option<CowHandle>| StageError { error, cow_handle };
    match cow_manager.setup(owner_id, rootfs).await {
        Ok(handle) => {
            if let Err(error) = journal(Some(&handle)) {
                return Err(fail(error, Some(handle)));
            }
            match stage_rootfs_device_for_jailer(chroot, &handle.dm_device, uid, gid).await {
                Ok(_) => Ok(Some(handle)),
                Err(e) => {
                    debug!(
                        owner_id,
                        error = %e,
                        "mknod failed, falling back to rootfs copy"
                    );
                    if let Err(error) = cow_manager.teardown_checked(&handle).await {
                        return Err(fail(error, Some(handle)));
                    }
                    journal(None).map_err(|error| fail(error, None))?;
                    stage_rootfs_copy_for_jailer(chroot, rootfs, uid, gid)
                        .await
                        .map_err(|error| fail(error, None))?;
                    Ok(None)
                }
            }
        }
        Err(e) if matches!(e, VmmError::Unavailable(_)) => Err(fail(e, None)),
        Err(e) => {
            debug!(
                owner_id,
                error = %e,
                "dm-snapshot unavailable, copying rootfs into chroot"
            );
            stage_rootfs_copy_for_jailer(chroot, rootfs, uid, gid)
                .await
                .map_err(|error| fail(error, None))?;
            Ok(None)
        }
    }
}

/// Stage a snapshot's vmstate/mem into `{chroot}/snapshots/{snapshot_id}`
/// via [`link_or_copy_for_jailer`] and return their chroot-relative paths
/// `(vmstate, mem)` for `SnapshotLoadParams`.
pub(super) async fn stage_snapshot_files(
    chroot: &Path,
    snapshot: &crate::snapshot::SnapshotMeta,
    uid: u32,
    gid: u32,
) -> Result<(String, Option<String>)> {
    let snap_in_chroot = chroot.join("snapshots").join(&snapshot.id);
    std::fs::create_dir_all(&snap_in_chroot).map_err(VmmError::Io)?;
    chown(
        &snap_in_chroot,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|e| VmmError::Process(format!("chown snap dir: {e}")))?;

    link_or_copy_for_jailer(
        &snapshot.vmstate_path,
        &snap_in_chroot.join("vmstate"),
        uid,
        gid,
    )
    .await?;
    let mem = if let Some(ref mf) = snapshot.mem_path
        && mf.exists()
    {
        link_or_copy_for_jailer(mf, &snap_in_chroot.join("mem"), uid, gid).await?;
        Some(format!("/snapshots/{}/mem", snapshot.id))
    } else {
        None
    };
    Ok((format!("/snapshots/{}/vmstate", snapshot.id), mem))
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

pub(super) async fn kill_and_reap_fc_checked(
    process: &mut fc_sdk::FirecrackerProcess,
) -> Result<()> {
    if let Some(pid) = process.pid()
        && pid > 0
    {
        match nix::sys::signal::kill(
            #[allow(
                clippy::cast_possible_wrap,
                reason = "Firecracker pid fits platform pid_t"
            )]
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        ) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => {
                return Err(VmmError::Process(format!(
                    "kill firecracker {pid}: {error}"
                )));
            }
        }
    }
    match tokio::time::timeout(std::time::Duration::from_secs(5), process.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(VmmError::Process(format!("reap firecracker: {error}"))),
        Err(_) => Err(VmmError::Process("timed out reaping firecracker".into())),
    }
}

/// Tear down resources that could not be handed to their sandbox generation.
///
/// The resource-handoff channel closes without its explicit signal in this
/// case, so Remove joins this cleanup instead of aborting it. TAP/IP and the
/// jailer chroot remain managed by lifecycle cleanup or restart reconciliation.
async fn tear_down_orphaned_boot(
    mut process: fc_sdk::FirecrackerProcess,
    cow_handle: Option<CowHandle>,
    cow_manager: &CowManager,
) -> Result<()> {
    // Kill + reap FC before the dm teardown so `dmsetup remove` doesn't hit
    // EBUSY on the still-open block device.
    kill_and_reap_fc_checked(&mut process).await?;
    if let Some(handle) = cow_handle {
        cow_manager.teardown_checked(&handle).await?;
    }
    Ok(())
}

/// Perform the actual Firecracker boot: spawn process, configure, start VM.
///
/// The spawned process is transferred to its [`SandboxInstance`] immediately.
/// Cleanup is allowed to abort this task only after the paths/CoW phase has
/// finished and every live `CowHandle` has also been transferred.
#[allow(
    clippy::too_many_arguments,
    reason = "boot owns one exact sandbox generation and its handoff signal"
)]
async fn do_boot(
    id: &str,
    spec: &SandboxSpec,
    net_alloc: Option<&NetworkAllocation>,
    vm_dir: &Path,
    config: &VmmConfig,
    cow_manager: &CowManager,
    instances: &super::InstanceMap,
    generation: Uuid,
    resource_handoff: tokio::sync::oneshot::Sender<()>,
) -> std::result::Result<BootOutput, BootFailure> {
    let mut resource_handoff = Some(resource_handoff);
    let log_path = vm_dir.join("firecracker.log");
    let metrics_path = vm_dir.join("firecracker.metrics");
    // socket_path is used only for the direct (non-jailer) mode spawn.
    let socket_path = vm_dir.join("firecracker.sock");

    let fc_cfg = &config.firecracker;

    // Some Firecracker builds expect log/metrics targets to pre-exist when
    // --log-path/--metrics-path are provided. Pre-create both files to avoid
    // startup failures with ENOENT across version variants.
    let prepare_files = (|| -> Result<()> {
        if fc_cfg.jailer.is_some() {
            return Ok(());
        }
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).map_err(VmmError::Io)?;
        }
        std::fs::File::create(&log_path).map_err(VmmError::Io)?;
        std::fs::File::create(&metrics_path).map_err(VmmError::Io)?;
        Ok(())
    })();
    if let Err(error) = prepare_files {
        complete_resource_handoff(&mut resource_handoff);
        return Err(BootFailure {
            error,
            process: None,
            cow_handle: None,
        });
    }

    // Spawn the Firecracker process (direct or via Jailer).
    let process_result = if let Some(ref jc) = fc_cfg.jailer {
        spawn_jailer(jc, fc_cfg, id).await
    } else {
        spawn_direct(fc_cfg, id, &socket_path, &log_path, &metrics_path).await
    };
    let process = match process_result {
        Ok(process) => process,
        Err(error) => {
            complete_resource_handoff(&mut resource_handoff);
            return Err(BootFailure {
                error,
                process: None,
                cow_handle: None,
            });
        }
    };

    #[allow(
        clippy::cast_possible_wrap,
        reason = "Firecracker pid fits platform pid_t"
    )]
    let process_pid = process.pid().map(|pid| pid as i32);
    let process_socket = process.socket_path().to_owned();
    let spawned_record = super::reconcile::SandboxStateRecord::new(
        id,
        process_pid,
        net_alloc,
        None,
        fc_cfg.jailer.is_some(),
        None,
    );
    let journal_error = super::reconcile::write_state_record(vm_dir, &spawned_record).err();

    // Once spawn returns, make the process immediately owned by the instance.
    // Cleanup still waits for the paths/CoW phase before it may abort boot.
    let mut process = Some(process);
    let state = {
        let map = instances.read().unwrap();
        map.get(id).and_then(|instance| {
            let mut instance = instance.lock().unwrap();
            (instance.record_generation == Some(generation)).then(|| {
                instance.process = process.take();
                instance.state
            })
        })
    };

    let Some(state) = state else {
        // Closing the channel without the explicit signal makes cleanup join
        // this task instead of aborting it, so the outer failure path can tear
        // down these unhanded resources.
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "the current sandbox generation".into(),
                actual: "replaced or removed".into(),
            },
            process,
            cow_handle: None,
        });
    };
    if matches!(state, SandboxState::Stopping | SandboxState::Stopped) {
        complete_resource_handoff(&mut resource_handoff);
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "a sandbox still booting".into(),
                actual: state.to_string(),
            },
            process: None,
            cow_handle: None,
        });
    }
    if let Some(error) = journal_error {
        complete_resource_handoff(&mut resource_handoff);
        return Err(BootFailure {
            error,
            process: None,
            cow_handle: None,
        });
    }

    // Determine kernel, rootfs, and vsock paths.
    //
    // In jailer mode the files must exist inside the chroot, and paths passed
    // to the FC API are relative to the chroot root.  In direct mode the
    // host-absolute paths from the spec are used as-is.
    let mut cow_handle = None;
    let paths: Result<(String, String, String, PathBuf)> = async {
        if let Some(ref jc) = fc_cfg.jailer {
            // Jailer mode: stage kernel + rootfs into chroot.
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, id);

            // Kernel is always copied (small, ~16MB).
            let k = stage_kernel_for_jailer(&cr, &spec.kernel, jc.uid, jc.gid).await?;

            // Rootfs: try dm-snapshot + mknod, fall back to full copy.
            let r = match cow_manager.setup(id, &spec.rootfs).await {
                Ok(handle) => {
                    cow_handle = Some(handle);
                    let record = super::reconcile::SandboxStateRecord::new(
                        id,
                        process_pid,
                        net_alloc,
                        cow_handle.as_ref(),
                        true,
                        None,
                    );
                    super::reconcile::write_state_record(vm_dir, &record)?;
                    match stage_rootfs_device_for_jailer(
                        &cr,
                        &cow_handle.as_ref().unwrap().dm_device,
                        jc.uid,
                        jc.gid,
                    )
                    .await
                    {
                        Ok(path) => path,
                        Err(e) => {
                            debug!(
                                sandbox_id = %id,
                                error = %e,
                                "mknod failed, falling back to rootfs copy"
                            );
                            cow_manager
                                .teardown_checked(cow_handle.as_ref().unwrap())
                                .await?;
                            cow_handle = None;
                            let record = super::reconcile::SandboxStateRecord::new(
                                id,
                                process_pid,
                                net_alloc,
                                None,
                                true,
                                None,
                            );
                            super::reconcile::write_state_record(vm_dir, &record)?;
                            stage_rootfs_copy_for_jailer(&cr, &spec.rootfs, jc.uid, jc.gid).await?
                        }
                    }
                }
                Err(e) => {
                    if matches!(e, VmmError::Unavailable(_)) {
                        return Err(e);
                    }
                    debug!(
                        sandbox_id = %id,
                        error = %e,
                        "dm-snapshot unavailable, copying rootfs into chroot"
                    );
                    stage_rootfs_copy_for_jailer(&cr, &spec.rootfs, jc.uid, jc.gid).await?
                }
            };

            let vsock_host = cr.join("run/firecracker.vsock");
            Ok((k, r, "/run/firecracker.vsock".to_string(), vsock_host))
        } else {
            // Direct mode: try dm-snapshot CoW, fall back to using rootfs directly.
            // When CoW is active, create a stable `{vm_dir}/rootfs.link` symlink
            // pointing at the dm device.  Firecracker records the symlink path
            // (not the ephemeral dm device name) in the vmstate, so a restored
            // sandbox can recreate a new dm-snapshot and retarget the symlink
            // transparently.
            let rootfs = match cow_manager.setup(id, &spec.rootfs).await {
                Ok(handle) => {
                    cow_handle = Some(handle);
                    let record = super::reconcile::SandboxStateRecord::new(
                        id,
                        process_pid,
                        net_alloc,
                        cow_handle.as_ref(),
                        false,
                        None,
                    );
                    super::reconcile::write_state_record(vm_dir, &record)?;
                    create_rootfs_symlink(vm_dir, &cow_handle.as_ref().unwrap().dm_device)?
                }
                Err(e) => {
                    if matches!(e, VmmError::Unavailable(_)) {
                        return Err(e);
                    }
                    debug!(
                        sandbox_id = %id,
                        error = %e,
                        "dm-snapshot unavailable, using rootfs directly"
                    );
                    spec.rootfs.clone()
                }
            };
            let vsock_path = vm_dir.join("firecracker.vsock");
            Ok((
                spec.kernel.clone(),
                rootfs,
                vsock_path.to_str().unwrap().to_owned(),
                vsock_path,
            ))
        }
    }
    .await;

    // No await may occur between transferring a successful CoW handle and
    // completing this signal. Once signalled, Remove is allowed to abort us.
    let state = {
        let map = instances.read().unwrap();
        map.get(id).and_then(|instance| {
            let mut instance = instance.lock().unwrap();
            (instance.record_generation == Some(generation)).then(|| {
                if cow_handle.is_some() {
                    debug_assert!(instance.cow_handle.is_none());
                    instance.cow_handle = cow_handle.take();
                }
                instance.state
            })
        })
    };
    let Some(state) = state else {
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "the current sandbox generation".into(),
                actual: "replaced or removed during boot setup".into(),
            },
            process: None,
            cow_handle,
        });
    };
    complete_resource_handoff(&mut resource_handoff);

    let (kernel_path, rootfs_path, vsock_fc_path, vsock_host_path) =
        paths.map_err(|error| BootFailure {
            error,
            process: None,
            cow_handle: None,
        })?;
    if matches!(state, SandboxState::Stopping | SandboxState::Stopped) {
        return Err(BootFailure {
            error: VmmError::WrongState {
                id: id.to_owned(),
                expected: "a sandbox still booting".into(),
                actual: state.to_string(),
            },
            process: None,
            cow_handle: None,
        });
    }

    // Bind the readiness listener BEFORE InstanceStart: vm-agent dials host
    // port READY_PORT as soon as it is serving, and Firecracker forwards
    // that guest-initiated connect to `{uds_path}_{READY_PORT}` only if
    // someone is already listening there — otherwise the guest is reset and
    // the one readiness event is lost.
    let ready_listener = match vsock::ReadyListener::bind(&vsock_host_path) {
        Ok(listener) => listener,
        Err(error) => {
            return Err(BootFailure {
                error,
                process: None,
                cow_handle: None,
            });
        }
    };
    // In jailer mode Firecracker connect(2)s to the socket as the jailed
    // uid/gid, and connecting requires write permission on the socket file.
    if let Some(ref jc) = fc_cfg.jailer
        && let Err(e) = chown(
            ready_listener.path(),
            Some(Uid::from_raw(jc.uid)),
            Some(Gid::from_raw(jc.gid)),
        )
    {
        return Err(BootFailure {
            error: VmmError::Process(format!(
                "chown ready socket {}: {e}",
                ready_listener.path().display()
            )),
            process: None,
            cow_handle: None,
        });
    }

    // Configure and boot the VM.
    let vcpu_count =
        NonZeroU64::new(spec.vcpus.max(1) as u64).expect("max(1) guarantees a non-zero vCPU count");

    // Append static IP configuration to boot args so the kernel configures
    // eth0 before init runs.  The guest-side vm-agent parses this back via
    // `KernelIpParam::from_str` to derive the DNS nameserver.
    //
    // Every sandbox boots the identical fixed identity (CORE-81): the pool
    // IP stays a host-side property of the TAP, so snapshots taken from this
    // guest are network-agnostic and restore with zero guest-side work.
    let boot_args = if net_alloc.is_some() {
        if spec.boot_args.contains("ip=") {
            spec.boot_args.clone()
        } else {
            let ip_param = KernelIpParam {
                client: crate::network::invariant::GUEST_IP,
                gateway: crate::network::invariant::GUEST_GATEWAY,
                netmask: crate::network::invariant::GUEST_NETMASK,
            };
            format!("{} {ip_param}", spec.boot_args)
        }
    } else {
        spec.boot_args.clone()
    };

    let mut builder = VmBuilder::new(process_socket)
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
            return Err(BootFailure {
                error: VmmError::from(e),
                process: None,
                cow_handle: None,
            });
        }
    };
    Ok((vm, vsock_host_path, ready_listener))
}

fn complete_resource_handoff(signal: &mut Option<tokio::sync::oneshot::Sender<()>>) {
    if let Some(signal) = signal.take() {
        let _ = signal.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_failure_cannot_overwrite_shutdown() {
        let generation = Uuid::new_v4();
        let mut instance = SandboxInstance::new_with_generation(
            "box".into(),
            SandboxSpec::default(),
            None,
            PathBuf::from("/tmp/box"),
            generation,
        );

        assert!(can_mark_boot_failed(&instance, generation));
        instance.state = SandboxState::Stopping;
        assert!(!can_mark_boot_failed(&instance, generation));
        instance.state = SandboxState::Stopped;
        assert!(!can_mark_boot_failed(&instance, generation));
        assert!(!can_mark_boot_failed(&instance, Uuid::new_v4()));
    }
}
