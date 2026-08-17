use super::persistence::{SandboxRecordStore, SandboxTransition};
use super::types::action;
use super::*;
use arcbox_snapshot::SnapshotError;

type BootOutput = (Arc<fc_sdk::Vm>, PathBuf, UdsListener);

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
    warm_publish: Option<super::warm::WarmPublishTicket>,
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
            let agent_ready =
                match tokio::time::timeout(AGENT_GATE_TIMEOUT, vsock::wait_ready(&ready_listener))
                    .await
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => {
                        Err(VmmError::Vsock(format!("agent readiness gate: {error}")))
                    }
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

            let vsock: Arc<dyn arcbox_vm_driver::Vsock> =
                Arc::new(vsock::UdsVsock(vsock_uds_path.clone()));

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
                let vsock = Arc::clone(&vsock);
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        CLOCK_SYNC_TIMEOUT,
                        vsock::sync_clock(vsock.as_ref()),
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
                            // With an initial cmd the instance stays
                            // `Starting`: the tail below moves it straight
                            // to Running via the reserved Initial claim, so
                            // an Inspect-polling client can never see Ready
                            // during the warm-publish pause and steal the
                            // workload slot the cmd is owed (that silently
                            // dropped a template's default cmd — caught by
                            // the CORE-107 e2e).
                            inst.state = if spec.cmd.is_empty() {
                                SandboxState::Ready
                            } else {
                                SandboxState::Starting
                            };
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

            // First eligible create of this boot shape (CORE-77): capture
            // the warm snapshot while the guest is still idle, before the
            // initial cmd dirties it. Synchronous on purpose — the cmd must
            // not run before the checkpoint — and failures only warn: cache
            // population never fails a healthy boot.
            //
            // This MUST precede the READY event: checkpointing pauses the
            // guest for the duration, and a client that acts on READY the
            // moment it arrives would hit that pause with an execution and
            // hang. READY promises the sandbox accepts executions, so it
            // cannot fire while the guest is about to stop answering.
            if let Some(ticket) = &warm_publish {
                // A cmd-carrying instance is still `Starting` (see above);
                // the checkpoint precondition must match what this pipeline
                // set, not what an API caller would see.
                let expected = if spec.cmd.is_empty() {
                    SandboxState::Ready
                } else {
                    SandboxState::Starting
                };
                super::warm::publish_after_boot(
                    &id,
                    ticket,
                    &instances,
                    &config,
                    &cow_manager,
                    expected,
                )
                .await;
            }

            // Initial cmd + ready probe (CORE-107). Every cmd-carrying boot
            // starts the cmd here, through the reserved Initial claim — the
            // slot could not have been taken by anyone else. A probed boot
            // additionally needs the cmd running before it probes: the cmd
            // is the only listener source in a sandbox (vm-agent is init; a
            // docker ENTRYPOINT never runs). READY is held back until the
            // probe passes; expiry fails the boot. The durable Ready
            // transition sits after the probe on purpose — a probe failure
            // then fails from the recorded Starting phase, and a crash
            // mid-probe reconciles as an interrupted boot rather than a
            // Ready sandbox that never probed.
            let cmd_started = if spec.cmd.is_empty() {
                false
            } else {
                run_initial_cmd(&id, spec.clone(), vsock.as_ref(), &instances, &events_tx).await
            };
            if let Some(probe) = spec.ready_probe.clone()
                && let Err(probe_error) = run_ready_probe(&probe, vsock.as_ref()).await
            {
                let message = format!("ready probe failed: {probe_error}");
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
                error!(sandbox_id = %id, error = %probe_error, "sandbox ready probe failed");
                return;
            }

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

            let _ = events_tx.send(SandboxEvent::new(&id, action::READY));
            info!(sandbox_id = %id, "sandbox booted and ready");

            // A failed initial start released the claim (the sandbox is
            // Ready); give the cmd its one ordinary post-READY attempt. A
            // second failure is final — warned, the sandbox stays Ready,
            // the caller can still Run/Exec.
            if !cmd_started && !spec.cmd.is_empty() {
                let _ = run_initial_cmd(&id, spec, vsock.as_ref(), &instances, &events_tx).await;
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

/// Default probe deadline when the template leaves `timeout_seconds` at 0
/// (matches the WaitForPort daemon default).
const READY_PROBE_DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Delay between command-probe attempts.
const READY_PROBE_RETRY_MS: u64 = 500;

/// Run a template's readiness probe against the booted guest (CORE-107).
///
/// Port form: the vm-agent's listen-table watcher — never a connect probe,
/// which would perturb the workload. Command form: a one-shot exec retried
/// until it exits 0 or the deadline elapses.
pub(super) async fn run_ready_probe(
    probe: &crate::template_catalog::ReadyProbeSpec,
    vsock: &dyn arcbox_vm_driver::Vsock,
) -> Result<()> {
    use crate::template_catalog::ReadyProbeSpec;
    let effective = |timeout_seconds: u32| {
        std::time::Duration::from_secs(if timeout_seconds == 0 {
            READY_PROBE_DEFAULT_TIMEOUT_SECS
        } else {
            u64::from(timeout_seconds)
        })
    };
    match probe {
        ReadyProbeSpec::Port {
            port,
            timeout_seconds,
        } => match vsock::wait_for_port(vsock, *port, effective(*timeout_seconds)).await? {
            vsock::PortWait::Listening => Ok(()),
            vsock::PortWait::Deadline => Err(VmmError::DeadlineExceeded(format!(
                "no listener on port {port} within the ready-probe deadline"
            ))),
        },
        ReadyProbeSpec::Command {
            cmd,
            timeout_seconds,
        } => {
            let deadline = tokio::time::Instant::now() + effective(*timeout_seconds);
            let mut last_status: Option<String> = None;
            loop {
                // Each attempt is bounded twice over: the host-side timeout
                // caps the await even if the exec stream stalls, and the
                // remaining budget rides StartCommand.timeout_seconds so the
                // guest kills a never-exiting probe process instead of
                // leaking it. Without both, `timeout_seconds` would not be
                // an upper bound at all — a non-exiting probe command parked
                // this await forever.
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(VmmError::DeadlineExceeded(format!(
                        "ready-probe command did not exit 0 within the deadline ({})",
                        last_status.as_deref().unwrap_or("no attempt completed")
                    )));
                }
                // The guest kill timer has whole-second granularity; the
                // host timeout enforces the exact remaining budget.
                let budget_secs = u32::try_from(remaining.as_secs().max(1)).unwrap_or(u32::MAX);
                match tokio::time::timeout(remaining, run_probe_command(cmd, vsock, budget_secs))
                    .await
                {
                    Ok(Ok(ExitStatus::Code(0))) => return Ok(()),
                    Ok(Ok(status)) => last_status = Some(format!("last exit: {status:?}")),
                    Ok(Err(error)) => last_status = Some(format!("last error: {error}")),
                    Err(_) => {
                        return Err(VmmError::DeadlineExceeded(format!(
                            "ready-probe command did not exit within the deadline ({})",
                            last_status.as_deref().unwrap_or("no attempt completed")
                        )));
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(VmmError::DeadlineExceeded(format!(
                        "ready-probe command did not exit 0 within the deadline ({})",
                        last_status.as_deref().unwrap_or("no attempt completed")
                    )));
                }
                let nap = std::time::Duration::from_millis(READY_PROBE_RETRY_MS)
                    .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                tokio::time::sleep(nap).await;
            }
        }
    }
}

/// One probe attempt: run the command and wait for its exit status.
async fn run_probe_command(
    cmd: &[String],
    vsock: &dyn arcbox_vm_driver::Vsock,
    timeout_seconds: u32,
) -> Result<ExitStatus> {
    let start = StartCommand {
        cmd: cmd.to_vec(),
        env: HashMap::new(),
        working_dir: String::new(),
        user: String::new(),
        tty: false,
        tty_width: 80,
        tty_height: 24,
        timeout_seconds,
    };
    let (_input, mut output) = vsock::exec(vsock, start).await?;
    while let Some(chunk) = output.recv().await {
        if let OutputChunk::Exit(status) = chunk? {
            return Ok(status);
        }
    }
    Err(VmmError::Vsock(
        "probe command stream ended without an exit status".into(),
    ))
}

/// Start the initial `cmd` from the creation spec and drain its output.
///
/// Uses the same workload path as `Run` (`start_run_workload`), so state
/// transitions and events are identical; the output itself has no consumer
/// and is discarded chunk by chunk to keep the exit handler flowing. Also
/// driven by the warm-create restore path (CORE-77), which owes a restored
/// Create the same initial workload a cold boot runs.
///
/// Claims with `WorkloadClaim::Initial`: the boot/restore tails call this
/// while the instance is still `Starting` — the slot was reserved for the
/// initial cmd so a racing exec cannot steal it — and the post-READY retry
/// claims the released `Ready` with the same verb.
///
/// Returns whether the workload actually started (`true` = live). A failed
/// start gets one ordinary post-READY retry; a `false` from that attempt is
/// final (warned, the sandbox stays Ready, the caller can still Run/Exec).
pub(super) async fn run_initial_cmd(
    id: &SandboxId,
    spec: SandboxSpec,
    vsock: &dyn arcbox_vm_driver::Vsock,
    instances: &super::InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) -> bool {
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
    match super::workload::start_run_workload(
        id,
        vsock,
        start,
        instances,
        events_tx,
        super::workload::WorkloadClaim::Initial,
    )
    .await
    {
        Ok(mut rx) => {
            info!(sandbox_id = %id, "initial cmd started");
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            true
        }
        Err(e) => {
            warn!(sandbox_id = %id, error = %e, "initial cmd failed to start; sandbox stays ready");
            false
        }
    }
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
                        return Err(fail(error.into(), Some(handle)));
                    }
                    journal(None).map_err(|error| fail(error, None))?;
                    stage_rootfs_copy_for_jailer(chroot, rootfs, uid, gid)
                        .await
                        .map_err(|error| fail(error.into(), None))?;
                    Ok(None)
                }
            }
        }
        Err(e) if matches!(e, SnapshotError::Unavailable(_)) => Err(fail(e.into(), None)),
        Err(e) => {
            debug!(
                owner_id,
                error = %e,
                "dm-snapshot unavailable, copying rootfs into chroot"
            );
            stage_rootfs_copy_for_jailer(chroot, rootfs, uid, gid)
                .await
                .map_err(|error| fail(error.into(), None))?;
            Ok(None)
        }
    }
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
    let process_result: Result<fc_sdk::FirecrackerProcess> = async {
        let driver_config = FcDriverConfig::from(fc_cfg);
        Ok(if let Some(ref jc) = fc_cfg.jailer {
            spawn_jailer(&driver_config, &IsolationSpec::try_from(jc)?, id).await?
        } else {
            spawn_direct(&driver_config, id, &socket_path, &log_path, &metrics_path).await?
        })
    }
    .await;
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
                    if matches!(e, SnapshotError::Unavailable(_)) {
                        return Err(e.into());
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
                    if matches!(e, SnapshotError::Unavailable(_)) {
                        return Err(e.into());
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
    let ready_listener = match UdsListener::bind(&vsock_host_path, vsock::READY_PORT) {
        Ok(listener) => listener,
        Err(error) => {
            return Err(BootFailure {
                error: error.into(),
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
