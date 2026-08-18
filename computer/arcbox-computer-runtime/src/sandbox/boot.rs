use super::record::{SandboxRecordStore, SandboxTransition};
use super::types::action;
use super::*;
use arcbox_snapshot::SnapshotError;
use arcbox_vm_driver::net::GuestNetwork;

// The boot body and the readiness gate live with the machine that names them
// (`Effect::SpawnBoot` / `SpawnGate`); this module still drives them until
// R3 PR-F2 flips the manager onto the actor.
use crate::lifecycle::tasks::boot::{do_boot, wait_for_agent};

#[allow(
    clippy::too_many_arguments,
    reason = "boot task captures manager state"
)]
pub(super) async fn boot_sandbox(
    id: SandboxId,
    spec: SandboxSpec,
    net: Option<NetworkAttachment>,
    vm_dir: PathBuf,
    instances: Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: Arc<dyn GuestNetwork>,
    driver: Arc<dyn VmDriver>,
    config: Arc<VmmConfig>,
    events_tx: broadcast::Sender<SandboxEvent>,
    cow_manager: Arc<CowManager>,
    records: Arc<SandboxRecordStore>,
    generation: Uuid,
    warm_publish: Option<super::warm::WarmPublishTicket>,
    resource_handoff: tokio::sync::oneshot::Sender<()>,
    agents: Arc<dyn GuestAgentFactory>,
) {
    match do_boot(
        &id,
        &spec,
        net.as_ref(),
        &vm_dir,
        driver.as_ref(),
        agents.as_ref(),
        &config,
        &cow_manager,
        &instances,
        generation,
        resource_handoff,
    )
    .await
    {
        Ok((handle, ready_gate)) => {
            let current = instances.read().unwrap().get(&id).cloned();
            let is_current_generation = current
                .as_ref()
                .is_some_and(|arc| arc.lock().unwrap().record_generation == Some(generation));
            if !is_current_generation {
                info!(sandbox_id = %id, "stale sandbox boot completed");
                return;
            }

            let agent = match wait_for_agent(
                &id,
                &handle,
                net.as_ref(),
                ready_gate,
                agents.as_ref(),
            )
            .await
            {
                Ok(agent) => agent,
                Err(error) => {
                    let message = error.to_string();
                    fail_live_sandbox(
                        &id,
                        Some(generation),
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
                    error!(sandbox_id = %id, %error, "sandbox agent was not reachable after boot");
                    return;
                }
            };

            let ready_at = Utc::now();

            // Hand the running VM's handle to the instance. Every cleanup
            // resource was transferred before configuration could be aborted.
            let mut handle = Some(handle);
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
                            inst.handle = handle.take();
                            inst.net_identity = net.as_ref().map(|n| n.identity.clone());
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
                if let Err(frozen) = super::warm::publish_after_boot(
                    &id,
                    ticket,
                    &instances,
                    &config,
                    &cow_manager,
                    expected,
                )
                .await
                {
                    // The publish left the guest frozen with no way back:
                    // the boot fails rather than announcing READY.
                    let message = format!("warm snapshot publish left the guest frozen: {frozen}");
                    fail_live_sandbox(
                        &id,
                        Some(generation),
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
                    error!(sandbox_id = %id, error = %frozen, "sandbox warm publish froze the guest");
                    return;
                }
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
                run_initial_cmd(&id, spec.clone(), agent.as_ref(), &instances, &events_tx).await
            };
            if let Some(probe) = spec.ready_probe.clone()
                && let Err(probe_error) = run_ready_probe(&probe, agent.as_ref()).await
            {
                let message = format!("ready probe failed: {probe_error}");
                fail_live_sandbox(
                    &id,
                    Some(generation),
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
                fail_live_sandbox(
                    &id,
                    Some(generation),
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
                let _ = run_initial_cmd(&id, spec, agent.as_ref(), &instances, &events_tx).await;
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
                if can_mark_boot_failed(&inst, Some(generation)) {
                    (failure_record_visible, record_error) =
                        persist_boot_failure(&records, &id, Some(generation), &message);
                    inst.state = SandboxState::Failed;
                    inst.error = Some(message.clone());
                    if let Some(prepared) = failure.prepared.take() {
                        inst.prepared = Some(prepared);
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
            } else if let Some(prepared) = failure.prepared.take() {
                match tear_down_orphaned_boot(&*prepared, failure.cow_handle.take(), &cow_manager)
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

/// Whether `inst` is the generation a failure was observed on and can still
/// take it: a replaced instance, or one already stopping, keeps its own fate.
fn can_mark_boot_failed(inst: &SandboxInstance, generation: Option<Uuid>) -> bool {
    inst.record_generation == generation
        && !matches!(inst.state, SandboxState::Stopping | SandboxState::Stopped)
}

/// Persist the durable `Failed` transition. Returns whether the failure is
/// visible in the record store, and the durability or transition error if
/// any; an instance without a durable record (`None`) has nothing to persist.
fn persist_boot_failure(
    records: &SandboxRecordStore,
    id: &str,
    generation: Option<Uuid>,
    message: &str,
) -> (bool, Option<String>) {
    let Some(generation) = generation else {
        return (true, None);
    };
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

/// Fail a sandbox whose VM is up (or was) and whose cleanup resources all
/// sit on its instance: persist the failure, flip the instance to `Failed`,
/// release runtime resources (the VMM killed and reaped and its handle
/// dropped, CoW, TAP + IP, chroot), clear the crash journal, and broadcast
/// the FAILED event. Shared by the boot task's failure points and
/// by the flows that find a guest frozen with no way to thaw it; each caller
/// logs its own context line. Takes the instance's cleanup lock;
/// [`fail_live_sandbox_locked`] is for a caller already holding it.
#[allow(
    clippy::too_many_arguments,
    reason = "failure handling spans the boot task's captured manager state"
)]
pub(super) async fn fail_live_sandbox(
    id: &SandboxId,
    generation: Option<Uuid>,
    message: &str,
    vm_dir: &Path,
    instances: &super::InstanceMap,
    network: &Arc<dyn GuestNetwork>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
    records: &SandboxRecordStore,
    events_tx: &broadcast::Sender<SandboxEvent>,
) {
    let Some(instance) = instances.read().unwrap().get(id).cloned() else {
        return;
    };
    let cleanup_lock = instance.lock().unwrap().cleanup_lock.clone();
    let _cleanup_guard = cleanup_lock.lock().await;
    fail_live_sandbox_locked(
        id,
        generation,
        message,
        vm_dir,
        &instance,
        network,
        config,
        cow_manager,
        records,
        events_tx,
    )
    .await;
}

/// [`fail_live_sandbox`] for a caller that already holds `instance`'s cleanup
/// lock and knows the instance is the one registered under `id`.
#[allow(
    clippy::too_many_arguments,
    reason = "failure handling spans the manager's resource set"
)]
pub(super) async fn fail_live_sandbox_locked(
    id: &SandboxId,
    generation: Option<Uuid>,
    message: &str,
    vm_dir: &Path,
    instance: &Arc<Mutex<SandboxInstance>>,
    network: &Arc<dyn GuestNetwork>,
    config: &Arc<VmmConfig>,
    cow_manager: &Arc<CowManager>,
    records: &SandboxRecordStore,
    events_tx: &broadcast::Sender<SandboxEvent>,
) {
    let (failure_record_visible, failure_record_error) = {
        let mut inst = instance.lock().unwrap();
        if !can_mark_boot_failed(&inst, generation) {
            return;
        }
        let persisted = persist_boot_failure(records, id, generation, message);
        inst.state = SandboxState::Failed;
        inst.error = Some(message.to_owned());
        persisted
    };
    let cleanup_complete =
        match super::cleanup::release_runtime_resources(id, instance, network, config, cow_manager)
            .await
        {
            Ok(()) => true,
            Err(error) => {
                error!(sandbox_id = %id, error = %error, "sandbox failure cleanup incomplete");
                false
            }
        };
    if failure_record_visible && cleanup_complete {
        if let Err(error) = super::reconcile::clear_state_record(vm_dir) {
            error!(sandbox_id = %id, error = %error, "sandbox failure journal cleanup is not durable");
        }
    }
    let _ = events_tx.send(SandboxEvent::new(id, action::FAILED).with_attr("error", message));
    if let Some(error) = failure_record_error {
        error!(sandbox_id = %id, error, "failed to persist sandbox failure");
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
    agent: &dyn GuestAgent,
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
        } => match agent
            .wait_for_port(*port, effective(*timeout_seconds))
            .await?
        {
            PortWait::Listening => Ok(()),
            PortWait::Deadline => Err(VmmError::DeadlineExceeded(format!(
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
                match tokio::time::timeout(remaining, run_probe_command(cmd, agent, budget_secs))
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
    agent: &dyn GuestAgent,
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
    let (_input, mut output) = agent.exec(start).await?;
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
    agent: &dyn GuestAgent,
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
        agent,
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
pub fn create_rootfs_symlink(vm_dir: &Path, dm_device: &str) -> Result<String> {
    let link_path = vm_dir.join("rootfs.link");
    let _ = std::fs::remove_file(&link_path);
    std::os::unix::fs::symlink(dm_device, &link_path).map_err(VmmError::Io)?;
    link_path
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| VmmError::Config(format!("non-UTF-8 path: {}", link_path.display())))
}

/// Tear down resources that could not be handed to their sandbox generation.
///
/// The resource-handoff channel closes without its explicit signal in this
/// case, so Remove joins this cleanup instead of aborting it. TAP/IP and the
/// jailer chroot remain managed by lifecycle cleanup or restart reconciliation.
async fn tear_down_orphaned_boot(
    prepared: &dyn PreparedVm,
    cow_handle: Option<CowHandle>,
    cow_manager: &CowManager,
) -> Result<()> {
    // Kill + reap the VMM before the dm teardown so `dmsetup remove` doesn't
    // hit EBUSY on the still-open block device.
    prepared.discard().await?;
    if let Some(handle) = cow_handle {
        cow_manager.teardown_checked(&handle).await?;
    }
    Ok(())
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

        assert!(can_mark_boot_failed(&instance, Some(generation)));
        instance.state = SandboxState::Stopping;
        assert!(!can_mark_boot_failed(&instance, Some(generation)));
        instance.state = SandboxState::Stopped;
        assert!(!can_mark_boot_failed(&instance, Some(generation)));
        assert!(!can_mark_boot_failed(&instance, Some(Uuid::new_v4())));
    }
}
