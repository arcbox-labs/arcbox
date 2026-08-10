use super::types::action;
use super::*;

/// Which caller is taking the single-workload slot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkloadClaim {
    /// The public Run/Exec surface: claims from `Ready` only.
    Api,
    /// The boot/restore pipeline's own initial cmd: additionally claims
    /// from `Starting`. A boot with an initial cmd keeps the instance
    /// `Starting` until this claim, so an Inspect-polling client cannot
    /// slip an exec into the boot tail (the warm-snapshot publish pause is
    /// a wide window) and silently steal the slot the template's default
    /// cmd was owed — the CORE-107 e2e caught exactly that.
    Initial,
}

/// Guarded transition into `Running` — the sandbox's single-workload claim.
///
/// It is taken **before** any command is dispatched into the guest, so a
/// caller that loses a concurrent race (or arrives after a `stop` set
/// `Stopping`) is rejected with `WrongState` *without* having launched a
/// process. A blind assignment here was the original defect: two concurrent
/// `Run`s would both dispatch, then one would be told it lost — after its
/// command was already executing.
pub(super) fn claim_workload(
    id: &SandboxId,
    instances: &InstanceMap,
    claim: WorkloadClaim,
) -> Result<()> {
    let arc = instances
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .ok_or_else(|| VmmError::NotFound(id.clone()))?;
    let mut inst = arc.lock().unwrap();
    let allowed = inst.state == SandboxState::Ready
        || (claim == WorkloadClaim::Initial && inst.state == SandboxState::Starting);
    if !allowed {
        return Err(VmmError::WrongState {
            id: id.clone(),
            expected: match claim {
                WorkloadClaim::Api => "Ready".into(),
                WorkloadClaim::Initial => "Starting or Ready".into(),
            },
            actual: inst.state.to_string(),
        });
    }
    inst.state = SandboxState::Running;
    Ok(())
}

/// The public Run/Exec claim: `Ready → Running` only.
pub(super) fn claim_running(id: &SandboxId, instances: &InstanceMap) -> Result<()> {
    claim_workload(id, instances, WorkloadClaim::Api)
}

/// Roll a claim back to `Ready` after a failed dispatch.
///
/// Only downgrades when the sandbox is still `Running` (i.e. this claim still
/// owns it). If a concurrent `stop` moved it to `Stopping`, that transition is
/// left intact — stop owns the teardown from there.
pub(super) fn release_running(id: &SandboxId, instances: &InstanceMap) {
    // Drop the map read guard before taking the instance lock.
    let arc = instances.read().unwrap().get(id).cloned();
    if let Some(arc) = arc {
        let mut inst = arc.lock().unwrap();
        if inst.state == SandboxState::Running {
            inst.state = SandboxState::Ready;
        }
    }
}

/// Record a workload's exit and return the sandbox to `Ready`.
///
/// Runs when the `exit` chunk is observed. The `Ready` flip happens only from
/// `Running`. A concurrent `Stop` owns the `Stopping` state; workload exit
/// timestamps signal its drain without reopening the sandbox to new work.
pub(super) fn finish_workload(
    id: &SandboxId,
    status: ExitStatus,
    instances: &InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) {
    // Drop the map read guard before taking the instance lock.
    let arc = instances.read().unwrap().get(id).cloned();
    if let Some(arc) = arc {
        let mut inst = arc.lock().unwrap();
        inst.last_exit_status = Some(status);
        inst.last_exited_at = Some(Utc::now());
        if inst.state == SandboxState::Running {
            inst.state = SandboxState::Ready;
        }
    }
    let mut event = SandboxEvent::new(id, action::IDLE)
        .with_attr("exit_code", &status.conventional_code().to_string());
    if let ExitStatus::Signaled(signal) = status {
        event = event.with_attr("signal", &signal.to_string());
    }
    let _ = events_tx.send(event);
}

/// Spawn the watcher that mirrors a workload's output to the caller and drives
/// the exit-side state machine.
///
/// The watcher **always drains `inner_rx` to completion** so the `exit` chunk
/// is processed even after the caller drops its receiver. Coupling the state
/// update to a successful forward was the original defect: a consumer that
/// disconnected mid-workload broke the loop before the exit frame, stranding
/// the sandbox in `Running` forever. Now a gone consumer only stops the
/// forwarding; the drain (and the `Running → Ready` flip) continues.
fn spawn_exit_watcher(
    id: &SandboxId,
    inner_rx: tokio::sync::mpsc::Receiver<Result<OutputChunk>>,
    instances: &InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) -> tokio::sync::mpsc::Receiver<Result<OutputChunk>> {
    let (wrapped_tx, wrapped_rx) = tokio::sync::mpsc::channel(64);
    let instances = Arc::clone(instances);
    let events_tx = events_tx.clone();
    let sandbox_id = id.clone();
    tokio::spawn(async move {
        let mut inner_rx = inner_rx;
        let mut consumer_gone = false;
        while let Some(result) = inner_rx.recv().await {
            // Handle the exit chunk regardless of the consumer's presence.
            if let Ok(OutputChunk::Exit(status)) = &result {
                finish_workload(&sandbox_id, *status, &instances, &events_tx);
            }
            // Forward until the consumer goes away, then keep draining so the
            // exit chunk above is still reached.
            if !consumer_gone && wrapped_tx.send(result).await.is_err() {
                consumer_gone = true;
            }
        }
    });
    wrapped_rx
}

/// Start a non-interactive workload over the sandbox's vsock and wire up the
/// `Running → Ready` state machine.
///
/// Shared by `Run` (`WorkloadClaim::Api`) and the initial `cmd` launched by
/// the boot/restore tails (`WorkloadClaim::Initial`): claims the sandbox
/// **before** connecting so a losing racer never dispatches a command,
/// launches the session, then spawns the exit watcher. A launch failure
/// rolls the claim back to `Ready`.
pub(super) async fn start_run_workload(
    id: &SandboxId,
    uds_path: &Path,
    start: StartCommand,
    instances: &super::InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
    claim: WorkloadClaim,
) -> Result<tokio::sync::mpsc::Receiver<Result<OutputChunk>>> {
    claim_workload(id, instances, claim)?;

    let inner_rx = match vsock::run(uds_path, start).await {
        Ok(rx) => rx,
        Err(e) => {
            release_running(id, instances);
            return Err(e);
        }
    };
    let _ = events_tx.send(SandboxEvent::new(id, action::RUNNING));

    Ok(spawn_exit_watcher(id, inner_rx, instances, events_tx))
}

impl SandboxManager {
    #[allow(
        clippy::too_many_arguments,
        reason = "public API mirrors workload request"
    )]
    pub async fn run_in_sandbox(
        &self,
        id: &SandboxId,
        cmd: Vec<String>,
        env: HashMap<String, String>,
        working_dir: String,
        user: String,
        tty: bool,
        tty_size: Option<(u16, u16)>,
        timeout_seconds: u32,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<OutputChunk>>> {
        let uds_path = self.require_ready_vsock(id)?;

        let start = StartCommand {
            cmd,
            env,
            working_dir,
            user,
            tty,
            tty_width: tty_size.map_or(80, |(w, _)| w),
            tty_height: tty_size.map_or(24, |(_, h)| h),
            timeout_seconds,
        };

        start_run_workload(
            id,
            &uds_path,
            start,
            &self.instances,
            &self.events_tx,
            WorkloadClaim::Api,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-instance map in the given state for state-machine tests.
    fn instance_map(id: &str, state: SandboxState) -> InstanceMap {
        let mut inst = SandboxInstance::new(
            id.to_owned(),
            SandboxSpec::default(),
            None,
            PathBuf::from("/tmp/does-not-matter"),
        );
        inst.state = state;
        let map = HashMap::from([(id.to_owned(), Arc::new(Mutex::new(inst)))]);
        Arc::new(RwLock::new(map))
    }

    fn state_of(id: &str, instances: &InstanceMap) -> SandboxState {
        instances.read().unwrap()[id].lock().unwrap().state
    }

    #[test]
    fn claim_running_transitions_from_ready_only() {
        let instances = instance_map("s", SandboxState::Ready);
        claim_running(&"s".to_owned(), &instances).unwrap();
        assert_eq!(state_of("s", &instances), SandboxState::Running);

        // A second claim on the now-Running sandbox must be rejected — this is
        // the guard that stops a concurrent workload from being dispatched.
        let err = claim_running(&"s".to_owned(), &instances).unwrap_err();
        assert!(matches!(err, VmmError::WrongState { .. }));
        assert_eq!(state_of("s", &instances), SandboxState::Running);
    }

    #[test]
    fn initial_claim_reserves_the_slot_from_starting() {
        // The boot tail keeps a cmd-carrying instance `Starting`; only the
        // Initial claim may take the slot from there.
        let instances = instance_map("s", SandboxState::Starting);
        assert!(matches!(
            claim_running(&"s".to_owned(), &instances).unwrap_err(),
            VmmError::WrongState { .. }
        ));
        claim_workload(&"s".to_owned(), &instances, WorkloadClaim::Initial).unwrap();
        assert_eq!(state_of("s", &instances), SandboxState::Running);

        // The post-READY retry path claims from Ready with the same verb.
        let instances = instance_map("s", SandboxState::Ready);
        claim_workload(&"s".to_owned(), &instances, WorkloadClaim::Initial).unwrap();
        assert_eq!(state_of("s", &instances), SandboxState::Running);
    }

    #[test]
    fn claim_running_rejects_missing_and_stopping() {
        let instances = instance_map("s", SandboxState::Stopping);
        assert!(matches!(
            claim_running(&"s".to_owned(), &instances).unwrap_err(),
            VmmError::WrongState { .. }
        ));
        assert!(matches!(
            claim_running(&"missing".to_owned(), &instances).unwrap_err(),
            VmmError::NotFound(_)
        ));
    }

    #[test]
    fn release_running_only_downgrades_running() {
        let instances = instance_map("s", SandboxState::Running);
        release_running(&"s".to_owned(), &instances);
        assert_eq!(state_of("s", &instances), SandboxState::Ready);

        // A stop that won the race left Stopping; rollback must not clobber it.
        instances.read().unwrap()["s"].lock().unwrap().state = SandboxState::Stopping;
        release_running(&"s".to_owned(), &instances);
        assert_eq!(state_of("s", &instances), SandboxState::Stopping);
    }

    #[test]
    fn workload_exit_does_not_reopen_a_stopping_sandbox() {
        let instances = instance_map("s", SandboxState::Stopping);
        let (events_tx, _) = broadcast::channel(4);

        finish_workload(&"s".to_owned(), ExitStatus::Code(0), &instances, &events_tx);

        assert_eq!(state_of("s", &instances), SandboxState::Stopping);
        assert!(
            instances.read().unwrap()["s"]
                .lock()
                .unwrap()
                .last_exited_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn watcher_restores_ready_even_when_consumer_disconnects() {
        // Regression for the strand-in-Running bug: drop the consumer before
        // the exit chunk; the watcher must still process the exit and flip
        // Running → Ready.
        let instances = instance_map("s", SandboxState::Running);
        let (events_tx, _events_rx) = broadcast::channel(16);
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel(8);

        let wrapped_rx = spawn_exit_watcher(&"s".to_owned(), inner_rx, &instances, &events_tx);
        drop(wrapped_rx); // consumer gone immediately

        inner_tx
            .send(Ok(OutputChunk::Stdout(b"noise".to_vec())))
            .await
            .unwrap();
        inner_tx
            .send(Ok(OutputChunk::Exit(ExitStatus::Code(7))))
            .await
            .unwrap();
        drop(inner_tx); // guest side closes after exit

        // Give the detached watcher a moment to drain and update state.
        for _ in 0..50 {
            if state_of("s", &instances) == SandboxState::Ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(state_of("s", &instances), SandboxState::Ready);
        let last_exit_status = {
            let guard = instances.read().unwrap();
            guard["s"].lock().unwrap().last_exit_status
        };
        assert_eq!(last_exit_status, Some(ExitStatus::Code(7)));
    }

    #[tokio::test]
    async fn watcher_forwards_then_finishes_for_a_live_consumer() {
        let instances = instance_map("s", SandboxState::Running);
        let (events_tx, mut events_rx) = broadcast::channel(16);
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel(8);

        let mut wrapped_rx = spawn_exit_watcher(&"s".to_owned(), inner_rx, &instances, &events_tx);

        inner_tx
            .send(Ok(OutputChunk::Stdout(b"hello".to_vec())))
            .await
            .unwrap();
        let first = wrapped_rx.recv().await.unwrap().unwrap();
        assert!(matches!(first, OutputChunk::Stdout(data) if data == b"hello"));

        inner_tx
            .send(Ok(OutputChunk::Exit(ExitStatus::Code(0))))
            .await
            .unwrap();
        drop(inner_tx);

        // The forwarded exit chunk arrives, then the channel closes.
        let exit = wrapped_rx.recv().await.unwrap().unwrap();
        assert!(matches!(exit, OutputChunk::Exit(ExitStatus::Code(0))));
        assert!(wrapped_rx.recv().await.is_none());
        assert_eq!(state_of("s", &instances), SandboxState::Ready);

        // An "idle" event was broadcast on exit.
        let ev = events_rx.recv().await.unwrap();
        assert_eq!(ev.action, "idle");
    }
}
