use super::*;

/// Guarded `Ready → Running` transition.
///
/// This is the sandbox's single-workload claim. It is taken **before** any
/// command is dispatched into the guest, so a caller that loses a concurrent
/// race (or arrives after a `stop` set `Stopping`) is rejected with
/// `WrongState` *without* having launched a process. A blind assignment here
/// was the original defect: two concurrent `Run`s would both dispatch, then
/// one would be told it lost — after its command was already executing.
fn claim_running(id: &SandboxId, instances: &InstanceMap) -> Result<()> {
    let arc = instances
        .read()
        .unwrap()
        .get(id)
        .cloned()
        .ok_or_else(|| VmmError::NotFound(id.clone()))?;
    let mut inst = arc.lock().unwrap();
    if inst.state != SandboxState::Ready {
        return Err(VmmError::WrongState {
            id: id.clone(),
            expected: "Ready".into(),
            actual: inst.state.to_string(),
        });
    }
    inst.state = SandboxState::Running;
    Ok(())
}

/// Roll a claim back to `Ready` after a failed dispatch.
///
/// Only downgrades when the sandbox is still `Running` (i.e. this claim still
/// owns it). If a concurrent `stop` moved it to `Stopping`, that transition is
/// left intact — stop owns the teardown from there.
fn release_running(id: &SandboxId, instances: &InstanceMap) {
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
/// an active state (`Running` during a normal workload, `Stopping` while a
/// `stop` drains — where the flip is the drain's completion signal); a sandbox
/// already driven to `Stopped` is never resurrected.
fn finish_workload(
    id: &SandboxId,
    exit_code: i32,
    instances: &InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) {
    // Drop the map read guard before taking the instance lock.
    let arc = instances.read().unwrap().get(id).cloned();
    if let Some(arc) = arc {
        let mut inst = arc.lock().unwrap();
        inst.last_exit_code = Some(exit_code);
        inst.last_exited_at = Some(Utc::now());
        if matches!(inst.state, SandboxState::Running | SandboxState::Stopping) {
            inst.state = SandboxState::Ready;
        }
    }
    let _ = events_tx
        .send(SandboxEvent::new(id, "idle").with_attr("exit_code", &exit_code.to_string()));
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
            if let Ok(chunk) = &result
                && chunk.stream == "exit"
            {
                finish_workload(&sandbox_id, chunk.exit_code, &instances, &events_tx);
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
/// Shared by `Run` and the initial `cmd` launched right after boot: claims the
/// sandbox (`Ready → Running`) **before** connecting so a losing racer never
/// dispatches a command, launches the session, then spawns the exit watcher.
/// A launch failure rolls the claim back to `Ready`.
pub(super) async fn start_run_workload(
    id: &SandboxId,
    uds_path: &Path,
    start: StartCommand,
    instances: &super::InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) -> Result<tokio::sync::mpsc::Receiver<Result<OutputChunk>>> {
    claim_running(id, instances)?;

    let inner_rx = match vsock::run(uds_path, start).await {
        Ok(rx) => rx,
        Err(e) => {
            release_running(id, instances);
            return Err(e);
        }
    };
    let _ = events_tx.send(SandboxEvent::new(id, "running"));

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

        start_run_workload(id, &uds_path, start, &self.instances, &self.events_tx).await
    }

    /// Start an interactive exec session inside a ready sandbox.
    ///
    /// The sandbox must be in `Ready` state.  It transitions to `Running`
    /// immediately and back to `Ready` when the session ends.
    ///
    /// Returns `(input_sender, output_receiver)`:
    /// - Push [`ExecInputMsg`]s (stdin bytes, TTY resize, EOF) into `input_sender`.
    /// - Read [`OutputChunk`]s from `output_receiver` for stdout, stderr, and exit.
    #[allow(clippy::too_many_arguments, reason = "public API mirrors exec request")]
    pub async fn exec_in_sandbox(
        &self,
        id: &SandboxId,
        cmd: Vec<String>,
        env: HashMap<String, String>,
        working_dir: String,
        user: String,
        tty: bool,
        tty_size: Option<(u16, u16)>,
        timeout_seconds: u32,
    ) -> Result<(
        tokio::sync::mpsc::Sender<ExecInputMsg>,
        tokio::sync::mpsc::Receiver<Result<OutputChunk>>,
    )> {
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

        // Claim BEFORE opening the session (see start_run_workload): a losing
        // racer must not launch an interactive process in the guest.
        claim_running(id, &self.instances)?;

        let (in_tx, inner_rx) = match vsock::exec(&uds_path, start).await {
            Ok(pair) => pair,
            Err(e) => {
                release_running(id, &self.instances);
                return Err(e);
            }
        };
        let _ = self.events_tx.send(SandboxEvent::new(id, "running"));

        let wrapped_rx = spawn_exit_watcher(id, inner_rx, &self.instances, &self.events_tx);
        Ok((in_tx, wrapped_rx))
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
            .send(Ok(OutputChunk {
                stream: "stdout".into(),
                data: b"noise".to_vec(),
                exit_code: 0,
            }))
            .await
            .unwrap();
        inner_tx
            .send(Ok(OutputChunk {
                stream: "exit".into(),
                data: vec![],
                exit_code: 7,
            }))
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
        let last_exit_code = {
            let guard = instances.read().unwrap();
            guard["s"].lock().unwrap().last_exit_code
        };
        assert_eq!(last_exit_code, Some(7));
    }

    #[tokio::test]
    async fn watcher_forwards_then_finishes_for_a_live_consumer() {
        let instances = instance_map("s", SandboxState::Running);
        let (events_tx, mut events_rx) = broadcast::channel(16);
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel(8);

        let mut wrapped_rx = spawn_exit_watcher(&"s".to_owned(), inner_rx, &instances, &events_tx);

        inner_tx
            .send(Ok(OutputChunk {
                stream: "stdout".into(),
                data: b"hello".to_vec(),
                exit_code: 0,
            }))
            .await
            .unwrap();
        let first = wrapped_rx.recv().await.unwrap().unwrap();
        assert_eq!(first.data, b"hello");

        inner_tx
            .send(Ok(OutputChunk {
                stream: "exit".into(),
                data: vec![],
                exit_code: 0,
            }))
            .await
            .unwrap();
        drop(inner_tx);

        // The forwarded exit chunk arrives, then the channel closes.
        let exit = wrapped_rx.recv().await.unwrap().unwrap();
        assert_eq!(exit.stream, "exit");
        assert!(wrapped_rx.recv().await.is_none());
        assert_eq!(state_of("s", &instances), SandboxState::Ready);

        // An "idle" event was broadcast on exit.
        let ev = events_rx.recv().await.unwrap();
        assert_eq!(ev.action, "idle");
    }
}
