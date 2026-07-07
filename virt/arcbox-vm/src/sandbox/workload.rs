use super::*;

/// Start a non-interactive workload over the sandbox's vsock and wire up the
/// `Running → Ready` state machine.
///
/// Shared by `Run` and the initial `cmd` launched right after boot: connects
/// to the in-VM agent (retrying while it is still starting), flips the
/// sandbox to `Running` once the session is established, and spawns a
/// watcher that intercepts the exit chunk to restore `Ready`, record the
/// exit code, and broadcast an `idle` event.
pub(super) async fn start_run_workload(
    id: &SandboxId,
    uds_path: &Path,
    start: StartCommand,
    instances: &super::InstanceMap,
    events_tx: &broadcast::Sender<SandboxEvent>,
) -> Result<tokio::sync::mpsc::Receiver<Result<OutputChunk>>> {
    let inner_rx = vsock::run(uds_path, start).await?;

    // Claim the sandbox with a guarded Ready → Running transition. A `stop`
    // that raced this workload (e.g. arriving during the boot → initial-cmd
    // window) sets `Stopping` under the same lock; if it won, abort here
    // instead of clobbering its state and running on released resources.
    // `stop` then sees either `Running` (drains us) or its own `Stopping`
    // (we bailed) — never a lost update.
    {
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
    }
    let _ = events_tx.send(SandboxEvent::new(id, "running"));

    // Wrap the receiver to intercept MSG_EXIT and update state.
    let (wrapped_tx, wrapped_rx) = tokio::sync::mpsc::channel(64);
    let instances = Arc::clone(instances);
    let events_tx = events_tx.clone();
    let sandbox_id = id.clone();
    tokio::spawn(async move {
        let mut inner_rx = inner_rx;
        while let Some(result) = inner_rx.recv().await {
            let send_result = match &result {
                Ok(chunk) if chunk.stream == "exit" => {
                    let exit_code = chunk.exit_code;
                    let value = instances.read().unwrap().get(&sandbox_id).cloned();
                    if let Some(arc) = value {
                        let mut inst = arc.lock().unwrap();
                        inst.last_exit_code = Some(exit_code);
                        inst.last_exited_at = Some(Utc::now());
                        // Return to Ready only from an active state. During a
                        // stop's drain the state is Stopping — flipping to
                        // Ready is the drain's completion signal — but never
                        // resurrect a sandbox stop has already driven to
                        // Stopped (its resources are gone).
                        if matches!(inst.state, SandboxState::Running | SandboxState::Stopping) {
                            inst.state = SandboxState::Ready;
                        }
                    }
                    let _ = events_tx.send(
                        SandboxEvent::new(&sandbox_id, "idle")
                            .with_attr("exit_code", &exit_code.to_string()),
                    );
                    wrapped_tx.send(result).await
                }
                _ => wrapped_tx.send(result).await,
            };
            if send_result.is_err() {
                break;
            }
        }
    });

    Ok(wrapped_rx)
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

        let (in_tx, inner_rx) = vsock::exec(&uds_path, start).await?;

        // Guarded Ready → Running transition (see start_run_workload): abort
        // if a stop raced this exec session rather than clobber its state.
        {
            let inst = self.get_instance(id)?;
            let mut guard = inst.lock().unwrap();
            if guard.state != SandboxState::Ready {
                return Err(VmmError::WrongState {
                    id: id.clone(),
                    expected: "Ready".into(),
                    actual: guard.state.to_string(),
                });
            }
            guard.state = SandboxState::Running;
        }
        let _ = self.events_tx.send(SandboxEvent::new(id, "running"));

        // Wrap the output receiver to intercept MSG_EXIT and update state.
        let (wrapped_tx, wrapped_rx) = tokio::sync::mpsc::channel(64);
        let instances = Arc::clone(&self.instances);
        let events_tx = self.events_tx.clone();
        let sandbox_id = id.clone();
        tokio::spawn(async move {
            let mut inner_rx = inner_rx;
            while let Some(result) = inner_rx.recv().await {
                let send_result = match &result {
                    Ok(chunk) if chunk.stream == "exit" => {
                        let exit_code = chunk.exit_code;
                        let value = instances.read().unwrap().get(&sandbox_id).cloned();
                        if let Some(arc) = value {
                            let mut inst = arc.lock().unwrap();
                            inst.last_exit_code = Some(exit_code);
                            inst.last_exited_at = Some(Utc::now());
                            // See start_run_workload: only return to Ready from
                            // an active state; never resurrect a Stopped sandbox.
                            if matches!(inst.state, SandboxState::Running | SandboxState::Stopping)
                            {
                                inst.state = SandboxState::Ready;
                            }
                        }
                        let _ = events_tx.send(
                            SandboxEvent::new(&sandbox_id, "idle")
                                .with_attr("exit_code", &exit_code.to_string()),
                        );
                        wrapped_tx.send(result).await
                    }
                    _ => wrapped_tx.send(result).await,
                };
                if send_result.is_err() {
                    break;
                }
            }
        });

        Ok((in_tx, wrapped_rx))
    }
}
