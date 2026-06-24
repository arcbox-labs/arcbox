use super::*;

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

        let inner_rx = vsock::run(&uds_path, start).await?;

        // Transition to Running only after vsock session is established.
        {
            let inst = self.get_instance(id)?;
            inst.lock().unwrap().state = SandboxState::Running;
        }
        let _ = self.events_tx.send(SandboxEvent::new(id, "running"));

        // Wrap the receiver to intercept MSG_EXIT and update state.
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
                            inst.state = SandboxState::Ready;
                            inst.last_exit_code = Some(exit_code);
                            inst.last_exited_at = Some(Utc::now());
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

        // Transition to Running only after vsock session is established.
        {
            let inst = self.get_instance(id)?;
            inst.lock().unwrap().state = SandboxState::Running;
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
                            inst.state = SandboxState::Ready;
                            inst.last_exit_code = Some(exit_code);
                            inst.last_exited_at = Some(Utc::now());
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
