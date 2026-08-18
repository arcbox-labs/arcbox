//! What a caller asks of one computer, and what it is told.
//!
//! The machine answers `Handled` with no effects whenever it has nothing
//! to do; turning that into `Ok` (an idempotent pause) or `WrongState` (a
//! non-forced remove of a busy computer) is this half of the actor, which
//! is also where a caller parks until the effect that answers it lands.

use super::*;

impl ComputerActor {
    pub(super) async fn on_command(&mut self, machine: &mut Machine, command: Command) {
        match command {
            Command::Provision {
                provision,
                outcome,
                reply,
            } => {
                self.outcome = outcome;
                let restore = matches!(provision, Provision::Restore { .. });
                if !self.dispatch(machine, Event::Provision(provision)).await {
                    let _ = reply.send(Err(self.wrong_state("a fresh computer")));
                } else if restore {
                    // A restore's caller waits for READY; a create returns
                    // while its boot runs.
                    self.waiters.push((Answer::Ready, reply));
                } else {
                    let _ = reply.send(self.acknowledged());
                }
            }
            Command::Checkpoint { reply } => {
                if self.dispatch(machine, Event::Checkpoint).await {
                    self.capture_reply = Some(reply);
                } else {
                    let _ = reply.send(Err(self.wrong_state("Ready")));
                }
            }
            Command::Pause { reason, reply } => {
                self.pause_reason = reason;
                if self.dispatch(machine, Event::Pause { reason }).await {
                    self.waiters.push((Answer::Paused, reply));
                } else {
                    // Pausing a paused computer is a no-op.
                    let _ = reply.send(match self.public() {
                        Some(SandboxState::Paused) => Ok(()),
                        _ => Err(self.wrong_state("Ready")),
                    });
                }
            }
            Command::Resume { reason, reply } => {
                self.resume_reason = reason;
                if self.dispatch(machine, Event::Resume).await {
                    self.waiters.push((Answer::Resumed, reply));
                } else {
                    // Resuming a live computer is a no-op.
                    let _ = reply.send(match self.public() {
                        Some(SandboxState::Ready | SandboxState::Running) => Ok(()),
                        _ => Err(self.wrong_state("Paused")),
                    });
                }
            }
            Command::Stop { budget, reply } => {
                let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
                if self.dispatch(machine, Event::Stop { budget_ms }).await {
                    self.waiters.push((Answer::Stopped, reply));
                    return;
                }
                match self.public() {
                    // A stop asked for during a launch is deferred until the
                    // launch resolves, rather than refused as today's
                    // `stop_sandbox` does: the alternative is a stop racing a
                    // boot that is still acquiring resources.
                    Some(SandboxState::Starting) => {
                        self.pending_stop.get_or_insert(budget);
                        self.waiters.push((Answer::Stopped, reply));
                    }
                    Some(SandboxState::Stopping) => self.waiters.push((Answer::Stopped, reply)),
                    Some(SandboxState::Stopped) => {
                        let _ = reply.send(Ok(()));
                    }
                    _ => {
                        let _ = reply.send(Err(self.wrong_state("Ready, Running, or Stopping")));
                    }
                }
            }
            Command::Remove { force, reply } => {
                if self.dispatch(machine, Event::Remove { force }).await {
                    self.waiters.push((Answer::Removed, reply));
                } else if matches!(machine.state(), State::Removing {}) {
                    // Concurrent removals coalesce onto the one under way.
                    self.waiters.push((Answer::Removed, reply));
                } else if matches!(machine.state(), State::Gone {}) {
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(
                        self.wrong_state("non-running (pass force=true to override)")
                    ));
                }
            }
            Command::ClaimWorkload { claim, reply } => {
                let taken = self.dispatch(machine, Event::ClaimWorkload { claim }).await;
                let _ = reply.send(if taken {
                    Ok(())
                } else {
                    Err(self.wrong_state(match claim {
                        WorkloadClaim::Api => "Ready",
                        WorkloadClaim::Initial => "Starting or Ready",
                    }))
                });
            }
            Command::WorkloadExited { status } => {
                self.exit_status = Some(status);
                self.dispatch(machine, Event::WorkloadExited).await;
            }
            Command::SetLifecycle { deadlines, reply } => {
                self.deadlines = deadlines;
                self.rearm(*machine.state());
                let _ = reply.send(Ok(()));
            }
            Command::VmExited => {
                self.error
                    .get_or_insert_with(|| format!("computer {} exited unexpectedly", self.id));
                self.dispatch(machine, Event::VmExited).await;
            }
        }
    }

    pub(super) fn answer(&mut self, answer: Answer) {
        let unconfirmed = self.unconfirmed.take();
        let mut remaining = Vec::new();
        for (parked, reply) in std::mem::take(&mut self.waiters) {
            if parked == answer {
                let _ = reply.send(match &unconfirmed {
                    Some(detail) => Err(VmmError::AckUnconfirmed {
                        id: self.id.clone(),
                        detail: detail.clone(),
                    }),
                    None => Ok(()),
                });
            } else {
                remaining.push((parked, reply));
            }
        }
        self.waiters = remaining;
    }

    /// What a caller is told once its flow is under way: `Ok`, or the visible
    /// but unconfirmed durable write the flow left behind.
    fn acknowledged(&mut self) -> Result<()> {
        match self.unconfirmed.take() {
            Some(detail) => Err(VmmError::AckUnconfirmed {
                id: self.id.clone(),
                detail,
            }),
            None => Ok(()),
        }
    }

    /// Fails every parked caller this failure cancels.
    ///
    /// A parked `Remove` is the exception: a failure elsewhere is what starts
    /// its teardown, so the removal answers it — a removal that fails on its
    /// own release keeps waiting for the retry. The typed error goes to the
    /// first caller; further ones (coalesced verbs) get its text.
    pub(super) fn fail_waiters(&mut self, error: VmmError) {
        let text = error.to_string();
        let mut typed = Some(error);
        let mut remaining = Vec::new();
        for (parked, reply) in std::mem::take(&mut self.waiters) {
            if parked == Answer::Removed {
                remaining.push((parked, reply));
            } else {
                let _ = reply.send(Err(typed
                    .take()
                    .unwrap_or_else(|| VmmError::Other(text.clone()))));
            }
        }
        self.waiters = remaining;
    }

    fn wrong_state(&self, expected: &str) -> VmmError {
        VmmError::WrongState {
            id: self.id.clone(),
            expected: expected.to_owned(),
            actual: self
                .public()
                .map_or_else(|| "unknown".to_owned(), |state| state.to_string()),
        }
    }
}
