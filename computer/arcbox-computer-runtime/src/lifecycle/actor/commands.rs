//! What a caller asks of one computer, and what it is told.
//!
//! The machine answers `Handled` with no effects whenever it has nothing
//! to do; turning that into `Ok` (an idempotent pause) or `WrongState` (a
//! non-forced remove of a busy computer) is this half of the actor, which
//! is also where a caller parks until the effect that answers it lands.

use chrono::Utc;

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
                    self.park(Answer::Ready, reply);
                } else {
                    let _ = reply.send(self.acknowledged());
                }
            }
            Command::Checkpoint { spec, reply } => {
                self.capture = Some(spec);
                if self.dispatch(machine, Event::Checkpoint).await {
                    self.capture_reply = Some(reply);
                } else {
                    self.capture = None;
                    let _ = reply.send(Err(self.wrong_state("Ready")));
                }
            }
            Command::Pause { reason, reply } => {
                self.pause_reason = reason;
                if self.dispatch(machine, Event::Pause { reason }).await {
                    self.park(Answer::Paused, reply);
                } else {
                    // Pausing a paused computer is a no-op.
                    let _ = reply.send(match self.public() {
                        ComputerState::Paused => Ok(()),
                        _ => Err(self.wrong_state("Ready")),
                    });
                }
            }
            Command::Resume { reason, reply } => {
                self.resume_reason = reason;
                if self.dispatch(machine, Event::Resume).await {
                    self.park(Answer::Resumed, reply);
                } else {
                    // Resuming a live computer is a no-op.
                    let _ = reply.send(match self.public() {
                        ComputerState::Ready | ComputerState::Running => Ok(()),
                        _ => Err(self.wrong_state("Paused")),
                    });
                }
            }
            Command::Stop { budget, reply } => {
                let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
                if self.dispatch(machine, Event::Stop { budget_ms }).await {
                    self.park(Answer::Stopped, reply);
                    return;
                }
                // A stop asked for during a launch is deferred until the
                // launch resolves, rather than refused as today's
                // `stop_sandbox` does: the alternative is a stop racing a
                // boot that is still acquiring resources.
                if launching(*machine.state()) {
                    self.pending_stop.get_or_insert(budget);
                    self.waiters.push((Answer::Stopped, reply));
                    return;
                }
                match self.public() {
                    ComputerState::Stopping => self.park(Answer::Stopped, reply),
                    // `stop_sandbox`'s retry. A `Stopped` write that was
                    // visible but not confirmed kept the crash journal, and
                    // a second stop is the only thing that finishes it —
                    // answering `Ok` would leave a journal naming resources
                    // that are already gone for the next startup sweep.
                    ComputerState::Stopped => {
                        let _ = reply.send(self.finish_stop());
                    }
                    _ => {
                        let _ = reply.send(Err(self.wrong_state("Ready, Running, or Stopping")));
                    }
                }
            }
            Command::Remove { force, reply } => {
                // Parked *before* the dispatch: a teardown can fail during
                // it — a panicked sub-task is found while its effects are
                // still being applied — and that error has to reach the
                // caller that asked for the removal.
                self.waiters.push((Answer::Removed, reply));
                if self.dispatch(machine, Event::Remove { force }).await {
                    return;
                }
                match machine.state() {
                    // A removal under way coalesces. One that *stopped* — a
                    // release that failed, a panicked sub-task — is re-driven
                    // instead: `removing` swallows the retry, so nothing else
                    // would ever answer it, and a retried
                    // `remove_sandbox_impl` re-runs the teardown today.
                    State::Removing {} => {
                        if self.inflight.is_none() && self.retry.is_none() {
                            self.restart_teardown(*machine.state()).await;
                        }
                    }
                    // `gone` with a step still parked is not done: the
                    // durable record — and with it the id — is what that step
                    // is trying to release, so the reply just pushed waits
                    // for the retry rather than being answered now.
                    State::Gone {} if self.stalled.is_some() => {
                        if self.retry.is_none() {
                            self.resume_stalled().await;
                        }
                    }
                    State::Gone {} => self.answer(Answer::Removed),
                    // Refused, and nothing acted — so the reply is still the
                    // one just parked.
                    _ => {
                        let refused = self.wrong_state("non-running (pass force=true to override)");
                        if let Some((_, reply)) = self.waiters.pop() {
                            let _ = reply.send(Err(refused));
                        }
                    }
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
            Command::WorkloadExited { outcome } => {
                {
                    // The stop's drain polls for this: it is how a graceful
                    // stop knows the workload it is waiting out has finished.
                    let mut runtime = self.runtime.lock().unwrap();
                    if let WorkloadOutcome::Exited(status) = &outcome {
                        runtime.last_exit_status = Some(*status);
                    }
                    runtime.last_exited_at = Some(Utc::now());
                }
                self.exit = Some(outcome);
                self.dispatch(machine, Event::WorkloadExited).await;
            }
            Command::ReleaseWorkload => {
                self.dispatch(machine, Event::WorkloadReleased).await;
            }
            Command::SetLifecycle { update, reply } => {
                // `set_sandbox_lifecycle` refuses a computer on its way out:
                // nothing is left for a deadline to fire on, and the record
                // it would persist to is about to be a tombstone.
                if matches!(
                    self.public(),
                    ComputerState::Stopping | ComputerState::Stopped | ComputerState::Failed
                ) {
                    let _ = reply.send(Err(
                        self.wrong_state("a live computer (not stopping, stopped, or failed)")
                    ));
                    return;
                }
                if let Some(ttl) = update.ttl_seconds {
                    self.deadlines.ttl =
                        (ttl > 0).then(|| Utc::now() + chrono::Duration::seconds(i64::from(ttl)));
                }
                if let Some(idle) = update.idle_timeout_seconds {
                    self.deadlines.idle_timeout_seconds = idle;
                }
                if let Some(policy) = update.on_idle {
                    self.deadlines.on_idle = policy;
                }
                let deadlines = self.deadlines;
                {
                    // Mirrored onto the runtime too: it is what the startup
                    // sweep reads a computer's deadlines back from, so a
                    // reader that reaches for either finds the same policy.
                    let mut runtime = self.runtime.lock().unwrap();
                    runtime.ttl_deadline = deadlines.ttl;
                    runtime.spec.idle_timeout_seconds = deadlines.idle_timeout_seconds;
                    runtime.spec.on_idle = deadlines.on_idle;
                }
                // The timers live in this task; the record is what a restart
                // re-arms them from, so an acknowledged change has to be on
                // disk as well (`set_sandbox_lifecycle` today).
                let persisted = self.persist_lifecycle();
                self.rearm(*machine.state());
                // `Inspect` reports the deadlines, so the read view has to
                // move with them.
                self.publish_state(*machine.state());
                let _ = reply.send(persisted);
            }
            Command::VmExited => {
                self.error
                    .get_or_insert_with(|| format!("computer {} exited unexpectedly", self.id));
                self.dispatch(machine, Event::VmExited).await;
            }
        }
    }

    /// Re-confirms a computer that is already stopped, and drops the crash
    /// journal its first stop could not.
    fn finish_stop(&mut self) -> Result<()> {
        let Some(generation) = self.generation else {
            return Ok(());
        };
        self.records
            .transition(&self.id, generation, ComputerTransition::Stopped)?
            .confirmed("computer stop retry")?;
        // The write just confirmed, so whatever blocked the first clear is
        // answered.
        self.unblock_journal();
        self.clear_journal();
        Ok(())
    }

    /// Parks a caller on the answer its flow owes it — unless the flow
    /// already failed on a required durable write, in which case there is
    /// nothing left to answer it and the caller hears now.
    fn park(&mut self, answer: Answer, reply: Reply) {
        match self.answer_error.take() {
            Some(detail) => {
                let _ = reply.send(Err(ComputerError::Unavailable(detail)));
            }
            None => self.waiters.push((answer, reply)),
        }
    }

    pub(super) fn answer(&mut self, answer: Answer) {
        let unconfirmed = self.unconfirmed.take();
        let failed = self.answer_error.take();
        let mut remaining = Vec::new();
        for (parked, reply) in std::mem::take(&mut self.waiters) {
            if parked == answer {
                let _ = reply.send(match (&failed, &unconfirmed) {
                    // The flow reached its answer, but a step of it failed
                    // loudly on the way; the caller hears that first.
                    (Some(detail), _) => Err(ComputerError::Unavailable(detail.clone())),
                    (None, Some(detail)) => Err(ComputerError::AckUnconfirmed {
                        id: self.id.clone(),
                        detail: detail.clone(),
                    }),
                    (None, None) => Ok(()),
                });
            } else {
                remaining.push((parked, reply));
            }
        }
        self.waiters = remaining;
    }

    /// What a caller is told once its flow is under way: `Ok`, the durable
    /// write that failed before it could start, or the visible but
    /// unconfirmed one it left behind.
    fn acknowledged(&mut self) -> Result<()> {
        if let Some(detail) = self.answer_error.take() {
            return Err(ComputerError::Unavailable(detail));
        }
        match self.unconfirmed.take() {
            Some(detail) => Err(ComputerError::AckUnconfirmed {
                id: self.id.clone(),
                detail,
            }),
            None => Ok(()),
        }
    }

    /// Fails every parked caller this failure cancels, and reports how many
    /// heard it.
    ///
    /// A parked `Remove` is the exception: a failure elsewhere is what starts
    /// its teardown, so the removal is what answers it. The removal's own
    /// release failure is [`Self::fail_every_waiter`].
    pub(super) fn fail_waiters(&mut self, error: ComputerError) -> usize {
        self.fail_parked(error, false)
    }

    /// [`Self::fail_waiters`], including the parked removals — for the one
    /// failure no later answer can reach, a removal's own release.
    pub(super) fn fail_every_waiter(&mut self, error: ComputerError) -> usize {
        self.fail_parked(error, true)
    }

    /// The typed error goes to the first caller; further ones (coalesced
    /// verbs) get its text, since an error is not `Clone`.
    fn fail_parked(&mut self, error: ComputerError, removals_too: bool) -> usize {
        let text = error.to_string();
        let mut typed = Some(error);
        let mut answered = 0;
        let mut remaining = Vec::new();
        for (parked, reply) in std::mem::take(&mut self.waiters) {
            if parked == Answer::Removed && !removals_too {
                remaining.push((parked, reply));
            } else {
                answered += 1;
                let _ = reply.send(Err(typed
                    .take()
                    .unwrap_or_else(|| ComputerError::Other(text.clone()))));
            }
        }
        self.waiters = remaining;
        answered
    }

    fn wrong_state(&self, expected: &str) -> ComputerError {
        ComputerError::WrongState {
            id: self.id.clone(),
            expected: expected.to_owned(),
            actual: self.public().to_string(),
        }
    }
}
