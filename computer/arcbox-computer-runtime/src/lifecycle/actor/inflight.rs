//! The in-flight sub-task: spawning it, preempting it, and taking what it
//! reports.
//!
//! This is the half that makes a force-remove able to cancel a boot, and
//! the half that keeps a superseded task from driving the machine.

use tracing::{debug, error, warn};

use super::*;

impl ComputerActor {
    /// Spawns `task` as the in-flight sub-task. Every spawn takes a fresh
    /// epoch, so a completion the superseded task already enqueued is
    /// recognized as stale.
    pub(super) fn spawn<F>(&mut self, handoff: Handoff, task: F)
    where
        F: std::future::Future<Output = Report> + Send + 'static,
    {
        if let Some(previous) = self.inflight.take() {
            previous.handle.abort();
        }
        self.epoch += 1;
        let epoch = self.epoch;
        let completions = self.completions_tx.clone();
        let handle = tokio::spawn(async move {
            let report = task.await;
            let _ = completions.send(Completion { epoch, report });
        });
        self.inflight = Some(Preemptible { handle, handoff });
    }

    /// Cancels the in-flight sub-task, waiting out its resource handoff first.
    ///
    /// The outcomes `cleanup::cancel_and_join_boot` has: the handoff lands
    /// and the task is aborted; the task ended without signalling, so it is
    /// joined instead and its own failure cleanup finishes; the wait elapses,
    /// in which case the task is re-parked and the rest of the teardown
    /// stalls until a retry takes it; or the join itself reports a panic,
    /// which the teardown carries to its caller rather than swallowing. A
    /// task that unwinds its own resources ([`Handoff::JoinOnly`]) is only
    /// ever joined — see there.
    pub(super) async fn abort_inflight(&mut self) -> Flow {
        let Some(mut task) = self.inflight.take() else {
            self.epoch += 1;
            return Flow::Continue;
        };
        match std::mem::replace(&mut task.handoff, Handoff::Abortable) {
            Handoff::Awaited(mut signal) => {
                match tokio::time::timeout(HANDOFF_TIMEOUT, &mut signal).await {
                    // Every resource created before the next cancellation
                    // point is now the computer's, so aborting cannot strand
                    // one.
                    Ok(Ok(())) => task.handle.abort(),
                    // The producer ended without declaring abort safety: it
                    // is tearing down what it never handed over, so it is
                    // joined rather than cut short — and a retry after a
                    // stalled join must join it too.
                    Ok(Err(_)) => task.handoff = Handoff::JoinOnly,
                    Err(_) => {
                        task.handoff = Handoff::Awaited(signal);
                        return self.stall(task);
                    }
                }
            }
            Handoff::Abortable => task.handle.abort(),
            // Aborting would drop the unwind with the resources still
            // allocated, so the teardown waits — bounded, and stalling onto
            // the same backoff if the task outlives it.
            Handoff::JoinOnly => {
                task.handoff = Handoff::JoinOnly;
            }
        }
        match tokio::time::timeout(HANDOFF_TIMEOUT, &mut task.handle).await {
            Err(_) => return self.stall(task),
            // A cancelled task is what we asked for. A panicked one is not:
            // `cancel_and_join_boot` maps it onto an error that leaves
            // `remove_sandbox_impl` through `?`, so the release and the
            // record unlink never run — the record and its journal survive
            // for the startup sweep, and a retry (whose join is clean)
            // finishes the job. Carrying on would delete both while whatever
            // the panicking task never transferred was still out there.
            Ok(Err(error)) if !error.is_cancelled() => {
                error!(sandbox_id = %self.id, %error, "a computer sub-task panicked");
                self.fail_every_waiter(VmmError::Process(format!(
                    "computer {} sub-task panicked: {error}",
                    self.id
                )));
                self.epoch += 1;
                return Flow::Stalled;
            }
            Ok(_) => {}
        }
        self.epoch += 1;
        self.retry_backoff = RETRY_INITIAL;
        Flow::Continue
    }

    /// Re-parks an un-abortable sub-task and schedules the retry the rest of
    /// the teardown waits on.
    fn stall(&mut self, task: Preemptible) -> Flow {
        warn!(
            sandbox_id = %self.id,
            retry_millis = self.retry_backoff.as_millis(),
            "the computer's in-flight work still owns resources; retrying the teardown"
        );
        self.inflight = Some(task);
        self.retry = Some(Box::pin(tokio::time::sleep(self.retry_backoff)));
        self.retry_backoff = self.retry_backoff.saturating_mul(2).min(RETRY_MAX);
        Flow::Stalled
    }

    /// Re-drives a teardown that stopped rather than finished — its release
    /// failed, or a panicked sub-task abandoned it. Today's equivalent is a
    /// retried `remove_sandbox_impl`, which re-runs the whole teardown.
    pub(super) async fn restart_teardown(&mut self, state: State) {
        if self.stalled.is_some() {
            self.resume_stalled().await;
        } else {
            self.apply(
                Effect::SpawnRelease {
                    scope: ReleaseScope::Full,
                },
                state,
            )
            .await;
        }
    }

    /// Retries the abort a stalled teardown is waiting on, then replays it.
    pub(super) async fn resume_stalled(&mut self) {
        let Some(stalled) = self.stalled.take() else {
            return;
        };
        if self.abort_inflight().await == Flow::Stalled {
            self.stalled = Some(stalled);
            return;
        }
        let mut effects = stalled.effects.into_iter();
        while let Some(effect) = effects.next() {
            if Box::pin(self.apply(effect, stalled.state)).await == Flow::Stalled {
                self.stalled = Some(Stalled {
                    state: stalled.state,
                    effects: effects.collect(),
                });
                return;
            }
        }
    }

    pub(super) async fn on_completion(&mut self, machine: &mut Machine, completion: Completion) {
        if completion.epoch != self.epoch {
            debug!(
                sandbox_id = %self.id,
                stale = completion.epoch,
                current = self.epoch,
                "dropping a superseded sub-task's completion"
            );
            return;
        }
        // A boot signals its handoff *before* it completes, but the two
        // arrive on different channels and `select!` picks either. The
        // machine must still see them in order — `AgentReady` is handled in
        // `booting`, which only `ResourcesHandedOff` reaches.
        let handed_off = match self.inflight.take().map(|task| task.handoff) {
            Some(Handoff::Awaited(mut signal)) => signal.try_recv().is_ok(),
            _ => false,
        };
        if handed_off {
            self.dispatch(machine, Event::ResourcesHandedOff).await;
        }
        // A journal `failure()` deferred goes only once the release it
        // describes has *finished*: what it records is exactly the resources
        // a restart would otherwise have to reclaim, so dropping it behind a
        // release that failed turns a clean failure into orphans.
        if std::mem::take(&mut self.clear_journal_after_release)
            && matches!(completion.report, Report::Released(_))
        {
            self.clear_journal();
        }
        let event = match completion.report {
            Report::Booted(agent) => {
                self.publish_agent(agent);
                Some(Event::AgentReady)
            }
            Report::Restored(agent, outcome) => {
                self.outcome = outcome;
                self.publish_agent(agent);
                Some(Event::Restored)
            }
            Report::Resumed(agent) => {
                self.publish_agent(agent);
                Some(Event::Restored)
            }
            Report::Gated => Some(Event::Gated),
            Report::Captured(snapshot_id) => {
                if let Some(reply) = self.capture_reply.take() {
                    let _ = reply.send(Ok(snapshot_id.clone()));
                }
                self.pause_snapshot_id = Some(snapshot_id.clone());
                Some(Event::CaptureDone { snapshot_id })
            }
            Report::Released(ReleaseScope::Full) => Some(Event::RemoveDone),
            Report::Released(ReleaseScope::KeepDisk) => Some(Event::ReleasedForPause),
            // The failure path's own release: the machine parked at `failed`
            // and waits for nothing.
            Report::Released(ReleaseScope::Runtime) => None,
            Report::Stopped => Some(Event::StopDone),
            Report::Failed(failure) => {
                error!(sandbox_id = %self.id, error = failure.message(), "computer sub-task failed");
                self.error = Some(failure.message());
                let event = failure.event();
                let error = failure.into_error();
                if let Some(reply) = self.capture_reply.take() {
                    let _ =
                        reply.send(Err(VmmError::Other(self.error.clone().unwrap_or_default())));
                }
                // A launch that failed has nothing left to stop, so a stop
                // deferred behind it got what it asked for. Answered before
                // the drain below, which would otherwise hand it the launch's
                // error instead.
                if self.pending_stop.take().is_some() {
                    self.answer(Answer::Stopped);
                }
                if matches!(machine.state(), State::Removing {}) {
                    // The removal's own release: `removing` coalesces the
                    // failure, so nothing else will ever answer its caller —
                    // and `remove_sandbox_impl` hands this error straight back
                    // today.
                    self.fail_every_waiter(error);
                } else {
                    self.fail_waiters(error);
                }
                Some(event)
            }
        };
        if let Some(event) = event {
            self.dispatch(machine, event).await;
        }
        self.serve_pending_stop(machine).await;
    }

    /// Serves a stop that arrived while a launch was in flight, now that the
    /// launch has resolved.
    ///
    /// Keyed on the machine's state rather than the public one: a gate whose
    /// initial `cmd` has claimed the slot reads `Running` while its launch is
    /// very much still in flight, and a stop dispatched there is swallowed
    /// and lost.
    async fn serve_pending_stop(&mut self, machine: &mut Machine) {
        let Some(budget) = self.pending_stop else {
            return;
        };
        if launching(*machine.state()) {
            return;
        }
        self.pending_stop = None;
        match self.public() {
            Some(SandboxState::Ready | SandboxState::Running) => {
                let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
                self.dispatch(machine, Event::Stop { budget_ms }).await;
            }
            // Nothing left to stop.
            _ => self.answer(Answer::Stopped),
        }
    }
}
