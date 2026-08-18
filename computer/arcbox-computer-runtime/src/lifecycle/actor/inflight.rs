//! The in-flight sub-task: spawning it, preempting it, and taking what it
//! reports.
//!
//! This is the half that makes a force-remove able to cancel a boot, and
//! the half that keeps a superseded task from driving the machine.

use tokio::sync::oneshot;
use tracing::{debug, error, warn};

use super::*;

impl ComputerActor {
    /// Spawns `task` as the in-flight sub-task. Every spawn takes a fresh
    /// epoch, so a completion the superseded task already enqueued is
    /// recognized as stale.
    pub(super) fn spawn<F>(&mut self, handoff: Option<oneshot::Receiver<()>>, task: F)
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
    /// Three outcomes, exactly as `cleanup::cancel_and_join_boot` has them:
    /// the handoff lands and the task is aborted; the task ended without
    /// signalling, so it is joined instead and its own failure cleanup
    /// finishes; or the wait elapses, in which case the task is re-parked and
    /// the rest of the teardown stalls until a retry takes it.
    pub(super) async fn abort_inflight(&mut self) -> Flow {
        let Some(mut task) = self.inflight.take() else {
            self.epoch += 1;
            return Flow::Continue;
        };
        if let Some(mut handoff) = task.handoff.take() {
            match tokio::time::timeout(HANDOFF_TIMEOUT, &mut handoff).await {
                // Every resource created before the next cancellation point
                // is now the computer's, so aborting cannot strand one.
                Ok(Ok(())) => task.handle.abort(),
                // The producer ended without declaring abort safety: join it
                // so its own failure cleanup can finish.
                Ok(Err(_)) => {}
                Err(_) => {
                    task.handoff = Some(handoff);
                    return self.stall(task);
                }
            }
        } else {
            task.handle.abort();
        }
        if tokio::time::timeout(HANDOFF_TIMEOUT, &mut task.handle)
            .await
            .is_err()
        {
            return self.stall(task);
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
            "the computer's boot has not handed its resources over; retrying the teardown"
        );
        self.inflight = Some(task);
        self.retry = Some(Box::pin(tokio::time::sleep(self.retry_backoff)));
        self.retry_backoff = self.retry_backoff.saturating_mul(2).min(RETRY_MAX);
        Flow::Stalled
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
        let handed_off = self
            .inflight
            .take()
            .and_then(|mut task| task.handoff.take())
            .is_some_and(|mut signal| signal.try_recv().is_ok());
        if handed_off {
            self.dispatch(machine, Event::ResourcesHandedOff).await;
        }
        if self.clear_journal_after_release {
            self.clear_journal_after_release = false;
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
                self.fail_waiters(error);
                Some(event)
            }
        };
        if let Some(event) = event {
            self.dispatch(machine, event).await;
        }
        self.serve_pending_stop(machine).await;
    }

    /// Serves a stop that arrived while a launch was in flight, now that the
    /// launch has resolved. A launch that failed has nothing left to stop.
    async fn serve_pending_stop(&mut self, machine: &mut Machine) {
        let Some(budget) = self.pending_stop else {
            return;
        };
        match self.public() {
            Some(SandboxState::Ready | SandboxState::Running) => {
                self.pending_stop = None;
                let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
                self.dispatch(machine, Event::Stop { budget_ms }).await;
            }
            // Still launching: wait for the next completion.
            Some(SandboxState::Starting) => {}
            _ => {
                self.pending_stop = None;
                self.answer(Answer::Stopped);
            }
        }
    }
}
