//! Executing what a transition asked for: the durable record, the crash
//! journal, the event bus, the two deadline timers, and the sub-task
//! spawns.
//!
//! The machine names an effect; everything about *how* it is carried out —
//! which transition a phase becomes, what an unconfirmed write costs the
//! caller, which attributes an event carries — lives here.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::oneshot;
use tracing::{error, warn};

use super::*;

impl ComputerActor {
    /// Executes one effect. `state` is the state the transition landed in —
    /// what the timers and the durable writes are relative to.
    pub(super) async fn apply(&mut self, effect: Effect, state: State) -> Flow {
        match effect {
            Effect::PersistPhase { phase, durability } => self.persist(phase, durability),
            Effect::CommitRestored { durability } => self.commit(
                PersistPhase::Ready,
                SandboxTransition::ReadyWithOutcome(self.outcome.clone()),
                durability,
            ),
            Effect::ForgetRecord(end) => {
                self.forget(end);
                // Before REMOVED is announced, as `remove_sandbox_impl`
                // drops its map entry before broadcasting: a reader that
                // acts on the event must not still find the computer.
                (self.unregister)();
            }
            Effect::ClearJournal => {
                // `failure()` asks for the clear in the same breath as the
                // release it must follow; `stopping`/`releasing` ask once
                // their release has already reported.
                if self.inflight.is_some() {
                    self.clear_journal_after_release = true;
                } else {
                    self.clear_journal();
                }
            }
            Effect::SpawnBoot { warm } => {
                let (handed_off, handoff) = oneshot::channel();
                let tasks = Arc::clone(&self.tasks);
                self.spawn(Handoff::Awaited(handoff), async move {
                    match tasks.boot(warm, handed_off).await {
                        Ok(agent) => Report::Booted(agent),
                        Err(failure) => Report::Failed(failure),
                    }
                });
            }
            Effect::SpawnGate => {
                let tasks = Arc::clone(&self.tasks);
                self.spawn(Handoff::Abortable, async move {
                    match tasks.gate().await {
                        Ok(()) => Report::Gated,
                        Err(failure) => Report::Failed(failure),
                    }
                });
            }
            Effect::SpawnRestore { origin } => {
                let tasks = Arc::clone(&self.tasks);
                // A restore keeps its lease and CoW handle in locals until
                // it commits, and unwinds them itself: it is joined, never
                // aborted.
                self.spawn(Handoff::JoinOnly, async move {
                    match tasks.restore(origin).await {
                        Ok((agent, outcome)) => Report::Restored(agent, outcome),
                        Err(failure) => Report::Failed(failure),
                    }
                });
            }
            Effect::SpawnCheckpoint { hold } => {
                let tasks = Arc::clone(&self.tasks);
                let spec = self.capture.take();
                self.spawn(Handoff::Abortable, async move {
                    match tasks.checkpoint(hold, spec).await {
                        Ok(info) => Report::Captured(info),
                        Err(failure) => Report::Failed(failure),
                    }
                });
            }
            Effect::SpawnResume => {
                let tasks = Arc::clone(&self.tasks);
                // Same as a restore: everything it re-creates is unwound by
                // its own failure path, out of locals nothing else can see.
                self.spawn(Handoff::JoinOnly, async move {
                    match tasks.resume().await {
                        Ok(agent) => Report::Resumed(agent),
                        Err(failure) => Report::Failed(failure),
                    }
                });
            }
            Effect::SpawnStop { budget_ms, drain } => {
                self.forget_agent();
                let tasks = Arc::clone(&self.tasks);
                let budget = Duration::from_millis(budget_ms);
                self.spawn(Handoff::Abortable, async move {
                    match tasks.stop(budget, drain).await {
                        Ok(()) => Report::Stopped,
                        Err(failure) => Report::Failed(failure),
                    }
                });
            }
            Effect::SpawnRelease { scope } => {
                // A release kills and reaps the VMM and drops its handle, so
                // nothing dials this computer from here on.
                self.forget_agent();
                let tasks = Arc::clone(&self.tasks);
                self.spawn(Handoff::Abortable, async move {
                    match tasks.release(scope).await {
                        Ok(()) => Report::Released(scope),
                        Err(failure) => Report::Failed(failure),
                    }
                });
            }
            Effect::AbortInflight => return self.abort_inflight().await,
            Effect::Publish(notify) => self.publish(notify),
            Effect::ArmTimer(timer) => self.arm(timer, state),
            Effect::CancelTimer(Timer::Ttl) => self.ttl = None,
            Effect::CancelTimer(Timer::Idle) => self.idle = None,
            Effect::Answer(answer) => self.answer(answer),
        }
        Flow::Continue
    }

    fn persist(&mut self, phase: PersistPhase, durability: Durability) {
        let transition = match phase {
            PersistPhase::Starting => SandboxTransition::Starting(self.outcome.clone()),
            PersistPhase::Ready => SandboxTransition::Ready,
            PersistPhase::Stopping => SandboxTransition::Stopping,
            PersistPhase::Stopped => SandboxTransition::Stopped,
            PersistPhase::Failed => {
                SandboxTransition::Failed(self.error.clone().unwrap_or_default())
            }
            PersistPhase::Removing => SandboxTransition::Removing,
            PersistPhase::Pausing => SandboxTransition::Pausing,
            PersistPhase::Paused => SandboxTransition::Paused {
                snapshot_id: self.pause_snapshot_id.clone().unwrap_or_default(),
            },
            PersistPhase::Resuming => SandboxTransition::Resuming,
            // The provisioning intent is written before there is a machine to
            // ask for it, so no transition names it.
            PersistPhase::Creating => return,
        };
        self.commit(phase, transition, durability);
    }

    fn commit(
        &mut self,
        phase: PersistPhase,
        transition: SandboxTransition,
        durability: Durability,
    ) {
        let Some(generation) = self.generation else {
            return;
        };
        let commit = match self.records.transition(&self.id, generation, transition) {
            Ok(commit) => commit,
            // A refused write is not an unconfirmed one: nothing was
            // recorded at all. Every treatment below assumes the phase is at
            // least visible — warning and carrying on would leave the
            // computer running past a phase its record never entered — so
            // the flow fails the way its own sub-task's failure would.
            Err(error) => {
                return self.fail_write(&format!("recording {} failed: {error}", phase.as_str()));
            }
        };
        let Some(error) = commit.durability_error else {
            return;
        };
        let phase = phase.as_str();
        match durability {
            Durability::Warn => {
                warn!(sandbox_id = %self.id, error, phase, "durable write is unconfirmed; continuing");
            }
            Durability::GateJournal => {
                // The gate *is* the handling: an unconfirmed write keeps the
                // crash journal, so a restart still finds the resources it
                // records.
                warn!(sandbox_id = %self.id, error, phase, "durable write is unconfirmed; keeping the crash journal");
                self.journal_blocked = true;
            }
            Durability::Report(Unconfirmed::Ack) => self.unconfirmed = Some(error),
            Durability::Report(Unconfirmed::Unavailable) => self.fail_write(&format!(
                "state is visible, but durability is unconfirmed: {error}"
            )),
            Durability::Report(Unconfirmed::RevertToPaused) => {
                // The restart sweep trusts the phase: an unconfirmed
                // `Resuming` reads back as cleanly paused, and the restore's
                // journaled resources would never be released.
                self.commit(
                    PersistPhase::Paused,
                    SandboxTransition::Paused {
                        snapshot_id: self.pause_snapshot_id.clone().unwrap_or_default(),
                    },
                    Durability::Warn,
                );
                self.fail_write(&format!(
                    "state is visible, but durability is unconfirmed: {error}"
                ));
            }
        }
    }

    /// A durable write the flow cannot continue without: fail it the way its
    /// own sub-task's failure would.
    ///
    /// `answer_error` as well as the parked callers, because the flows that
    /// answer *immediately* have nothing parked — a cold create is told its
    /// boot is under way as soon as the machine acts, and that answer has to
    /// carry this instead.
    fn fail_write(&mut self, detail: &str) {
        let error = VmmError::Unavailable(format!("computer {} {detail}", self.id));
        self.error = Some(error.to_string());
        self.answer_error = Some(error.to_string());
        self.fail_waiters(error);
        self.queued.push_back(Event::Failure);
    }

    fn forget(&mut self, end: RecordEnd) {
        let Some(generation) = self.generation else {
            return;
        };
        let outcome = match end {
            RecordEnd::Aborted => self.records.abort_provision(&self.id, generation),
            RecordEnd::Removed => self.records.finish_remove(&self.id, generation),
        };
        match outcome {
            Ok(commit) => {
                if let Some(error) = commit.durability_error {
                    self.unconfirmed = Some(error);
                }
            }
            Err(error) => {
                error!(sandbox_id = %self.id, %error, "failed to forget the computer's record");
            }
        }
    }

    /// Drops the crash journal — never before the durable write that made it
    /// redundant is confirmed *and* the release it describes has completed.
    /// Persists the resolved deadline knobs. The timers themselves live in
    /// this task, so the record is the only thing a restart can re-arm them
    /// from — an acknowledged change that is not on disk silently reverts.
    pub(super) fn persist_lifecycle(&self) -> Result<()> {
        let Some(generation) = self.generation else {
            return Ok(());
        };
        self.records
            .update_lifecycle(
                &self.id,
                generation,
                self.deadlines.ttl,
                self.deadlines.idle_timeout_seconds,
                self.deadlines.on_idle,
            )?
            .confirmed("computer lifecycle update")
    }

    pub(super) fn clear_journal(&mut self) {
        if std::mem::take(&mut self.journal_blocked) {
            return;
        }
        if let Err(error) = crate::sandbox::reconcile::clear_state_record(&self.vm_dir) {
            error!(sandbox_id = %self.id, %error, "crash journal cleanup is not durable");
        }
    }

    pub(super) fn public(&self) -> SandboxState {
        self.snapshot_tx.borrow().state
    }

    /// Mirrors the machine's state into the runtime and republishes the read
    /// snapshot from it.
    ///
    /// The runtime's `state` is what a sub-task reads to see a teardown that
    /// started while it was running — the cooperative half of preemption. The
    /// snapshot is what every reader sees, and it is re-projected on every
    /// transition and completion rather than patched field by field: the
    /// fields the flows write (the lease a restore reserved, the timestamps,
    /// the pause checkpoint) change out here, not in the machine.
    pub(super) fn publish_state(&self, state: State) {
        let public = state.to_public();
        let projected = {
            let mut runtime = self.runtime.lock().unwrap();
            runtime.state = public;
            ComputerSnapshot::project(&runtime, public, self.deadlines)
        };
        self.snapshot_tx.send_modify(|snapshot| {
            let agent = snapshot.agent.take();
            *snapshot = projected;
            snapshot.agent = agent;
        });
    }

    pub(super) fn publish_agent(&self, agent: Arc<dyn GuestAgent>) {
        self.snapshot_tx
            .send_modify(|snapshot| snapshot.agent = Some(agent));
    }

    fn forget_agent(&self) {
        self.snapshot_tx
            .send_modify(|snapshot| snapshot.agent = None);
    }

    fn publish(&mut self, notify: Notify) {
        let event = SandboxEvent::new(&self.id, notify_action(notify));
        let event = match notify {
            Notify::Failed => {
                let error = self.error.clone().unwrap_or_default();
                self.runtime.lock().unwrap().error = Some(error.clone());
                self.snapshot_tx
                    .send_modify(|snapshot| snapshot.error = Some(error.clone()));
                event.with_attr("error", &error)
            }
            Notify::Pausing => event.with_attr("reason", self.pause_reason.as_str()),
            Notify::Resumed => event.with_attr("reason", &self.resume_reason.clone()),
            Notify::Idle => match self.exit.take() {
                Some(WorkloadOutcome::Exited(status)) => {
                    let event =
                        event.with_attr("exit_code", &status.conventional_code().to_string());
                    match status {
                        ExitStatus::Signaled(signal) => {
                            event.with_attr("signal", &signal.to_string())
                        }
                        ExitStatus::Code(_) => event,
                    }
                }
                // The session broke before an exit chunk arrived. The guest
                // kills the workload when its host connection drops, so the
                // computer is idle either way — but there is no status to
                // report, only why (`execution::abort_workload`).
                Some(WorkloadOutcome::Broke(error)) => event.with_attr("error", &error),
                None => event,
            },
            _ => event,
        };
        let _ = self.events_tx.send(event);
    }

    fn arm(&mut self, timer: Timer, state: State) {
        if !*self.timers_enabled.borrow() {
            return;
        }
        let public = state.to_public();
        match timer {
            Timer::Ttl => {
                self.ttl = deadlines::ttl_due(public, self.deadlines.ttl).map(|deadline| {
                    Box::pin(tokio::time::sleep(deadlines::remaining(
                        deadline,
                        Utc::now(),
                    )))
                });
            }
            Timer::Idle => {
                self.idle = deadlines::idle_due(public, self.deadlines.idle_timeout_seconds)
                    .map(|after| Box::pin(tokio::time::sleep(after)));
            }
        }
    }

    /// Re-arms both deadlines against the current state — what `SetLifecycle`
    /// and the timers gate flipping on both need.
    pub(super) fn rearm(&mut self, state: State) {
        self.arm(Timer::Ttl, state);
        self.arm(Timer::Idle, state);
    }
}

/// The event action a notification publishes. Goes through `types::action`,
/// so a renamed action is a compile error here rather than a silently
/// unmatched string.
fn notify_action(notify: Notify) -> &'static str {
    match notify {
        Notify::Created => action::CREATED,
        Notify::Ready => action::READY,
        Notify::Running => action::RUNNING,
        Notify::Idle => action::IDLE,
        Notify::Stopping => action::STOPPING,
        Notify::Stopped => action::STOPPED,
        Notify::Failed => action::FAILED,
        Notify::Removed => action::REMOVED,
        Notify::Pausing => action::PAUSING,
        Notify::Paused => action::PAUSED,
        Notify::Resumed => action::RESUMED,
    }
}
