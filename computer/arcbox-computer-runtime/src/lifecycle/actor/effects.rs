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
            Effect::PersistPhase { phase, durability } => return self.persist(phase, durability),
            Effect::CommitRestored { durability } => {
                return self.commit(
                    PersistPhase::Ready,
                    SandboxTransition::ReadyWithOutcome(self.outcome.clone()),
                    durability,
                );
            }
            Effect::ForgetRecord(end) => return self.forget(end),
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
                // Read here, not in the task: this runs in the same poll as
                // the transition, so an exit recorded before it is the one
                // the drain is already waiting for.
                let drain = if drain {
                    Drain::Until {
                        since: self.runtime.lock().unwrap().last_exited_at,
                    }
                } else {
                    Drain::No
                };
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
            Effect::Detach => match self.tasks.detach().await {
                // The machine has not moved yet: it emitted this effect and
                // stayed put, so the handover's own outcome is what decides.
                Ok(()) => {
                    // The data plane reads the agent straight off the snapshot
                    // and never round-trips the mailbox, so the state alone
                    // cannot stop it — and `detached` projects `Ready`, which
                    // is exactly what `require_alive_agent` admits. Dropping
                    // the agent is what keeps an exec or a file write out of a
                    // guest the successor now owns; a stop and a release do
                    // the same for the same reason.
                    self.forget_agent();
                    self.queued.push_back(Event::Detached);
                }
                // Stay where we are. The VM is still ours and still usable —
                // it simply dies with this process, which is what a failed
                // handover has always meant. Failing the computer instead
                // would write `Failed` over a record the successor's sweep
                // still has to read as `Ready`.
                Err(failure) => {
                    self.fail_waiters(failure.into_error());
                }
            },
            Effect::AbortInflight => return self.abort_inflight().await,
            Effect::Publish(notify) => self.publish(notify),
            Effect::ArmTimer(timer) => self.arm(timer, state),
            Effect::CancelTimer(Timer::Ttl) => self.ttl = None,
            Effect::CancelTimer(Timer::Idle) => self.idle = None,
            Effect::Answer(answer) => {
                // The removal that unwound a failed flow has finished and
                // the record is forgotten, so the flow's caller can hear —
                // and re-claim the id it is about to fall back onto.
                if answer == Answer::Removed
                    && let Some(error) = self.unwinding.take()
                {
                    self.fail_waiters(error);
                }
                self.answer(answer);
            }
        }
        Flow::Continue
    }

    fn persist(&mut self, phase: PersistPhase, durability: Durability) -> Flow {
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
            PersistPhase::Paused => {
                // What a paused computer retains, recorded where every
                // reader of it looks: `Inspect` and `List` size the
                // checkpoint and the overlay from here, and a resume finds
                // its checkpoint here. `paused_at` is set once — the resume
                // unwind writes `Paused` again and must not restamp it.
                let mut runtime = self.runtime.lock().unwrap();
                runtime.paused_at.get_or_insert_with(Utc::now);
                runtime
                    .pause_snapshot_id
                    .clone_from(&self.pause_snapshot_id);
                SandboxTransition::Paused {
                    snapshot_id: self.pause_snapshot_id.clone().unwrap_or_default(),
                }
            }
            PersistPhase::Resuming => SandboxTransition::Resuming,
            // The provisioning intent is written before there is a machine to
            // ask for it, so no transition names it.
            PersistPhase::Creating => return Flow::Continue,
        };
        self.commit(phase, transition, durability)
    }

    fn commit(
        &mut self,
        phase: PersistPhase,
        transition: SandboxTransition,
        durability: Durability,
    ) -> Flow {
        let Some(generation) = self.generation else {
            return Flow::Continue;
        };
        let commit = match self.records.transition(&self.id, generation, transition) {
            Ok(commit) => commit,
            // A refused write is not an unconfirmed one: nothing was
            // recorded at all.
            //
            // What that costs depends on what the phase was for. A phase the
            // flow is *about to act on* — `Stopping` before a shutdown,
            // `Removing` before a release, `Resuming` before a resume — must
            // stop it, which is what `stop_sandbox`, `begin_removal` and
            // `resume_sandbox` do with their `?`. A phase that only records
            // where the computer *ended up* must not: `persist_boot_failure`
            // reports the failure and lets the release run, keeping the
            // crash journal — which is exactly what `GateJournal` means.
            Err(error) if matches!(durability, Durability::GateJournal) => {
                error!(
                    sandbox_id = %self.id,
                    %error,
                    phase = phase.as_str(),
                    "durable write was refused; keeping the crash journal"
                );
                self.journal_blocked = true;
                return Flow::Continue;
            }
            Err(error) => {
                return self.fail_write(&format!("recording {} failed: {error}", phase.as_str()));
            }
        };
        let Some(error) = commit.durability_error else {
            return Flow::Continue;
        };
        let phase = phase.as_str();
        match durability {
            Durability::Warn => {
                warn!(sandbox_id = %self.id, error, phase, "durable write is unconfirmed; continuing");
                Flow::Continue
            }
            Durability::GateJournal => {
                // The gate *is* the handling: an unconfirmed write keeps the
                // crash journal, so a restart still finds the resources it
                // records.
                warn!(sandbox_id = %self.id, error, phase, "durable write is unconfirmed; keeping the crash journal");
                self.journal_blocked = true;
                Flow::Continue
            }
            Durability::Report(Unconfirmed::Ack) => {
                self.unconfirmed = Some(error);
                Flow::Continue
            }
            Durability::Report(Unconfirmed::Unavailable) => self.fail_write(&format!(
                "state is visible, but durability is unconfirmed: {error}"
            )),
            Durability::Report(Unconfirmed::RevertToPaused) => {
                // The restart sweep trusts the phase: an unconfirmed
                // `Resuming` reads back as cleanly paused, and the restore's
                // journaled resources would never be released.
                // A revert that is itself refused already failed the flow;
                // running the outer report as well would queue a second
                // `Failure` and fail the same callers twice.
                let reverted = self.commit(
                    PersistPhase::Paused,
                    SandboxTransition::Paused {
                        snapshot_id: self.pause_snapshot_id.clone().unwrap_or_default(),
                    },
                    Durability::Warn,
                );
                if reverted == Flow::Refused {
                    return reverted;
                }
                self.fail_write(&format!(
                    "state is visible, but durability is unconfirmed: {error}"
                ))
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
    ///
    /// A parked *removal* hears too, unlike every other failure: the removal
    /// is normally what answers them, and here it is the thing that did not
    /// happen. `begin_removal` propagates a refused `Removing` write the same
    /// way, before anything is torn down.
    fn fail_write(&mut self, detail: &str) -> Flow {
        let message = format!("computer {} {detail}", self.id);
        let error = VmmError::Unavailable(message.clone());
        self.error = Some(error.to_string());
        // Parked to be reported only when nobody was there to hear it: the
        // flows that answer immediately (a cold create) have nothing parked,
        // and leaving it set after it *was* delivered would poison the next
        // caller with a failure that is already answered.
        if self.fail_every_waiter(error) == 0 {
            self.answer_error = Some(message);
        }
        self.queued.push_back(Event::Failure);
        // The rest of this transition described work the write was recording:
        // a resume, a shutdown, a release. None of it may happen now.
        Flow::Refused
    }

    /// Deletes the durable record, and with it the computer's claim on its
    /// id.
    ///
    /// A refusal stalls the teardown rather than continuing past it:
    /// `remove_sandbox_impl` propagates a failed `finish_remove` *before* it
    /// drops its map entry, because the record still owns the id and only a
    /// retry that re-runs the deletion can free it. Reporting the removal
    /// done here would leave that id un-creatable until the next startup
    /// sweep.
    pub(super) fn forget(&mut self, end: RecordEnd) -> Flow {
        let Some(generation) = self.generation else {
            (self.unregister)();
            return Flow::Continue;
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
                // Before REMOVED is announced, as `remove_sandbox_impl` drops
                // its map entry before broadcasting: a reader that acts on
                // the event must not still find the computer.
                (self.unregister)();
                self.retry_backoff = RETRY_INITIAL;
                // The teardown finished, so whatever failed loudly on the
                // way is no longer what its caller needs to hear.
                self.answer_error = None;
                Flow::Continue
            }
            Err(error) => {
                error!(
                    sandbox_id = %self.id,
                    %error,
                    retry_millis = self.retry_backoff.as_millis(),
                    "the computer's record would not delete; retrying the teardown"
                );
                self.answer_error = Some(format!(
                    "computer {}: the record would not delete: {error}",
                    self.id
                ));
                self.stalled_on = StalledStep::Record(end);
                self.schedule_retry();
                Flow::Stalled
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

    /// Lets the next journal clear through: the write that blocked it has
    /// since been confirmed.
    pub(super) fn unblock_journal(&mut self) {
        self.journal_blocked = false;
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
