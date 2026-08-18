//! The per-computer lifecycle actor: sole owner of one computer's state
//! machine, and the only thing that executes its effects.
//!
//! One actor task per computer. Manager verbs arrive as [`Command`]s on an
//! `mpsc`; the slow flows run in sub-tasks ([`ComputerTasks`]) whose
//! epoch-tagged completions come back on a second channel; the public state
//! is published on a `watch` no reader has to wait for. Same shape, and
//! deliberately the same idiom, as `arcbox-engine`'s `vm_lifecycle::actor`.
//!
//! Three properties are why it exists at all:
//!
//! - **A force-remove preempts an in-flight boot.** The mailbox replaces the
//!   per-computer cleanup lock, which had no preemption: a Remove issued
//!   during a capture waited for the capture. The slow work lives in
//!   sub-tasks precisely so [`Effect::AbortInflight`] can cancel one —
//!   bounded by the boot's own resource handoff (see [`Self::abort_inflight`]).
//! - **The data plane never round-trips the mailbox.** The guest agent rides
//!   the [`ComputerSnapshot`], so exec and the file verbs read it lock-free
//!   and call the guest directly. An actor hop per exec would be a latency
//!   regression measured against the cold-start baselines.
//! - **The timers are the actor's own.** A per-computer actor *is* the
//!   generation, so the epoch-stamped timer slots and `Weak` staleness checks
//!   a detached expiry task needed collapse into two `Sleep`s in the select
//!   loop.
//!
//! What the machine deliberately does not carry, the actor does: an event's
//! attributes (the PAUSING reason, the FAILED error, the IDLE exit code), the
//! parked replies, and the failure text a durable `Failed` write records.
//!
//! Nothing constructs one yet: R3 PR-F1 lands the actor and moves the flow
//! bodies onto [`ComputerTasks`] one file at a time; PR-F2 flips the manager
//! onto it and implements the port.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use statig::blocking::IntoStateMachineExt;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::debug;
use uuid::Uuid;

use super::effect::{
    Answer, Durability, Effect, Effects, Notify, RecordEnd, ReleaseScope, Timer, Unconfirmed,
};
use super::event::{Event, PauseReason, Provision};
use super::machine::{ComputerLifecycle, State};
use super::tasks::{ComputerTasks, TaskFailure};
use crate::agent::{ExitStatus, GuestAgent};
use crate::error::{Result, VmmError};
use crate::sandbox::policy::deadlines;
use crate::sandbox::record::{
    PersistPhase, SandboxProvisionOutcome, SandboxRecordStore, SandboxTransition,
};
use crate::sandbox::types::action;
use crate::sandbox::workload::WorkloadClaim;
use crate::sandbox::{IdleAction, SandboxEvent, SandboxId, SandboxState};

mod commands;
mod effects;
mod inflight;

/// How long a teardown waits for an in-flight boot to hand its resources over
/// before giving up and retrying. Until that signal the task owns resources
/// the computer does not, so aborting it would strand them.
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);
/// Backoff bounds for a teardown that could not take the handoff. Mirrors
/// `cleanup::TTL_REMOVE_RETRY_*`; PR-F2 puts them on the injected `Clock`.
const RETRY_INITIAL: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(5);

/// A parked caller.
type Reply = oneshot::Sender<Result<()>>;

/// A verb addressed to one computer.
pub(super) enum Command {
    /// Drive the provisioned computer's first flow. A cold boot is answered
    /// as soon as it is under way (`create` returns `starting`); a restore is
    /// answered by READY, which is what its caller waits for.
    Provision {
        provision: Provision,
        outcome: SandboxProvisionOutcome,
        reply: Reply,
    },
    /// Capture a user checkpoint; answered with the catalog id.
    Checkpoint {
        reply: oneshot::Sender<Result<String>>,
    },
    Pause {
        reason: PauseReason,
        reply: Reply,
    },
    Resume {
        /// Surfaced verbatim as the RESUMED event's reason
        /// (`sandbox::pause_reason`).
        reason: String,
        reply: Reply,
    },
    Stop {
        budget: Duration,
        reply: Reply,
    },
    Remove {
        force: bool,
        reply: Reply,
    },
    /// Take the single-workload slot.
    ClaimWorkload {
        claim: WorkloadClaim,
        reply: Reply,
    },
    /// The workload's exit chunk arrived.
    WorkloadExited {
        status: ExitStatus,
    },
    /// Replace the deadline policy (`SetLifecycle`, CORE-60).
    SetLifecycle {
        deadlines: Deadlines,
        reply: Reply,
    },
    /// The guest went away without being asked to.
    VmExited,
}

/// The deadline policy of one computer: the hard lifetime cap, and the idle
/// window with the action it fires.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Deadlines {
    pub(super) ttl: Option<DateTime<Utc>>,
    pub(super) idle_timeout_seconds: u32,
    pub(super) on_idle: IdleAction,
}

/// What a read of a computer sees without touching the mailbox.
///
/// [`Self::agent`] is the point (§B.6 of the R3 plan): it is present exactly
/// while the guest is dialable, so exec, the file verbs and the workload path
/// take it from here and call the guest directly rather than asking the actor
/// for it. PR-F2 grows this into the full read path (the lease, the
/// timestamps, the pause state) as the manager's instance dies.
#[derive(Clone, Default)]
pub(super) struct ComputerSnapshot {
    /// `None` until the actor has published its first state.
    pub(super) state: Option<SandboxState>,
    pub(super) agent: Option<Arc<dyn GuestAgent>>,
    pub(super) error: Option<String>,
}

/// A sub-task's outcome, tagged with the epoch of the task that produced it.
///
/// `JoinHandle::abort` is best-effort: a task that had already finished and
/// enqueued its outcome is unaffected, so a completion from a superseded task
/// can still be sitting in the channel after a force-remove. The actor bumps
/// its epoch on every spawn and abort and drops completions that do not match.
struct Completion {
    epoch: u64,
    report: Report,
}

/// What a completed sub-task tells the actor.
enum Report {
    Booted(Arc<dyn GuestAgent>),
    Restored(Arc<dyn GuestAgent>, SandboxProvisionOutcome),
    Resumed(Arc<dyn GuestAgent>),
    Gated,
    Captured(String),
    Released(ReleaseScope),
    Stopped,
    Failed(TaskFailure),
}

/// The in-flight sub-task.
struct Preemptible {
    handle: JoinHandle<()>,
    handoff: Handoff,
}

/// What a teardown may do to the sub-task it preempts.
///
/// The distinction is which side owns the resources the task allocated. Only
/// the boot hands them over mid-flight, which is what makes it abortable at
/// all; the flows that keep theirs in locals until they commit unwind them
/// themselves, and aborting one drops that unwind on the floor — a
/// `CowHandle` has no `Drop`, and a `NetworkLease` is owed back to the pool
/// from `reserve` on.
enum Handoff {
    /// The task signals once every cleanup resource is the computer's; until
    /// then an abort would strand one, so the teardown waits for the signal
    /// (and stalls if it does not come). The boot's `resource_handoff`.
    Awaited(oneshot::Receiver<()>),
    /// Nothing the computer would have to reclaim: abortable at will.
    Abortable,
    /// The task unwinds what it allocated itself, out of locals nothing else
    /// can see, so it is joined rather than aborted — restore and resume,
    /// which nothing can preempt today either.
    JoinOnly,
}

/// A teardown parked behind a handoff that has not landed yet.
struct Stalled {
    state: State,
    effects: Vec<Effect>,
}

/// Whether the effect drain may continue.
#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Stalled,
}

/// The lifecycle actor.
pub(super) struct ComputerActor {
    id: SandboxId,
    /// The durable record's generation, `None` for a computer with no record
    /// — the durable effects are then no-ops, as they are today.
    generation: Option<Uuid>,
    vm_dir: PathBuf,
    records: Arc<SandboxRecordStore>,
    events_tx: broadcast::Sender<SandboxEvent>,
    tasks: Arc<dyn ComputerTasks>,
    commands: mpsc::UnboundedReceiver<Command>,
    completions_tx: mpsc::UnboundedSender<Completion>,
    completions: mpsc::UnboundedReceiver<Completion>,
    snapshot_tx: watch::Sender<ComputerSnapshot>,
    /// Effect sink handed to every dispatch as the statig context.
    effects: Effects,
    /// Events an effect asked for, dispatched in order once the current
    /// drain ends: a refused durable write fails the flow that asked for it.
    queued: VecDeque<Event>,
    waiters: Vec<(Answer, Reply)>,
    capture_reply: Option<oneshot::Sender<Result<String>>>,
    /// A graceful stop asked for while a launch was in flight, dispatched as
    /// soon as the launch resolves. Today's `stop_sandbox` answers
    /// `WrongState` there; deferring is what the engine's actor does and what
    /// the R3 plan specifies (§B.3).
    pending_stop: Option<Duration>,
    inflight: Option<Preemptible>,
    epoch: u64,
    /// The teardown parked behind a handoff, replayed when a retry takes it.
    /// This is `cleanup::expire_sandbox`'s retry loop, collapsed into the
    /// actor: the handoff is the only transient failure a removal has.
    stalled: Option<Stalled>,
    retry_backoff: Duration,
    /// The reason of the failure being recorded, for the durable `Failed`
    /// write and the FAILED event.
    error: Option<String>,
    /// The pause checkpoint the durable `Paused` write names.
    pause_snapshot_id: Option<String>,
    /// The provision outcome the `Starting` and atomic-`Ready` writes carry.
    outcome: SandboxProvisionOutcome,
    /// Attributes of the events a transition asks for.
    pause_reason: PauseReason,
    resume_reason: String,
    exit_status: Option<ExitStatus>,
    /// A visible-but-unconfirmed durable write, reported to the next caller
    /// the flow answers.
    unconfirmed: Option<String>,
    /// A step of the flow that failed loudly without stopping it — a
    /// panicked sub-task — reported to the caller its answer reaches.
    answer_error: Option<String>,
    /// A journal clear owed to a release that is still running: the journal
    /// records exactly the resources a restart would have to reclaim, so it
    /// may only be dropped once they are gone.
    clear_journal_after_release: bool,
    /// Set when a `GateJournal` write did not confirm: the journal then stays,
    /// which is what the gate exists for.
    journal_blocked: bool,
    deadlines: Deadlines,
    ttl: Option<Pin<Box<tokio::time::Sleep>>>,
    idle: Option<Pin<Box<tokio::time::Sleep>>>,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
    /// `false` keeps both deadline timers unarmed: a manager that was never
    /// shared (`SandboxManager::into_shared`) fires no timers, which unit
    /// tests of unrelated surfaces rely on.
    timers_enabled: watch::Receiver<bool>,
}

/// What one actor is built from.
pub(super) struct ComputerSeed {
    pub(super) id: SandboxId,
    pub(super) generation: Option<Uuid>,
    pub(super) vm_dir: PathBuf,
    pub(super) records: Arc<SandboxRecordStore>,
    pub(super) events_tx: broadcast::Sender<SandboxEvent>,
    pub(super) tasks: Arc<dyn ComputerTasks>,
    pub(super) deadlines: Deadlines,
    pub(super) timers_enabled: watch::Receiver<bool>,
}

impl ComputerActor {
    pub(super) fn new(
        seed: ComputerSeed,
        commands: mpsc::UnboundedReceiver<Command>,
        snapshot_tx: watch::Sender<ComputerSnapshot>,
    ) -> Self {
        let (completions_tx, completions) = mpsc::unbounded_channel();
        Self {
            id: seed.id,
            generation: seed.generation,
            vm_dir: seed.vm_dir,
            records: seed.records,
            events_tx: seed.events_tx,
            tasks: seed.tasks,
            commands,
            completions_tx,
            completions,
            snapshot_tx,
            effects: Effects::default(),
            queued: VecDeque::new(),
            waiters: Vec::new(),
            capture_reply: None,
            pending_stop: None,
            inflight: None,
            epoch: 0,
            stalled: None,
            retry_backoff: RETRY_INITIAL,
            error: None,
            pause_snapshot_id: None,
            outcome: SandboxProvisionOutcome::default(),
            pause_reason: PauseReason::Requested,
            resume_reason: crate::sandbox::pause_reason::RESUME.to_owned(),
            exit_status: None,
            unconfirmed: None,
            answer_error: None,
            clear_journal_after_release: false,
            journal_blocked: false,
            deadlines: seed.deadlines,
            ttl: None,
            idle: None,
            retry: None,
            timers_enabled: seed.timers_enabled,
        }
    }

    /// Runs until the computer is gone or every command sender is dropped.
    pub(super) async fn run(mut self) {
        let mut machine = ComputerLifecycle
            .uninitialized_state_machine()
            .init_with_context(&mut self.effects);
        drop(self.effects.take());
        self.publish_state(*machine.state());

        loop {
            tokio::select! {
                command = self.commands.recv() => {
                    let Some(command) = command else { break };
                    self.on_command(&mut machine, command).await;
                }
                Some(completion) = self.completions.recv() => {
                    self.on_completion(&mut machine, completion).await;
                }
                landed = handoff(&mut self.inflight) => {
                    // The signal is consumed either way — a producer that
                    // ended without it cannot send it later — but what that
                    // leaves behind differs. Signalled: the resources are
                    // the computer's and the task is abortable. Dropped: the
                    // task is on its own failure path, tearing down what it
                    // never handed over, and must be joined rather than cut
                    // short (`cancel_and_join_boot`'s middle arm).
                    if let Some(task) = self.inflight.as_mut() {
                        task.handoff = if landed {
                            Handoff::Abortable
                        } else {
                            Handoff::JoinOnly
                        };
                    }
                    if landed {
                        self.dispatch(&mut machine, Event::ResourcesHandedOff).await;
                    }
                }
                () = due(&mut self.ttl) => {
                    self.ttl = None;
                    self.dispatch(&mut machine, Event::TtlExpired).await;
                }
                () = due(&mut self.idle) => {
                    self.idle = None;
                    let action = self.deadlines.on_idle;
                    self.dispatch(&mut machine, Event::IdleExpired { action }).await;
                }
                () = due(&mut self.retry) => {
                    self.retry = None;
                    self.resume_stalled().await;
                }
                Ok(()) = self.timers_enabled.changed() => self.rearm(*machine.state()),
            }
            if matches!(machine.state(), State::Gone {}) {
                break;
            }
        }

        if let Some(task) = self.inflight.take() {
            task.handle.abort();
        }
        // A caller parked on an answer this computer will never give — a
        // stop deferred behind a launch a removal then preempted, say —
        // would otherwise learn only that its channel closed.
        for (_, reply) in self.waiters.drain(..) {
            let _ = reply.send(Err(VmmError::NotFound(self.id.clone())));
        }
        if let Some(reply) = self.capture_reply.take() {
            let _ = reply.send(Err(VmmError::NotFound(self.id.clone())));
        }
    }

    /// Dispatches one event, publishes the new public state, and executes the
    /// effects the transition emitted. Returns whether the machine acted:
    /// `Handled` with no effects is the machine saying it has nothing to do,
    /// and what the caller is then told is the actor's decision.
    async fn dispatch(&mut self, machine: &mut Machine, event: Event) -> bool {
        let before = *machine.state();
        machine.handle_with_context(&event, &mut self.effects);
        let after = *machine.state();
        let effects = self.effects.take();
        let acted = !effects.is_empty() || before != after;

        if before.to_public() != after.to_public() {
            debug!(
                sandbox_id = %self.id,
                from = %before.to_public(),
                to = %after.to_public(),
                "computer lifecycle transition"
            );
            self.publish_state(after);
        }
        let mut effects = effects.into_iter();
        while let Some(effect) = effects.next() {
            if self.apply(effect, after).await == Flow::Stalled {
                self.stalled = Some(Stalled {
                    state: after,
                    effects: effects.collect(),
                });
                break;
            }
        }
        while let Some(queued) = self.queued.pop_front() {
            Box::pin(self.dispatch(machine, queued)).await;
        }
        acted
    }
}

/// The initialized machine the actor drives.
type Machine = statig::blocking::InitializedStateMachine<ComputerLifecycle>;

/// Awaits the in-flight task's resource handoff, staying pending when there is
/// none to wait for. `false` means the producer ended without signalling.
async fn handoff(inflight: &mut Option<Preemptible>) -> bool {
    match inflight.as_mut().map(|task| &mut task.handoff) {
        Some(Handoff::Awaited(signal)) => signal.await.is_ok(),
        _ => std::future::pending().await,
    }
}

/// Whether this state's launch is still in flight. A stop asked for here is
/// deferred until it resolves rather than refused — and it is the machine's
/// state that says so, not the public projection: a gate whose initial `cmd`
/// has claimed the workload slot already reads `Running`.
const fn launching(state: State) -> bool {
    matches!(
        state,
        State::Provisioning {}
            | State::Staging {}
            | State::Booting {}
            | State::Restoring { .. }
            | State::Gating { .. }
            | State::Resuming {}
    )
}

/// Awaits an optional deadline, staying pending while unarmed.
async fn due(timer: &mut Option<Pin<Box<tokio::time::Sleep>>>) {
    match timer {
        Some(sleep) => sleep.as_mut().await,
        None => std::future::pending().await,
    }
}
