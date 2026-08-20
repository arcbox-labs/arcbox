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

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
pub use super::event::PauseReason;
use super::event::{Event, Provision};
use super::machine::{ComputerLifecycle, State};
use super::tasks::{CaptureSpec, ComputerTasks, Drain, TaskFailure};
use arcbox_vm_driver::VmHandle;
use arcbox_vm_driver::net::NetworkLease;

use crate::agent::{ExitStatus, GuestAgent};
use crate::error::{Result, VmmError};
use crate::lifecycle::runtime::ComputerRuntime;
use crate::sandbox::policy::deadlines;
use crate::sandbox::record::{
    PersistPhase, SandboxProvisionOutcome, SandboxRecordStore, SandboxTransition,
};
use crate::sandbox::types::action;
use crate::sandbox::workload::WorkloadClaim;
use crate::sandbox::{
    CheckpointInfo, IdleAction, LifecycleUpdate, SandboxEvent, SandboxId, SandboxState,
};

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

/// One computer's mailbox: the only way to ask its actor for anything.
///
/// A closed mailbox means the computer is gone — the actor's loop ends only
/// once its record has been forgotten, or once the last sender was dropped
/// without the reservation being committed — so both failures answer
/// `NotFound`, which is what a caller racing a removal is told today.
#[derive(Clone)]
pub struct Mailbox(mpsc::UnboundedSender<Command>);

impl Mailbox {
    pub(crate) fn new(sender: mpsc::UnboundedSender<Command>) -> Self {
        Self(sender)
    }

    /// Asks the actor for something and waits for its answer.
    pub(crate) async fn ask<T>(
        &self,
        id: &SandboxId,
        command: impl FnOnce(oneshot::Sender<Result<T>>) -> Command,
    ) -> Result<T> {
        let (reply, answer) = oneshot::channel();
        self.0
            .send(command(reply))
            .map_err(|_| VmmError::NotFound(id.clone()))?;
        answer.await.map_err(|_| VmmError::NotFound(id.clone()))?
    }

    /// Tells the actor something it does not answer.
    pub(crate) fn tell(&self, command: Command) {
        let _ = self.0.send(command);
    }

    /// A handle that does **not** keep the actor alive, for the flows the
    /// actor itself spawns: a sub-task holding a live sender would make its
    /// own computer unstoppable.
    pub(crate) fn downgrade(&self) -> WeakMailbox {
        WeakMailbox(self.0.downgrade())
    }
}

/// A [`Mailbox`] that does not keep its actor running. See
/// [`Mailbox::downgrade`].
#[derive(Clone)]
pub struct WeakMailbox(mpsc::WeakUnboundedSender<Command>);

impl WeakMailbox {
    pub(crate) fn upgrade(&self) -> Option<Mailbox> {
        self.0.upgrade().map(Mailbox)
    }
}

/// A verb addressed to one computer.
pub enum Command {
    /// Drive the provisioned computer's first flow. A cold boot is answered
    /// as soon as it is under way (`create` returns `starting`); a restore is
    /// answered by READY, which is what its caller waits for.
    Provision {
        provision: Provision,
        outcome: SandboxProvisionOutcome,
        reply: Reply,
    },
    /// Capture a user checkpoint; answered with the catalog entry.
    Checkpoint {
        spec: CaptureSpec,
        reply: oneshot::Sender<Result<CheckpointInfo>>,
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
    /// The workload ended.
    WorkloadExited {
        outcome: WorkloadOutcome,
    },
    /// The dispatch a claim was taken for failed, so the slot goes back
    /// without a workload having run.
    ReleaseWorkload,
    /// Adjust the deadline policy (`SetLifecycle`, CORE-60).
    ///
    /// The *patch*, not the resolved value: two concurrent partial updates
    /// that each read the current policy and sent a whole one would have the
    /// second undo the first's field, which `None means unchanged` promises
    /// it does not. Resolved in the actor, where they are serialized.
    SetLifecycle {
        update: LifecycleUpdate,
        reply: Reply,
    },
    /// The guest went away without being asked to.
    VmExited,
}

/// How a workload ended: with a status, or with its session broken before
/// one arrived. `execution::run_session`'s two branches; both leave the
/// computer idle, and only the attributes of the IDLE event differ.
#[derive(Debug, Clone)]
pub enum WorkloadOutcome {
    Exited(ExitStatus),
    Broke(String),
}

/// The deadline policy of one computer: the hard lifetime cap, and the idle
/// window with the action it fires.
#[derive(Debug, Clone, Copy, Default)]
pub struct Deadlines {
    pub ttl: Option<DateTime<Utc>>,
    pub idle_timeout_seconds: u32,
    pub on_idle: IdleAction,
}

/// What a read of a computer sees without touching the mailbox.
///
/// The whole read path — `inspect`, `list`, the network identity, the handle
/// a graceful exit hands over — is a fold over these, so no reader waits on a
/// mailbox and no reader takes a lock a lifecycle transition also needs. The
/// actor is the only writer, and it republishes after every transition and
/// every sub-task completion.
///
/// [`Self::agent`] is the sharpest edge of that (§B.6 of the R3 plan): it is
/// present exactly while the guest is dialable, so exec and the file verbs
/// take it from here and call the guest directly rather than asking the actor
/// for it.
#[derive(Clone)]
pub struct ComputerSnapshot {
    pub state: SandboxState,
    pub agent: Option<Arc<dyn GuestAgent>>,
    /// The running VM, for the graceful hand-over a process exit does.
    pub handle: Option<Arc<dyn VmHandle>>,
    pub error: Option<String>,
    pub labels: HashMap<String, String>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub lease: Option<NetworkLease>,
    pub vm_dir: PathBuf,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub last_exited_at: Option<DateTime<Utc>>,
    pub last_exit_status: Option<ExitStatus>,
    pub paused_at: Option<DateTime<Utc>>,
    pub pause_snapshot_id: Option<String>,
    /// The live dm-snapshot overlay file, while the computer holds one.
    ///
    /// Carried on the snapshot because storage accounting must read it
    /// lock-free: a computer that adopted a pre-warmed slot (CORE-78) keeps
    /// its overlay under the slot's name until pause renames it, so the
    /// path cannot be derived from the sandbox id alone. `None` in copy
    /// mode and once pause has detached the overlay.
    pub cow_file: Option<PathBuf>,
    pub deadlines: Deadlines,
}

impl ComputerSnapshot {
    /// The read view of `runtime` in `state`, under `deadlines`.
    ///
    /// Everything but the agent, which the actor publishes and withdraws
    /// with the guest's reachability rather than reading it off the runtime.
    pub fn project(runtime: &ComputerRuntime, state: SandboxState, deadlines: Deadlines) -> Self {
        Self {
            state,
            agent: None,
            handle: runtime.handle.clone(),
            error: runtime.error.clone(),
            labels: runtime.labels.clone(),
            vcpus: runtime.spec.vcpus,
            memory_mib: runtime.spec.memory_mib,
            lease: runtime.network.clone(),
            vm_dir: runtime.vm_dir.clone(),
            created_at: runtime.created_at,
            ready_at: runtime.ready_at,
            last_exited_at: runtime.last_exited_at,
            last_exit_status: runtime.last_exit_status,
            paused_at: runtime.paused_at,
            pause_snapshot_id: runtime.pause_snapshot_id.clone(),
            cow_file: runtime
                .cow_handle
                .as_ref()
                .map(|handle| handle.cow_file.clone()),
            deadlines,
        }
    }
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
    Captured(CheckpointInfo),
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

/// A teardown parked on a step that could not complete yet: the rest of its
/// effects, and the step to retry first.
struct Stalled {
    retry: StalledStep,
    state: State,
    effects: Vec<Effect>,
}

/// What a stalled teardown is waiting on.
enum StalledStep {
    /// The in-flight sub-task has not handed its resources over.
    Handoff,
    /// The durable record would not delete. Until it does, the id is still
    /// owned — `remove_sandbox_impl` propagates that failure rather than
    /// dropping its map entry, because only a retry can free the id.
    Record(RecordEnd),
}

/// Whether the effect drain may continue.
#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    /// Parked on a step that has not finished; the rest is replayed when a
    /// retry takes it.
    Stalled,
    /// A required step was refused. The rest of the transition is abandoned
    /// — it described work that must not happen without it.
    Refused,
}

/// The lifecycle actor.
pub struct ComputerActor {
    id: SandboxId,
    /// The resources this computer holds, shared with the sub-tasks the
    /// actor spawns. The actor is the only other writer: it mirrors the
    /// public state into it, records the workload's exit, and projects the
    /// read snapshot from it.
    runtime: Arc<Mutex<ComputerRuntime>>,
    /// Drops this computer's registry entry. Called when the record is
    /// forgotten, before REMOVED is announced — `remove_sandbox_impl`'s own
    /// order — and again when the actor stops for any other reason.
    unregister: Arc<dyn Fn() + Send + Sync>,
    /// The durable record's generation, `None` for a computer with no record
    /// — the durable effects are then no-ops, as they are today.
    generation: Option<Uuid>,
    vm_dir: PathBuf,
    records: Arc<SandboxRecordStore>,
    events_tx: broadcast::Sender<SandboxEvent>,
    tasks: Arc<dyn ComputerTasks>,
    seeded: Seeded,
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
    capture_reply: Option<oneshot::Sender<Result<CheckpointInfo>>>,
    /// A graceful stop asked for while a launch was in flight, dispatched as
    /// soon as the launch resolves. Today's `stop_sandbox` answers
    /// `WrongState` there; deferring is what the engine's actor does and what
    /// the R3 plan specifies (§B.3).
    pending_stop: Option<Duration>,
    inflight: Option<Preemptible>,
    epoch: u64,
    /// The teardown parked on a step it could not finish, replayed when a
    /// retry takes it. This is `cleanup::expire_sandbox`'s retry loop,
    /// collapsed into the actor.
    stalled: Option<Stalled>,
    /// What the step currently being applied stalled on, read by
    /// [`Self::park_stalled`].
    stalled_on: StalledStep,
    retry_backoff: Duration,
    /// The reason of the failure being recorded, for the durable `Failed`
    /// write and the FAILED event.
    error: Option<String>,
    /// The pause checkpoint the durable `Paused` write names.
    pause_snapshot_id: Option<String>,
    /// What the capture the actor is about to spawn records. `None` is the
    /// pause's own, which names itself.
    capture: Option<CaptureSpec>,
    /// The provision outcome the `Starting` and atomic-`Ready` writes carry.
    outcome: SandboxProvisionOutcome,
    /// Attributes of the events a transition asks for.
    pause_reason: PauseReason,
    resume_reason: String,
    exit: Option<WorkloadOutcome>,
    /// A visible-but-unconfirmed durable write, reported to the next caller
    /// the flow answers.
    unconfirmed: Option<String>,
    /// A step of the flow that failed loudly without stopping it — a
    /// panicked sub-task — reported to the caller its answer reaches.
    answer_error: Option<String>,
    /// The failure a removal is unwinding, held until that removal ends.
    /// Its caller must not hear before the id is free again.
    unwinding: Option<VmmError>,
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

/// How a computer's machine starts.
///
/// A fresh one is provisioned by its caller. The other two are the startup
/// sweep's: `Recovered` adopts the phase recovery left in the record, and
/// `Adopted` is the computer whose VM the sweep took back — already usable,
/// having never booted in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seeded {
    Fresh,
    Recovered(PersistPhase),
    Adopted,
}

/// What one actor is built from.
pub struct ComputerSeed {
    pub id: SandboxId,
    pub runtime: Arc<Mutex<ComputerRuntime>>,
    pub unregister: Arc<dyn Fn() + Send + Sync>,
    pub generation: Option<Uuid>,
    pub vm_dir: PathBuf,
    pub records: Arc<SandboxRecordStore>,
    pub events_tx: broadcast::Sender<SandboxEvent>,
    pub tasks: Arc<dyn ComputerTasks>,
    pub deadlines: Deadlines,
    pub timers_enabled: watch::Receiver<bool>,
    pub seeded: Seeded,
}

impl ComputerActor {
    pub fn new(
        seed: ComputerSeed,
        commands: mpsc::UnboundedReceiver<Command>,
        snapshot_tx: watch::Sender<ComputerSnapshot>,
    ) -> Self {
        let (completions_tx, completions) = mpsc::unbounded_channel();
        Self {
            id: seed.id,
            runtime: seed.runtime,
            unregister: seed.unregister,
            generation: seed.generation,
            vm_dir: seed.vm_dir,
            records: seed.records,
            events_tx: seed.events_tx,
            tasks: seed.tasks,
            seeded: seed.seeded,
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
            stalled_on: StalledStep::Handoff,
            retry_backoff: RETRY_INITIAL,
            error: None,
            pause_snapshot_id: None,
            capture: None,
            outcome: SandboxProvisionOutcome::default(),
            pause_reason: PauseReason::Requested,
            resume_reason: crate::sandbox::pause_reason::RESUME.to_owned(),
            exit: None,
            unconfirmed: None,
            answer_error: None,
            unwinding: None,
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
    pub async fn run(mut self) {
        let mut machine = ComputerLifecycle
            .uninitialized_state_machine()
            .init_with_context(&mut self.effects);
        drop(self.effects.take());
        self.publish_state(*machine.state());
        // The sweep's computers start where recovery left them, and their
        // deadlines are re-armed from the record — `resync_lifecycle_timers`
        // after the startup sweep, without the epoch-stamped slots it needed
        // to tell a stale timer from a live one.
        match self.seeded {
            Seeded::Fresh => {}
            Seeded::Recovered(phase) => {
                self.dispatch(&mut machine, Event::Recovered { phase })
                    .await;
            }
            Seeded::Adopted => {
                // Published before the state, so no reader ever sees a
                // `Ready` computer it cannot dial.
                if let Some(agent) = self.tasks.adopted_agent() {
                    self.publish_agent(agent);
                }
                self.dispatch(&mut machine, Event::Adopted).await;
            }
        }
        self.rearm(*machine.state());

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
                    // An idle pause reports itself as one: the PAUSING event's
                    // reason is how a client tells the detector's pause from a
                    // client's, and only the expiry knows which this is.
                    if matches!(action, IdleAction::Pause) {
                        self.pause_reason = PauseReason::IdleTimeout;
                    }
                    self.dispatch(&mut machine, Event::IdleExpired { action }).await;
                }
                () = due(&mut self.retry) => {
                    self.retry = None;
                    self.resume_stalled().await;
                }
                Ok(()) = self.timers_enabled.changed() => self.rearm(*machine.state()),
            }
            // A computer whose record would not delete is not gone yet: its
            // id is still owned, and the retry below is what frees it.
            if matches!(machine.state(), State::Gone {}) && self.stalled.is_none() {
                break;
            }
        }

        if let Some(task) = self.inflight.take() {
            task.handle.abort();
        }
        // Whatever stopped this actor — its record forgotten, or the last
        // sender dropped by a reservation nobody committed — nothing can
        // reach the computer through the registry any more.
        (self.unregister)();
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
        }
        // Before the drain, because a sub-task an effect spawns reads the
        // public state off the runtime — the checkpoint's precondition, and
        // the boot's cooperative teardown check.
        self.publish_state(after);
        let mut effects = effects.into_iter();
        while let Some(effect) = effects.next() {
            match self.apply(effect, after).await {
                Flow::Continue => {}
                Flow::Stalled => {
                    self.park_stalled(after, effects.collect());
                    break;
                }
                // Dropped, not parked: a `Resuming` write that was refused
                // must not be followed by the resume it was recording, and a
                // refused `Stopping` must not be followed by the shutdown.
                Flow::Refused => break,
            }
        }
        // And after it, because the effects themselves write to the runtime
        // — what a pause retained, the failure text — and a caller answered
        // by one of them reads the snapshot the moment it returns.
        self.publish_state(after);
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
