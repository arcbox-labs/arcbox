//! The computer lifecycle as a `statig` hierarchical state machine: the
//! transition table itself. The hierarchy, the effect discipline and what the
//! actor answers rather than the machine are in the module docs.

use statig::prelude::*;

use super::effect::{
    Answer, Durability, Effect, Effects, Notify, RecordEnd, ReleaseScope, Timer, Unconfirmed,
};
use super::event::{Event, PauseReason, Provision, RestoreOrigin};
use crate::sandbox::IdleAction;
use crate::sandbox::record::PersistPhase;
use crate::sandbox::workload::WorkloadClaim;

pub(super) type Outcome = statig::Outcome<State>;

/// Zero-sized `statig` shared storage: every durable value lives on the actor
/// and transition outputs flow through [`Effects`].
#[derive(Debug, Default)]
pub(super) struct ComputerLifecycle;

#[state_machine(
    initial = "State::provisioning()",
    state(derive(Debug, Clone, Copy, PartialEq, Eq)),
    superstate(derive(Debug))
)]
impl ComputerLifecycle {
    /// A forced `Remove` and the TTL cap destroy from anywhere; every failure
    /// class degrades to `failed` unless a state below claims it (a recoverable
    /// capture failure, a resume that unwound). The final arm swallows the
    /// rest: a command a state does not act on is the actor's to answer, and an
    /// observation nobody waits for is noise.
    #[superstate]
    fn computer(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            // A non-forced remove that reaches here passed the busy gate — the
            // states projecting Starting/Running refuse it below — so it does
            // exactly what a forced one does.
            Event::Remove { .. } | Event::TtlExpired => {
                context.removal();
                Transition(State::removing())
            }
            Event::Frozen | Event::Failure | Event::Stranded | Event::VmExited => {
                context.failure();
                Transition(State::failed())
            }
            _ => Handled,
        }
    }

    /// The durable intent (`Creating`) exists and nothing else does.
    #[state(superstate = "computer")]
    fn provisioning(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::Provision(Provision::Boot { warm }) => {
                context.persist(PersistPhase::Starting, Durability::Report(Unconfirmed::Ack));
                context.emit(Effect::SpawnBoot { warm: *warm });
                context.emit(Effect::Publish(Notify::Created));
                context.emit(Effect::ArmTimer(Timer::Ttl));
                Transition(State::staging())
            }
            // The restore path commits `ReadyWithOutcome` in one hop from
            // `Creating`, so it writes nothing on the way in. The origin
            // rides the state: it decides whether this restore owes the
            // Create event contract, and only the state is still around when
            // the restore reports back.
            Event::Provision(Provision::Restore { origin }) => {
                context.emit(Effect::SpawnRestore { origin: *origin });
                Transition(State::restoring(*origin))
            }
            Event::Failure => {
                context.emit(Effect::ForgetRecord(RecordEnd::Aborted));
                Transition(State::gone())
            }
            // Recovery already applied its own durable verdict
            // (`policy::recovery::plan`); the machine adopts what it left.
            Event::Recovered { phase } => match phase {
                PersistPhase::Creating => Handled,
                PersistPhase::Starting
                | PersistPhase::Ready
                | PersistPhase::Stopping
                | PersistPhase::Pausing
                | PersistPhase::Resuming
                | PersistPhase::Failed => Transition(State::failed()),
                PersistPhase::Stopped => Transition(State::stopped()),
                PersistPhase::Paused => Transition(State::paused()),
                PersistPhase::Removing => Transition(State::removing()),
            },
            // The sweep took the VM back with everything it was running on,
            // so this computer is usable from here without a launch — the
            // record already says `Ready` and recovery left it that way.
            Event::Adopted => Transition(State::ready()),
            Event::Remove { force: false } => Handled,
            _ => Super,
        }
    }

    /// Resources are being acquired but are still local to the boot task, so
    /// an abort could strand one: `ResourcesHandedOff` makes it abortable.
    #[state(superstate = "computer")]
    fn staging(event: &Event) -> Outcome {
        match event {
            Event::ResourcesHandedOff => Transition(State::booting()),
            Event::Remove { force: false } => Handled,
            _ => Super,
        }
    }

    #[superstate(superstate = "computer")]
    fn launching(event: &Event) -> Outcome {
        match event {
            // Already past staging; a duplicate signal is noise.
            Event::ResourcesHandedOff | Event::Remove { force: false } => Handled,
            _ => Super,
        }
    }

    #[state(superstate = "launching")]
    fn booting(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::AgentReady => {
                context.emit(Effect::SpawnGate);
                Transition(State::gating(false, false))
            }
            _ => Super,
        }
    }

    #[state(superstate = "launching")]
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "statig passes state-local storage by reference"
    )]
    fn restoring(origin: &RestoreOrigin, event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::Restored => {
                context.emit(Effect::CommitRestored {
                    durability: Durability::Report(Unconfirmed::Ack),
                });
                // The warm-create reroute owes the Create event contract:
                // a watcher sees CREATED then READY for this id, in that
                // order, exactly as a cold boot emits them. A Restore RPC
                // announces itself with READY alone.
                if matches!(origin, RestoreOrigin::WarmCreate) {
                    context.emit(Effect::Publish(Notify::Created));
                }
                context.emit(Effect::ArmTimer(Timer::Ttl));
                context.emit(Effect::SpawnGate);
                Transition(State::gating(true, false))
            }
            // A restore that fails before its commit is rolled back, not
            // failed in place: `rollback_restore` force-removes the record and
            // every artefact, so the id and its request key are free again and
            // a warm create can fall back to a cold boot. (Failing before any
            // resource exists is `abort_provision` today — the same end, one
            // durable write cheaper.) It force-removes either way, so a
            // stranded restore takes the same path.
            Event::Failure | Event::Stranded | Event::VmExited | Event::Frozen => {
                context.removal();
                Transition(State::removing())
            }
            _ => Super,
        }
    }

    /// The VM is up and READY is withheld: the warm publish freezes the guest
    /// and the initial `cmd` owns the workload slot, so a client acting on an
    /// early READY would hit a stopped guest or steal that slot.
    ///
    /// `claimed` is that slot: the boot's own `cmd` takes it here, *before*
    /// READY, and it must survive the gate — the workload it started is still
    /// running when READY lands, and its exit is what publishes IDLE.
    #[state(superstate = "computer")]
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "statig passes state-local storage by reference"
    )]
    fn gating(committed: &bool, claimed: &bool, event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::Gated => {
                // A cold boot commits `Ready` here, after the probe, so a
                // probe failure fails from the recorded `Starting`. A restore
                // committed it in one hop before the gate ran: writing it
                // again would put an fsync on the restore's hot path and could
                // refuse a computer that is already durably `Ready`.
                if !*committed {
                    context.persist(
                        PersistPhase::Ready,
                        Durability::Report(Unconfirmed::Unavailable),
                    );
                }
                context.emit(Effect::Publish(Notify::Ready));
                context.emit(Effect::Answer(Answer::Ready));
                if *claimed {
                    // READY announces a computer that is already running its
                    // own `cmd`: the idle window opens when that workload
                    // exits, not here.
                    Transition(State::running())
                } else {
                    context.emit(Effect::ArmTimer(Timer::Idle));
                    Transition(State::ready())
                }
            }
            // The slot is reserved for this boot's own `cmd` — an API claim
            // cannot reach a computer that has not announced READY, and a
            // second initial claim is the same one workload twice.
            Event::ClaimWorkload {
                claim: WorkloadClaim::Initial,
            } if !*claimed => {
                context.emit(Effect::Publish(Notify::Running));
                Transition(State::gating(*committed, true))
            }
            // The boot's own `cmd` can outlive neither the gate nor its own
            // exit: a ready probe still running when it finishes leaves the
            // computer idle, and READY then opens the idle window as it does
            // for a `cmd`-less boot.
            Event::WorkloadExited if *claimed => {
                context.emit(Effect::Publish(Notify::Idle));
                Transition(State::gating(*committed, false))
            }
            // The dispatch the claim was taken for failed: the slot goes
            // back, balancing the RUNNING the claim announced.
            Event::WorkloadReleased if *claimed => {
                context.emit(Effect::Publish(Notify::Idle));
                Transition(State::gating(*committed, false))
            }
            // A restore's gate runs *after* its atomic commit, so its failure
            // is unwound with the post-commit verb: force-remove, freeing the
            // id and its request key so a warm create can fall back to a cold
            // boot (`restore_from_snapshot`'s probe branch). A cold boot's
            // gate is pre-commit and parks at `failed` through `computer`.
            Event::Failure | Event::Frozen | Event::Stranded if *committed => {
                context.removal();
                Transition(State::removing())
            }
            Event::ClaimWorkload { .. } | Event::Remove { force: false } => Handled,
            _ => Super,
        }
    }

    /// The three states holding a settled live handle — which is exactly the
    /// set a handover can act on, and why `Detach` sits beside `Stop` here.
    #[superstate(superstate = "computer")]
    fn active(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::Stop { budget_ms } => {
                context.stop(*budget_ms, false);
                Transition(State::stopping())
            }
            // No transition: the port call decides. A handover that fails
            // leaves a computer that is still ours and still usable, so the
            // machine must not have moved off the state it came from.
            Event::Detach => {
                context.emit(Effect::Detach);
                Handled
            }
            Event::Detached => {
                context.emit(Effect::Answer(Answer::Detached));
                // The TTL and idle windows belong to whoever owns the VM, and
                // that is no longer this process; leaving them armed would have
                // an expiry tear down a guest the successor is adopting.
                context.emit(Effect::CancelTimer(Timer::Ttl));
                context.emit(Effect::CancelTimer(Timer::Idle));
                Transition(State::detached())
            }
            _ => Super,
        }
    }

    #[state(superstate = "active")]
    fn ready(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::ClaimWorkload { .. } => {
                context.emit(Effect::CancelTimer(Timer::Idle));
                context.emit(Effect::Publish(Notify::Running));
                Transition(State::running())
            }
            Event::Pause { .. } => {
                context.persist(PersistPhase::Pausing, Durability::Warn);
                context.emit(Effect::CancelTimer(Timer::Idle));
                context.emit(Effect::Publish(Notify::Pausing));
                context.emit(Effect::SpawnCheckpoint { hold: true });
                Transition(State::capturing())
            }
            Event::IdleExpired {
                action: IdleAction::Pause,
            } => Self::ready(
                &Event::Pause {
                    reason: PauseReason::IdleTimeout,
                },
                context,
            ),
            Event::IdleExpired {
                action: IdleAction::Kill,
            } => {
                context.removal();
                Transition(State::removing())
            }
            Event::Checkpoint => {
                context.emit(Effect::CancelTimer(Timer::Idle));
                context.emit(Effect::SpawnCheckpoint { hold: false });
                Transition(State::checkpointing())
            }
            _ => Super,
        }
    }

    /// The workload hot path: no record write, so a crash here reads `Ready`.
    #[state(superstate = "active")]
    fn running(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::WorkloadExited => {
                context.emit(Effect::Publish(Notify::Idle));
                context.emit(Effect::ArmTimer(Timer::Idle));
                Transition(State::ready())
            }
            // The claim announced RUNNING before the dispatch it was taken
            // for, so giving it back owes the balancing IDLE — a subscriber
            // must not be left believing a workload is running. It carries no
            // exit status, because nothing ran.
            Event::WorkloadReleased => {
                context.emit(Effect::Publish(Notify::Idle));
                context.emit(Effect::ArmTimer(Timer::Idle));
                Transition(State::ready())
            }
            // The only stop that has a workload to drain first.
            Event::Stop { budget_ms } => {
                context.stop(*budget_ms, true);
                Transition(State::stopping())
            }
            // One workload at a time, and neither pause nor checkpoint may
            // freeze a guest that is running one.
            Event::ClaimWorkload { .. }
            | Event::Pause { .. }
            | Event::Checkpoint
            | Event::IdleExpired { .. }
            | Event::Remove { force: false } => Handled,
            _ => Super,
        }
    }

    /// Holds `Ready` for the duration of a capture, closing the race where a
    /// `Run` claims the slot while the guest is frozen (`to_public` still
    /// answers `Ready`, so the wire is unchanged).
    #[state(superstate = "active")]
    fn checkpointing(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            // A recoverable capture failure leaves the guest running and the
            // computer usable; only `Frozen` degrades it, through `computer`.
            // Either way the idle window restarts: it is cancelled on the way
            // in, and the expiry swallowed below would otherwise be lost —
            // the timer is one-shot, so a computer that idled through a
            // checkpoint would never idle again.
            Event::CaptureDone { .. } | Event::Failure => {
                context.emit(Effect::ArmTimer(Timer::Idle));
                Transition(State::ready())
            }
            Event::ClaimWorkload { .. }
            | Event::Pause { .. }
            | Event::Checkpoint
            | Event::IdleExpired { .. } => Handled,
            _ => Super,
        }
    }

    /// A pause in flight is not interruptible: `Pausing` has no durable edge to
    /// `Stopping`, and the guest is on its way to being released.
    #[superstate(superstate = "computer")]
    fn suspending(event: &Event) -> Outcome {
        match event {
            Event::Stop { .. } => Handled,
            _ => Super,
        }
    }

    #[state(superstate = "suspending")]
    fn capturing(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::CaptureDone { .. } => {
                context.release(ReleaseScope::KeepDisk);
                Transition(State::releasing())
            }
            // Recoverable: the driver resumed the guest itself, so a failed
            // pause must leave a usable computer behind.
            Event::Failure => {
                context.persist(PersistPhase::Ready, Durability::Warn);
                context.emit(Effect::Publish(Notify::Ready));
                context.emit(Effect::ArmTimer(Timer::Idle));
                Transition(State::ready())
            }
            _ => Super,
        }
    }

    #[state(superstate = "suspending")]
    fn releasing(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::ReleasedForPause => {
                context.persist(PersistPhase::Paused, Durability::GateJournal);
                context.emit(Effect::ClearJournal);
                context.emit(Effect::Publish(Notify::Paused));
                context.emit(Effect::Answer(Answer::Paused));
                Transition(State::paused())
            }
            _ => Super,
        }
    }

    #[state(superstate = "computer")]
    fn paused(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::Resume => {
                context.persist(
                    PersistPhase::Resuming,
                    Durability::Report(Unconfirmed::RevertToPaused),
                );
                context.emit(Effect::SpawnResume);
                Transition(State::resuming())
            }
            // Idempotent.
            Event::Pause { .. } => Handled,
            _ => Super,
        }
    }

    #[state(superstate = "computer")]
    fn resuming(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::Restored => {
                context.persist(PersistPhase::Ready, Durability::Warn);
                context.emit(Effect::Publish(Notify::Resumed));
                context.emit(Effect::Answer(Answer::Resumed));
                context.emit(Effect::ArmTimer(Timer::Idle));
                Transition(State::ready())
            }
            // The restore unwound: retained state is intact, so park back at
            // `Paused` — which keeps its original `paused_at` — and let a retry
            // or a Remove work. A resume that could *not* unwind is
            // `Stranded` and falls through to `computer`, which fails the
            // computer: recording `Paused` for a half-allocated one would
            // have the restart sweep reinstate it as resumable and drop the
            // journal naming what it still holds.
            Event::Failure => {
                context.persist(PersistPhase::Paused, Durability::Warn);
                context.emit(Effect::Publish(Notify::Paused));
                Transition(State::paused())
            }
            Event::Remove { force: false } => Handled,
            _ => Super,
        }
    }

    #[state(superstate = "computer")]
    fn stopping(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::StopDone => {
                context.persist(PersistPhase::Stopped, Durability::GateJournal);
                context.emit(Effect::ClearJournal);
                context.emit(Effect::CancelTimer(Timer::Ttl));
                context.emit(Effect::Publish(Notify::Stopped));
                context.emit(Effect::Answer(Answer::Stopped));
                Transition(State::stopped())
            }
            // Expected: we asked for it.
            Event::VmExited => Handled,
            _ => Super,
        }
    }

    /// Nothing left to expire, nothing left to fail: only `Remove` acts.
    #[superstate(superstate = "computer")]
    fn resting(event: &Event) -> Outcome {
        match event {
            Event::TtlExpired
            | Event::IdleExpired { .. }
            | Event::VmExited
            | Event::Failure
            | Event::Stranded
            | Event::Frozen => Handled,
            _ => Super,
        }
    }

    #[state(superstate = "resting")]
    fn stopped() -> Outcome {
        Super
    }

    #[state(superstate = "resting")]
    fn failed() -> Outcome {
        Super
    }

    #[state(superstate = "computer")]
    fn removing(event: &Event, context: &mut Effects) -> Outcome {
        match event {
            Event::RemoveDone => {
                context.emit(Effect::ForgetRecord(RecordEnd::Removed));
                context.emit(Effect::Publish(Notify::Removed));
                context.emit(Effect::Answer(Answer::Removed));
                Transition(State::gone())
            }
            // Coalesce concurrent removals and anything the teardown trips.
            Event::Remove { .. }
            | Event::TtlExpired
            | Event::Failure
            | Event::Stranded
            | Event::Frozen
            | Event::VmExited => Handled,
            _ => Super,
        }
    }

    /// Handed to the next process: this one no longer owns the VM.
    ///
    /// Deliberately **not** under `computer`, unlike every other resting state.
    /// A `Remove` or a TTL expiry reaching that superstate would release TAP,
    /// the CoW device and the jail out from under a live guest the successor
    /// has adopted, and a `Stop` would drive `handle.shutdown` into a handle
    /// whose waiter has stood down — burning the budget and then SIGKILLing the
    /// VM that was just reported as handed over. Swallowing everything here is
    /// what makes the handover final. The record is left exactly as it was,
    /// which is what the successor's sweep adopts from.
    #[state]
    fn detached() -> Outcome {
        Handled
    }

    /// The record is forgotten; the actor is on its way out.
    #[state]
    fn gone() -> Outcome {
        Handled
    }
}
