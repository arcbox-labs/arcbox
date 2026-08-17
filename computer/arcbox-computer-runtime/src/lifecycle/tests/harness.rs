//! The scratch harness every lifecycle test drives the machine through, plus
//! the exhaustive walk the invariant tests are written against.

use statig::prelude::*;

use crate::lifecycle::effect::{Durability, Effect, Effects, ReleaseScope};
use crate::lifecycle::event::{Event, PauseReason, Provision, RestoreOrigin};
use crate::lifecycle::machine::{ComputerLifecycle, State};
use crate::sandbox::IdleAction;
use crate::sandbox::record::PersistPhase;
use crate::sandbox::workload::WorkloadClaim;

pub(super) type Machine = statig::blocking::InitializedStateMachine<ComputerLifecycle>;

pub(super) const BUDGET_MS: u64 = 30_000;

/// A durable write, as a test reads it back off the effect vector.
pub(super) fn persist(phase: PersistPhase, durability: Durability) -> Effect {
    Effect::PersistPhase { phase, durability }
}

pub(super) fn release(scope: ReleaseScope) -> Effect {
    Effect::SpawnRelease { scope }
}

pub(super) fn machine(context: &mut Effects) -> Machine {
    ComputerLifecycle
        .uninitialized_state_machine()
        .init_with_context(context)
}

/// Replays `events` from a fresh machine, discarding what they emitted.
pub(super) fn reach(events: &[Event]) -> (Machine, Effects) {
    let mut context = Effects::default();
    let mut sm = machine(&mut context);
    for event in events {
        sm.handle_with_context(event, &mut context);
    }
    context.take();
    (sm, context)
}

/// Dispatches `event`, returning the resulting state and its effects.
pub(super) fn step(sm: &mut Machine, context: &mut Effects, event: &Event) -> (State, Vec<Effect>) {
    sm.handle_with_context(event, context);
    (*sm.state(), context.take())
}

/// Every leaf, identified by an ordinal. The exhaustive match is what stops a
/// new state from being added without a row in the tables below.
pub(super) fn ordinal(state: State) -> usize {
    match state {
        State::Provisioning {} => 0,
        State::Staging {} => 1,
        State::Booting {} => 2,
        State::Restoring {} => 3,
        State::Gating {} => 4,
        State::Ready {} => 5,
        State::Running {} => 6,
        State::Checkpointing {} => 7,
        State::Capturing {} => 8,
        State::Releasing {} => 9,
        State::Paused {} => 10,
        State::Resuming {} => 11,
        State::Stopping {} => 12,
        State::Stopped {} => 13,
        State::Failed {} => 14,
        State::Removing {} => 15,
        State::Gone {} => 16,
    }
}

pub(super) const LEAVES: usize = 17;

/// One event of every shape the actor can deliver. `Recovered` is excluded:
/// it seeds a machine rather than moving one, and has its own table.
pub(super) fn alphabet() -> Vec<Event> {
    vec![
        Event::Provision(Provision::Boot { warm: false }),
        Event::Provision(Provision::Boot { warm: true }),
        Event::Provision(Provision::Restore {
            origin: RestoreOrigin::Restore,
        }),
        Event::Provision(Provision::Restore {
            origin: RestoreOrigin::WarmCreate,
        }),
        Event::ResourcesHandedOff,
        Event::AgentReady,
        Event::Restored,
        Event::Gated,
        Event::ClaimWorkload {
            claim: WorkloadClaim::Api,
        },
        Event::ClaimWorkload {
            claim: WorkloadClaim::Initial,
        },
        Event::WorkloadExited,
        Event::Checkpoint,
        Event::CaptureDone {
            snapshot_id: "snap".to_owned(),
        },
        Event::Pause {
            reason: PauseReason::Requested,
        },
        Event::Pause {
            reason: PauseReason::IdleTimeout,
        },
        Event::ReleasedForPause,
        Event::Resume,
        Event::Stop {
            budget_ms: BUDGET_MS,
        },
        Event::StopDone,
        Event::Remove { force: false },
        Event::Remove { force: true },
        Event::RemoveDone,
        Event::Failure,
        Event::Frozen,
        Event::VmExited,
        Event::TtlExpired,
        Event::IdleExpired {
            action: IdleAction::Kill,
        },
        Event::IdleExpired {
            action: IdleAction::Pause,
        },
    ]
}

pub(super) const ALL_PHASES: [PersistPhase; 10] = [
    PersistPhase::Creating,
    PersistPhase::Starting,
    PersistPhase::Ready,
    PersistPhase::Stopping,
    PersistPhase::Stopped,
    PersistPhase::Failed,
    PersistPhase::Removing,
    PersistPhase::Pausing,
    PersistPhase::Paused,
    PersistPhase::Resuming,
];

/// A reachable configuration: a state, the durable phase in effect there, and
/// the events that reach it.
#[derive(Debug, Clone)]
pub(super) struct Node {
    pub(super) state: State,
    pub(super) phase: Option<PersistPhase>,
    pub(super) path: Vec<Event>,
}

/// Walks every configuration reachable from a fresh machine and from each
/// recovery seeding, asserting as it goes that **every** durable write the
/// machine asks for is a legal move from the phase then in effect
/// (`sandbox::record::phase`'s edge set, the table PR-A pinned over all 30
/// pairs). A wrong `PersistPhase` on any edge fails here rather than as a
/// `WrongState` at runtime.
pub(super) fn explore() -> Vec<Node> {
    let mut queue: Vec<Node> = vec![Node {
        state: *reach(&[]).0.state(),
        phase: Some(PersistPhase::Creating),
        path: Vec::new(),
    }];
    // Recovery reconstructs a computer straight into a phase, so those states
    // are roots of their own rather than reachable from `provisioning`.
    for phase in ALL_PHASES {
        let path = vec![Event::Recovered { phase }];
        let (sm, _) = reach(&path);
        queue.push(Node {
            state: *sm.state(),
            phase: sm.state().durable(),
            path,
        });
    }

    let mut seen: Vec<(State, Option<PersistPhase>)> = Vec::new();
    let mut nodes: Vec<Node> = Vec::new();
    while let Some(node) = queue.pop() {
        if seen.contains(&(node.state, node.phase)) {
            continue;
        }
        seen.push((node.state, node.phase));
        nodes.push(node.clone());

        for event in alphabet() {
            let (mut sm, mut context) = reach(&node.path);
            let (state, effects) = step(&mut sm, &mut context, &event);
            let mut phase = node.phase;
            for effect in &effects {
                match effect {
                    Effect::PersistPhase { phase: next, .. } => {
                        let from = phase.expect("a durable write needs a record to write to");
                        assert!(
                            from.can_transition_to(*next),
                            "{:?} then {event:?}: {} -> {} is not a durable edge",
                            node.state,
                            from.as_str(),
                            next.as_str()
                        );
                        phase = Some(*next);
                    }
                    // The one move outside the edge set: `SandboxRecord::
                    // apply` waives it for `ReadyWithOutcome`, and only from
                    // `Creating`, so the machine must never emit it elsewhere.
                    Effect::CommitRestored { .. } => {
                        assert_eq!(
                            phase,
                            Some(PersistPhase::Creating),
                            "{:?} then {event:?}: an atomic Ready commit is only legal from Creating",
                            node.state
                        );
                        phase = Some(PersistPhase::Ready);
                    }
                    Effect::ForgetRecord(_) => phase = None,
                    _ => {}
                }
            }
            let mut path = node.path.clone();
            path.push(event);
            queue.push(Node { state, phase, path });
        }
    }
    nodes
}

/// Drives a cold create through to `ready`, discarding effects.
pub(super) fn ready_machine() -> (Machine, Effects) {
    reach(&[
        Event::Provision(Provision::Boot { warm: false }),
        Event::ResourcesHandedOff,
        Event::AgentReady,
        Event::Gated,
    ])
}
