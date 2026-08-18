//! The rules that must hold in every state: recovery's seeding, and the gates
//! `stop_sandbox`, `cleanup::begin_removal` and the two deadline timers apply.

use super::harness::{ALL_PHASES, BUDGET_MS, explore, ordinal, reach, ready_machine, step};
use crate::lifecycle::effect::{
    Answer, Durability, Effect, Effects, Notify, RecordEnd, ReleaseScope, Timer,
};
use crate::lifecycle::event::Event;
use crate::lifecycle::machine::State;
use crate::sandbox::policy::recovery::{JournalEvidence, RecoveryAction, plan};
use crate::sandbox::record::PersistPhase;
use crate::sandbox::{IdleAction, SandboxState};

/// `sandbox::policy::recovery::plan`'s verdict for a phase whose journal the
/// startup sweep tore down — the evidence a seeded machine corresponds to.
///
/// The real function, not a table checked by eye: the two cannot drift.
/// `Swept` is the one evidence a `Recovered` event can carry, since the
/// machine is seeded from what the sweep already acted on; the refusals and
/// the reclaimed-alive verdict never reach this path, and
/// `sandbox/policy/recovery.rs`'s own exhaustive table covers them.
fn recovery_plan(phase: PersistPhase) -> RecoveryAction {
    plan(phase, JournalEvidence::Swept)
}

#[test]
fn recovery_seeds_the_state_its_own_verdict_leaves_behind() {
    for phase in ALL_PHASES {
        let (sm, _) = reach(&[Event::Recovered { phase }]);
        let state = *sm.state();
        match recovery_plan(phase) {
            // Nobody acknowledged the intent, so the same request key still
            // resumes it: the machine stays where a fresh one starts.
            RecoveryAction::LeaveResumable => {
                assert_eq!(state.durable(), Some(PersistPhase::Creating), "{phase:?}");
                assert_eq!(state.to_public(), SandboxState::Starting, "{phase:?}");
            }
            // Recovery already wrote `Failed`; the machine only adopts it.
            RecoveryAction::Fail => {
                assert_eq!(state.durable(), Some(PersistPhase::Failed), "{phase:?}");
                assert_eq!(state.to_public(), SandboxState::Failed, "{phase:?}");
            }
            RecoveryAction::Reinstate(public) => {
                assert_eq!(state.durable(), Some(phase), "{phase:?}");
                assert_eq!(state.to_public(), public, "{phase:?}");
            }
            RecoveryAction::FinishRemove => {
                assert_eq!(state.durable(), Some(PersistPhase::Removing), "{phase:?}");
            }
            // Both refusals answer a sweep that found no journal or adopted
            // a phase it must not: neither seeds a machine.
            refused @ (RecoveryAction::RefuseUnjournaled | RecoveryAction::RefuseAdopted) => {
                panic!("{phase:?} with a swept journal cannot yield {refused:?}")
            }
        }
        // A seeded machine must still be drivable to its end.
        let mut context = Effects::default();
        let mut sm = sm;
        step(&mut sm, &mut context, &Event::Remove { force: true });
        let (state, _) = step(&mut sm, &mut context, &Event::RemoveDone);
        assert!(
            matches!(state, State::Gone {} | State::Provisioning {}),
            "{phase:?} did not reach a terminal state"
        );
    }
}

// ----- narrative flows -----

/// Drives a cold create through to `ready`, discarding effects.
#[test]
fn a_stop_only_acts_while_the_guest_serves() {
    // `stop_sandbox` accepts Ready/Running/Stopping (and retries idempotently
    // from Stopped), answering WrongState elsewhere. Only the first two are a
    // state change, so re-entering `stopping` emits nothing; everything else
    // the machine swallows for the actor to answer.
    for node in explore() {
        let (mut sm, mut context) = reach(&node.path);
        let (state, effects) = step(
            &mut sm,
            &mut context,
            &Event::Stop {
                budget_ms: BUDGET_MS,
            },
        );
        // `active` is the superstate that serves: `gating` projects `Running`
        // once the boot's own cmd has claimed the slot, but its launch is
        // still in flight, so the actor defers the stop (`pending_stop`)
        // rather than the machine acting on it.
        let acts = matches!(
            node.state,
            State::Ready {} | State::Running {} | State::Checkpointing {}
        );
        assert_eq!(
            !effects.is_empty(),
            acts,
            "stop from {:?} emitted {effects:?}",
            node.state
        );
        if !acts {
            assert_eq!(ordinal(state), ordinal(node.state), "{:?}", node.state);
        }
    }
}

#[test]
fn a_non_forced_remove_is_refused_exactly_where_the_computer_is_busy() {
    // `cleanup::begin_removal` refuses `!force` on Running and Starting; the
    // machine mirrors that on the states projecting them. A removal already
    // under way (or done) coalesces instead.
    for node in explore() {
        let (mut sm, mut context) = reach(&node.path);
        let (_, effects) = step(&mut sm, &mut context, &Event::Remove { force: false });
        let busy = matches!(
            node.state.to_public(),
            SandboxState::Starting | SandboxState::Running
        ) || matches!(node.state, State::Removing {} | State::Gone {});
        assert_eq!(
            effects.is_empty(),
            busy,
            "non-forced remove from {:?} emitted {effects:?}",
            node.state
        );
    }
}

#[test]
fn a_forced_remove_tears_down_from_every_live_state() {
    for node in explore() {
        if matches!(node.state, State::Removing {} | State::Gone {}) {
            continue;
        }
        let (mut sm, mut context) = reach(&node.path);
        let (state, effects) = step(&mut sm, &mut context, &Event::Remove { force: true });
        assert!(matches!(state, State::Removing {}), "{:?}", node.state);
        assert_eq!(
            effects,
            vec![
                // The bounded handoff wait is inside AbortInflight: a boot
                // that has not handed its resources over cannot be aborted.
                Effect::AbortInflight,
                Effect::CancelTimer(Timer::Ttl),
                Effect::CancelTimer(Timer::Idle),
                Effect::PersistPhase {
                    phase: PersistPhase::Removing,
                    durability: Durability::Warn,
                },
                Effect::SpawnRelease {
                    scope: ReleaseScope::Full
                },
            ],
            "{:?}",
            node.state
        );

        let (state, effects) = step(&mut sm, &mut context, &Event::RemoveDone);
        assert!(matches!(state, State::Gone {}));
        assert_eq!(
            effects,
            vec![
                Effect::ForgetRecord(RecordEnd::Removed),
                Effect::Publish(Notify::Removed),
                Effect::Answer(Answer::Removed),
            ]
        );
    }
}

#[test]
fn the_ttl_cap_destroys_everywhere_except_a_resting_or_removed_computer() {
    for node in explore() {
        let (mut sm, mut context) = reach(&node.path);
        let (_, effects) = step(&mut sm, &mut context, &Event::TtlExpired);
        // `deadlines::ttl_due` drops the timer once a computer is terminal,
        // and a removal in flight coalesces.
        let inert = matches!(
            node.state,
            State::Stopped {} | State::Failed {} | State::Removing {} | State::Gone {}
        );
        assert_eq!(
            effects.is_empty(),
            inert,
            "ttl from {:?} emitted {effects:?}",
            node.state
        );
    }
}

#[test]
fn the_idle_policy_only_fires_on_a_ready_computer() {
    // `deadlines::idle_due` arms the timer only while Ready, and
    // `apply_idle_policy` re-checks Ready before acting.
    for node in explore() {
        for action in [IdleAction::Kill, IdleAction::Pause] {
            let (mut sm, mut context) = reach(&node.path);
            let (_, effects) = step(&mut sm, &mut context, &Event::IdleExpired { action });
            assert_eq!(
                !effects.is_empty(),
                matches!(node.state, State::Ready {}),
                "idle {action:?} from {:?} emitted {effects:?}",
                node.state
            );
        }
    }

    // The two policies: pause reuses the pause path verbatim, kill removes.
    let (mut sm, mut context) = ready_machine();
    let (state, effects) = step(
        &mut sm,
        &mut context,
        &Event::IdleExpired {
            action: IdleAction::Pause,
        },
    );
    assert_eq!(state.to_public(), SandboxState::Pausing);
    assert!(effects.contains(&Effect::Publish(Notify::Pausing)));

    let (mut sm, mut context) = ready_machine();
    let (state, _) = step(
        &mut sm,
        &mut context,
        &Event::IdleExpired {
            action: IdleAction::Kill,
        },
    );
    assert!(matches!(state, State::Removing {}));
}
