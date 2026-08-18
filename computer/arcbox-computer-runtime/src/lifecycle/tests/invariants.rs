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
use crate::sandbox::workload::WorkloadClaim;
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

/// The one recovery verdict `Recovered` cannot carry: an adopted computer's
/// record still says `Ready`, and the sweep took its VM back rather than
/// tearing it down, so it is usable without ever having booted here. Seeding
/// it from the phase alone would read `Ready` as the interrupted live phase
/// it is for every *other* evidence and fail the computer — losing a guest
/// the sweep had just saved.
#[test]
fn an_adopted_computer_is_seeded_ready_without_a_launch() {
    assert_eq!(
        plan(PersistPhase::Ready, JournalEvidence::Adopted),
        RecoveryAction::Reinstate(SandboxState::Ready),
    );
    let (sm, mut context) = reach(&[Event::Adopted]);
    let state = *sm.state();
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(state.durable(), Some(PersistPhase::Ready));

    // And it is a real `ready`, not a look-alike: it accepts work, pauses,
    // and stops like one that booted here.
    let mut sm = sm;
    let (state, _) = step(
        &mut sm,
        &mut context,
        &Event::ClaimWorkload {
            claim: WorkloadClaim::Api,
        },
    );
    assert_eq!(state.to_public(), SandboxState::Running);
}

/// Who may take the single-workload slot, over every state — the rule
/// `workload::claim_workload` enforced against `SandboxState`.
///
/// The two claims differ in exactly one place: the readiness gate holds the
/// slot for the boot's own `cmd`, and an `Api` claim cannot reach a computer
/// that has not announced READY. Everywhere else a claim is refused, and a
/// refusal must leave the computer where it was — a `Run` that lost the race
/// must not have moved anything.
#[test]
fn only_ready_and_the_gates_own_cmd_take_the_workload_slot() {
    for node in explore() {
        for claim in [WorkloadClaim::Api, WorkloadClaim::Initial] {
            let (mut sm, mut context) = reach(&node.path);
            let before = *sm.state();
            let (after, effects) = step(&mut sm, &mut context, &Event::ClaimWorkload { claim });
            let allowed = matches!(before, State::Ready {})
                || (claim == WorkloadClaim::Initial
                    && matches!(before, State::Gating { claimed: false, .. }));
            assert_eq!(
                after.to_public() == SandboxState::Running && !effects.is_empty(),
                allowed,
                "{before:?} with {claim:?}"
            );
            if !allowed {
                assert_eq!(before, after, "a refused claim moved {before:?}");
                assert!(effects.is_empty(), "a refused claim acted in {before:?}");
            }
        }
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

/// An idle expiry can only reach a computer that is still idle.
///
/// `expire_sandbox` took a `force` flag for exactly this: the TTL cap
/// destroys regardless of activity, while the idle detector passed
/// `force = false` so a non-forced removal would refuse a computer that had
/// turned busy between the timer firing and the teardown claiming it. The
/// actor closes that window rather than guarding it — the expiry and the
/// claim are both messages to the same task, so whichever arrives second
/// finds the state the first left. From `ready` the two flags emit the
/// identical teardown, so the surviving encoding is the forced one.
#[test]
fn an_idle_expiry_cannot_reach_a_busy_computer() {
    for action in [IdleAction::Kill, IdleAction::Pause] {
        for node in explore() {
            let (mut sm, mut context) = reach(&node.path);
            let before = *sm.state();
            let (after, effects) = step(&mut sm, &mut context, &Event::IdleExpired { action });
            if matches!(before, State::Ready {}) {
                assert_ne!(before, after, "{before:?} must act on an idle expiry");
                continue;
            }
            assert_eq!(before, after, "{before:?} acted on an idle expiry");
            assert!(effects.is_empty(), "{before:?} acted on an idle expiry");
        }
    }
}

/// And a `Kill` expiry from `ready` is the same teardown a forced remove is.
#[test]
fn an_idle_kill_is_the_teardown_a_forced_remove_runs() {
    let (mut sm, mut context) = ready_machine();
    let (state, killed) = step(
        &mut sm,
        &mut context,
        &Event::IdleExpired {
            action: IdleAction::Kill,
        },
    );
    assert!(matches!(state, State::Removing {}));

    let (mut sm, mut context) = ready_machine();
    let (state, removed) = step(&mut sm, &mut context, &Event::Remove { force: true });
    assert!(matches!(state, State::Removing {}));
    assert_eq!(killed, removed);
}
