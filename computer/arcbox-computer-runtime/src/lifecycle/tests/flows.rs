//! One flow at a time, with its exact effect vector — what a reviewer diffs
//! against the code PR-F moves onto the machine.

use super::harness::{BUDGET_MS, machine, persist, reach, ready_machine, release, step};
use crate::lifecycle::effect::{
    Answer, Durability, Effect, Effects, Notify, RecordEnd, ReleaseScope, Timer, Unconfirmed,
};
use crate::lifecycle::event::{Event, PauseReason, Provision, RestoreOrigin};
use crate::lifecycle::machine::State;
use crate::sandbox::record::PersistPhase;
use crate::sandbox::workload::WorkloadClaim;
use crate::sandbox::{IdleAction, SandboxState};

#[test]
fn a_cold_create_stages_boots_gates_and_only_then_announces_ready() {
    let mut context = Effects::default();
    let mut sm = machine(&mut context);

    let (state, effects) = step(
        &mut sm,
        &mut context,
        &Event::Provision(Provision::Boot { warm: true }),
    );
    assert_eq!(state.to_public(), SandboxState::Starting);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Starting, Durability::Report(Unconfirmed::Ack)),
            Effect::SpawnBoot { warm: true },
            Effect::Publish(Notify::Created),
            Effect::ArmTimer(Timer::Ttl),
        ]
    );

    // The handoff is what makes the boot task safely abortable.
    let (state, effects) = step(&mut sm, &mut context, &Event::ResourcesHandedOff);
    assert!(matches!(state, State::Booting {}));
    assert!(effects.is_empty());

    let (_, effects) = step(&mut sm, &mut context, &Event::AgentReady);
    assert_eq!(effects, vec![Effect::SpawnGate]);

    // READY is withheld until the gate (warm publish, initial cmd, probe) is
    // through, and its durable commit refuses on an unconfirmed write.
    let (state, effects) = step(&mut sm, &mut context, &Event::Gated);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(
        effects,
        vec![
            persist(
                PersistPhase::Ready,
                Durability::Report(Unconfirmed::Unavailable)
            ),
            Effect::Publish(Notify::Ready),
            Effect::Answer(Answer::Ready),
            Effect::ArmTimer(Timer::Idle),
        ]
    );
}

#[test]
fn a_restore_commits_ready_in_one_hop_before_its_gate() {
    let mut context = Effects::default();
    let mut sm = machine(&mut context);
    let (_, effects) = step(
        &mut sm,
        &mut context,
        &Event::Provision(Provision::Restore {
            origin: RestoreOrigin::WarmCreate,
        }),
    );
    assert_eq!(
        effects,
        vec![Effect::SpawnRestore {
            origin: RestoreOrigin::WarmCreate
        }]
    );

    let (state, effects) = step(&mut sm, &mut context, &Event::Restored);
    assert_eq!(state.to_public(), SandboxState::Starting);
    assert!(matches!(
        state,
        State::Gating {
            committed: true,
            claimed: false
        }
    ));
    assert_eq!(
        effects,
        vec![
            // Not a `PersistPhase`: `Creating -> Ready` is not in the edge
            // set, and the store waives it only for this commit.
            Effect::CommitRestored {
                durability: Durability::Report(Unconfirmed::Ack),
            },
            // A warm-create reroute owes the Create event contract.
            Effect::Publish(Notify::Created),
            Effect::ArmTimer(Timer::Ttl),
            Effect::SpawnGate,
        ]
    );

    // The gate then announces READY without writing the record again: a
    // second write would put an fsync on the restore's hot path and could
    // refuse a computer that is already durably `Ready`.
    let (state, effects) = step(&mut sm, &mut context, &Event::Gated);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(
        effects,
        vec![
            Effect::Publish(Notify::Ready),
            Effect::Answer(Answer::Ready),
            Effect::ArmTimer(Timer::Idle),
        ]
    );
}

#[test]
fn the_boots_own_cmd_claims_the_slot_the_gate_reserved_for_it() {
    // The reservation `gating` names is this claim: `start_run_workload`
    // takes it before READY, publishing RUNNING, and the workload's exit
    // publishes IDLE. So the claim has to survive the gate — landing in
    // `ready` instead would leave `WorkloadExited` with nothing to do and
    // drop the IDLE publish.
    let (mut sm, mut context) = reach(&[
        Event::Provision(Provision::Boot { warm: false }),
        Event::ResourcesHandedOff,
        Event::AgentReady,
    ]);
    let (state, effects) = step(
        &mut sm,
        &mut context,
        &Event::ClaimWorkload {
            claim: WorkloadClaim::Initial,
        },
    );
    assert!(matches!(
        state,
        State::Gating {
            committed: false,
            claimed: true
        }
    ));
    // A cmd-carrying boot reads `Running` from here on, exactly as the
    // instance does today — an Inspect during the gate cannot see `Ready`
    // and steal the slot.
    assert_eq!(state.to_public(), SandboxState::Running);
    assert_eq!(effects, vec![Effect::Publish(Notify::Running)]);

    // A second initial claim is the same workload twice: refused, for the
    // actor to answer.
    let (_, effects) = step(
        &mut sm,
        &mut context,
        &Event::ClaimWorkload {
            claim: WorkloadClaim::Initial,
        },
    );
    assert!(effects.is_empty());

    // READY then announces a computer that is already running its own cmd,
    // and the idle window opens only when that workload exits.
    let (state, effects) = step(&mut sm, &mut context, &Event::Gated);
    assert!(matches!(state, State::Running {}));
    assert_eq!(
        effects,
        vec![
            persist(
                PersistPhase::Ready,
                Durability::Report(Unconfirmed::Unavailable)
            ),
            Effect::Publish(Notify::Ready),
            Effect::Answer(Answer::Ready),
        ]
    );

    let (state, effects) = step(&mut sm, &mut context, &Event::WorkloadExited);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(
        effects,
        vec![Effect::Publish(Notify::Idle), Effect::ArmTimer(Timer::Idle)]
    );
}

#[test]
fn only_the_warm_create_reroute_announces_a_restore_as_a_create() {
    // A Restore RPC's computer is new to its caller but not to the Create
    // event contract: it announces itself with READY alone, and a watcher
    // that saw CREATED for it would be watching a create nobody asked for.
    let (mut sm, mut context) = reach(&[Event::Provision(Provision::Restore {
        origin: RestoreOrigin::Restore,
    })]);
    let (_, effects) = step(&mut sm, &mut context, &Event::Restored);
    assert!(
        !effects.contains(&Effect::Publish(Notify::Created)),
        "{effects:?}"
    );
}

#[test]
fn a_workload_round_trip_cancels_and_re_arms_the_idle_timer() {
    let (mut sm, mut context) = ready_machine();
    let (state, effects) = step(
        &mut sm,
        &mut context,
        &Event::ClaimWorkload {
            claim: WorkloadClaim::Api,
        },
    );
    assert_eq!(state.to_public(), SandboxState::Running);
    assert_eq!(
        effects,
        vec![
            Effect::CancelTimer(Timer::Idle),
            Effect::Publish(Notify::Running),
        ]
    );

    let (state, effects) = step(&mut sm, &mut context, &Event::WorkloadExited);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(
        effects,
        vec![Effect::Publish(Notify::Idle), Effect::ArmTimer(Timer::Idle)]
    );
}

#[test]
fn a_pause_captures_releases_and_parks_at_paused() {
    let (mut sm, mut context) = ready_machine();
    let (state, effects) = step(
        &mut sm,
        &mut context,
        &Event::Pause {
            reason: PauseReason::Requested,
        },
    );
    assert_eq!(state.to_public(), SandboxState::Pausing);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Pausing, Durability::Warn),
            Effect::CancelTimer(Timer::Idle),
            Effect::Publish(Notify::Pausing),
            Effect::SpawnCheckpoint { hold: true },
        ]
    );

    let (state, effects) = step(
        &mut sm,
        &mut context,
        &Event::CaptureDone {
            snapshot_id: "snap".to_owned(),
        },
    );
    assert_eq!(state.to_public(), SandboxState::Pausing);
    assert_eq!(effects, vec![release(ReleaseScope::KeepDisk)]);

    // Paused commits only once every runtime resource is gone, and the crash
    // journal is cleared only behind that confirmed write.
    let (state, effects) = step(&mut sm, &mut context, &Event::ReleasedForPause);
    assert_eq!(state.to_public(), SandboxState::Paused);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Paused, Durability::GateJournal),
            Effect::ClearJournal,
            Effect::Publish(Notify::Paused),
            Effect::Answer(Answer::Paused),
        ]
    );
}

#[test]
fn a_recoverable_capture_failure_leaves_a_usable_computer() {
    let (mut sm, mut context) = ready_machine();
    step(
        &mut sm,
        &mut context,
        &Event::Pause {
            reason: PauseReason::Requested,
        },
    );
    let (state, effects) = step(&mut sm, &mut context, &Event::Failure);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Ready, Durability::Warn),
            Effect::Publish(Notify::Ready),
            Effect::ArmTimer(Timer::Idle),
        ]
    );
}

#[test]
fn a_frozen_guest_fails_the_computer_from_either_capture_path() {
    for pause in [true, false] {
        let (mut sm, mut context) = ready_machine();
        let event = if pause {
            Event::Pause {
                reason: PauseReason::Requested,
            }
        } else {
            Event::Checkpoint
        };
        step(&mut sm, &mut context, &event);
        let (state, effects) = step(&mut sm, &mut context, &Event::Frozen);
        assert_eq!(state.to_public(), SandboxState::Failed, "pause={pause}");
        assert_eq!(
            effects,
            vec![
                persist(PersistPhase::Failed, Durability::GateJournal),
                release(ReleaseScope::Runtime),
                Effect::ClearJournal,
                Effect::CancelTimer(Timer::Idle),
                Effect::CancelTimer(Timer::Ttl),
                Effect::Publish(Notify::Failed),
            ]
        );
    }
}

#[test]
fn a_user_checkpoint_holds_ready_and_writes_no_record() {
    let (mut sm, mut context) = ready_machine();
    let (state, effects) = step(&mut sm, &mut context, &Event::Checkpoint);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(
        effects,
        vec![
            Effect::CancelTimer(Timer::Idle),
            Effect::SpawnCheckpoint { hold: false },
        ]
    );

    // The race this state exists to close: a Run cannot claim the slot while
    // the guest is frozen, and the idle policy cannot fire either.
    for blocked in [
        Event::ClaimWorkload {
            claim: WorkloadClaim::Api,
        },
        Event::Pause {
            reason: PauseReason::Requested,
        },
        Event::IdleExpired {
            action: IdleAction::Kill,
        },
    ] {
        let (state, effects) = step(&mut sm, &mut context, &blocked);
        assert!(matches!(state, State::Checkpointing {}), "{blocked:?}");
        assert!(effects.is_empty(), "{blocked:?}");
    }

    // A recoverable failure returns to Ready without a record write, exactly
    // as `checkpoint_sandbox` does today — with the idle window restarted,
    // since the expiry swallowed above consumed a one-shot timer.
    let (state, effects) = step(&mut sm, &mut context, &Event::Failure);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(effects, vec![Effect::ArmTimer(Timer::Idle)]);
}

#[test]
fn resume_reverts_to_paused_when_the_restore_unwinds() {
    let (mut sm, mut context) = reach(&[Event::Recovered {
        phase: PersistPhase::Paused,
    }]);
    let (state, effects) = step(&mut sm, &mut context, &Event::Resume);
    assert_eq!(state.to_public(), SandboxState::Starting);
    assert_eq!(
        effects,
        vec![
            persist(
                PersistPhase::Resuming,
                Durability::Report(Unconfirmed::RevertToPaused)
            ),
            Effect::SpawnResume,
        ]
    );

    let (state, effects) = step(&mut sm, &mut context, &Event::Failure);
    assert_eq!(state.to_public(), SandboxState::Paused);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Paused, Durability::Warn),
            Effect::Publish(Notify::Paused),
        ]
    );

    // ...and a second attempt still resumes to Ready.
    step(&mut sm, &mut context, &Event::Resume);
    let (state, effects) = step(&mut sm, &mut context, &Event::Restored);
    assert_eq!(state.to_public(), SandboxState::Ready);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Ready, Durability::Warn),
            Effect::Publish(Notify::Resumed),
            Effect::Answer(Answer::Resumed),
            Effect::ArmTimer(Timer::Idle),
        ]
    );
}

#[test]
fn a_resume_that_could_not_unwind_fails_instead_of_parking_at_paused() {
    // The crash-safety half of the two-valued resume failure: `Paused` is a
    // promise that the retained state is whole and the computer is
    // resumable, and a restart sweep reads it that way. A resume that left
    // resources allocated has not kept that promise.
    let (mut sm, mut context) = reach(&[
        Event::Recovered {
            phase: PersistPhase::Paused,
        },
        Event::Resume,
    ]);
    let (state, effects) = step(&mut sm, &mut context, &Event::Stranded);
    assert_eq!(state.to_public(), SandboxState::Failed);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Failed, Durability::GateJournal),
            release(ReleaseScope::Runtime),
            Effect::ClearJournal,
            Effect::CancelTimer(Timer::Idle),
            Effect::CancelTimer(Timer::Ttl),
            Effect::Publish(Notify::Failed),
        ]
    );
}

#[test]
fn a_stop_drains_through_stopping_and_clears_the_journal() {
    let (mut sm, mut context) = ready_machine();
    let (state, effects) = step(
        &mut sm,
        &mut context,
        &Event::Stop {
            budget_ms: BUDGET_MS,
        },
    );
    assert_eq!(state.to_public(), SandboxState::Stopping);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Stopping, Durability::Warn),
            Effect::CancelTimer(Timer::Idle),
            Effect::Publish(Notify::Stopping),
            Effect::SpawnStop {
                budget_ms: BUDGET_MS
            },
        ]
    );

    // The VM exiting is what we asked for, not a failure.
    let (state, effects) = step(&mut sm, &mut context, &Event::VmExited);
    assert_eq!(state.to_public(), SandboxState::Stopping);
    assert!(effects.is_empty());

    let (state, effects) = step(&mut sm, &mut context, &Event::StopDone);
    assert_eq!(state.to_public(), SandboxState::Stopped);
    assert_eq!(
        effects,
        vec![
            persist(PersistPhase::Stopped, Durability::GateJournal),
            Effect::ClearJournal,
            Effect::CancelTimer(Timer::Ttl),
            Effect::Publish(Notify::Stopped),
            Effect::Answer(Answer::Stopped),
        ]
    );
}

#[test]
fn an_unacknowledged_provision_forgets_its_record() {
    let mut context = Effects::default();
    let mut sm = machine(&mut context);
    let (state, effects) = step(&mut sm, &mut context, &Event::Failure);
    assert!(matches!(state, State::Gone {}));
    assert_eq!(effects, vec![Effect::ForgetRecord(RecordEnd::Aborted)]);
}

#[test]
fn the_pause_reasons_are_the_ones_the_event_stream_carries() {
    assert_eq!(PauseReason::Requested.as_str(), "pause");
    assert_eq!(PauseReason::IdleTimeout.as_str(), "idle_timeout");
}

#[test]
fn a_restore_that_fails_before_its_commit_is_rolled_back_not_parked() {
    // `rollback_restore` force-removes: the record and every artefact go, so
    // the id and its request key are free for a retry (and a warm create can
    // fall back to a cold boot). Parking at `Failed` would hold both.
    for failure in [Event::Failure, Event::VmExited, Event::Frozen] {
        let (mut sm, mut context) = reach(&[Event::Provision(Provision::Restore {
            origin: RestoreOrigin::WarmCreate,
        })]);
        let (state, effects) = step(&mut sm, &mut context, &failure);
        assert!(matches!(state, State::Removing {}), "{failure:?}");
        assert_eq!(
            effects,
            vec![
                Effect::AbortInflight,
                Effect::CancelTimer(Timer::Ttl),
                Effect::CancelTimer(Timer::Idle),
                persist(PersistPhase::Removing, Durability::Warn),
                release(ReleaseScope::Full),
            ],
            "{failure:?}"
        );

        let (state, effects) = step(&mut sm, &mut context, &Event::RemoveDone);
        assert!(matches!(state, State::Gone {}), "{failure:?}");
        assert_eq!(effects[0], Effect::ForgetRecord(RecordEnd::Removed));
    }
}
