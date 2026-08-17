//! Reachability, and the two projections over every leaf.

use super::harness::{LEAVES, explore, ordinal};
use crate::lifecycle::machine::State;
use crate::sandbox::SandboxState;
use crate::sandbox::record::PersistPhase;

#[test]
fn every_leaf_is_reachable_by_driving_events() {
    let mut seen = [false; LEAVES];
    for node in explore() {
        seen[ordinal(node.state)] = true;
    }
    assert!(
        seen.iter().all(|reached| *reached),
        "unreachable leaves: {:?}",
        seen.iter()
            .enumerate()
            .filter(|(_, reached)| !**reached)
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_leaf_projects_onto_a_public_state() {
    // An arm nobody projects is how a state becomes invisible to callers, so
    // this asserts the whole table rather than sampling it.
    let expected = [
        (0, SandboxState::Starting),  // provisioning
        (1, SandboxState::Starting),  // staging
        (2, SandboxState::Starting),  // booting
        (3, SandboxState::Starting),  // restoring
        (4, SandboxState::Starting),  // gating
        (5, SandboxState::Ready),     // ready
        (6, SandboxState::Running),   // running
        (7, SandboxState::Ready),     // checkpointing
        (8, SandboxState::Pausing),   // capturing
        (9, SandboxState::Pausing),   // releasing
        (10, SandboxState::Paused),   // paused
        (11, SandboxState::Starting), // resuming
        (12, SandboxState::Stopping), // stopping
        (13, SandboxState::Stopped),  // stopped
        (14, SandboxState::Failed),   // failed
        (15, SandboxState::Stopping), // removing
        (16, SandboxState::Stopped),  // gone
    ];
    assert_eq!(expected.len(), LEAVES);
    for node in explore() {
        let (_, public) = expected[ordinal(node.state)];
        assert_eq!(node.state.to_public(), public, "{:?}", node.state);
    }
}

#[test]
fn every_leaf_projects_onto_a_durable_phase() {
    use PersistPhase as P;
    let expected = [
        (0, Some(P::Creating)),  // provisioning: the reserved intent
        (1, Some(P::Starting)),  // staging
        (2, Some(P::Starting)),  // booting
        (3, Some(P::Creating)),  // restoring: commits Ready in one hop
        (4, None),               // gating: Starting on a boot, Ready on a restore
        (5, Some(P::Ready)),     // ready
        (6, Some(P::Ready)),     // running: the hot path writes nothing
        (7, Some(P::Ready)),     // checkpointing
        (8, Some(P::Pausing)),   // capturing
        (9, Some(P::Pausing)),   // releasing
        (10, Some(P::Paused)),   // paused
        (11, Some(P::Resuming)), // resuming
        (12, Some(P::Stopping)), // stopping
        (13, Some(P::Stopped)),  // stopped
        (14, Some(P::Failed)),   // failed
        (15, Some(P::Removing)), // removing
        (16, None),              // gone: the record is forgotten
    ];
    assert_eq!(expected.len(), LEAVES);
    for node in explore() {
        let (_, durable) = expected[ordinal(node.state)];
        assert_eq!(node.state.durable(), durable, "{:?}", node.state);
    }
}

#[test]
fn the_durable_projection_is_the_phase_actually_in_effect() {
    for node in explore() {
        if matches!(node.state, State::Gating {}) {
            // The exception `durable` documents: a cold boot arrives here on
            // `Starting` and commits `Ready` after the probe, a restore
            // arrives already `Ready`. Both really happen.
            assert!(
                node.phase == Some(PersistPhase::Starting)
                    || node.phase == Some(PersistPhase::Ready),
                "gating reached on {:?}",
                node.phase
            );
            continue;
        }
        assert_eq!(
            node.state.durable(),
            node.phase,
            "{:?} reached via {:?}",
            node.state,
            node.path
        );
    }
}
