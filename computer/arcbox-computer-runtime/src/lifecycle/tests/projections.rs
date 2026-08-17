//! Reachability, and the two projections over every leaf.

use super::harness::{LEAVES, explore, ordinal};
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
    // Indexed by `ordinal`. `gating` is the one leaf two paths reach on
    // different phases, so it carries the discriminator and lists both; the
    // walk below pins which one each path actually holds.
    let expected: [&[Option<P>]; LEAVES] = [
        &[Some(P::Creating)],                 // provisioning: the reserved intent
        &[Some(P::Starting)],                 // staging
        &[Some(P::Starting)],                 // booting
        &[Some(P::Creating)],                 // restoring: commits Ready in one hop
        &[Some(P::Starting), Some(P::Ready)], // gating
        &[Some(P::Ready)],                    // ready
        &[Some(P::Ready)],                    // running: the hot path writes nothing
        &[Some(P::Ready)],                    // checkpointing
        &[Some(P::Pausing)],                  // capturing
        &[Some(P::Pausing)],                  // releasing
        &[Some(P::Paused)],                   // paused
        &[Some(P::Resuming)],                 // resuming
        &[Some(P::Stopping)],                 // stopping
        &[Some(P::Stopped)],                  // stopped
        &[Some(P::Failed)],                   // failed
        &[Some(P::Removing)],                 // removing
        &[None],                              // gone: the record is forgotten
    ];
    for node in explore() {
        let durable = node.state.durable();
        assert!(
            expected[ordinal(node.state)].contains(&durable),
            "{:?} projects {durable:?}",
            node.state
        );
    }
}

#[test]
fn the_durable_projection_is_the_phase_actually_in_effect() {
    for node in explore() {
        assert_eq!(
            node.state.durable(),
            node.phase,
            "{:?} reached via {:?}",
            node.state,
            node.path
        );
    }
}
