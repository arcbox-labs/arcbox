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
    // this asserts the whole table rather than sampling it. `gating` is the
    // one leaf with two answers: the boot's own `cmd` claims the workload
    // slot before READY, and from there a caller reads `Running` — which is
    // what stops an Inspect-polling client from stealing that slot.
    let expected: [&[SandboxState]; LEAVES] = [
        &[SandboxState::Starting],                        // provisioning
        &[SandboxState::Starting],                        // staging
        &[SandboxState::Starting],                        // booting
        &[SandboxState::Starting],                        // restoring
        &[SandboxState::Starting, SandboxState::Running], // gating
        &[SandboxState::Ready],                           // ready
        &[SandboxState::Running],                         // running
        &[SandboxState::Ready],                           // checkpointing
        &[SandboxState::Pausing],                         // capturing
        &[SandboxState::Pausing],                         // releasing
        &[SandboxState::Paused],                          // paused
        &[SandboxState::Starting],                        // resuming
        &[SandboxState::Stopping],                        // stopping
        &[SandboxState::Stopped],                         // stopped
        &[SandboxState::Failed],                          // failed
        &[SandboxState::Stopping],                        // removing
        &[SandboxState::Stopped],                         // gone
    ];
    for node in explore() {
        let public = node.state.to_public();
        assert!(
            expected[ordinal(node.state)].contains(&public),
            "{:?} projects {public}",
            node.state
        );
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
