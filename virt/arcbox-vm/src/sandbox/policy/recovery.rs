//! Crash-recovery policy: what a restart makes of the crash journals and
//! durable records the previous process left behind.
//!
//! Pure classification over phases — the sweep and the normalization in
//! `super::super::reconcile` supply the evidence and carry out the actions
//! decided here.

use std::collections::HashSet;

use crate::sandbox::SandboxState;
use crate::sandbox::record::PersistPhase;

/// What the orphan sweep established about one sandbox's runtime resources
/// before recovery reads its durable record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox) enum JournalEvidence {
    /// The sweep found this sandbox's cleanup journal and tore down
    /// everything it listed.
    Swept,
    /// The sweep ran and found no journal for this sandbox.
    Unjournaled,
    /// No sweep ran, so nothing is known about its resources.
    Unchecked,
}

/// What startup recovery does with one durable record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox) enum RecoveryAction {
    /// A create intent nobody acknowledged: left as it is, so the same
    /// request key still resumes it.
    LeaveResumable,
    /// Interrupted mid-flight: durably failed, then kept as an inspectable
    /// instance.
    Fail,
    /// Already inactive before the restart: reconstructed in this state,
    /// without runtime handles.
    Reinstate(SandboxState),
    /// An interrupted removal: finished as a durable tombstone.
    FinishRemove,
    /// A live phase whose runtime resources were never journaled. The sweep
    /// cannot prove they are gone, so recovery refuses rather than declaring
    /// a sandbox failed while its VMM may still be running.
    RefuseUnjournaled,
}

/// What the startup sweep does with one crash journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox) enum SweepAction {
    /// Clear the journal and keep what is on disk.
    DropStaleJournal,
    /// Tear down everything the journal lists.
    Reclaim,
}

/// Recovery's verdict on a record in `phase`, given what the sweep saw.
pub(in crate::sandbox) fn plan(phase: PersistPhase, evidence: JournalEvidence) -> RecoveryAction {
    match phase {
        PersistPhase::Creating => RecoveryAction::LeaveResumable,
        // A live phase's runtime resources are journaled as they are
        // acquired, so a missing journal means the sweep never saw — and
        // never tore down — this sandbox's VMM, TAP and overlay.
        PersistPhase::Starting | PersistPhase::Ready | PersistPhase::Stopping => match evidence {
            JournalEvidence::Unjournaled => RecoveryAction::RefuseUnjournaled,
            JournalEvidence::Swept | JournalEvidence::Unchecked => RecoveryAction::Fail,
        },
        // An interrupted pause/resume died between resource states; the
        // sweep already tore down whatever its journal listed (including the
        // disk overlay), so the sandbox is unrecoverable. Unlike the live
        // phases above, a missing journal is normal here — a resume starts
        // from a Paused record whose journal was already cleared (after the
        // Paused commit) and re-journals as it re-allocates.
        PersistPhase::Pausing | PersistPhase::Resuming => RecoveryAction::Fail,
        // Paused commits only after every runtime resource was released, and
        // the sweep preserves durably Paused retained state (clearing any
        // stale journal), so a paused sandbox always survives a restart
        // resumable.
        PersistPhase::Paused => RecoveryAction::Reinstate(SandboxState::Paused),
        PersistPhase::Stopped => RecoveryAction::Reinstate(SandboxState::Stopped),
        PersistPhase::Failed => RecoveryAction::Reinstate(SandboxState::Failed),
        PersistPhase::Removing => RecoveryAction::FinishRemove,
    }
}

/// The sandboxes whose on-disk state a restart must keep: `Paused` is
/// committed only after `release_for_pause` (or the resume unwind) released
/// every runtime resource, so its retained overlay or parked rootfs is
/// deliberate, not debris.
pub(in crate::sandbox) fn retained_ids<'a>(
    records: impl IntoIterator<Item = (&'a str, PersistPhase)>,
) -> HashSet<String> {
    records
        .into_iter()
        .filter(|(_, phase)| *phase == PersistPhase::Paused)
        .map(|(id, _)| id.to_owned())
        .collect()
}

/// What to do with the crash journal `id` left behind.
///
/// A journal beside a retained sandbox is a leftover of the crash window
/// between its durable commit and the journal clear — not evidence of a
/// torn release — so it is dropped rather than acted on. Everything else,
/// including a journal with no durable record at all (a pre-warmed pool
/// slot), is an orphan.
pub(in crate::sandbox) fn sweep_action(id: &str, retained: &HashSet<String>) -> SweepAction {
    if retained.contains(id) {
        SweepAction::DropStaleJournal
    } else {
        SweepAction::Reclaim
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_durable_phase_has_one_recovery_action() {
        // (phase, verdict with a journal or with no sweep, verdict when the
        // sweep ran and found no journal).
        let table = [
            (
                PersistPhase::Creating,
                RecoveryAction::LeaveResumable,
                RecoveryAction::LeaveResumable,
            ),
            (
                PersistPhase::Starting,
                RecoveryAction::Fail,
                RecoveryAction::RefuseUnjournaled,
            ),
            (
                PersistPhase::Ready,
                RecoveryAction::Fail,
                RecoveryAction::RefuseUnjournaled,
            ),
            (
                PersistPhase::Stopping,
                RecoveryAction::Fail,
                RecoveryAction::RefuseUnjournaled,
            ),
            (
                PersistPhase::Stopped,
                RecoveryAction::Reinstate(SandboxState::Stopped),
                RecoveryAction::Reinstate(SandboxState::Stopped),
            ),
            (
                PersistPhase::Failed,
                RecoveryAction::Reinstate(SandboxState::Failed),
                RecoveryAction::Reinstate(SandboxState::Failed),
            ),
            (
                PersistPhase::Removing,
                RecoveryAction::FinishRemove,
                RecoveryAction::FinishRemove,
            ),
            (
                PersistPhase::Pausing,
                RecoveryAction::Fail,
                RecoveryAction::Fail,
            ),
            (
                PersistPhase::Paused,
                RecoveryAction::Reinstate(SandboxState::Paused),
                RecoveryAction::Reinstate(SandboxState::Paused),
            ),
            (
                PersistPhase::Resuming,
                RecoveryAction::Fail,
                RecoveryAction::Fail,
            ),
        ];

        for (phase, journaled, unjournaled) in table {
            for evidence in [JournalEvidence::Swept, JournalEvidence::Unchecked] {
                assert_eq!(plan(phase, evidence), journaled, "{phase:?} {evidence:?}");
            }
            assert_eq!(
                plan(phase, JournalEvidence::Unjournaled),
                unjournaled,
                "{phase:?} unjournaled"
            );
        }
    }

    #[test]
    fn only_a_paused_sandbox_retains_its_disk_state() {
        let retained = retained_ids([
            ("paused", PersistPhase::Paused),
            ("ready", PersistPhase::Ready),
            ("pausing", PersistPhase::Pausing),
            ("resuming", PersistPhase::Resuming),
            ("stopped", PersistPhase::Stopped),
        ]);
        assert_eq!(retained, HashSet::from(["paused".to_owned()]));
    }

    #[test]
    fn a_retained_sandboxs_journal_is_stale_and_every_other_one_is_an_orphan() {
        let retained = HashSet::from(["paused".to_owned()]);
        assert_eq!(
            sweep_action("paused", &retained),
            SweepAction::DropStaleJournal
        );
        assert_eq!(sweep_action("live", &retained), SweepAction::Reclaim);
        // A pre-warmed pool slot journals like a sandbox but has no durable
        // record at all.
        assert_eq!(sweep_action("pool-1f2e", &retained), SweepAction::Reclaim);
    }
}
