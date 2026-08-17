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
    /// The sweep found this sandbox's VM still running and reclaimed it:
    /// its handle, its lease's datapath and its disk overlay belong to this
    /// process again, and nothing it listed was torn down.
    Adopted,
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
    /// The sweep reported adopting a sandbox from a phase it must not adopt.
    /// Recovery refuses rather than guess: the alternatives are declaring a
    /// live sandbox failed or claiming a readiness nobody established, and
    /// the VM is safe meanwhile — this process holds its handle.
    RefuseAdopted,
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
    match (phase, evidence) {
        // An adopted sandbox never stopped being usable: the sweep took its
        // VM back rather than tearing it down, so it is reinstated with the
        // runtime state it already had. `Ready`, not `Running` — the
        // workload the previous process was streaming did not survive it,
        // and `Running` is what refuses the next `Run`.
        (PersistPhase::Ready, JournalEvidence::Adopted) => {
            RecoveryAction::Reinstate(SandboxState::Ready)
        }
        // The sweep adopts a durably `Ready` sandbox and nothing else
        // (`reconcile::adopt_or_kill`), so this pairing is unreachable by
        // construction rather than merely unusual.
        (_, JournalEvidence::Adopted) => RecoveryAction::RefuseAdopted,

        (PersistPhase::Creating, _) => RecoveryAction::LeaveResumable,
        // A live phase's runtime resources are journaled as they are
        // acquired, so a missing journal means the sweep never saw — and
        // never tore down — this sandbox's VMM, TAP and overlay.
        (
            PersistPhase::Starting | PersistPhase::Ready | PersistPhase::Stopping,
            JournalEvidence::Unjournaled,
        ) => RecoveryAction::RefuseUnjournaled,
        (PersistPhase::Starting | PersistPhase::Ready | PersistPhase::Stopping, _) => {
            RecoveryAction::Fail
        }
        // An interrupted pause/resume died between resource states; the
        // sweep already tore down whatever its journal listed (including the
        // disk overlay), so the sandbox is unrecoverable. Unlike the live
        // phases above, a missing journal is normal here — a resume starts
        // from a Paused record whose journal was already cleared (after the
        // Paused commit) and re-journals as it re-allocates.
        (PersistPhase::Pausing | PersistPhase::Resuming, _) => RecoveryAction::Fail,
        // Paused commits only after every runtime resource was released, and
        // the sweep preserves durably Paused retained state (clearing any
        // stale journal), so a paused sandbox always survives a restart
        // resumable.
        (PersistPhase::Paused, _) => RecoveryAction::Reinstate(SandboxState::Paused),
        (PersistPhase::Stopped, _) => RecoveryAction::Reinstate(SandboxState::Stopped),
        (PersistPhase::Failed, _) => RecoveryAction::Reinstate(SandboxState::Failed),
        (PersistPhase::Removing, _) => RecoveryAction::FinishRemove,
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

    /// All ten phases against all four evidences: every pairing has one
    /// stated verdict, including the ones only a sweep bug could produce.
    #[test]
    fn every_durable_phase_has_one_recovery_action() {
        // (phase, verdict with a journal or with no sweep, verdict when the
        // sweep ran and found no journal, verdict when the sweep adopted the
        // sandbox's live VM).
        let table = [
            (
                PersistPhase::Creating,
                RecoveryAction::LeaveResumable,
                RecoveryAction::LeaveResumable,
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Starting,
                RecoveryAction::Fail,
                RecoveryAction::RefuseUnjournaled,
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Ready,
                RecoveryAction::Fail,
                RecoveryAction::RefuseUnjournaled,
                RecoveryAction::Reinstate(SandboxState::Ready),
            ),
            (
                PersistPhase::Stopping,
                RecoveryAction::Fail,
                RecoveryAction::RefuseUnjournaled,
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Stopped,
                RecoveryAction::Reinstate(SandboxState::Stopped),
                RecoveryAction::Reinstate(SandboxState::Stopped),
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Failed,
                RecoveryAction::Reinstate(SandboxState::Failed),
                RecoveryAction::Reinstate(SandboxState::Failed),
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Removing,
                RecoveryAction::FinishRemove,
                RecoveryAction::FinishRemove,
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Pausing,
                RecoveryAction::Fail,
                RecoveryAction::Fail,
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Paused,
                RecoveryAction::Reinstate(SandboxState::Paused),
                RecoveryAction::Reinstate(SandboxState::Paused),
                RecoveryAction::RefuseAdopted,
            ),
            (
                PersistPhase::Resuming,
                RecoveryAction::Fail,
                RecoveryAction::Fail,
                RecoveryAction::RefuseAdopted,
            ),
        ];

        assert_eq!(table.len(), 10, "every durable phase is covered");
        for (phase, journaled, unjournaled, adopted) in table {
            for evidence in [JournalEvidence::Swept, JournalEvidence::Unchecked] {
                assert_eq!(plan(phase, evidence), journaled, "{phase:?} {evidence:?}");
            }
            assert_eq!(
                plan(phase, JournalEvidence::Unjournaled),
                unjournaled,
                "{phase:?} unjournaled"
            );
            assert_eq!(
                plan(phase, JournalEvidence::Adopted),
                adopted,
                "{phase:?} adopted"
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
