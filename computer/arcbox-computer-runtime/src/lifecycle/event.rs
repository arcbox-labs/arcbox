//! What the computer lifecycle is told: manager commands, sub-task
//! completions, and observations. Every variant has a producer; none is dead
//! vocabulary.

use crate::sandbox::record::PersistPhase;
use crate::sandbox::workload::WorkloadClaim;
use crate::sandbox::{IdleAction, pause_reason};

/// How a provisioned computer comes up. The two arms carry what the flows
/// decide before the machine is driven: whether a warm-publish ticket was
/// taken, and which restore this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provision {
    /// `warm` = a warm-snapshot publish ticket was taken, so the boot tail
    /// must checkpoint the idle guest before announcing readiness.
    Boot {
        warm: bool,
    },
    Restore {
        origin: RestoreOrigin,
    },
}

/// Why a restore is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOrigin {
    /// The Restore RPC: the computer announces itself with READY alone.
    Restore,
    /// The warm-create reroute (CORE-77): watchers must see CREATED then
    /// READY, and the spec's initial `cmd` runs after Ready.
    WarmCreate,
}

/// Why a pause is running; projects onto the PAUSING event's `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    Requested,
    IdleTimeout,
}

impl PauseReason {
    /// The wire reason the PAUSING event reports.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Requested => pause_reason::PAUSE,
            Self::IdleTimeout => pause_reason::IDLE_TIMEOUT,
        }
    }
}

/// A lifecycle event: a manager command, a sub-task completion, or an
/// observation. Every variant has a producer; none is dead vocabulary.
#[derive(Debug, Clone)]
pub(super) enum Event {
    // Manager commands. `ProvisionIntent` answers `Replay`/`Blocked` from the
    // record store without driving a machine at all.
    Provision(Provision),
    Checkpoint,
    Pause {
        reason: PauseReason,
    },
    Resume,
    /// `budget_ms` covers workload drain plus guest shutdown.
    Stop {
        budget_ms: u64,
    },
    /// `force: false` is refused while the computer is busy.
    Remove {
        force: bool,
    },
    /// Give the VM up without stopping it, so the next process can adopt it.
    /// Only the states holding a settled live handle act on it; everywhere
    /// else the actor answers, because a computer mid-launch or mid-teardown
    /// has nothing a successor could take.
    Detach,
    ClaimWorkload {
        claim: WorkloadClaim,
    },
    /// The workload ended — with an exit status, or with the session broken
    /// before one arrived. Both publish IDLE; the actor holds which.
    WorkloadExited,
    /// The claim was given back without a workload ever running: the guest
    /// refused the dispatch the claim was taken for. Nothing to announce —
    /// the computer simply goes back to accepting work.
    WorkloadReleased,
    // Sub-task completions.
    /// The boot task transferred every cleanup resource onto the computer, so
    /// aborting it can no longer strand one.
    ResourcesHandedOff,
    /// The guest agent dialed back: the readiness gate accepted.
    AgentReady,
    /// A restore — from a checkpoint, or of a paused computer — completed.
    Restored,
    /// The readiness gate finished (warm publish, initial `cmd`, ready probe),
    /// so READY may be announced.
    Gated,
    CaptureDone {
        snapshot_id: String,
    },
    ReleasedForPause,
    StopDone,
    RemoveDone,
    /// The handover succeeded: the VM is the next process's, and dropping this
    /// process's handle no longer kills it. Raised by the effect rather than by
    /// a sub-task — a handover that *failed* leaves the computer exactly where
    /// it was, so there is no failure edge to model.
    Detached,
    /// A recoverable failure: whatever usable state the computer had survives.
    Failure,
    /// The guest is quiesced with no verb able to thaw it — the port is
    /// hold-then-kill by design, so it cannot go back to `Ready`.
    Frozen,
    /// A failure whose unwind did not complete: resources the flow allocated
    /// are still held, so the computer cannot go back to the phase it came
    /// from.
    ///
    /// The distinction is crash safety, not cosmetics. A resume that unwound
    /// leaves the retained pause state intact and parks back at `Paused`; one
    /// that did not leaves a half-allocated computer, and recording that as
    /// cleanly `Paused` would have the restart sweep `Reinstate` it as
    /// resumable and drop its journal as a stale pause. `resume_sandbox`
    /// has always been two-valued here (`ResumeFailure::unwound`); the
    /// vocabulary now is too.
    Stranded,
    // Observations.
    /// The VM exited without being asked to.
    VmExited,
    TtlExpired,
    IdleExpired {
        action: IdleAction,
    },
    /// Startup recovery reconstructed a computer from its durable record.
    Recovered {
        phase: PersistPhase,
    },
    /// The startup sweep found this computer's VM still running and took it
    /// back, with its lease, its disk overlay and its handle. It never
    /// stopped being usable, and it never booted in this process — the one
    /// way into `ready` that runs no launch.
    Adopted,
}
