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
pub(super) enum Provision {
    /// `warm` = a warm-snapshot publish ticket was taken, so the boot tail
    /// must checkpoint the idle guest before announcing readiness.
    Boot {
        warm: bool,
    },
    Restore {
        origin: RestoreOrigin,
    },
}

/// Why a restore is running. Mirrors `sandbox::checkpoint::RestoreOrigin`,
/// which is `pub(in crate::sandbox)` and so unreachable from here; PR-F
/// unifies them when the restore task moves into this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RestoreOrigin {
    /// The Restore RPC: the computer announces itself with READY alone.
    Restore,
    /// The warm-create reroute (CORE-77): watchers must see CREATED then
    /// READY, and the spec's initial `cmd` runs after Ready.
    WarmCreate,
}

/// Why a pause is running; projects onto the PAUSING event's `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PauseReason {
    Requested,
    IdleTimeout,
}

impl PauseReason {
    /// The wire reason the PAUSING event reports.
    pub(super) fn as_str(self) -> &'static str {
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
    ClaimWorkload {
        claim: WorkloadClaim,
    },
    WorkloadExited,
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
    /// A recoverable failure: whatever usable state the computer had survives.
    Failure,
    /// The guest is quiesced with no verb able to thaw it — the port is
    /// hold-then-kill by design, so it cannot go back to `Ready`.
    Frozen,
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
}
