//! The two questions asked about a lifecycle state: what a caller sees, and
//! what a crash-restart reads back.
//!
//! They are deliberately different. `running` is the workload hot path and
//! writes no record, so it is durably `Ready`; `gating` and `removing` have no
//! `SandboxState` of their own.

use super::machine::State;
use crate::sandbox::SandboxState;
use crate::sandbox::record::PersistPhase;

impl State {
    /// What a caller sees. Today a gated computer reads `Starting` (a boot
    /// owing its initial `cmd` holds it there) and a removal writes `Stopping`.
    pub(super) fn to_public(self) -> SandboxState {
        match self {
            Self::Provisioning {}
            | Self::Staging {}
            | Self::Booting {}
            | Self::Restoring {}
            | Self::Resuming {} => SandboxState::Starting,
            // A gate whose reservation the boot's own `cmd` has taken is
            // already running that workload, which is what a caller sees.
            Self::Gating { claimed: false, .. } => SandboxState::Starting,
            Self::Gating { claimed: true, .. } => SandboxState::Running,
            Self::Ready {} | Self::Checkpointing {} => SandboxState::Ready,
            Self::Running {} => SandboxState::Running,
            Self::Capturing {} | Self::Releasing {} => SandboxState::Pausing,
            Self::Paused {} => SandboxState::Paused,
            Self::Stopping {} | Self::Removing {} => SandboxState::Stopping,
            // A removed computer is gone from the map; nothing reads `gone`.
            Self::Stopped {} | Self::Gone {} => SandboxState::Stopped,
            Self::Failed {} => SandboxState::Failed,
        }
    }

    /// What a crash-restart reads back, or `None` when no record answers.
    ///
    /// The phase **in effect** while the machine sits here, not the one its
    /// entry writes: `running`/`checkpointing` write nothing and are durably
    /// `Ready`, and `provisioning`/`restoring` sit on the `Creating` intent
    /// reserved before the machine was driven.
    ///
    /// `gating` is the leaf a computer reaches by two paths whose durable
    /// phase differs — a cold boot commits `Ready` *after* the ready probe, so
    /// a probe failure fails from the recorded `Starting`, while a restore
    /// commits it *before*, so a crash mid-probe reconciles as a dead-but-Ready
    /// computer. Both orderings are load-bearing and documented at their sites,
    /// which is why the state carries the discriminator rather than the
    /// projection guessing.
    pub(super) fn durable(self) -> Option<PersistPhase> {
        match self {
            Self::Provisioning {} | Self::Restoring {} => Some(PersistPhase::Creating),
            Self::Staging {} | Self::Booting {} => Some(PersistPhase::Starting),
            // A cold boot arrives here still `Starting` and commits `Ready`
            // after the probe; a restore arrives already committed.
            Self::Gating { committed, .. } => Some(if committed {
                PersistPhase::Ready
            } else {
                PersistPhase::Starting
            }),
            Self::Gone {} => None,
            Self::Ready {} | Self::Running {} | Self::Checkpointing {} => Some(PersistPhase::Ready),
            Self::Capturing {} | Self::Releasing {} => Some(PersistPhase::Pausing),
            Self::Paused {} => Some(PersistPhase::Paused),
            Self::Resuming {} => Some(PersistPhase::Resuming),
            Self::Stopping {} => Some(PersistPhase::Stopping),
            Self::Stopped {} => Some(PersistPhase::Stopped),
            Self::Failed {} => Some(PersistPhase::Failed),
            Self::Removing {} => Some(PersistPhase::Removing),
        }
    }
}
