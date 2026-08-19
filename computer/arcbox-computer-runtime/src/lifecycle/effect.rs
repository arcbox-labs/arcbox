//! What the computer lifecycle asks for: the effects a transition emits, and
//! the buffer the actor reads them out of.
//!
//! The machine only *describes* what should happen. The actor owns the driver
//! handle, the record store, the network, the timers and the event bus, and is
//! the sole executor.

use super::event::RestoreOrigin;
use crate::sandbox::record::PersistPhase;

/// Lifecycle notification a transition asks the actor to publish. 1:1 with
/// `sandbox::types::action`; the actor adds the event's attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Notify {
    Created,
    Ready,
    Running,
    Idle,
    Stopping,
    Stopped,
    Failed,
    Removed,
    Pausing,
    Paused,
    Resumed,
}

/// How hard a durable write is pushed — the three shapes today's code has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Durability {
    /// Warn and continue: `Stopping`, `Pausing`, `Removing`, the two reverts.
    Warn,
    /// The crash journal may only be cleared once the write is confirmed:
    /// `Stopped`, `Paused`, `Failed`.
    GateJournal,
    /// An unconfirmed write is reported to the caller.
    Report(Unconfirmed),
}

/// What an unconfirmed durable write costs the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unconfirmed {
    /// Visible but not proven durable (`AckUnconfirmed`).
    Ack,
    /// Refuse the operation (`Unavailable`) — the READY commit.
    Unavailable,
    /// Park the record back at `Paused` and refuse: the restart sweep trusts
    /// the phase, so an unconfirmed `Resuming` would read as cleanly paused
    /// and the restore's journaled resources would never be released.
    RevertToPaused,
}

/// Which resources a release drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseScope {
    /// VMM (and the area its files were staged into, which the driver
    /// takes with it), CoW, TAP + IP; the record stays inspectable.
    Runtime,
    /// The pause release: the same, but the disk overlay is retained.
    KeepDisk,
    /// Everything, including retained pause state and the working directory.
    Full,
}

/// How a durable record ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordEnd {
    /// `abort_provision`: an intent nobody acknowledged.
    Aborted,
    /// `finish_remove`: the tombstone of a completed removal.
    Removed,
}

/// The two lifecycle timers: the hard lifetime cap, and the idle window that
/// is armed only while `ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Timer {
    Ttl,
    Idle,
}

/// A reply a transition owes parked callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Answer {
    Ready,
    Resumed,
    Paused,
    Stopped,
    Removed,
}

/// A side effect emitted by a transition, executed by the actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Effect {
    PersistPhase {
        phase: PersistPhase,
        durability: Durability,
    },
    /// `Ready` reached in one hop from `Creating`: the restore path's atomic
    /// commit, which carries the provision outcome the skipped `Starting`
    /// write would have persisted. It is the one durable move outside the
    /// edge set — `ComputerRecord::apply` allows it only from `Creating`
    /// (`atomic_ready`), so no other state may emit it.
    CommitRestored {
        durability: Durability,
    },
    ForgetRecord(RecordEnd),
    SpawnBoot {
        warm: bool,
    },
    SpawnRestore {
        origin: RestoreOrigin,
    },
    /// Warm publish, initial `cmd`, ready probe.
    SpawnGate,
    /// `hold` keeps the guest quiesced afterwards (the pause path): guest
    /// progress past the memory image would diverge from the retained overlay.
    SpawnCheckpoint {
        hold: bool,
    },
    SpawnResume,
    SpawnStop {
        budget_ms: u64,
        /// Whether a workload is running and owed the budget to finish
        /// before the guest is asked to shut down.
        drain: bool,
    },
    SpawnRelease {
        scope: ReleaseScope,
    },
    /// Wait out the boot task's resource handoff, then abort it.
    AbortInflight,
    Publish(Notify),
    ArmTimer(Timer),
    CancelTimer(Timer),
    Answer(Answer),
    /// Clear the crash journal — only ever after a confirmed durable write.
    ClearJournal,
}

/// External context: the effect sink a dispatch writes into. Owned by the
/// actor and passed by `&mut` to every `handle_with_context`.
#[derive(Debug, Default)]
pub(super) struct Effects {
    items: Vec<Effect>,
}

impl Effects {
    pub(super) fn emit(&mut self, effect: Effect) {
        self.items.push(effect);
    }

    pub(super) fn persist(&mut self, phase: PersistPhase, durability: Durability) {
        self.emit(Effect::PersistPhase { phase, durability });
    }

    pub(super) fn release(&mut self, scope: ReleaseScope) {
        self.emit(Effect::SpawnRelease { scope });
    }

    /// The graceful stop: `stop_sandbox`. `drain` says whether a workload is
    /// running and owed the budget to finish first — the machine knows,
    /// because it is the state the stop came from.
    pub(super) fn stop(&mut self, budget_ms: u64, drain: bool) {
        self.persist(PersistPhase::Stopping, Durability::Warn);
        self.emit(Effect::CancelTimer(Timer::Idle));
        self.emit(Effect::Publish(Notify::Stopping));
        self.emit(Effect::SpawnStop { budget_ms, drain });
    }

    /// Shared teardown: what `remove_sandbox_impl` does once its busy gate has
    /// passed. The bounded handoff wait lives inside `AbortInflight`.
    pub(super) fn removal(&mut self) {
        self.emit(Effect::AbortInflight);
        self.emit(Effect::CancelTimer(Timer::Ttl));
        self.emit(Effect::CancelTimer(Timer::Idle));
        self.persist(PersistPhase::Removing, Durability::Warn);
        self.release(ReleaseScope::Full);
    }

    /// Shared failure: `sandbox::boot::fail_live_sandbox` — persist `Failed`,
    /// release the runtime, clear the journal behind both, drop the timers,
    /// publish FAILED. The journal clear is gated on the write being
    /// confirmed *and* the release completing: what it records is the
    /// resources a restart would otherwise have to reclaim.
    pub(super) fn failure(&mut self) {
        self.persist(PersistPhase::Failed, Durability::GateJournal);
        self.release(ReleaseScope::Runtime);
        self.emit(Effect::ClearJournal);
        self.emit(Effect::CancelTimer(Timer::Idle));
        self.emit(Effect::CancelTimer(Timer::Ttl));
        self.emit(Effect::Publish(Notify::Failed));
    }

    /// Drains the effects accumulated since the last call.
    pub(super) fn take(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.items)
    }
}
