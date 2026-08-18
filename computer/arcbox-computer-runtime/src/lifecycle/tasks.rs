//! The slow work a lifecycle transition asks for: one verb per `Spawn*`
//! effect, run in a sub-task the actor owns.
//!
//! The machine decides *that* a flow should run and the actor sequences it;
//! this port runs it. Keeping the two apart is what makes the actor's
//! sequencing — preemption, epochs, the boot's resource handoff, the parked
//! replies — testable with no VMM, no driver and no record store, and it is
//! the seam R3 PR-F1 moves the flow bodies onto one file at a time while the
//! manager still drives them.
//!
//! Every verb reports back exactly once. A failure says which *class* it is,
//! because that is what the machine branches on: a recoverable one leaves the
//! computer where it was ([`TaskFailure::recoverable`]), a frozen guest cannot
//! go back to `Ready` ([`TaskFailure::frozen`]).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::oneshot;

pub mod boot;
pub mod checkpoint;
pub mod pause;
pub mod release;
pub mod restore;
pub mod resume;

use super::effect::ReleaseScope;
use super::event::{Event, RestoreOrigin};
use crate::agent::GuestAgent;
use crate::error::VmmError;
use crate::sandbox::CheckpointInfo;
use crate::sandbox::record::SandboxProvisionOutcome;

/// What a sub-task hands back: its own success value, or the failure class
/// the machine branches on.
pub type TaskResult<T = ()> = std::result::Result<T, TaskFailure>;

/// A sub-task failure: the error the caller gets, plus the class the machine
/// branches on.
///
/// The event is private so a failure can only be built through the
/// constructors below — an arbitrary `Event` here would let a task's error
/// path drive the machine anywhere.
#[derive(Debug)]
pub struct TaskFailure {
    event: Event,
    error: VmmError,
}

impl TaskFailure {
    /// Whatever usable state the computer had survives: the flow unwound what
    /// it had allocated.
    pub fn recoverable(error: VmmError) -> Self {
        Self {
            event: Event::Failure,
            error,
        }
    }

    /// The guest is quiesced with no verb able to thaw it: the port is
    /// hold-then-kill by design, so the computer cannot go back to `Ready`.
    pub fn frozen(error: VmmError) -> Self {
        Self {
            event: Event::Frozen,
            error,
        }
    }

    /// The flow could not unwind what it had allocated, so the computer
    /// cannot go back to the phase it came from — see [`Event::Stranded`].
    pub fn stranded(error: VmmError) -> Self {
        Self {
            event: Event::Stranded,
            error,
        }
    }

    /// The event this failure drives the machine with.
    pub(super) fn event(&self) -> Event {
        self.event.clone()
    }

    /// The reason as the FAILED event and the durable record carry it.
    pub(super) fn message(&self) -> String {
        self.error.to_string()
    }

    /// The error the parked caller gets.
    pub(super) fn into_error(self) -> VmmError {
        self.error
    }
}

/// The flows the actor spawns. One method per `Spawn*` effect.
#[async_trait]
pub trait ComputerTasks: Send + Sync + 'static {
    /// Boot the VM and wait for the guest agent to announce itself.
    ///
    /// `handed_off` is signalled once every cleanup resource the boot
    /// allocated belongs to the computer rather than to this task — until
    /// then aborting the task would strand one, which is why the actor waits
    /// for it before it may abort. `warm` asks the boot tail to publish a
    /// warm snapshot before readiness is announced.
    async fn boot(
        &self,
        warm: bool,
        handed_off: oneshot::Sender<()>,
    ) -> TaskResult<Arc<dyn GuestAgent>>;

    /// The readiness gate: the warm publish, the initial `cmd` and the ready
    /// probe — everything READY is withheld for.
    async fn gate(&self) -> TaskResult;

    /// Restore the computer from a checkpoint, up to the point where the
    /// guest is configured and reachable.
    async fn restore(
        &self,
        origin: RestoreOrigin,
    ) -> TaskResult<(Arc<dyn GuestAgent>, SandboxProvisionOutcome)>;

    /// Capture a checkpoint. `hold` keeps the guest quiesced afterwards (the
    /// pause path): progress past the memory image would diverge from the
    /// retained disk overlay.
    async fn checkpoint(&self, hold: bool) -> TaskResult<CheckpointInfo>;

    /// Restore a paused computer in place, back onto a fresh network.
    async fn resume(&self) -> TaskResult<Arc<dyn GuestAgent>>;

    /// Shut the guest down and release its runtime resources within
    /// `budget`. `drain` gives a running workload the budget to finish
    /// first.
    async fn stop(&self, budget: Duration, drain: bool) -> TaskResult;

    /// Release the resources `scope` names.
    async fn release(&self, scope: ReleaseScope) -> TaskResult;
}
