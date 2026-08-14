//! How this process image ends, and the one place that decides it.
//!
//! Three things can retire a running agent: a self-update the gateway
//! requires, an operator `Restart`, and a termination signal. They differ only
//! in what happens *after* the teardown, so they share everything before it —
//! the same shutdown token, so the agent always takes one teardown path, and
//! the same "no new offers" answer, so admission never has to know which of
//! them is in force.
//!
//! [`Handover`] owns that fact. Its state is a lattice that only ever climbs:
//!
//! ```text
//! None < Update < Restart < ForcedRestart < Terminating
//! ```
//!
//! Escalation is therefore just "record the higher one", and the two rules
//! that used to be enforced by hand fall out of the ordering:
//!
//! - a `--force` restart escalates a graceful one that is still waiting on a
//!   job, and a graceful request arriving after it does not walk it back;
//! - [`Reason::Terminating`] is the top and is set only by the signal handler,
//!   so a SIGTERM landing on an agent that is waiting out its last job stops
//!   the process instead of restarting it. The alternative — a shutdown token
//!   cancelled by either party, with no record of which — cannot tell a
//!   stop from a restart, and under `launchctl bootout` the job would
//!   resurrect itself and die only at `ExitTimeOut`.
//!
//! The one revocable transition is a self-update that became moot (the pin
//! moved back to this build before the swap). It is a compare-exchange from
//! exactly [`Reason::Update`], which is why it cannot clear a restart that has
//! escalated past it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::state::AgentState;

/// Why this process image is going away, and how much running work that is
/// allowed to disturb.
///
/// The discriminants are the lattice: [`Handover`] compares and stores them as
/// `u8`, so the declaration order below is load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Reason {
    /// Not going anywhere.
    None = 0,
    /// A self-update is staged. Revocable — see [`Handover::update_became_moot`].
    Update = 1,
    /// An operator restart. Waits for in-flight jobs; latching.
    Restart = 2,
    /// An operator restart that will not wait: in-flight jobs are cancelled,
    /// tearing down their runner process groups and containers.
    ForcedRestart = 3,
    /// A termination signal. Terminal: the process was told to stop, so
    /// nothing may turn its shutdown back into a re-exec.
    Terminating = 4,
}

impl Reason {
    fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::Update,
            2 => Self::Restart,
            3 => Self::ForcedRestart,
            4 => Self::Terminating,
            // Only `ReasonCell` writes this cell, and only from `Reason as u8`.
            _ => Self::None,
        }
    }
}

/// The single cell holding the [`Reason`] in force, shared between
/// [`Handover`] and the [`AgentState`] that publishes the observable draining
/// flag.
///
/// It is a type of its own for one reason: the flag must be *derived* from the
/// live reason inside the watch channel's write lock
/// ([`AgentState::refresh_draining`]), never mirrored from a bool computed
/// before that lock is taken. A precomputed mirror loses updates — two
/// transitions racing each compute from their own pre-store snapshot, and the
/// loser republishes a value that nothing afterwards corrects, because a
/// handover happens a handful of times per process and never unwinds.
///
/// [`Handover`] is the only writer, and every transition rule lives there.
pub struct ReasonCell(AtomicU8);

impl ReasonCell {
    pub(crate) fn new() -> Self {
        Self(AtomicU8::new(Reason::None as u8))
    }

    /// The reason in force.
    pub fn current(&self) -> Reason {
        Reason::from_u8(self.0.load(Ordering::Relaxed))
    }

    /// Whether this image is on its way out — what admission and the
    /// observable flag consult. True for a termination too: the process is
    /// stopping either way, and admitting a job into a teardown only means
    /// killing it.
    pub fn pending(&self) -> bool {
        self.current() != Reason::None
    }

    /// Climb the lattice to `reason`, returning what was in force before.
    fn escalate(&self, reason: Reason) -> Reason {
        Reason::from_u8(self.0.fetch_max(reason as u8, Ordering::Relaxed))
    }

    /// Drop back to [`Reason::None`] from exactly [`Reason::Update`], leaving
    /// anything that escalated past it in force. Reports whether it cleared.
    fn revoke_update(&self) -> bool {
        self.0
            .compare_exchange(
                Reason::Update as u8,
                Reason::None as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Jump to the top of the lattice, unconditionally.
    fn terminate(&self) {
        self.0.store(Reason::Terminating as u8, Ordering::Relaxed);
    }
}

/// What a [`Handover::request`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requested {
    /// This call recorded the reason; the caller drives the teardown.
    Recorded,
    /// The same or a stronger reason is already in force, and this request
    /// rides it.
    AlreadyPending,
    /// The process is shutting down for good; no handover is possible.
    ShuttingDown,
}

/// How the process is meant to end, read once the teardown has finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Terminate normally.
    Exit,
    /// Replace this process image with this binary, preserving argv (see
    /// [`crate::reexec`]). The running executable for a restart, the freshly
    /// swapped managed binary for a self-update.
    Exec(PathBuf),
}

/// The shared "this image is going away" fact: which reason is in force, the
/// shutdown token every teardown path runs on, and the mirror of both onto the
/// observable [`AgentState`].
///
/// Shared between the local control plane (which records operator restarts),
/// the attach loop (self-updates), the runner supervisor (which reads it to
/// close admission) and the signal handler (which vetoes the lot).
pub struct Handover {
    /// The reason cell `state` derives its observable draining flag from — the
    /// same allocation, not a copy, so the two can never disagree.
    reason: Arc<ReasonCell>,
    /// The image to replace this one with, recorded by [`Handover::commit`].
    /// Set at most once — see there for why first-commit-wins is the right
    /// tie-break.
    exec: OnceLock<PathBuf>,
    shutdown: CancellationToken,
    state: AgentState,
}

impl Handover {
    /// Build a handover over a fresh shutdown token, writing into the reason
    /// cell `state` already holds. Every transition republishes the observable
    /// draining flag, so no caller has to remember to mirror one.
    pub fn new(state: AgentState) -> Arc<Self> {
        Arc::new(Self {
            reason: Arc::clone(state.handover_reason()),
            exec: OnceLock::new(),
            shutdown: CancellationToken::new(),
            state,
        })
    }

    /// The token every long-running task shuts down on. Cancelled by
    /// [`Self::terminate`] and by [`Self::commit`]; child tokens (one per
    /// attachment) cascade from it.
    pub fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// Record `reason`, escalating monotonically.
    ///
    /// Recording only closes admission; bringing the process down is the
    /// caller's next step, because a graceful restart has to wait for the
    /// supervisor to quiesce first (see [`Self::commit`]).
    pub fn request(&self, reason: Reason) -> Requested {
        let previous = self.reason.escalate(reason);
        let requested = if previous == Reason::Terminating {
            Requested::ShuttingDown
        } else if previous >= reason {
            Requested::AlreadyPending
        } else {
            Requested::Recorded
        };
        self.mirror();
        requested
    }

    /// Clear a self-update that became moot — the pin moved back to this build
    /// before the swap (a rollback racing the drain), so admission may reopen.
    ///
    /// A compare-exchange from exactly [`Reason::Update`]: an operator restart
    /// that escalated past it, or a termination signal, is left in force. That
    /// is the whole reason this is not a plain store — a process committed to
    /// re-exec must not start admitting jobs that its own teardown will kill.
    pub fn update_became_moot(&self) {
        if self.reason.revoke_update() {
            self.mirror();
            info!("self-update became moot; resuming");
        }
    }

    /// Commit to the handover: record `binary` as the image to come back as,
    /// then bring the process down so the teardown can run and
    /// [`Self::outcome`] be read on the other side.
    ///
    /// `binary` is resolved before the teardown starts, never after: the
    /// restart path resolves `current_exe` while answering the RPC, and the
    /// self-update path has already swapped the managed binary into place. A
    /// path that cannot be produced is therefore an error the caller can still
    /// report, rather than one that surfaces after the agent has torn itself
    /// down with nothing to come back as.
    pub fn commit(&self, binary: PathBuf) {
        if let Err(ignored) = self.exec.set(binary) {
            // Two commits raced — a forced restart landing while a graceful
            // one was still quiescing, or a self-update landing during a
            // restart's drain. First wins, and that is safe because every
            // path names the same file: a restart commits `current_exe`, and
            // self-update refuses to run unless `current_exe` *is* the managed
            // binary (`update::ensure_managed`), whose new bytes are already
            // swapped in before it commits.
            info!(
                ignored = %ignored.display(),
                committed = %self.exec.get().expect("set() only fails when already set").display(),
                "handover already committed to an image"
            );
        }
        self.shutdown.cancel();
    }

    /// Record that the process is stopping for good, then cancel — in that
    /// order, so no task can observe the cancellation before the veto and
    /// mistake a termination for the restart it was waiting on.
    pub fn terminate(&self) {
        self.reason.terminate();
        self.mirror();
        self.shutdown.cancel();
    }

    /// The reason in force.
    pub fn reason(&self) -> Reason {
        self.reason.current()
    }

    /// Whether this image is on its way out — what admission consults; see
    /// [`ReasonCell::pending`].
    pub fn pending(&self) -> bool {
        self.reason.pending()
    }

    /// How to end the process. Read after the teardown, not at request time: a
    /// termination signal arriving mid-restart clears the intent, so "a
    /// restart was requested" and "this shutdown is a restart" are different
    /// questions.
    pub fn outcome(&self) -> Outcome {
        match (self.reason(), self.exec.get()) {
            (Reason::None | Reason::Terminating, _) => Outcome::Exit,
            (_, Some(binary)) => Outcome::Exec(binary.clone()),
            // Unreachable in practice: only `commit` and `terminate` cancel
            // the shutdown, and the first arm covers the latter. Exiting is
            // the safe reading of "something else stopped us" — coming back
            // uncommitted would defy whatever did.
            (reason, None) => {
                warn!(?reason, "shutdown without a committed image; exiting");
                Outcome::Exit
            }
        }
    }

    /// Republish the observable draining flag. Deliberately passes no value:
    /// the state reads this very cell under its write lock, which is what keeps
    /// two racing transitions from publishing a stale flag (see [`ReasonCell`]).
    fn mirror(&self) {
        self.state.refresh_draining();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::PersistedSettings;

    /// Only the observable draining flag is under test here, so the rest of
    /// the seed is whatever a fresh install would carry.
    fn seed() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            linux_runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: crate::config::DockerMode::Auto,
            runner_script: None,
            windows_runner_script: None,
            participate: true,
            vm_mode: crate::config::VmMode::Auto,
            macos_runner_image: "tahoe-base".to_owned(),
        }
    }

    fn handover() -> Arc<Handover> {
        Handover::new(AgentState::new(&seed()))
    }

    #[test]
    fn a_first_request_is_recorded_and_a_repeat_is_not() {
        let handover = handover();
        assert_eq!(handover.reason(), Reason::None);
        assert_eq!(handover.request(Reason::Restart), Requested::Recorded);
        assert_eq!(handover.request(Reason::Restart), Requested::AlreadyPending);
        assert_eq!(handover.reason(), Reason::Restart);
    }

    #[test]
    fn force_upgrades_a_pending_graceful_restart() {
        let handover = handover();
        assert_eq!(handover.request(Reason::Restart), Requested::Recorded);
        assert_eq!(handover.request(Reason::ForcedRestart), Requested::Recorded);
        assert_eq!(handover.reason(), Reason::ForcedRestart);
    }

    #[test]
    fn graceful_never_downgrades_a_pending_force() {
        let handover = handover();
        assert_eq!(handover.request(Reason::ForcedRestart), Requested::Recorded);
        assert_eq!(handover.request(Reason::Restart), Requested::AlreadyPending);
        assert_eq!(handover.reason(), Reason::ForcedRestart);
    }

    /// A termination signal reaching a pending restart must leave nothing to
    /// re-exec: `serve` reads the outcome after the shutdown it shares with the
    /// signal handler, and cannot otherwise tell which of them cancelled it.
    #[test]
    fn termination_vetoes_a_pending_restart_and_every_later_one() {
        let handover = handover();
        assert_eq!(handover.request(Reason::Restart), Requested::Recorded);

        handover.terminate();

        assert_eq!(handover.outcome(), Outcome::Exit);
        assert!(handover.shutdown().is_cancelled());
        assert_eq!(
            handover.request(Reason::ForcedRestart),
            Requested::ShuttingDown
        );
        assert_eq!(handover.outcome(), Outcome::Exit);
    }

    /// A committed handover names the image `main` comes back as.
    #[test]
    fn a_committed_handover_yields_the_image_to_exec() {
        let handover = handover();
        handover.request(Reason::Restart);
        handover.commit(PathBuf::from("/opt/arcbox-fleet-agent"));

        assert!(handover.shutdown().is_cancelled());
        assert_eq!(
            handover.outcome(),
            Outcome::Exec(PathBuf::from("/opt/arcbox-fleet-agent"))
        );
    }

    /// The signal wins even against a restart that already committed: both
    /// cancel the same token, so without the veto the process would come back
    /// after being told to stop. This is the window between a graceful
    /// restart's last job releasing and `serve` reading the outcome.
    #[test]
    fn termination_after_a_commit_still_exits() {
        let handover = handover();
        handover.request(Reason::Restart);
        handover.commit(PathBuf::from("/opt/arcbox-fleet-agent"));

        handover.terminate();

        assert_eq!(handover.outcome(), Outcome::Exit);
    }

    /// The revocation is scoped to the reason that owns it. A restart is not an
    /// update, so a moot update cannot reopen admission underneath it — the
    /// jobs admitted in that window would be killed by the teardown the restart
    /// is waiting to run.
    #[test]
    fn a_moot_update_clears_only_an_update() {
        let update = handover();
        update.request(Reason::Update);
        update.update_became_moot();
        assert_eq!(update.reason(), Reason::None);
        assert!(!update.pending());

        let escalated = handover();
        escalated.request(Reason::Update);
        escalated.request(Reason::Restart);
        escalated.update_became_moot();
        assert_eq!(escalated.reason(), Reason::Restart);
        assert!(escalated.pending());

        let terminating = handover();
        terminating.request(Reason::Update);
        terminating.terminate();
        terminating.update_became_moot();
        assert_eq!(terminating.reason(), Reason::Terminating);
    }

    /// Every transition mirrors onto the observable flag, so a client watching
    /// the agent sees it stop accepting work without any writer having to
    /// remember to say so.
    #[test]
    fn the_observable_draining_flag_tracks_the_reason() {
        let state = AgentState::new(&seed());
        let handover = Handover::new(state.clone());
        assert!(!state.current().draining);

        handover.request(Reason::Update);
        assert!(state.current().draining);

        handover.update_became_moot();
        assert!(!state.current().draining);

        handover.request(Reason::Restart);
        assert!(state.current().draining);
    }

    /// The operator's drain and the handover are independent inputs to that
    /// one flag: neither may clear the other.
    #[test]
    fn an_operator_drain_and_a_handover_do_not_clear_each_other() {
        let state = AgentState::new(&seed());
        let handover = Handover::new(state.clone());

        state.set_operator_draining(true);
        handover.request(Reason::Update);
        handover.update_became_moot();
        assert!(state.current().draining, "the operator drain still holds");

        state.set_operator_draining(false);
        handover.request(Reason::Restart);
        state.set_operator_draining(false);
        assert!(state.current().draining, "the restart still holds");
    }
}
