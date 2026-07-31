//! Operator-requested process restart: the intent recorded by
//! `FleetLifecycleService.Restart`, consumed by [`crate::serve`] once the
//! shutdown it triggers has run to completion.
//!
//! The restart itself is deliberately *not* implemented here as its own
//! teardown path: it cancels the process shutdown token, so the agent takes
//! exactly the SIGTERM route (attach teardown, runner drain, control-server
//! stop), and `serve` re-execs instead of exiting once that finishes.

use std::sync::atomic::{AtomicU8, Ordering};

/// How much in-flight work a restart is allowed to disturb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartMode {
    /// Stop accepting new offers and wait for in-flight jobs to finish
    /// before the re-exec. Unbounded, like a self-update's pre-swap drain: a
    /// restart must never kill a customer's running job.
    Graceful,
    /// Cancel in-flight jobs (tearing down their runner process groups and
    /// containers, bounded by the attach shutdown grace) and re-exec now.
    Force,
}

const NONE: u8 = 0;
const GRACEFUL: u8 = NONE + 1;
const FORCE: u8 = GRACEFUL + 1;
/// A termination signal, which outranks every restart: the process was told
/// to stop, so nothing may turn its shutdown back into a re-exec. Terminal,
/// and the reason the ordering above is load-bearing — [`RestartIntent`]
/// only ever moves up.
const TERMINATING: u8 = FORCE + 1;

/// What a [`RestartIntent::request`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requested {
    /// This call recorded the mode; the caller drives the shutdown.
    Recorded,
    /// A restart in the same or a stronger mode is already under way, and
    /// this request rides it.
    AlreadyPending,
    /// The process is already shutting down for good; no restart is possible.
    ShuttingDown,
}

/// Whether a restart has been requested, and in which mode. Readable
/// synchronously after the async shutdown completes, which is why this is an
/// atomic rather than living in the supervisor's `Mutex<State>`.
///
/// Shared between the supervisor (which records requests) and the shutdown
/// signal handler (which vetoes them), so a SIGTERM racing a pending restart
/// resolves one way: the process stops.
#[derive(Debug, Default)]
pub struct RestartIntent(AtomicU8);

impl RestartIntent {
    /// Record `mode` — monotonically, so `Force` upgrades a pending
    /// `Graceful` (an operator escalating past a job that will not finish),
    /// `Graceful` never downgrades a pending `Force`, and neither can
    /// resurrect a process that is [`TERMINATING`].
    pub fn request(&self, mode: RestartMode) -> Requested {
        let requested = match mode {
            RestartMode::Graceful => GRACEFUL,
            RestartMode::Force => FORCE,
        };
        match self.0.fetch_max(requested, Ordering::Relaxed) {
            TERMINATING => Requested::ShuttingDown,
            previous if previous >= requested => Requested::AlreadyPending,
            _ => Requested::Recorded,
        }
    }

    /// Record that the process is shutting down for good (a termination
    /// signal). Overrides any pending restart, and cannot be overridden: the
    /// last word between "stop" and "come back" belongs to "stop".
    pub fn terminate(&self) {
        self.0.store(TERMINATING, Ordering::Relaxed);
    }

    /// The mode to restart in, or `None` when no restart was requested (the
    /// [`Default`] state, [`NONE`]) or a termination signal vetoed it.
    pub fn mode(&self) -> Option<RestartMode> {
        match self.0.load(Ordering::Relaxed) {
            GRACEFUL => Some(RestartMode::Graceful),
            FORCE => Some(RestartMode::Force),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_request_is_recorded_and_a_repeat_is_not() {
        let intent = RestartIntent::default();
        assert_eq!(intent.mode(), None);
        assert_eq!(intent.request(RestartMode::Graceful), Requested::Recorded);
        assert_eq!(
            intent.request(RestartMode::Graceful),
            Requested::AlreadyPending
        );
        assert_eq!(intent.mode(), Some(RestartMode::Graceful));
    }

    #[test]
    fn force_upgrades_a_pending_graceful() {
        let intent = RestartIntent::default();
        assert_eq!(intent.request(RestartMode::Graceful), Requested::Recorded);
        assert_eq!(intent.request(RestartMode::Force), Requested::Recorded);
        assert_eq!(intent.mode(), Some(RestartMode::Force));
    }

    #[test]
    fn graceful_never_downgrades_a_pending_force() {
        let intent = RestartIntent::default();
        assert_eq!(intent.request(RestartMode::Force), Requested::Recorded);
        assert_eq!(
            intent.request(RestartMode::Graceful),
            Requested::AlreadyPending
        );
        assert_eq!(intent.mode(), Some(RestartMode::Force));
    }

    /// A termination signal reaching a pending restart must leave nothing to
    /// re-exec: `serve` reads `mode()` after the shutdown it shares with the
    /// signal handler, and cannot otherwise tell which of them cancelled it.
    #[test]
    fn termination_vetoes_a_pending_restart_and_every_later_one() {
        let intent = RestartIntent::default();
        assert_eq!(intent.request(RestartMode::Graceful), Requested::Recorded);

        intent.terminate();

        assert_eq!(intent.mode(), None);
        assert_eq!(intent.request(RestartMode::Force), Requested::ShuttingDown);
        assert_eq!(intent.mode(), None);
    }
}
