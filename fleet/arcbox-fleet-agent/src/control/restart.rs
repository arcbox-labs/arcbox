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

/// Whether a restart has been requested, and in which mode. Readable
/// synchronously after the async shutdown completes, which is why this is an
/// atomic rather than living in the supervisor's `Mutex<State>`.
#[derive(Debug, Default)]
pub struct RestartIntent(AtomicU8);

impl RestartIntent {
    /// Record `mode`, returning whether this call is the one that changed
    /// the intent — the caller uses that to drive the shutdown exactly once.
    /// `Force` upgrades a pending `Graceful` (an operator escalating past a
    /// job that will not finish); `Graceful` never downgrades a pending
    /// `Force`, and a repeated request is a no-op.
    pub fn request(&self, mode: RestartMode) -> bool {
        let requested = match mode {
            RestartMode::Graceful => GRACEFUL,
            RestartMode::Force => FORCE,
        };
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (requested > current).then_some(requested)
            })
            .is_ok()
    }

    /// The recorded mode, or `None` while no restart has been requested
    /// (the [`Default`] state, [`NONE`]).
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
        assert!(intent.request(RestartMode::Graceful));
        assert!(!intent.request(RestartMode::Graceful));
        assert_eq!(intent.mode(), Some(RestartMode::Graceful));
    }

    #[test]
    fn force_upgrades_a_pending_graceful() {
        let intent = RestartIntent::default();
        assert!(intent.request(RestartMode::Graceful));
        assert!(intent.request(RestartMode::Force));
        assert_eq!(intent.mode(), Some(RestartMode::Force));
    }

    #[test]
    fn graceful_never_downgrades_a_pending_force() {
        let intent = RestartIntent::default();
        assert!(intent.request(RestartMode::Force));
        assert!(!intent.request(RestartMode::Graceful));
        assert_eq!(intent.mode(), Some(RestartMode::Force));
    }
}
