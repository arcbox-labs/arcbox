//! Lifecycle deadline policy (CORE-21/60): whether a sandbox's TTL and idle
//! timers should be armed at all, and how long is left on one.
//!
//! Pure — `super::super::timers` owns the epoch-stamped slots, the sleeping
//! tasks and the expiry actions, and `crate::lifecycle`'s actor owns the two
//! `Sleep`s that replace them.
//!
//! `pub` below is only the lint's spelling: this module is private and its
//! parent is `pub(crate)`, so these reach the crate and no further.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::sandbox::ComputerState;

/// The TTL deadline to arm for a sandbox in `state`, or `None` when its
/// timer belongs cancelled.
///
/// A terminal sandbox has nothing left to expire, and the live path cancels
/// its TTL on the STOPPED/FAILED edge. Without this guard the restart
/// resync would re-arm one — recovery restores `ttl_deadline` for every
/// record regardless of state — so whether a stopped sandbox's record gets
/// reaped would depend on whether the agent happened to bounce.
pub fn ttl_due(state: ComputerState, deadline: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match state {
        ComputerState::Stopped | ComputerState::Failed => None,
        _ => deadline,
    }
}

/// How long a sandbox in `state` may sit idle before its `on_idle` policy
/// fires, or `None` when its timer belongs cancelled.
///
/// Idle detection only makes sense while a sandbox is `Ready`: every other
/// state either has a workload running or is on its way out.
pub fn idle_due(state: ComputerState, timeout_seconds: u32) -> Option<Duration> {
    (state == ComputerState::Ready && timeout_seconds != 0)
        .then(|| Duration::from_secs(u64::from(timeout_seconds)))
}

/// How long is left until `deadline`; an already-past deadline is due now.
pub fn remaining(deadline: DateTime<Utc>, now: DateTime<Utc>) -> Duration {
    (deadline - now).to_std().unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STATES: [ComputerState; 8] = [
        ComputerState::Starting,
        ComputerState::Ready,
        ComputerState::Running,
        ComputerState::Stopping,
        ComputerState::Stopped,
        ComputerState::Failed,
        ComputerState::Pausing,
        ComputerState::Paused,
    ];

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    #[test]
    fn only_a_terminal_sandbox_drops_its_ttl() {
        let deadline = at(1_700_000_000);
        for state in ALL_STATES {
            let terminal = matches!(state, ComputerState::Stopped | ComputerState::Failed);
            // A paused sandbox still expires: the TTL caps total lifetime
            // regardless of activity.
            assert_eq!(
                ttl_due(state, Some(deadline)),
                (!terminal).then_some(deadline),
                "{state}"
            );
            assert_eq!(ttl_due(state, None), None, "{state} without a deadline");
        }
    }

    #[test]
    fn only_a_ready_sandbox_with_a_timeout_goes_idle() {
        for state in ALL_STATES {
            let ready = state == ComputerState::Ready;
            assert_eq!(
                idle_due(state, 30),
                ready.then(|| Duration::from_secs(30)),
                "{state}"
            );
            assert_eq!(idle_due(state, 0), None, "{state} with idle disabled");
        }
    }

    #[test]
    fn a_past_deadline_is_due_now() {
        assert_eq!(remaining(at(100), at(40)), Duration::from_secs(60));
        assert_eq!(remaining(at(100), at(100)), Duration::ZERO);
        assert_eq!(remaining(at(100), at(101)), Duration::ZERO);
    }
}
