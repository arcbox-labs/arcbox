//! Recovery policy for VM failure handling.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Backoff strategy for recovery retries.
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Fixed delay between retries.
    Fixed(Duration),
    /// Exponential backoff with maximum.
    Exponential {
        /// Initial delay.
        initial: Duration,
        /// Maximum delay.
        max: Duration,
    },
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self::Exponential {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(10),
        }
    }
}

/// Recovery action after failure.
#[derive(Debug)]
pub enum RecoveryAction {
    /// Retry after the specified delay.
    RetryAfter(Duration),
    /// Give up and report the error.
    GiveUp(String),
}

/// Recovery policy for VM failures.
pub struct RecoveryPolicy {
    /// Maximum retry attempts.
    max_retries: u32,
    /// Backoff strategy.
    backoff: BackoffStrategy,
    /// Current retry count.
    retries: AtomicU32,
}

impl RecoveryPolicy {
    /// Creates a new recovery policy.
    #[must_use]
    pub const fn new(max_retries: u32, backoff: BackoffStrategy) -> Self {
        Self {
            max_retries,
            backoff,
            retries: AtomicU32::new(0),
        }
    }

    /// Handles a failure and returns the recovery action.
    pub fn handle_failure(&self, error: &str) -> RecoveryAction {
        let retries = self.retries.fetch_add(1, Ordering::SeqCst);

        if retries >= self.max_retries {
            return RecoveryAction::GiveUp(error.to_string());
        }

        let delay = match &self.backoff {
            BackoffStrategy::Fixed(d) => *d,
            BackoffStrategy::Exponential { initial, max } => {
                let multiplier = 1u32.checked_shl(retries).unwrap_or(u32::MAX);
                let delay = initial.saturating_mul(multiplier);
                delay.min(*max)
            }
        };

        RecoveryAction::RetryAfter(delay)
    }

    /// Resets the retry counter.
    pub fn reset(&self) {
        self.retries.store(0, Ordering::SeqCst);
    }

    /// Returns the current retry count.
    pub fn retry_count(&self) -> u32 {
        self.retries.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_policy_fixed_backoff() {
        let policy = RecoveryPolicy::new(3, BackoffStrategy::Fixed(Duration::from_millis(100)));

        // First failure: retry
        match policy.handle_failure("test error") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Second failure: retry
        match policy.handle_failure("test error") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Third failure: retry
        match policy.handle_failure("test error") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Fourth failure: give up
        match policy.handle_failure("test error") {
            RecoveryAction::GiveUp(_) => {}
            RecoveryAction::RetryAfter(_) => panic!("expected GiveUp"),
        }
    }

    #[test]
    fn test_recovery_policy_exponential_backoff() {
        let policy = RecoveryPolicy::new(
            5,
            BackoffStrategy::Exponential {
                initial: Duration::from_millis(100),
                max: Duration::from_secs(1),
            },
        );

        // First failure: 100ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Second failure: 200ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(200)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Third failure: 400ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(400)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Fourth failure: 800ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(800)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Fifth failure: capped at 1000ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_secs(1)),
            RecoveryAction::GiveUp(_) => panic!("expected RetryAfter"),
        }

        // Sixth failure: give up
        match policy.handle_failure("test") {
            RecoveryAction::GiveUp(_) => {}
            RecoveryAction::RetryAfter(_) => panic!("expected GiveUp"),
        }
    }

    #[test]
    fn test_recovery_policy_reset() {
        let policy = RecoveryPolicy::new(2, BackoffStrategy::Fixed(Duration::from_millis(100)));

        // First failure
        let _ = policy.handle_failure("test");
        assert_eq!(policy.retry_count(), 1);

        // Reset
        policy.reset();
        assert_eq!(policy.retry_count(), 0);
    }
}
