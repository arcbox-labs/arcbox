//! Health monitoring for VM lifecycle.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Health monitor for VM.
///
/// Tracks consecutive health-check failures and signals when the
/// threshold is exceeded.  The monitoring loop itself is not yet
/// implemented — `interval` is stored for future use.
pub struct HealthMonitor {
    /// Health check interval (reserved for the future monitoring loop).
    #[allow(dead_code)]
    interval: Duration,
    /// Maximum consecutive failures before reporting unhealthy.
    max_failures: u32,
    /// Current failure count.
    failures: AtomicU32,
    /// Shutdown signal.
    shutdown: CancellationToken,
}

impl HealthMonitor {
    /// Creates a new health monitor.
    #[must_use]
    pub fn new(interval: Duration, max_failures: u32) -> Self {
        Self {
            interval,
            max_failures,
            failures: AtomicU32::new(0),
            shutdown: CancellationToken::new(),
        }
    }

    /// Returns the shutdown token for stopping the monitor.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Resets the failure counter.
    pub fn reset(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    /// Returns true if the VM is considered healthy.
    pub fn is_healthy(&self) -> bool {
        self.failures.load(Ordering::SeqCst) < self.max_failures
    }

    /// Records a successful health check.
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    /// Records a failed health check.
    ///
    /// Returns true if the failure threshold has been exceeded.
    pub fn record_failure(&self) -> bool {
        let failures = self.failures.fetch_add(1, Ordering::SeqCst) + 1;
        failures >= self.max_failures
    }

    /// Stops the health monitor.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_monitor() {
        let monitor = HealthMonitor::new(Duration::from_secs(5), 3);

        assert!(monitor.is_healthy());

        // First failure
        assert!(!monitor.record_failure());
        assert!(monitor.is_healthy());

        // Second failure
        assert!(!monitor.record_failure());
        assert!(monitor.is_healthy());

        // Third failure - threshold exceeded
        assert!(monitor.record_failure());
        assert!(!monitor.is_healthy());

        // Reset
        monitor.reset();
        assert!(monitor.is_healthy());
    }

    #[test]
    fn test_health_monitor_success_resets() {
        let monitor = HealthMonitor::new(Duration::from_secs(5), 3);

        // Two failures
        monitor.record_failure();
        monitor.record_failure();

        // Success resets
        monitor.record_success();
        assert!(monitor.is_healthy());

        // Need 3 more failures to exceed threshold
        assert!(!monitor.record_failure());
        assert!(!monitor.record_failure());
        assert!(monitor.record_failure());
    }
}
