//! Unified timer wheel for network flow timeout management.
//!
//! Replaces per-flow `tokio::time::timeout()` calls with a single shared
//! timer that scans all registered deadlines on a fixed tick interval,
//! reducing wakeup count from O(N) to O(1).

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Action to take when a timer expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerAction {
    /// TCP bridge: close a pending SYN.
    SynTimeout,
    /// Socket proxy: remove an expired UDP flow.
    UdpFlowExpiry,
    /// Socket proxy: remove an expired ICMP echo.
    IcmpTimeout,
    /// Inbound relay: remove an expired inbound flow.
    InboundExpiry,
    /// TCP bridge: remove a pre-connected stream that was never claimed.
    PreConnectedExpiry,
}

/// An entry returned when a timer expires.
#[derive(Debug)]
pub struct ExpiredEntry<K> {
    /// The key identifying the flow.
    pub key: K,
    /// The action to take for this expired flow.
    pub action: TimerAction,
}

struct TimerEntry {
    deadline: Instant,
    action: TimerAction,
}

/// A coarse-grained timer wheel for network flow timeouts.
///
/// Instead of N independent `tokio::time::timeout()` objects (one per flow),
/// a single tick scans all registered deadlines. This reduces the tokio
/// runtime wakeup count from O(active_flows) to O(1).
///
/// # Usage
///
/// ```ignore
/// let mut wheel = TimerWheel::new(Duration::from_secs(1));
/// wheel.register(flow_id, Duration::from_secs(60), TimerAction::UdpFlowExpiry);
///
/// // In the event loop, on each tick:
/// for expired in wheel.advance() {
///     handle_expired(expired.key, expired.action);
/// }
/// ```
pub struct TimerWheel<K: Hash + Eq + Clone> {
    entries: HashMap<K, TimerEntry>,
    tick_interval: Duration,
}

impl<K: Hash + Eq + Clone> TimerWheel<K> {
    /// Create a new timer wheel with the given tick interval.
    pub fn new(tick_interval: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            tick_interval,
        }
    }

    /// Register a new timer. If the key already exists, its deadline is updated.
    pub fn register(&mut self, key: K, timeout: Duration, action: TimerAction) {
        let deadline = Instant::now() + timeout;
        self.entries.insert(key, TimerEntry { deadline, action });
    }

    /// Cancel a timer by key. Returns `true` if it existed.
    pub fn cancel(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Advance the wheel: collect and remove all expired entries.
    pub fn advance(&mut self) -> Vec<ExpiredEntry<K>> {
        let now = Instant::now();
        let mut expired = Vec::new();
        self.entries.retain(|key, entry| {
            if entry.deadline <= now {
                expired.push(ExpiredEntry {
                    key: key.clone(),
                    action: entry.action,
                });
                false
            } else {
                true
            }
        });
        expired
    }

    /// Number of registered timers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the wheel has no registered timers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The tick interval this wheel was configured with.
    #[must_use]
    pub fn tick_interval(&self) -> Duration {
        self.tick_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_register_and_advance() {
        let mut wheel = TimerWheel::<u32>::new(Duration::from_secs(1));
        wheel.register(1, Duration::from_millis(10), TimerAction::SynTimeout);
        wheel.register(2, Duration::from_mins(1), TimerAction::UdpFlowExpiry);
        assert_eq!(wheel.len(), 2);

        thread::sleep(Duration::from_millis(20));
        let expired = wheel.advance();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, 1);
        assert_eq!(expired[0].action, TimerAction::SynTimeout);
        assert_eq!(wheel.len(), 1);
    }

    #[test]
    fn test_cancel() {
        let mut wheel = TimerWheel::<u32>::new(Duration::from_secs(1));
        wheel.register(1, Duration::from_mins(1), TimerAction::SynTimeout);
        assert!(wheel.cancel(&1));
        assert!(!wheel.cancel(&1));
        assert!(wheel.is_empty());
    }

    #[test]
    fn test_update_existing() {
        let mut wheel = TimerWheel::<u32>::new(Duration::from_secs(1));
        wheel.register(1, Duration::from_mins(1), TimerAction::SynTimeout);
        wheel.register(1, Duration::from_millis(10), TimerAction::IcmpTimeout);
        assert_eq!(wheel.len(), 1);

        thread::sleep(Duration::from_millis(20));
        let expired = wheel.advance();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].action, TimerAction::IcmpTimeout);
    }

    #[test]
    fn test_advance_no_expired() {
        let mut wheel = TimerWheel::<u32>::new(Duration::from_secs(1));
        wheel.register(1, Duration::from_mins(1), TimerAction::SynTimeout);
        let expired = wheel.advance();
        assert!(expired.is_empty());
        assert_eq!(wheel.len(), 1);
    }

    #[test]
    fn test_empty_wheel() {
        let mut wheel = TimerWheel::<u32>::new(Duration::from_secs(1));
        assert!(wheel.is_empty());
        assert_eq!(wheel.len(), 0);
        let expired = wheel.advance();
        assert!(expired.is_empty());
    }

    #[test]
    fn test_tick_interval() {
        let wheel = TimerWheel::<u32>::new(Duration::from_millis(500));
        assert_eq!(wheel.tick_interval(), Duration::from_millis(500));
    }

    #[test]
    fn test_multiple_expirations() {
        let mut wheel = TimerWheel::<u32>::new(Duration::from_secs(1));
        wheel.register(1, Duration::from_millis(5), TimerAction::SynTimeout);
        wheel.register(2, Duration::from_millis(5), TimerAction::UdpFlowExpiry);
        wheel.register(3, Duration::from_mins(1), TimerAction::InboundExpiry);

        thread::sleep(Duration::from_millis(15));
        let expired = wheel.advance();
        assert_eq!(expired.len(), 2);
        assert_eq!(wheel.len(), 1); // only the 60s timer remains
    }
}
