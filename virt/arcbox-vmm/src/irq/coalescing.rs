use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Configuration for timer-based interrupt coalescing.
///
/// Trades a small latency increase for significant wakeup reduction.
/// When an interrupt fires, a coalescing window opens; additional interrupts
/// within the window are accumulated and delivered as a single notification
/// when the window expires or the count threshold is reached.
#[derive(Debug, Clone)]
pub struct CoalescingConfig {
    /// Maximum delay before delivering a pending interrupt.
    pub max_delay: Duration,
    /// Force delivery after this many pending interrupts.
    pub max_coalesce_count: u32,
    /// Whether coalescing is enabled.
    pub enabled: bool,
}

impl Default for CoalescingConfig {
    fn default() -> Self {
        Self {
            max_delay: Duration::from_micros(50),
            max_coalesce_count: 64,
            enabled: true,
        }
    }
}

impl CoalescingConfig {
    /// Preset for virtio-net: moderate latency tolerance.
    #[must_use]
    pub fn for_net() -> Self {
        Self {
            max_delay: Duration::from_micros(50),
            max_coalesce_count: 64,
            enabled: true,
        }
    }

    /// Preset for virtio-blk: lower latency tolerance.
    #[must_use]
    pub fn for_block() -> Self {
        Self {
            max_delay: Duration::from_micros(25),
            max_coalesce_count: 32,
            enabled: true,
        }
    }

    /// Preset for virtio-fs: batches well.
    #[must_use]
    pub fn for_fs() -> Self {
        Self {
            max_delay: Duration::from_micros(50),
            max_coalesce_count: 64,
            enabled: true,
        }
    }

    /// Preset for virtio-vsock: control plane, latency insensitive.
    #[must_use]
    pub fn for_vsock() -> Self {
        Self {
            max_delay: Duration::from_micros(100),
            max_coalesce_count: 128,
            enabled: true,
        }
    }

    /// Disabled coalescing — pass through immediately.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

/// Per-IRQ coalescing state.
///
/// Tracks pending interrupt count and timer state for a single IRQ line.
pub struct CoalescingState {
    /// Number of interrupts accumulated in the current window.
    pub pending_count: AtomicU32,
    /// Whether the coalescing timer is armed.
    pub timer_armed: AtomicBool,
    /// When the timer was armed (for expiry check).
    pub last_armed: Mutex<Option<Instant>>,
    /// Configuration for this IRQ line.
    pub config: CoalescingConfig,
}

impl CoalescingState {
    /// Creates a new coalescing state with the given configuration.
    #[must_use]
    pub fn new(config: CoalescingConfig) -> Self {
        Self {
            pending_count: AtomicU32::new(0),
            timer_armed: AtomicBool::new(false),
            last_armed: Mutex::new(None),
            config,
        }
    }

    /// Record a pending interrupt.
    ///
    /// Returns `true` if immediate delivery is needed (count exceeds threshold).
    pub fn record(&self) -> bool {
        let count = self.pending_count.fetch_add(1, Ordering::Relaxed);
        if count + 1 >= self.config.max_coalesce_count {
            return true;
        }
        if count == 0 {
            // First interrupt in window — arm timer
            self.timer_armed.store(true, Ordering::Release);
            *self.last_armed.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        }
        false
    }

    /// Flush coalesced state. Returns the number of coalesced interrupts.
    pub fn flush(&self) -> u32 {
        let count = self.pending_count.swap(0, Ordering::SeqCst);
        self.timer_armed.store(false, Ordering::Release);
        *self.last_armed.lock().unwrap_or_else(|e| e.into_inner()) = None;
        count
    }

    /// Check if the coalescing timer has expired.
    #[must_use]
    pub fn timer_expired(&self) -> bool {
        if !self.timer_armed.load(Ordering::Acquire) {
            return false;
        }
        let guard = self.last_armed.lock().unwrap_or_else(|e| e.into_inner());
        guard.is_some_and(|armed_at| armed_at.elapsed() >= self.config.max_delay)
    }
}
