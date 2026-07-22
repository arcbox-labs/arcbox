//! Lightweight counters for the RX inject thread.
//!
//! Lifetime totals for shutdown logs; interval deltas for 1 Hz debug so the
//! current coalesce regime is visible without a host sampler.

use std::time::{Duration, Instant};

/// Per-thread inject path counters.
#[derive(Debug, Default)]
pub struct InjectStats {
    pub frames_injected: u64,
    pub flushes: u64,
    pub irqs_fired: u64,
    pub irqs_suppressed: u64,
    pub batch_sum: u64,
    pub window_us: u32,
    pub window_us_max: u32,
    pub expand_events: u64,
    pub shrink_events: u64,
    last_log: Option<Instant>,
    /// Snapshot of counters at the last log (for interval rates).
    prev_frames: u64,
    prev_flushes: u64,
    prev_irqs_fired: u64,
    prev_irqs_suppressed: u64,
    prev_batch_sum: u64,
    prev_expand: u64,
    prev_shrink: u64,
}

impl InjectStats {
    /// Record one flush of `batch` frames with notify decision `fired`.
    ///
    /// `window_us` is the gather budget that applied to this batch (not the
    /// post-observe value).
    pub fn on_flush(&mut self, batch: u16, fired: bool, window_us: u32) {
        self.flushes += 1;
        self.batch_sum += u64::from(batch);
        self.frames_injected += u64::from(batch);
        if fired {
            self.irqs_fired += 1;
        } else {
            self.irqs_suppressed += 1;
        }
        self.window_us = window_us;
        self.window_us_max = self.window_us_max.max(window_us);
    }

    /// Copy expand/shrink tallies from the policy.
    pub fn sync_policy_events(&mut self, expand: u64, shrink: u64) {
        self.expand_events = expand;
        self.shrink_events = shrink;
    }

    /// Log at most once per second at debug level (interval deltas + current window).
    pub fn maybe_log(&mut self) {
        let now = Instant::now();
        let due = self
            .last_log
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1));
        if !due {
            return;
        }
        self.last_log = Some(now);

        let d_frames = self.frames_injected.saturating_sub(self.prev_frames);
        let d_flushes = self.flushes.saturating_sub(self.prev_flushes);
        let d_irqs = self.irqs_fired.saturating_sub(self.prev_irqs_fired);
        let d_suppressed = self
            .irqs_suppressed
            .saturating_sub(self.prev_irqs_suppressed);
        let d_batch_sum = self.batch_sum.saturating_sub(self.prev_batch_sum);
        let d_expand = self.expand_events.saturating_sub(self.prev_expand);
        let d_shrink = self.shrink_events.saturating_sub(self.prev_shrink);

        let fpi = if d_irqs == 0 {
            0.0
        } else {
            d_frames as f64 / d_irqs as f64
        };
        let avg_batch = if d_flushes == 0 {
            0.0
        } else {
            d_batch_sum as f64 / d_flushes as f64
        };

        tracing::debug!(
            frames = d_frames,
            flushes = d_flushes,
            irqs_fired = d_irqs,
            irqs_suppressed = d_suppressed,
            frames_per_irq = format!("{fpi:.1}"),
            avg_batch = format!("{avg_batch:.1}"),
            window_us = self.window_us,
            window_us_max = self.window_us_max,
            expand = d_expand,
            shrink = d_shrink,
            frames_total = self.frames_injected,
            irqs_total = self.irqs_fired,
            "rx-inject coalesce stats"
        );

        self.prev_frames = self.frames_injected;
        self.prev_flushes = self.flushes;
        self.prev_irqs_fired = self.irqs_fired;
        self.prev_irqs_suppressed = self.irqs_suppressed;
        self.prev_batch_sum = self.batch_sum;
        self.prev_expand = self.expand_events;
        self.prev_shrink = self.shrink_events;
    }
}
