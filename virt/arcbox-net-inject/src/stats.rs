//! Lightweight counters for the RX inject thread.
//!
//! Lifetime totals for shutdown logs; interval deltas for 1 Hz debug so the
//! current coalesce regime is visible without a host sampler.

use std::time::{Duration, Instant};

use crate::coalesce::CoalescePolicy;

/// Per-thread inject path counters.
#[derive(Debug, Default)]
pub struct InjectStats {
    frames_injected: u64,
    flushes: u64,
    irqs_fired: u64,
    irqs_suppressed: u64,
    batch_sum: u64,
    window_us: u32,
    window_us_max: u32,
    expand_events: u64,
    shrink_events: u64,
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
    /// Lifetime frames published to the used ring.
    #[must_use]
    pub const fn frames_injected(&self) -> u64 {
        self.frames_injected
    }

    /// Lifetime non-empty flushes.
    #[must_use]
    pub const fn flushes(&self) -> u64 {
        self.flushes
    }

    /// Lifetime IRQs that actually fired.
    #[must_use]
    pub const fn irqs_fired(&self) -> u64 {
        self.irqs_fired
    }

    /// Peak gather window observed (microseconds).
    #[must_use]
    pub const fn window_us_max(&self) -> u32 {
        self.window_us_max
    }

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

    /// Refresh expand/shrink tallies from the policy and note the budget in effect.
    pub fn sync_from_policy(&mut self, policy: &CoalescePolicy, window_budget_us: u32) {
        self.expand_events = policy.expand_events();
        self.shrink_events = policy.shrink_events();
        self.window_us = window_budget_us;
    }

    /// Log at most once per second at debug level (interval deltas + current window).
    ///
    /// Runs at 1 Hz only; allocating short display strings for rates is fine.
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
            frames_per_irq = fpi,
            avg_batch = avg_batch,
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
