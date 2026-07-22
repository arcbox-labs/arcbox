//! Adaptive gather-window policy for RX inject interrupt coalescing.
//!
//! The inject loop batches up to [`BATCH_SIZE`] frames within a gather
//! window. Under multi-flow load, GSO cannot merge across flows, so frame
//! rate rises and a fixed 200 µs window still kicks the guest too often.
//!
//! Classification must **not** use wall-clock `spent` (dominated by
//! `recv_timeout` idle wait). Instead:
//!
//! - **Expand** when the gather hit [`BATCH_SIZE`] early, or when a
//!   full-window gather published ≥ [`EXPAND_MIN_BATCH`] frames (real
//!   multi-flow / high fps load — single-stream GSO sits below this).
//! - **Shrink** when the gather was idle or very light (`batch` <
//!   [`QUIET_MAX_BATCH`]), including empty timeouts so the window decays
//!   after load.
//! - **Hold** in the single-stream band between those thresholds.

/// Max frames per outer inject loop (shared with `inject`).
pub const BATCH_SIZE: usize = 256;

/// Default / quiet gather window (microseconds).
pub const WINDOW_DEFAULT_US: u32 = 200;

/// Floor under quiet load.
pub const WINDOW_MIN_US: u32 = 100;

/// Cap under sustained multi-flow pressure.
pub const WINDOW_MAX_US: u32 = 800;

/// Minimum batch (used entries) to treat a full-window gather as busy.
///
/// At 200 µs: ~12 frames ≈ 60k fps — above single-stream GSO (~7 @ 37k fps
/// / 10 Gbps) and into multi-flow territory.
pub const EXPAND_MIN_BATCH: u16 = 12;

/// Batches strictly below this shrink (idle / very light).
pub const QUIET_MAX_BATCH: u16 = 4;

/// Adaptive gather window for one inject loop iteration.
#[derive(Debug, Clone)]
pub struct CoalescePolicy {
    window_us: u32,
    expand_events: u64,
    shrink_events: u64,
}

impl Default for CoalescePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl CoalescePolicy {
    /// Starts at the historical fixed 200 µs window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            window_us: WINDOW_DEFAULT_US,
            expand_events: 0,
            shrink_events: 0,
        }
    }

    /// Current gather budget for the next outer loop.
    #[must_use]
    pub const fn window_us(&self) -> u32 {
        self.window_us
    }

    /// High-level counters for tests / logging.
    #[must_use]
    pub const fn expand_events(&self) -> u64 {
        self.expand_events
    }

    /// High-level counters for tests / logging.
    #[must_use]
    pub const fn shrink_events(&self) -> u64 {
        self.shrink_events
    }

    /// Update after a gather.
    ///
    /// * `batch` — used-ring entries published (0 = empty idle timeout)
    /// * `filled_early` — gather stopped because `batch` hit [`BATCH_SIZE`]
    ///   (not because the window expired)
    /// * `allow_adapt` — false on descriptor-exhaustion so storms neither
    ///   expand nor shrink the window
    pub fn observe(&mut self, batch: u16, filled_early: bool, allow_adapt: bool) {
        if !allow_adapt {
            return;
        }

        let busy = filled_early || batch >= EXPAND_MIN_BATCH;
        let quiet = batch < QUIET_MAX_BATCH;

        if busy {
            let next = ((u64::from(self.window_us) * 3) / 2) as u32;
            let next = next.clamp(WINDOW_MIN_US, WINDOW_MAX_US);
            if next > self.window_us {
                self.expand_events += 1;
            }
            self.window_us = next;
        } else if quiet {
            let next = ((u64::from(self.window_us) * 3) / 4) as u32;
            let next = next.clamp(WINDOW_MIN_US, WINDOW_MAX_US);
            if next < self.window_us {
                self.shrink_events += 1;
            }
            self.window_us = next;
        }
        // else hold (single-stream band)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_default() {
        let p = CoalescePolicy::new();
        assert_eq!(p.window_us(), WINDOW_DEFAULT_US);
    }

    #[test]
    fn expands_to_cap_under_full_batches() {
        let mut p = CoalescePolicy::new();
        for _ in 0..16 {
            p.observe(256, true, true);
        }
        assert_eq!(p.window_us(), WINDOW_MAX_US);
        assert!(p.expand_events() >= 1);
    }

    #[test]
    fn timeout_small_batch_does_not_expand() {
        let mut p = CoalescePolicy::new();
        // Production light timeout (few frames, window expired) — hold or shrink.
        p.observe(8, false, true);
        assert_eq!(
            p.window_us(),
            WINDOW_DEFAULT_US,
            "single-stream band must hold"
        );
        p.observe(2, false, true);
        assert!(p.window_us() < WINDOW_DEFAULT_US, "very light must shrink");
    }

    #[test]
    fn multi_flow_timeout_expands() {
        let mut p = CoalescePolicy::new();
        // ~14 frames / 200 µs ≈ 70k fps multi-flow band.
        p.observe(14, false, true);
        assert!(p.window_us() > WINDOW_DEFAULT_US);
    }

    #[test]
    fn shrinks_after_load_via_idle() {
        let mut p = CoalescePolicy::new();
        for _ in 0..8 {
            p.observe(64, false, true);
        }
        assert!(p.window_us() > WINDOW_DEFAULT_US);

        for _ in 0..24 {
            p.observe(0, false, true);
        }
        assert!(p.window_us() <= WINDOW_DEFAULT_US);
        assert!(p.shrink_events() >= 1);
    }

    #[test]
    fn medium_single_stream_holds() {
        let mut p = CoalescePolicy::new();
        p.observe(64, false, true);
        let high = p.window_us();
        // 7 frames ≈ 37k fps GSO — hold, do not expand further or shrink.
        p.observe(7, false, true);
        assert_eq!(p.window_us(), high);
    }

    #[test]
    fn no_adapt_when_disallowed() {
        let mut p = CoalescePolicy::new();
        for _ in 0..8 {
            p.observe(256, true, true);
        }
        let high = p.window_us();
        for _ in 0..16 {
            p.observe(0, false, false);
            p.observe(256, true, false);
        }
        assert_eq!(p.window_us(), high);
    }

    #[test]
    fn never_exceeds_cap() {
        let mut p = CoalescePolicy::new();
        for _ in 0..100 {
            p.observe(256, true, true);
        }
        assert_eq!(p.window_us(), WINDOW_MAX_US);
    }

    #[test]
    fn never_below_floor() {
        let mut p = CoalescePolicy::new();
        for _ in 0..100 {
            p.observe(0, false, true);
        }
        assert!(p.window_us() >= WINDOW_MIN_US);
    }
}
