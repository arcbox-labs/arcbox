//! Adaptive gather-window policy for RX inject interrupt coalescing.
//!
//! The inject loop batches up to [`BATCH_SIZE`] frames within a gather
//! window. Under multi-flow load, GSO cannot merge across flows, so frame
//! rate rises and a fixed 200 µs window still kicks the guest too often.
//!
//! Classification must **not** use wall-clock `spent` (dominated by
//! `recv_timeout` idle wait). Absolute frame counts would also be wrong:
//! 12 frames is ~60k fps at 200 µs but only ~15k fps at 800 µs, so a
//! multi-flow burst that raised the window would keep a later single
//! stream "busy" forever. We classify by **implied fps** over the budget
//! that applied to the gather:
//!
//! - **Expand** when the gather hit [`BATCH_SIZE`] early, or implied fps
//!   ≥ [`EXPAND_MIN_FPS`] (multi-flow / high frame-rate).
//! - **Shrink** when idle/very light (`batch` < [`QUIET_MAX_BATCH`]), or
//!   when the window is elevated above default and fps has fallen below
//!   multi-flow (so single-stream after a burst can decay).
//! - **Hold** for cold single-stream GSO near the default window.

/// Max frames per outer inject loop (shared with `inject`).
pub const BATCH_SIZE: usize = 256;

/// Default / quiet gather window (microseconds).
pub const WINDOW_DEFAULT_US: u32 = 200;

/// Floor under quiet load.
pub const WINDOW_MIN_US: u32 = 100;

/// Cap under sustained multi-flow pressure.
pub const WINDOW_MAX_US: u32 = 800;

/// Implied frames/s at or above which a full-window gather is busy.
///
/// ~12 frames / 200 µs ≈ 60k fps — above single-stream GSO (~37k @ 10 Gbps)
/// and into multi-flow territory.
pub const EXPAND_MIN_FPS: u64 = 60_000;

/// Batches strictly below this always shrink (idle / near-empty timeout).
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
    /// * `window_budget_us` — gather budget that applied to this round
    /// * `filled_early` — gather stopped because `batch` hit [`BATCH_SIZE`]
    /// * `allow_adapt` — false on descriptor-exhaustion so storms neither
    ///   expand nor shrink the window (and the following idle tick should
    ///   also pass false — see inject loop)
    pub fn observe(
        &mut self,
        batch: u16,
        window_budget_us: u32,
        filled_early: bool,
        allow_adapt: bool,
    ) {
        if !allow_adapt {
            return;
        }

        let rate = implied_fps(batch, window_budget_us);
        let busy = filled_early || rate >= EXPAND_MIN_FPS;
        // Idle / near-empty always decays. If the window was raised by a
        // multi-flow burst and fps has dropped below multi-flow, decay so a
        // following single stream does not sit at the 800 µs cap.
        let quiet = batch < QUIET_MAX_BATCH
            || (self.window_us > WINDOW_DEFAULT_US && rate < EXPAND_MIN_FPS);

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
        // else hold (cold single-stream near default)
    }
}

/// Frames per second implied by `batch` over `window_budget_us`.
fn implied_fps(batch: u16, window_budget_us: u32) -> u64 {
    if window_budget_us == 0 {
        return 0;
    }
    u64::from(batch).saturating_mul(1_000_000) / u64::from(window_budget_us)
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
            p.observe(256, WINDOW_DEFAULT_US, true, true);
        }
        assert_eq!(p.window_us(), WINDOW_MAX_US);
        assert!(p.expand_events() >= 1);
    }

    #[test]
    fn timeout_single_stream_holds_at_default() {
        let mut p = CoalescePolicy::new();
        // ~7 frames / 200 µs ≈ 35k fps — below expand, not idle.
        p.observe(7, WINDOW_DEFAULT_US, false, true);
        assert_eq!(p.window_us(), WINDOW_DEFAULT_US);
        p.observe(2, WINDOW_DEFAULT_US, false, true);
        assert!(p.window_us() < WINDOW_DEFAULT_US, "very light must shrink");
    }

    #[test]
    fn multi_flow_timeout_expands() {
        let mut p = CoalescePolicy::new();
        // ~14 frames / 200 µs ≈ 70k fps.
        p.observe(14, WINDOW_DEFAULT_US, false, true);
        assert!(p.window_us() > WINDOW_DEFAULT_US);
    }

    #[test]
    fn elevated_window_decays_under_single_stream_rate() {
        let mut p = CoalescePolicy::new();
        for _ in 0..8 {
            p.observe(64, WINDOW_DEFAULT_US, false, true);
        }
        assert!(p.window_us() > WINDOW_DEFAULT_US);
        let high = p.window_us();
        // ~30 frames / 800 µs ≈ 37k fps single stream after multi-flow.
        // Absolute batch 30 would look "busy" under the old fixed-12 rule.
        p.observe(30, high, false, true);
        assert!(
            p.window_us() < high,
            "must decay when fps is single-stream after a multi-flow peak"
        );
    }

    #[test]
    fn shrinks_after_load_via_idle() {
        let mut p = CoalescePolicy::new();
        for _ in 0..8 {
            p.observe(64, WINDOW_DEFAULT_US, false, true);
        }
        assert!(p.window_us() > WINDOW_DEFAULT_US);

        for _ in 0..24 {
            p.observe(0, p.window_us(), false, true);
        }
        assert!(p.window_us() <= WINDOW_DEFAULT_US);
        assert!(p.shrink_events() >= 1);
    }

    #[test]
    fn no_adapt_when_disallowed() {
        let mut p = CoalescePolicy::new();
        for _ in 0..8 {
            p.observe(256, WINDOW_DEFAULT_US, true, true);
        }
        let high = p.window_us();
        for _ in 0..16 {
            p.observe(0, high, false, false);
            p.observe(256, high, true, false);
        }
        assert_eq!(p.window_us(), high);
    }

    #[test]
    fn never_exceeds_cap() {
        let mut p = CoalescePolicy::new();
        for _ in 0..100 {
            p.observe(256, WINDOW_MAX_US, true, true);
        }
        assert_eq!(p.window_us(), WINDOW_MAX_US);
    }

    #[test]
    fn never_below_floor() {
        let mut p = CoalescePolicy::new();
        for _ in 0..100 {
            p.observe(0, WINDOW_DEFAULT_US, false, true);
        }
        assert!(p.window_us() >= WINDOW_MIN_US);
    }
}
