//! In-guest memory pressure detection (pure logic).
//!
//! While the host keeps a `WatchMemoryPressure` stream open (it does so only
//! while the balloon is shrunk), the Linux agent samples `/proc/meminfo` and
//! `/proc/vmstat` and feeds the numbers through [`PressureDetector`]. This
//! module owns parsing and the trip decision; the sampler loop and stream
//! writing live in the Linux-only agent module. Kept platform-neutral so the
//! logic is unit-testable on any development host.
//!
//! The signals are deliberately balloon-accounting-independent: a shrunk
//! balloon leaves `MemAvailable` at roughly the configured headroom under
//! both virtio-balloon accounting modes (with and without
//! `DEFLATE_ON_OOM`), and `workingset_refault` counts thrashing directly.
//! This sampling path is the portable fallback: once the detector arms, the
//! Linux agent upgrades to a kernel PSI trigger on `/proc/pressure/memory`
//! (the guest kernel now ships `CONFIG_PSI`) and pauses sampling, dropping
//! back here only when the trigger is unavailable. This module's contract is
//! unchanged either way.

/// Refault-rate samples that must consecutively exceed the threshold before
/// tripping. Damps one-off bursts (e.g. a cold-started binary faulting its
/// text pages in) that are not sustained thrash.
pub const REFAULT_CONSECUTIVE_SAMPLES: u32 = 2;

/// Healthy samples (`MemAvailable` at or above the floor) required before
/// the detector arms.
///
/// A watch opens right after the host sets a lower balloon target, and the
/// inflation itself pollutes both signals until it converges: it evicts the
/// page cache (a large refault burst as background daemons re-touch their
/// mappings) and pins `MemAvailable` near zero for the whole inflation —
/// tens of seconds for a many-GiB shrink, hardware-validated. Fixed-length
/// warm-ups cannot cover a duration set by inflation speed, so the detector
/// instead *arms* on the first evidence of a settled guest: consecutive
/// healthy readings.
pub const ARM_AFTER_HEALTHY_SAMPLES: u32 = 3;

/// Samples after which a detector that never armed trips anyway.
///
/// A guest that never reaches a healthy reading is not still inflating —
/// staged descent bounds each step to ~2 GiB (seconds of inflation), so a
/// minute without a single healthy streak means the step was undersized
/// (usage grew mid-step). Restoring then is the correct fail-safe, and
/// this cap bounds the worst-case self-heal latency.
pub const SETTLE_CAP_SAMPLES: u32 = 60;

/// PSI trigger window in microseconds. Fixed at 1s: the kernel accepts
/// windows of 500ms–10s, and 1s matches the sampler cadence the trigger
/// replaces.
pub const PSI_WINDOW_US: u32 = 1_000_000;

/// Default PSI trigger threshold: 100ms of full (all non-idle tasks)
/// memory stall within [`PSI_WINDOW_US`].
pub const PSI_DEFAULT_FULL_STALL_US: u32 = 100_000;

/// Resolves the host-requested PSI stall threshold (µs): 0 means the
/// agent default, and the kernel rejects thresholds above the window.
#[must_use]
pub fn psi_stall_threshold_us(requested: u64) -> u32 {
    if requested == 0 {
        return PSI_DEFAULT_FULL_STALL_US;
    }
    u32::try_from(requested)
        .unwrap_or(PSI_WINDOW_US)
        .min(PSI_WINDOW_US)
}

/// Thresholds for a pressure watch, provided by the host per request.
///
/// A zero threshold disables that signal.
#[derive(Debug, Clone, Copy)]
pub struct PressureThresholds {
    /// Trip immediately when `MemAvailable` drops below this many bytes.
    pub min_available_bytes: u64,
    /// Trip when the page refault rate (pages/second) stays at or above this
    /// for [`REFAULT_CONSECUTIVE_SAMPLES`] consecutive samples.
    pub max_refault_rate: u64,
}

/// A tripped pressure signal. Mirrors `MemoryPressureEvent.Reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureSignal {
    /// `MemAvailable` fell below the requested floor.
    LowAvailable,
    /// The page refault rate exceeded the requested threshold.
    RefaultSpike,
}

/// Stateful trip decision across successive samples.
///
/// Starts in a *settling* phase while balloon inflation converges: the
/// refault signal is ignored and only [`SETTLE_CAP_SAMPLES`] going by
/// without a single healthy streak trips (as `LowAvailable`). After
/// [`ARM_AFTER_HEALTHY_SAMPLES`] consecutive healthy readings the detector
/// arms: the floor trips instantly, refault after
/// [`REFAULT_CONSECUTIVE_SAMPLES`] consecutive hits.
#[derive(Debug)]
pub struct PressureDetector {
    thresholds: PressureThresholds,
    armed: bool,
    samples_seen: u32,
    healthy_streak: u32,
    refault_hits: u32,
}

impl PressureDetector {
    /// Creates a detector for the given thresholds.
    #[must_use]
    pub fn new(thresholds: PressureThresholds) -> Self {
        Self {
            thresholds,
            armed: false,
            samples_seen: 0,
            healthy_streak: 0,
            refault_hits: 0,
        }
    }

    /// Whether the settling phase has completed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// Feeds one sample. `refault_rate` is pages/second since the previous
    /// sample. Returns the tripped signal, if any; low-available wins when
    /// both trip.
    pub fn evaluate(&mut self, available_bytes: u64, refault_rate: u64) -> Option<PressureSignal> {
        let floor = self.thresholds.min_available_bytes;
        let refault = self.thresholds.max_refault_rate;
        self.samples_seen = self.samples_seen.saturating_add(1);

        if !self.armed {
            if available_bytes >= floor {
                self.healthy_streak += 1;
                if self.healthy_streak >= ARM_AFTER_HEALTHY_SAMPLES {
                    self.armed = true;
                }
            } else {
                self.healthy_streak = 0;
            }
            if !self.armed {
                // Never-settled guests get their memory back after the cap;
                // anything before that is inflation still converging. A
                // healthy sample mid-streak is progress, not a trip.
                if self.samples_seen >= SETTLE_CAP_SAMPLES && available_bytes < floor {
                    return Some(PressureSignal::LowAvailable);
                }
                return None;
            }
            // Freshly armed on a healthy sample: nothing to trip yet.
            return None;
        }

        if refault == 0 || refault_rate < refault {
            self.refault_hits = 0;
        } else {
            self.refault_hits += 1;
        }

        if floor > 0 && available_bytes < floor {
            return Some(PressureSignal::LowAvailable);
        }
        if refault > 0 && self.refault_hits >= REFAULT_CONSECUTIVE_SAMPLES {
            return Some(PressureSignal::RefaultSpike);
        }
        None
    }
}

/// Parses `MemAvailable` (bytes) out of `/proc/meminfo` content.
#[must_use]
pub fn parse_mem_available(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// Parses cumulative workingset refaults out of `/proc/vmstat` content:
/// `workingset_refault_file + workingset_refault_anon`, falling back to the
/// pre-5.9 combined `workingset_refault` counter.
#[must_use]
pub fn parse_workingset_refaults(vmstat: &str) -> Option<u64> {
    let mut split_total: Option<u64> = None;
    let mut combined: Option<u64> = None;

    for line in vmstat.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        match name {
            "workingset_refault_anon" | "workingset_refault_file" => {
                let value: u64 = value.parse().ok()?;
                split_total = Some(split_total.unwrap_or(0).saturating_add(value));
            }
            "workingset_refault" => combined = value.parse().ok(),
            _ => {}
        }
    }

    split_total.or(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn thresholds(min_available: u64, max_refault: u64) -> PressureThresholds {
        PressureThresholds {
            min_available_bytes: min_available,
            max_refault_rate: max_refault,
        }
    }

    /// A detector armed by three healthy samples.
    fn armed(min_available: u64, max_refault: u64) -> PressureDetector {
        let mut d = PressureDetector::new(thresholds(min_available, max_refault));
        for _ in 0..ARM_AFTER_HEALTHY_SAMPLES {
            assert_eq!(d.evaluate(u64::MAX, 0), None);
        }
        assert!(d.is_armed(), "three healthy samples must arm the detector");
        d
    }

    #[test]
    fn meminfo_parses_mem_available_kb() {
        let meminfo = "MemTotal:       16384000 kB\nMemFree:          262144 kB\nMemAvailable:     524288 kB\nBuffers:            1024 kB\n";
        assert_eq!(parse_mem_available(meminfo), Some(524_288 * 1024));
    }

    #[test]
    fn meminfo_without_mem_available_is_none() {
        // MemAvailable requires 3.14+; treat absence as "unknown", never 0.
        let meminfo = "MemTotal: 16384000 kB\nMemFree: 262144 kB\n";
        assert_eq!(parse_mem_available(meminfo), None);
    }

    #[test]
    fn meminfo_malformed_number_is_none() {
        assert_eq!(parse_mem_available("MemAvailable: lots kB\n"), None);
    }

    #[test]
    fn vmstat_sums_file_and_anon_refaults() {
        let vmstat = "nr_free_pages 100\nworkingset_refault_anon 1500\nworkingset_refault_file 2500\npgfault 999\n";
        assert_eq!(parse_workingset_refaults(vmstat), Some(4000));
    }

    #[test]
    fn vmstat_falls_back_to_combined_counter() {
        // Pre-5.9 kernels expose a single combined counter.
        let vmstat = "nr_free_pages 100\nworkingset_refault 4200\npgfault 999\n";
        assert_eq!(parse_workingset_refaults(vmstat), Some(4200));
    }

    #[test]
    fn vmstat_without_refault_counters_is_none() {
        assert_eq!(parse_workingset_refaults("nr_free_pages 100\n"), None);
    }

    #[test]
    fn low_available_trips_immediately_once_armed() {
        let mut d = armed(128 * MIB, 0);
        assert_eq!(d.evaluate(64 * MIB, 0), Some(PressureSignal::LowAvailable));
    }

    #[test]
    fn available_above_floor_does_not_trip() {
        let mut d = armed(128 * MIB, 0);
        assert_eq!(d.evaluate(256 * MIB, 0), None);
    }

    #[test]
    fn refault_spike_requires_consecutive_samples() {
        let mut d = armed(0, 2000);
        assert_eq!(d.evaluate(u64::MAX, 5000), None, "first hit must not trip");
        assert_eq!(
            d.evaluate(u64::MAX, 5000),
            Some(PressureSignal::RefaultSpike),
            "second consecutive hit trips"
        );
    }

    #[test]
    fn refault_dip_resets_consecutive_count() {
        let mut d = armed(0, 2000);
        assert_eq!(d.evaluate(u64::MAX, 5000), None);
        assert_eq!(d.evaluate(u64::MAX, 100), None, "dip resets the streak");
        assert_eq!(d.evaluate(u64::MAX, 5000), None, "streak restarts");
        assert_eq!(
            d.evaluate(u64::MAX, 5000),
            Some(PressureSignal::RefaultSpike)
        );
    }

    #[test]
    fn zero_refault_threshold_disables_refault_signal() {
        let mut d = armed(0, 0);
        assert_eq!(d.evaluate(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn low_available_wins_over_refault_spike() {
        let mut d = armed(128 * MIB, 2000);
        assert_eq!(d.evaluate(u64::MAX, 5000), None);
        assert_eq!(
            d.evaluate(64 * MIB, 5000),
            Some(PressureSignal::LowAvailable)
        );
    }

    #[test]
    fn psi_threshold_zero_uses_default() {
        assert_eq!(psi_stall_threshold_us(0), PSI_DEFAULT_FULL_STALL_US);
    }

    #[test]
    fn psi_threshold_clamps_to_window() {
        assert_eq!(
            psi_stall_threshold_us(u64::from(PSI_WINDOW_US) * 10),
            PSI_WINDOW_US
        );
        assert_eq!(psi_stall_threshold_us(u64::MAX), PSI_WINDOW_US);
    }

    #[test]
    fn psi_threshold_passes_sane_values() {
        assert_eq!(psi_stall_threshold_us(150_000), 150_000);
    }

    /// Hardware-validated regression #1: balloon inflation evicts the page
    /// cache, and the refault burst from background daemons re-warming it
    /// must not trip a restore while the guest is still settling. (The
    /// burst can outlive arming, which is why the host disables the
    /// refault signal by default and relies on the floor.)
    #[test]
    fn settling_ignores_post_inflation_refault_burst() {
        let mut d = PressureDetector::new(thresholds(128 * MIB, 2000));
        // Healthy memory + refault burst: settling, then arming, no trip.
        assert_eq!(d.evaluate(256 * MIB, 50_000), None);
        assert_eq!(d.evaluate(256 * MIB, 50_000), None);
        assert_eq!(d.evaluate(256 * MIB, 50_000), None);
        assert!(d.is_armed());
        // Once armed, a sustained burst counts as thrash again.
        assert_eq!(d.evaluate(256 * MIB, 50_000), None);
        assert_eq!(
            d.evaluate(256 * MIB, 50_000),
            Some(PressureSignal::RefaultSpike)
        );
    }

    /// Hardware-validated regression #2: `MemAvailable` is pinned near zero
    /// for the whole inflation (tens of seconds for a many-GiB shrink). The
    /// floor must not trip until the guest has settled once, however long
    /// the inflation takes.
    #[test]
    fn settling_tolerates_arbitrarily_long_inflation() {
        let mut d = PressureDetector::new(thresholds(128 * MIB, 0));
        for _ in 0..(SETTLE_CAP_SAMPLES - 1) {
            assert_eq!(d.evaluate(0, 0), None, "inflation must not trip the floor");
        }
        assert!(!d.is_armed());
        // Inflation converges; the guest settles and the detector arms.
        for _ in 0..ARM_AFTER_HEALTHY_SAMPLES {
            assert_eq!(d.evaluate(256 * MIB, 0), None);
        }
        assert!(d.is_armed());
        // Armed: real pressure now trips instantly.
        assert_eq!(d.evaluate(64 * MIB, 0), Some(PressureSignal::LowAvailable));
    }

    /// A guest that never settles was undersized by the entry probe;
    /// restoring at the cap is the fail-safe.
    #[test]
    fn never_settling_trips_at_the_cap() {
        let mut d = PressureDetector::new(thresholds(128 * MIB, 0));
        for _ in 0..(SETTLE_CAP_SAMPLES - 1) {
            assert_eq!(d.evaluate(0, 0), None);
        }
        assert_eq!(d.evaluate(0, 0), Some(PressureSignal::LowAvailable));
    }

    #[test]
    fn settling_healthy_streak_resets_on_dip() {
        let mut d = PressureDetector::new(thresholds(128 * MIB, 0));
        assert_eq!(d.evaluate(256 * MIB, 0), None);
        assert_eq!(d.evaluate(256 * MIB, 0), None);
        assert_eq!(d.evaluate(0, 0), None, "dip resets the healthy streak");
        assert!(!d.is_armed());
        for _ in 0..ARM_AFTER_HEALTHY_SAMPLES {
            assert_eq!(d.evaluate(256 * MIB, 0), None);
        }
        assert!(d.is_armed());
    }
}
