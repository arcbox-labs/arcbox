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
//! The guest kernel ships without `CONFIG_PSI`; if that changes the sampler
//! can switch to PSI triggers without touching this contract.

/// Refault-rate samples that must consecutively exceed the threshold before
/// tripping. Damps one-off bursts (e.g. a cold-started binary faulting its
/// text pages in) that are not sustained thrash.
pub const REFAULT_CONSECUTIVE_SAMPLES: u32 = 2;

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
#[derive(Debug)]
pub struct PressureDetector {
    thresholds: PressureThresholds,
    refault_hits: u32,
}

impl PressureDetector {
    /// Creates a detector for the given thresholds.
    #[must_use]
    pub fn new(thresholds: PressureThresholds) -> Self {
        Self {
            thresholds,
            refault_hits: 0,
        }
    }

    /// Feeds one sample. `refault_rate` is pages/second since the previous
    /// sample. Returns the tripped signal, if any; low-available wins when
    /// both trip.
    pub fn evaluate(&mut self, available_bytes: u64, refault_rate: u64) -> Option<PressureSignal> {
        let floor = self.thresholds.min_available_bytes;
        let refault = self.thresholds.max_refault_rate;

        if refault > 0 && refault_rate >= refault {
            self.refault_hits += 1;
        } else {
            self.refault_hits = 0;
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
    fn low_available_trips_immediately() {
        let mut d = PressureDetector::new(thresholds(128 * MIB, 0));
        assert_eq!(d.evaluate(64 * MIB, 0), Some(PressureSignal::LowAvailable));
    }

    #[test]
    fn available_above_floor_does_not_trip() {
        let mut d = PressureDetector::new(thresholds(128 * MIB, 0));
        assert_eq!(d.evaluate(256 * MIB, 0), None);
    }

    #[test]
    fn zero_floor_disables_available_signal() {
        let mut d = PressureDetector::new(thresholds(0, 0));
        assert_eq!(d.evaluate(0, 0), None);
    }

    #[test]
    fn refault_spike_requires_consecutive_samples() {
        let mut d = PressureDetector::new(thresholds(0, 2000));
        assert_eq!(d.evaluate(u64::MAX, 5000), None, "first hit must not trip");
        assert_eq!(
            d.evaluate(u64::MAX, 5000),
            Some(PressureSignal::RefaultSpike),
            "second consecutive hit trips"
        );
    }

    #[test]
    fn refault_dip_resets_consecutive_count() {
        let mut d = PressureDetector::new(thresholds(0, 2000));
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
        let mut d = PressureDetector::new(thresholds(0, 0));
        assert_eq!(d.evaluate(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn low_available_wins_over_refault_spike() {
        let mut d = PressureDetector::new(thresholds(128 * MIB, 2000));
        assert_eq!(d.evaluate(u64::MAX, 5000), None);
        assert_eq!(
            d.evaluate(64 * MIB, 5000),
            Some(PressureSignal::LowAvailable)
        );
    }
}
