//! Performance statistics for the datapath.
//!
//! This module provides cache-line aligned counters for tracking
//! datapath performance metrics without causing false sharing.

use std::sync::atomic::{AtomicU64, Ordering};

use super::CachePadded;

/// Datapath performance statistics.
///
/// All counters are cache-line aligned to prevent false sharing
/// when updated from different threads.
#[derive(Debug)]
pub struct DatapathStats {
    /// Total packets transmitted (guest -> host).
    pub tx_packets: CachePadded<AtomicU64>,
    /// Total bytes transmitted.
    pub tx_bytes: CachePadded<AtomicU64>,
    /// TX packets dropped due to full queue.
    pub tx_dropped: CachePadded<AtomicU64>,
    /// TX errors.
    pub tx_errors: CachePadded<AtomicU64>,

    /// Total packets received (host -> guest).
    pub rx_packets: CachePadded<AtomicU64>,
    /// Total bytes received.
    pub rx_bytes: CachePadded<AtomicU64>,
    /// RX packets dropped due to full queue.
    pub rx_dropped: CachePadded<AtomicU64>,
    /// RX errors.
    pub rx_errors: CachePadded<AtomicU64>,

    /// NAT translations performed.
    pub nat_translations: CachePadded<AtomicU64>,
    /// NAT fast path hits.
    pub nat_fast_path_hits: CachePadded<AtomicU64>,
    /// NAT slow path lookups.
    pub nat_slow_path_lookups: CachePadded<AtomicU64>,
    /// NAT connection tracking entries created.
    pub nat_connections_created: CachePadded<AtomicU64>,
    /// NAT connection tracking entries expired.
    pub nat_connections_expired: CachePadded<AtomicU64>,

    /// Poll loop iterations.
    pub poll_iterations: CachePadded<AtomicU64>,
    /// Poll loop iterations with work done.
    pub poll_work_done: CachePadded<AtomicU64>,
    /// Poll loop busy spins (no work).
    pub poll_busy_spins: CachePadded<AtomicU64>,

    /// Batch sizes histogram (power of 2 buckets).
    /// [0]: 1 packet, [1]: 2 packets, [2]: 4 packets, etc.
    pub batch_histogram: [CachePadded<AtomicU64>; 8],
}

impl Default for DatapathStats {
    fn default() -> Self {
        Self::new()
    }
}

impl DatapathStats {
    /// Creates new empty statistics.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tx_packets: CachePadded::new(AtomicU64::new(0)),
            tx_bytes: CachePadded::new(AtomicU64::new(0)),
            tx_dropped: CachePadded::new(AtomicU64::new(0)),
            tx_errors: CachePadded::new(AtomicU64::new(0)),

            rx_packets: CachePadded::new(AtomicU64::new(0)),
            rx_bytes: CachePadded::new(AtomicU64::new(0)),
            rx_dropped: CachePadded::new(AtomicU64::new(0)),
            rx_errors: CachePadded::new(AtomicU64::new(0)),

            nat_translations: CachePadded::new(AtomicU64::new(0)),
            nat_fast_path_hits: CachePadded::new(AtomicU64::new(0)),
            nat_slow_path_lookups: CachePadded::new(AtomicU64::new(0)),
            nat_connections_created: CachePadded::new(AtomicU64::new(0)),
            nat_connections_expired: CachePadded::new(AtomicU64::new(0)),

            poll_iterations: CachePadded::new(AtomicU64::new(0)),
            poll_work_done: CachePadded::new(AtomicU64::new(0)),
            poll_busy_spins: CachePadded::new(AtomicU64::new(0)),

            batch_histogram: [
                CachePadded::new(AtomicU64::new(0)),
                CachePadded::new(AtomicU64::new(0)),
                CachePadded::new(AtomicU64::new(0)),
                CachePadded::new(AtomicU64::new(0)),
                CachePadded::new(AtomicU64::new(0)),
                CachePadded::new(AtomicU64::new(0)),
                CachePadded::new(AtomicU64::new(0)),
                CachePadded::new(AtomicU64::new(0)),
            ],
        }
    }

    /// Records transmitted packets.
    #[inline]
    pub fn record_tx(&self, packets: u64, bytes: u64) {
        self.tx_packets.0.fetch_add(packets, Ordering::Relaxed);
        self.tx_bytes.0.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records a TX drop.
    #[inline]
    pub fn record_tx_drop(&self) {
        self.tx_dropped.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a TX error.
    #[inline]
    pub fn record_tx_error(&self) {
        self.tx_errors.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Records received packets.
    #[inline]
    pub fn record_rx(&self, packets: u64, bytes: u64) {
        self.rx_packets.0.fetch_add(packets, Ordering::Relaxed);
        self.rx_bytes.0.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records an RX drop.
    #[inline]
    pub fn record_rx_drop(&self) {
        self.rx_dropped.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an RX error.
    #[inline]
    pub fn record_rx_error(&self) {
        self.rx_errors.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a NAT translation.
    #[inline]
    pub fn record_nat_translation(&self, fast_path: bool) {
        self.nat_translations.0.fetch_add(1, Ordering::Relaxed);
        if fast_path {
            self.nat_fast_path_hits.0.fetch_add(1, Ordering::Relaxed);
        } else {
            self.nat_slow_path_lookups.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a new NAT connection.
    #[inline]
    pub fn record_nat_connection_created(&self) {
        self.nat_connections_created
            .0
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records an expired NAT connection.
    #[inline]
    pub fn record_nat_connection_expired(&self) {
        self.nat_connections_expired
            .0
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a poll iteration.
    #[inline]
    pub fn record_poll(&self, work_done: bool) {
        self.poll_iterations.0.fetch_add(1, Ordering::Relaxed);
        if work_done {
            self.poll_work_done.0.fetch_add(1, Ordering::Relaxed);
        } else {
            self.poll_busy_spins.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a batch size in the histogram.
    #[inline]
    pub fn record_batch_size(&self, size: usize) {
        // Map size to bucket: 0 for 0, 0 for 1, 1 for 2-3, 2 for 4-7, etc.
        let bucket = if size == 0 {
            0
        } else {
            (usize::BITS - (size - 1).leading_zeros()) as usize
        };
        let bucket = bucket.min(self.batch_histogram.len() - 1);
        self.batch_histogram[bucket]
            .0
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a snapshot of current statistics.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            tx_packets: self.tx_packets.0.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.0.load(Ordering::Relaxed),
            tx_dropped: self.tx_dropped.0.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.0.load(Ordering::Relaxed),

            rx_packets: self.rx_packets.0.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.0.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.0.load(Ordering::Relaxed),
            rx_errors: self.rx_errors.0.load(Ordering::Relaxed),

            nat_translations: self.nat_translations.0.load(Ordering::Relaxed),
            nat_fast_path_hits: self.nat_fast_path_hits.0.load(Ordering::Relaxed),
            nat_slow_path_lookups: self.nat_slow_path_lookups.0.load(Ordering::Relaxed),
            nat_connections_created: self.nat_connections_created.0.load(Ordering::Relaxed),
            nat_connections_expired: self.nat_connections_expired.0.load(Ordering::Relaxed),

            poll_iterations: self.poll_iterations.0.load(Ordering::Relaxed),
            poll_work_done: self.poll_work_done.0.load(Ordering::Relaxed),
            poll_busy_spins: self.poll_busy_spins.0.load(Ordering::Relaxed),
        }
    }

    /// Resets all counters to zero.
    pub fn reset(&self) {
        self.tx_packets.0.store(0, Ordering::Relaxed);
        self.tx_bytes.0.store(0, Ordering::Relaxed);
        self.tx_dropped.0.store(0, Ordering::Relaxed);
        self.tx_errors.0.store(0, Ordering::Relaxed);

        self.rx_packets.0.store(0, Ordering::Relaxed);
        self.rx_bytes.0.store(0, Ordering::Relaxed);
        self.rx_dropped.0.store(0, Ordering::Relaxed);
        self.rx_errors.0.store(0, Ordering::Relaxed);

        self.nat_translations.0.store(0, Ordering::Relaxed);
        self.nat_fast_path_hits.0.store(0, Ordering::Relaxed);
        self.nat_slow_path_lookups.0.store(0, Ordering::Relaxed);
        self.nat_connections_created.0.store(0, Ordering::Relaxed);
        self.nat_connections_expired.0.store(0, Ordering::Relaxed);

        self.poll_iterations.0.store(0, Ordering::Relaxed);
        self.poll_work_done.0.store(0, Ordering::Relaxed);
        self.poll_busy_spins.0.store(0, Ordering::Relaxed);

        for bucket in &self.batch_histogram {
            bucket.0.store(0, Ordering::Relaxed);
        }
    }
}

/// A point-in-time snapshot of datapath statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatsSnapshot {
    /// Total packets transmitted.
    pub tx_packets: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// TX packets dropped.
    pub tx_dropped: u64,
    /// TX errors.
    pub tx_errors: u64,

    /// Total packets received.
    pub rx_packets: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// RX packets dropped.
    pub rx_dropped: u64,
    /// RX errors.
    pub rx_errors: u64,

    /// NAT translations performed.
    pub nat_translations: u64,
    /// NAT fast path hits.
    pub nat_fast_path_hits: u64,
    /// NAT slow path lookups.
    pub nat_slow_path_lookups: u64,
    /// NAT connections created.
    pub nat_connections_created: u64,
    /// NAT connections expired.
    pub nat_connections_expired: u64,

    /// Poll iterations.
    pub poll_iterations: u64,
    /// Poll work done.
    pub poll_work_done: u64,
    /// Poll busy spins.
    pub poll_busy_spins: u64,
}

impl StatsSnapshot {
    /// Returns the total packets (TX + RX).
    #[inline]
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.tx_packets + self.rx_packets
    }

    /// Returns the total bytes (TX + RX).
    #[inline]
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.tx_bytes + self.rx_bytes
    }

    /// Returns the NAT fast path hit rate (0.0 - 1.0).
    #[inline]
    #[must_use]
    pub fn nat_hit_rate(&self) -> f64 {
        if self.nat_translations == 0 {
            0.0
        } else {
            self.nat_fast_path_hits as f64 / self.nat_translations as f64
        }
    }

    /// Returns the poll efficiency (ratio of iterations with work).
    #[inline]
    #[must_use]
    pub fn poll_efficiency(&self) -> f64 {
        if self.poll_iterations == 0 {
            0.0
        } else {
            self.poll_work_done as f64 / self.poll_iterations as f64
        }
    }

    /// Computes the delta between two snapshots.
    #[must_use]
    pub fn delta(&self, prev: &Self) -> Self {
        Self {
            tx_packets: self.tx_packets.saturating_sub(prev.tx_packets),
            tx_bytes: self.tx_bytes.saturating_sub(prev.tx_bytes),
            tx_dropped: self.tx_dropped.saturating_sub(prev.tx_dropped),
            tx_errors: self.tx_errors.saturating_sub(prev.tx_errors),

            rx_packets: self.rx_packets.saturating_sub(prev.rx_packets),
            rx_bytes: self.rx_bytes.saturating_sub(prev.rx_bytes),
            rx_dropped: self.rx_dropped.saturating_sub(prev.rx_dropped),
            rx_errors: self.rx_errors.saturating_sub(prev.rx_errors),

            nat_translations: self.nat_translations.saturating_sub(prev.nat_translations),
            nat_fast_path_hits: self
                .nat_fast_path_hits
                .saturating_sub(prev.nat_fast_path_hits),
            nat_slow_path_lookups: self
                .nat_slow_path_lookups
                .saturating_sub(prev.nat_slow_path_lookups),
            nat_connections_created: self
                .nat_connections_created
                .saturating_sub(prev.nat_connections_created),
            nat_connections_expired: self
                .nat_connections_expired
                .saturating_sub(prev.nat_connections_expired),

            poll_iterations: self.poll_iterations.saturating_sub(prev.poll_iterations),
            poll_work_done: self.poll_work_done.saturating_sub(prev.poll_work_done),
            poll_busy_spins: self.poll_busy_spins.saturating_sub(prev.poll_busy_spins),
        }
    }
}

impl std::fmt::Display for StatsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Datapath Statistics:")?;
        writeln!(
            f,
            "  TX: {} packets, {} bytes, {} dropped, {} errors",
            self.tx_packets, self.tx_bytes, self.tx_dropped, self.tx_errors
        )?;
        writeln!(
            f,
            "  RX: {} packets, {} bytes, {} dropped, {} errors",
            self.rx_packets, self.rx_bytes, self.rx_dropped, self.rx_errors
        )?;
        writeln!(
            f,
            "  NAT: {} translations ({:.1}% fast path)",
            self.nat_translations,
            self.nat_hit_rate() * 100.0
        )?;
        writeln!(
            f,
            "  Poll: {} iterations ({:.1}% efficient)",
            self.poll_iterations,
            self.poll_efficiency() * 100.0
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_basic() {
        let stats = DatapathStats::new();

        stats.record_tx(10, 1000);
        stats.record_rx(5, 500);
        stats.record_tx_drop();
        stats.record_rx_error();

        let snap = stats.snapshot();
        assert_eq!(snap.tx_packets, 10);
        assert_eq!(snap.tx_bytes, 1000);
        assert_eq!(snap.rx_packets, 5);
        assert_eq!(snap.rx_bytes, 500);
        assert_eq!(snap.tx_dropped, 1);
        assert_eq!(snap.rx_errors, 1);
    }

    #[test]
    fn test_stats_nat() {
        let stats = DatapathStats::new();

        stats.record_nat_translation(true);
        stats.record_nat_translation(true);
        stats.record_nat_translation(false);

        let snap = stats.snapshot();
        assert_eq!(snap.nat_translations, 3);
        assert_eq!(snap.nat_fast_path_hits, 2);
        assert_eq!(snap.nat_slow_path_lookups, 1);
        assert!((snap.nat_hit_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_stats_reset() {
        let stats = DatapathStats::new();

        stats.record_tx(100, 10000);
        stats.reset();

        let snap = stats.snapshot();
        assert_eq!(snap.tx_packets, 0);
        assert_eq!(snap.tx_bytes, 0);
    }

    #[test]
    fn test_snapshot_delta() {
        let stats = DatapathStats::new();

        stats.record_tx(10, 1000);
        let snap1 = stats.snapshot();

        stats.record_tx(5, 500);
        let snap2 = stats.snapshot();

        let delta = snap2.delta(&snap1);
        assert_eq!(delta.tx_packets, 5);
        assert_eq!(delta.tx_bytes, 500);
    }

    #[test]
    fn test_batch_histogram() {
        let stats = DatapathStats::new();

        stats.record_batch_size(1);
        stats.record_batch_size(2);
        stats.record_batch_size(4);
        stats.record_batch_size(8);
        stats.record_batch_size(64);

        assert_eq!(stats.batch_histogram[0].0.load(Ordering::Relaxed), 1); // 1
        assert_eq!(stats.batch_histogram[1].0.load(Ordering::Relaxed), 1); // 2
        assert_eq!(stats.batch_histogram[2].0.load(Ordering::Relaxed), 1); // 4
        assert_eq!(stats.batch_histogram[3].0.load(Ordering::Relaxed), 1); // 8
        assert_eq!(stats.batch_histogram[6].0.load(Ordering::Relaxed), 1); // 64
    }
}
