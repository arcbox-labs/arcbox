//! # arcbox-perf
//!
//! Performance monitoring for ArcBox Pro.
//!
//! Features:
//!
//! - **Real-time metrics**: CPU, memory, I/O, network
//! - **Historical data**: Time-series storage
//! - **Alerts**: Threshold-based notifications
//! - **Profiling**: Container and VM profiling
//!
//! ## License
//!
//! This crate is licensed under BSL-1.1, which converts to MIT after 2 years.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};

/// System metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// CPU usage (0-100).
    pub cpu_percent: f64,
    /// Memory used in bytes.
    pub memory_used: u64,
    /// Memory total in bytes.
    pub memory_total: u64,
    /// Disk read bytes/sec.
    pub disk_read_bps: u64,
    /// Disk write bytes/sec.
    pub disk_write_bps: u64,
    /// Network RX bytes/sec.
    pub net_rx_bps: u64,
    /// Network TX bytes/sec.
    pub net_tx_bps: u64,
}

/// Container metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerMetrics {
    /// Container ID.
    pub id: String,
    /// CPU usage (0-100).
    pub cpu_percent: f64,
    /// Memory used in bytes.
    pub memory_used: u64,
    /// Memory limit in bytes.
    pub memory_limit: u64,
    /// Block I/O read bytes.
    pub block_read: u64,
    /// Block I/O write bytes.
    pub block_write: u64,
    /// Network RX bytes.
    pub net_rx: u64,
    /// Network TX bytes.
    pub net_tx: u64,
}

/// Performance monitor.
pub struct PerfMonitor {
    /// Sample interval in milliseconds.
    sample_interval_ms: u64,
}

impl PerfMonitor {
    /// Creates a new performance monitor.
    #[must_use]
    pub fn new(sample_interval_ms: u64) -> Self {
        Self { sample_interval_ms }
    }

    /// Collects system metrics.
    #[must_use]
    pub fn collect_system(&self) -> SystemMetrics {
        // TODO: Collect real metrics
        SystemMetrics::default()
    }

    /// Collects container metrics.
    #[must_use]
    pub fn collect_container(&self, id: &str) -> ContainerMetrics {
        ContainerMetrics {
            id: id.to_string(),
            ..Default::default()
        }
    }

    /// Returns the sample interval.
    #[must_use]
    pub fn sample_interval_ms(&self) -> u64 {
        self.sample_interval_ms
    }
}

impl Default for PerfMonitor {
    fn default() -> Self {
        Self::new(1000)
    }
}
