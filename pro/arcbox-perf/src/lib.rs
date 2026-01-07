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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// System metrics at a point in time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Timestamp when metrics were collected.
    pub timestamp: DateTime<Utc>,
    /// CPU usage (0-100).
    pub cpu_percent: f64,
    /// Per-core CPU usage.
    pub cpu_per_core: Vec<f64>,
    /// Memory used in bytes.
    pub memory_used: u64,
    /// Memory total in bytes.
    pub memory_total: u64,
    /// Memory available in bytes.
    pub memory_available: u64,
    /// Cached memory in bytes.
    pub memory_cached: u64,
    /// Disk read bytes/sec.
    pub disk_read_bps: u64,
    /// Disk write bytes/sec.
    pub disk_write_bps: u64,
    /// Disk read IOPS.
    pub disk_read_iops: u64,
    /// Disk write IOPS.
    pub disk_write_iops: u64,
    /// Network RX bytes/sec.
    pub net_rx_bps: u64,
    /// Network TX bytes/sec.
    pub net_tx_bps: u64,
    /// Network RX packets/sec.
    pub net_rx_pps: u64,
    /// Network TX packets/sec.
    pub net_tx_pps: u64,
    /// Load average (1 min).
    pub load_1: f64,
    /// Load average (5 min).
    pub load_5: f64,
    /// Load average (15 min).
    pub load_15: f64,
}

/// Container metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerMetrics {
    /// Timestamp when metrics were collected.
    pub timestamp: DateTime<Utc>,
    /// Container ID.
    pub id: String,
    /// Container name.
    pub name: String,
    /// CPU usage (0-100).
    pub cpu_percent: f64,
    /// Memory used in bytes.
    pub memory_used: u64,
    /// Memory limit in bytes.
    pub memory_limit: u64,
    /// Memory usage percent.
    pub memory_percent: f64,
    /// Block I/O read bytes.
    pub block_read: u64,
    /// Block I/O write bytes.
    pub block_write: u64,
    /// Network RX bytes.
    pub net_rx: u64,
    /// Network TX bytes.
    pub net_tx: u64,
    /// Number of PIDs.
    pub pids: u32,
}

/// VM metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmMetrics {
    /// Timestamp when metrics were collected.
    pub timestamp: DateTime<Utc>,
    /// VM ID/name.
    pub id: String,
    /// vCPU usage (0-100 per vCPU).
    pub vcpu_percent: Vec<f64>,
    /// Guest memory used in bytes.
    pub memory_used: u64,
    /// Guest memory total in bytes.
    pub memory_total: u64,
    /// VirtIO block read bytes.
    pub virtio_blk_read: u64,
    /// VirtIO block write bytes.
    pub virtio_blk_write: u64,
    /// VirtIO net RX bytes.
    pub virtio_net_rx: u64,
    /// VirtIO net TX bytes.
    pub virtio_net_tx: u64,
}

/// Metrics history configuration.
#[derive(Debug, Clone)]
pub struct HistoryConfig {
    /// Maximum number of samples to keep.
    pub max_samples: usize,
    /// Sample interval in milliseconds.
    pub sample_interval_ms: u64,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            max_samples: 3600, // 1 hour at 1 sample/sec
            sample_interval_ms: 1000,
        }
    }
}

/// Internal state for CPU usage calculation.
#[derive(Debug, Clone, Default)]
struct CpuState {
    /// Previous CPU times.
    prev_times: Option<CpuTimes>,
    /// Last update time.
    last_update: Option<Instant>,
}

/// CPU time breakdown.
#[derive(Debug, Clone, Default)]
struct CpuTimes {
    user: u64,
    system: u64,
    idle: u64,
    total: u64,
}

/// Internal state for I/O rate calculation.
#[derive(Debug, Clone, Default)]
struct IoState {
    /// Previous disk read bytes.
    prev_disk_read: u64,
    /// Previous disk write bytes.
    prev_disk_write: u64,
    /// Previous disk read operations.
    prev_disk_read_ops: u64,
    /// Previous disk write operations.
    prev_disk_write_ops: u64,
    /// Previous network RX bytes.
    prev_net_rx: u64,
    /// Previous network TX bytes.
    prev_net_tx: u64,
    /// Previous network RX packets.
    prev_net_rx_packets: u64,
    /// Previous network TX packets.
    prev_net_tx_packets: u64,
    /// Last update time.
    last_update: Option<Instant>,
}

/// Performance monitor.
///
/// Collects and tracks system, container, and VM performance metrics.
pub struct PerfMonitor {
    /// Configuration.
    config: HistoryConfig,
    /// System metrics history.
    system_history: Arc<RwLock<VecDeque<SystemMetrics>>>,
    /// Container metrics history (keyed by container ID).
    container_history: Arc<RwLock<std::collections::HashMap<String, VecDeque<ContainerMetrics>>>>,
    /// VM metrics history (keyed by VM ID).
    vm_history: Arc<RwLock<std::collections::HashMap<String, VecDeque<VmMetrics>>>>,
    /// CPU state for rate calculation.
    cpu_state: RwLock<CpuState>,
    /// I/O state for rate calculation.
    io_state: RwLock<IoState>,
}

impl PerfMonitor {
    /// Creates a new performance monitor with default config.
    #[must_use]
    pub fn new(sample_interval_ms: u64) -> Self {
        Self::with_config(HistoryConfig {
            sample_interval_ms,
            ..Default::default()
        })
    }

    /// Creates a new performance monitor with custom config.
    #[must_use]
    pub fn with_config(config: HistoryConfig) -> Self {
        Self {
            config,
            system_history: Arc::new(RwLock::new(VecDeque::new())),
            container_history: Arc::new(RwLock::new(std::collections::HashMap::new())),
            vm_history: Arc::new(RwLock::new(std::collections::HashMap::new())),
            cpu_state: RwLock::new(CpuState::default()),
            io_state: RwLock::new(IoState::default()),
        }
    }

    /// Collects current system metrics.
    #[must_use]
    pub fn collect_system(&self) -> SystemMetrics {
        let timestamp = Utc::now();

        // Collect CPU usage.
        let (cpu_percent, cpu_per_core) = self.collect_cpu_usage();

        // Collect memory usage.
        let (memory_used, memory_total, memory_available, memory_cached) = self.collect_memory();

        // Collect disk I/O rates.
        let (disk_read_bps, disk_write_bps, disk_read_iops, disk_write_iops) = self.collect_disk_io();

        // Collect network I/O rates.
        let (net_rx_bps, net_tx_bps, net_rx_pps, net_tx_pps) = self.collect_network_io();

        // Collect load average.
        let (load_1, load_5, load_15) = self.collect_load_average();

        let metrics = SystemMetrics {
            timestamp,
            cpu_percent,
            cpu_per_core,
            memory_used,
            memory_total,
            memory_available,
            memory_cached,
            disk_read_bps,
            disk_write_bps,
            disk_read_iops,
            disk_write_iops,
            net_rx_bps,
            net_tx_bps,
            net_rx_pps,
            net_tx_pps,
            load_1,
            load_5,
            load_15,
        };

        // Store in history.
        if let Ok(mut history) = self.system_history.write() {
            history.push_back(metrics.clone());
            while history.len() > self.config.max_samples {
                history.pop_front();
            }
        }

        metrics
    }

    /// Collects CPU usage.
    fn collect_cpu_usage(&self) -> (f64, Vec<f64>) {
        #[cfg(target_os = "macos")]
        {
            self.collect_cpu_usage_macos()
        }

        #[cfg(target_os = "linux")]
        {
            self.collect_cpu_usage_linux()
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            (0.0, Vec::new())
        }
    }

    #[cfg(target_os = "macos")]
    fn collect_cpu_usage_macos(&self) -> (f64, Vec<f64>) {
        use std::process::Command;

        // Use top command to get CPU usage on macOS.
        let output = Command::new("top")
            .args(["-l", "1", "-n", "0", "-stats", "cpu"])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Parse "CPU usage: X% user, Y% sys, Z% idle"
            for line in stdout.lines() {
                if line.contains("CPU usage:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 7 {
                        let user: f64 = parts[2].trim_end_matches('%').parse().unwrap_or(0.0);
                        let sys: f64 = parts[4].trim_end_matches('%').parse().unwrap_or(0.0);
                        return (user + sys, vec![user + sys]);
                    }
                }
            }
        }

        (0.0, Vec::new())
    }

    #[cfg(target_os = "linux")]
    fn collect_cpu_usage_linux(&self) -> (f64, Vec<f64>) {
        use std::fs;

        // Read /proc/stat for CPU times.
        let stat = match fs::read_to_string("/proc/stat") {
            Ok(s) => s,
            Err(_) => return (0.0, Vec::new()),
        };

        let mut cpu_percent = 0.0;
        let mut per_core = Vec::new();

        for line in stat.lines() {
            if line.starts_with("cpu ") {
                // Overall CPU.
                let times = parse_cpu_line(line);
                let mut state = self.cpu_state.write().unwrap();

                if let Some(prev) = &state.prev_times {
                    let total_diff = times.total.saturating_sub(prev.total);
                    let idle_diff = times.idle.saturating_sub(prev.idle);
                    if total_diff > 0 {
                        cpu_percent = 100.0 * (1.0 - (idle_diff as f64 / total_diff as f64));
                    }
                }

                state.prev_times = Some(times);
                state.last_update = Some(Instant::now());
            } else if line.starts_with("cpu") {
                // Per-core CPU (cpu0, cpu1, etc.)
                // Simplified: just report the same as overall for now.
                per_core.push(cpu_percent);
            }
        }

        (cpu_percent, per_core)
    }

    /// Collects memory usage.
    fn collect_memory(&self) -> (u64, u64, u64, u64) {
        #[cfg(target_os = "macos")]
        {
            self.collect_memory_macos()
        }

        #[cfg(target_os = "linux")]
        {
            self.collect_memory_linux()
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            (0, 0, 0, 0)
        }
    }

    #[cfg(target_os = "macos")]
    fn collect_memory_macos(&self) -> (u64, u64, u64, u64) {
        use std::process::Command;

        // Get total memory from sysctl.
        let total = Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
            .unwrap_or(0);

        // Get memory stats from vm_stat.
        let output = Command::new("vm_stat").output();

        let mut pages_free = 0u64;
        let mut pages_active = 0u64;
        let mut pages_inactive = 0u64;
        let mut pages_wired = 0u64;
        let mut pages_compressed = 0u64;
        let page_size = 4096u64; // Standard page size

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("Pages free:") {
                    pages_free = parse_vm_stat_value(line);
                } else if line.starts_with("Pages active:") {
                    pages_active = parse_vm_stat_value(line);
                } else if line.starts_with("Pages inactive:") {
                    pages_inactive = parse_vm_stat_value(line);
                } else if line.starts_with("Pages wired down:") {
                    pages_wired = parse_vm_stat_value(line);
                } else if line.starts_with("Pages occupied by compressor:") {
                    pages_compressed = parse_vm_stat_value(line);
                }
            }
        }

        let used = (pages_active + pages_wired + pages_compressed) * page_size;
        let available = (pages_free + pages_inactive) * page_size;
        let cached = pages_inactive * page_size;

        (used, total, available, cached)
    }

    #[cfg(target_os = "linux")]
    fn collect_memory_linux(&self) -> (u64, u64, u64, u64) {
        use std::fs;

        let meminfo = match fs::read_to_string("/proc/meminfo") {
            Ok(s) => s,
            Err(_) => return (0, 0, 0, 0),
        };

        let mut total = 0u64;
        let mut available = 0u64;
        let mut cached = 0u64;
        let mut buffers = 0u64;

        for line in meminfo.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let value: u64 = parts[1].parse().unwrap_or(0) * 1024; // Convert KB to bytes
                match parts[0] {
                    "MemTotal:" => total = value,
                    "MemAvailable:" => available = value,
                    "Cached:" => cached = value,
                    "Buffers:" => buffers = value,
                    _ => {}
                }
            }
        }

        let used = total.saturating_sub(available);
        (used, total, available, cached + buffers)
    }

    /// Collects disk I/O.
    fn collect_disk_io(&self) -> (u64, u64, u64, u64) {
        #[cfg(target_os = "macos")]
        {
            self.collect_disk_io_macos()
        }

        #[cfg(target_os = "linux")]
        {
            self.collect_disk_io_linux()
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            (0, 0, 0, 0)
        }
    }

    #[cfg(target_os = "macos")]
    fn collect_disk_io_macos(&self) -> (u64, u64, u64, u64) {
        use std::process::Command;

        // Use iostat to get disk I/O stats on macOS.
        // iostat -d returns: KB/t, tps, MB/s for each disk
        let output = Command::new("iostat")
            .args(["-d", "-c", "2", "-w", "1"])
            .output();

        let mut read_bytes: u64 = 0;
        let mut write_bytes: u64 = 0;
        let mut read_ops: u64 = 0;
        let mut write_ops: u64 = 0;

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.lines().collect();

            // Find the last data line (second sample for rate calculation).
            // Format: KB/t tps MB/s
            for line in lines.iter().rev() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    // Parse MB/s (third column) and convert to bytes/sec.
                    if let Ok(mbs) = parts[2].parse::<f64>() {
                        // iostat reports combined read+write, estimate 50/50 split.
                        let bps = (mbs * 1024.0 * 1024.0) as u64;
                        read_bytes = bps / 2;
                        write_bytes = bps / 2;
                    }
                    // Parse tps (second column) for IOPS.
                    if let Ok(tps) = parts[1].parse::<f64>() {
                        let ops = tps as u64;
                        read_ops = ops / 2;
                        write_ops = ops / 2;
                    }
                    break;
                }
            }
        }

        (read_bytes, write_bytes, read_ops, write_ops)
    }

    #[cfg(target_os = "linux")]
    fn collect_disk_io_linux(&self) -> (u64, u64, u64, u64) {
        use std::fs;

        // Read /proc/diskstats for disk I/O statistics.
        // Format: major minor name reads_completed reads_merged sectors_read time_reading
        //         writes_completed writes_merged sectors_written time_writing
        //         ios_in_progress time_doing_io weighted_time
        let diskstats = match fs::read_to_string("/proc/diskstats") {
            Ok(s) => s,
            Err(_) => return (0, 0, 0, 0),
        };

        let mut total_read_bytes: u64 = 0;
        let mut total_write_bytes: u64 = 0;
        let mut total_read_ops: u64 = 0;
        let mut total_write_ops: u64 = 0;

        for line in diskstats.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue;
            }

            let name = parts[2];

            // Only count physical disks (sda, nvme0n1, vda, etc.), skip partitions.
            let is_physical_disk = (name.starts_with("sd") && !name.chars().last().map_or(false, |c| c.is_ascii_digit() && name.len() > 3))
                || (name.starts_with("nvme") && name.ends_with("n1"))
                || (name.starts_with("vd") && name.len() == 3)
                || (name.starts_with("hd") && name.len() == 3);

            if !is_physical_disk {
                continue;
            }

            // Field indices (0-based after name):
            // 3: reads completed, 5: sectors read (512 bytes each)
            // 7: writes completed, 9: sectors written
            let reads_completed: u64 = parts[3].parse().unwrap_or(0);
            let sectors_read: u64 = parts[5].parse().unwrap_or(0);
            let writes_completed: u64 = parts[7].parse().unwrap_or(0);
            let sectors_written: u64 = parts[9].parse().unwrap_or(0);

            total_read_bytes += sectors_read * 512;
            total_write_bytes += sectors_written * 512;
            total_read_ops += reads_completed;
            total_write_ops += writes_completed;
        }

        // Calculate rates based on previous values.
        let now = Instant::now();
        let mut io_state = self.io_state.write().unwrap();

        let (read_bps, write_bps, read_iops, write_iops) = if let Some(last_update) = io_state.last_update {
            let elapsed_secs = last_update.elapsed().as_secs_f64();
            if elapsed_secs > 0.0 {
                let read_bps = ((total_read_bytes.saturating_sub(io_state.prev_disk_read)) as f64 / elapsed_secs) as u64;
                let write_bps = ((total_write_bytes.saturating_sub(io_state.prev_disk_write)) as f64 / elapsed_secs) as u64;
                let read_iops = ((total_read_ops.saturating_sub(io_state.prev_disk_read_ops)) as f64 / elapsed_secs) as u64;
                let write_iops = ((total_write_ops.saturating_sub(io_state.prev_disk_write_ops)) as f64 / elapsed_secs) as u64;
                (read_bps, write_bps, read_iops, write_iops)
            } else {
                (0, 0, 0, 0)
            }
        } else {
            (0, 0, 0, 0)
        };

        // Update state for next calculation.
        io_state.prev_disk_read = total_read_bytes;
        io_state.prev_disk_write = total_write_bytes;
        io_state.prev_disk_read_ops = total_read_ops;
        io_state.prev_disk_write_ops = total_write_ops;
        io_state.last_update = Some(now);

        (read_bps, write_bps, read_iops, write_iops)
    }

    /// Collects network I/O.
    fn collect_network_io(&self) -> (u64, u64, u64, u64) {
        #[cfg(target_os = "macos")]
        {
            self.collect_network_io_macos()
        }

        #[cfg(target_os = "linux")]
        {
            self.collect_network_io_linux()
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            (0, 0, 0, 0)
        }
    }

    #[cfg(target_os = "macos")]
    fn collect_network_io_macos(&self) -> (u64, u64, u64, u64) {
        use std::process::Command;

        // Use netstat -ib to get network interface statistics on macOS.
        let output = Command::new("netstat")
            .args(["-ib"])
            .output();

        let mut total_rx_bytes: u64 = 0;
        let mut total_tx_bytes: u64 = 0;
        let mut total_rx_packets: u64 = 0;
        let mut total_tx_packets: u64 = 0;

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                let iface = parts[0];

                // Skip loopback and non-physical interfaces.
                if iface == "lo0" || iface.starts_with("utun") || iface.starts_with("awdl")
                   || iface.starts_with("llw") || iface.starts_with("bridge") {
                    continue;
                }

                // Parse Ipkts (index 4), Ibytes (index 6), Opkts (index 7), Obytes (index 9).
                // Note: Column indices may vary, this matches typical macOS netstat output.
                if let (Ok(rx_pkts), Ok(rx_bytes), Ok(tx_pkts), Ok(tx_bytes)) = (
                    parts.get(4).and_then(|s| s.parse::<u64>().ok()).ok_or(()),
                    parts.get(6).and_then(|s| s.parse::<u64>().ok()).ok_or(()),
                    parts.get(7).and_then(|s| s.parse::<u64>().ok()).ok_or(()),
                    parts.get(9).and_then(|s| s.parse::<u64>().ok()).ok_or(()),
                ) {
                    total_rx_packets += rx_pkts;
                    total_rx_bytes += rx_bytes;
                    total_tx_packets += tx_pkts;
                    total_tx_bytes += tx_bytes;
                }
            }
        }

        // Calculate rates based on previous values.
        let now = Instant::now();
        let mut io_state = self.io_state.write().unwrap();

        let (rx_bps, tx_bps, rx_pps, tx_pps) = if let Some(last_update) = io_state.last_update {
            let elapsed_secs = last_update.elapsed().as_secs_f64();
            if elapsed_secs > 0.0 {
                let rx_bps = ((total_rx_bytes.saturating_sub(io_state.prev_net_rx)) as f64 / elapsed_secs) as u64;
                let tx_bps = ((total_tx_bytes.saturating_sub(io_state.prev_net_tx)) as f64 / elapsed_secs) as u64;
                let rx_pps = ((total_rx_packets.saturating_sub(io_state.prev_net_rx_packets)) as f64 / elapsed_secs) as u64;
                let tx_pps = ((total_tx_packets.saturating_sub(io_state.prev_net_tx_packets)) as f64 / elapsed_secs) as u64;
                (rx_bps, tx_bps, rx_pps, tx_pps)
            } else {
                (0, 0, 0, 0)
            }
        } else {
            (0, 0, 0, 0)
        };

        // Update state for next calculation.
        io_state.prev_net_rx = total_rx_bytes;
        io_state.prev_net_tx = total_tx_bytes;
        io_state.prev_net_rx_packets = total_rx_packets;
        io_state.prev_net_tx_packets = total_tx_packets;
        io_state.last_update = Some(now);

        (rx_bps, tx_bps, rx_pps, tx_pps)
    }

    #[cfg(target_os = "linux")]
    fn collect_network_io_linux(&self) -> (u64, u64, u64, u64) {
        use std::fs;

        // Read /proc/net/dev for network interface statistics.
        // Format: Interface | bytes packets errs drop fifo frame compressed multicast |
        //                   | bytes packets errs drop fifo colls carrier compressed
        let netdev = match fs::read_to_string("/proc/net/dev") {
            Ok(s) => s,
            Err(_) => return (0, 0, 0, 0),
        };

        let mut total_rx_bytes: u64 = 0;
        let mut total_tx_bytes: u64 = 0;
        let mut total_rx_packets: u64 = 0;
        let mut total_tx_packets: u64 = 0;

        for line in netdev.lines().skip(2) {
            let line = line.trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 17 {
                continue;
            }

            let iface = parts[0].trim_end_matches(':');

            // Skip loopback and virtual interfaces.
            if iface == "lo" || iface.starts_with("veth") || iface.starts_with("docker")
               || iface.starts_with("br-") || iface.starts_with("virbr") {
                continue;
            }

            // Fields: iface rx_bytes rx_packets ... (8 rx fields) tx_bytes tx_packets ...
            let rx_bytes: u64 = parts[1].parse().unwrap_or(0);
            let rx_packets: u64 = parts[2].parse().unwrap_or(0);
            let tx_bytes: u64 = parts[9].parse().unwrap_or(0);
            let tx_packets: u64 = parts[10].parse().unwrap_or(0);

            total_rx_bytes += rx_bytes;
            total_tx_bytes += tx_bytes;
            total_rx_packets += rx_packets;
            total_tx_packets += tx_packets;
        }

        // Calculate rates based on previous values.
        let now = Instant::now();
        let mut io_state = self.io_state.write().unwrap();

        let (rx_bps, tx_bps, rx_pps, tx_pps) = if let Some(last_update) = io_state.last_update {
            let elapsed_secs = last_update.elapsed().as_secs_f64();
            if elapsed_secs > 0.0 {
                let rx_bps = ((total_rx_bytes.saturating_sub(io_state.prev_net_rx)) as f64 / elapsed_secs) as u64;
                let tx_bps = ((total_tx_bytes.saturating_sub(io_state.prev_net_tx)) as f64 / elapsed_secs) as u64;
                let rx_pps = ((total_rx_packets.saturating_sub(io_state.prev_net_rx_packets)) as f64 / elapsed_secs) as u64;
                let tx_pps = ((total_tx_packets.saturating_sub(io_state.prev_net_tx_packets)) as f64 / elapsed_secs) as u64;
                (rx_bps, tx_bps, rx_pps, tx_pps)
            } else {
                (0, 0, 0, 0)
            }
        } else {
            (0, 0, 0, 0)
        };

        // Update state for next calculation.
        io_state.prev_net_rx = total_rx_bytes;
        io_state.prev_net_tx = total_tx_bytes;
        io_state.prev_net_rx_packets = total_rx_packets;
        io_state.prev_net_tx_packets = total_tx_packets;
        io_state.last_update = Some(now);

        (rx_bps, tx_bps, rx_pps, tx_pps)
    }

    /// Collects load average.
    fn collect_load_average(&self) -> (f64, f64, f64) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let mut loadavg: [f64; 3] = [0.0; 3];
            unsafe {
                if libc::getloadavg(loadavg.as_mut_ptr(), 3) == 3 {
                    return (loadavg[0], loadavg[1], loadavg[2]);
                }
            }
        }
        (0.0, 0.0, 0.0)
    }

    /// Collects container metrics.
    #[must_use]
    pub fn collect_container(&self, id: &str, name: &str) -> ContainerMetrics {
        let metrics = ContainerMetrics {
            timestamp: Utc::now(),
            id: id.to_string(),
            name: name.to_string(),
            ..Default::default()
        };

        // Store in history.
        if let Ok(mut history) = self.container_history.write() {
            let container_history = history.entry(id.to_string()).or_default();
            container_history.push_back(metrics.clone());
            while container_history.len() > self.config.max_samples {
                container_history.pop_front();
            }
        }

        metrics
    }

    /// Collects VM metrics.
    #[must_use]
    pub fn collect_vm(&self, id: &str) -> VmMetrics {
        let metrics = VmMetrics {
            timestamp: Utc::now(),
            id: id.to_string(),
            ..Default::default()
        };

        // Store in history.
        if let Ok(mut history) = self.vm_history.write() {
            let vm_history = history.entry(id.to_string()).or_default();
            vm_history.push_back(metrics.clone());
            while vm_history.len() > self.config.max_samples {
                vm_history.pop_front();
            }
        }

        metrics
    }

    /// Returns system metrics history.
    #[must_use]
    pub fn system_history(&self) -> Vec<SystemMetrics> {
        self.system_history
            .read()
            .map(|h| h.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns container metrics history.
    #[must_use]
    pub fn container_history(&self, id: &str) -> Vec<ContainerMetrics> {
        self.container_history
            .read()
            .ok()
            .and_then(|h| h.get(id).map(|v| v.iter().cloned().collect()))
            .unwrap_or_default()
    }

    /// Returns VM metrics history.
    #[must_use]
    pub fn vm_history(&self, id: &str) -> Vec<VmMetrics> {
        self.vm_history
            .read()
            .ok()
            .and_then(|h| h.get(id).map(|v| v.iter().cloned().collect()))
            .unwrap_or_default()
    }

    /// Returns the sample interval.
    #[must_use]
    pub fn sample_interval_ms(&self) -> u64 {
        self.config.sample_interval_ms
    }

    /// Clears all history.
    pub fn clear_history(&self) {
        if let Ok(mut h) = self.system_history.write() {
            h.clear();
        }
        if let Ok(mut h) = self.container_history.write() {
            h.clear();
        }
        if let Ok(mut h) = self.vm_history.write() {
            h.clear();
        }
    }
}

impl Default for PerfMonitor {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Parses CPU line from /proc/stat.
#[cfg(target_os = "linux")]
fn parse_cpu_line(line: &str) -> CpuTimes {
    let parts: Vec<u64> = line
        .split_whitespace()
        .skip(1) // Skip "cpu" or "cpuN"
        .filter_map(|s| s.parse().ok())
        .collect();

    if parts.len() >= 4 {
        let user = parts[0];
        let nice = parts[1];
        let system = parts[2];
        let idle = parts[3];
        let iowait = parts.get(4).copied().unwrap_or(0);
        let irq = parts.get(5).copied().unwrap_or(0);
        let softirq = parts.get(6).copied().unwrap_or(0);

        let total = user + nice + system + idle + iowait + irq + softirq;

        CpuTimes {
            user: user + nice,
            system: system + irq + softirq,
            idle: idle + iowait,
            total,
        }
    } else {
        CpuTimes::default()
    }
}

/// Parses value from vm_stat output line.
#[cfg(target_os = "macos")]
fn parse_vm_stat_value(line: &str) -> u64 {
    line.split(':')
        .nth(1)
        .and_then(|s| s.trim().trim_end_matches('.').parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_system_metrics() {
        let monitor = PerfMonitor::default();
        let metrics = monitor.collect_system();

        // Basic sanity checks.
        assert!(metrics.cpu_percent >= 0.0 && metrics.cpu_percent <= 100.0);
        assert!(metrics.memory_total > 0 || cfg!(not(any(target_os = "macos", target_os = "linux"))));
    }

    #[test]
    fn test_history_limit() {
        let monitor = PerfMonitor::with_config(HistoryConfig {
            max_samples: 5,
            sample_interval_ms: 100,
        });

        // Collect more samples than the limit.
        for _ in 0..10 {
            monitor.collect_system();
        }

        let history = monitor.system_history();
        assert_eq!(history.len(), 5);
    }

    #[test]
    fn test_container_metrics() {
        let monitor = PerfMonitor::default();
        let metrics = monitor.collect_container("test-container", "test");

        assert_eq!(metrics.id, "test-container");
        assert_eq!(metrics.name, "test");
    }

    #[test]
    fn test_vm_metrics() {
        let monitor = PerfMonitor::default();
        let metrics = monitor.collect_vm("test-vm");

        assert_eq!(metrics.id, "test-vm");
    }

    #[test]
    fn test_clear_history() {
        let monitor = PerfMonitor::default();

        monitor.collect_system();
        monitor.collect_container("c1", "container1");
        monitor.collect_vm("vm1");

        assert!(!monitor.system_history().is_empty());

        monitor.clear_history();

        assert!(monitor.system_history().is_empty());
        assert!(monitor.container_history("c1").is_empty());
        assert!(monitor.vm_history("vm1").is_empty());
    }
}
