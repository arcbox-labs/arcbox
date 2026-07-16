//! Live resource monitor for the System VM (`abctl top`).
//!
//! Subscribes to `StatsService.Watch` and renders one refreshed frame per
//! sample. Samples carry cumulative counters; the rates shown are deltas
//! between consecutive samples over the guest's monotonic clock, so a
//! stalled stream never fabricates activity.

use anyhow::{Context, Result, bail};
use arcbox_grpc::v1::stats_service_client::StatsServiceClient;
use arcbox_protocol::v1::{MachineStats, StatsWatchRequest};
use clap::Args;
use tonic::transport::Endpoint;

use super::OutputFormat;
use super::machine::UnixConnector;

/// Arguments for `abctl top`.
#[derive(Debug, Args)]
pub struct TopArgs {
    /// Print a single computed sample and exit (implied by --format json).
    #[arg(long)]
    pub once: bool,
}

pub async fn execute(args: TopArgs, format: OutputFormat) -> Result<()> {
    let socket_path = super::resolve_grpc_socket_path();
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector::new(socket_path.clone()))
        .await
        .with_context(|| {
            format!(
                "Failed to connect to ArcBox gRPC daemon at {}",
                socket_path.display()
            )
        })?;
    let mut client = StatsServiceClient::new(channel);
    let mut stream = client
        .watch(StatsWatchRequest {
            machine_id: String::new(),
        })
        .await
        .context("subscribing to machine stats")?
        .into_inner();

    let once = args.once || matches!(format, OutputFormat::Json | OutputFormat::Quiet);
    let mut previous: Option<MachineStats> = None;
    loop {
        let sample = match stream.message().await? {
            Some(sample) => sample,
            None => bail!("stats stream ended (daemon shutting down?)"),
        };
        let Some(prev) = previous.replace(sample) else {
            continue; // baseline for the first delta
        };
        let Some(computed) = ComputedStats::from_delta(&prev, &sample) else {
            continue; // counters reset (guest rebooted): rebaseline
        };

        match format {
            OutputFormat::Json | OutputFormat::Quiet => {
                println!("{}", serde_json::to_string_pretty(&computed)?);
            }
            OutputFormat::Table => {
                if !args.once {
                    // Clear screen and home the cursor between frames.
                    print!("\x1b[2J\x1b[H");
                }
                print!("{}", computed.render());
            }
        }
        if once {
            return Ok(());
        }
    }
}

/// Rates and gauges derived from two consecutive samples.
#[derive(Debug, serde::Serialize)]
struct ComputedStats {
    cpu_percent: f64,
    online_cpus: u32,
    loadavg1: f64,
    memory_total_bytes: u64,
    memory_used_bytes: u64,
    memory_used_percent: f64,
    /// Negative when the guest kernel lacks CONFIG_PSI.
    memory_psi_full_avg10: f64,
    disk_read_bytes_per_sec: f64,
    disk_write_bytes_per_sec: f64,
    net_rx_bytes_per_sec: f64,
    net_tx_bytes_per_sec: f64,
}

impl ComputedStats {
    /// `None` when the guest clock or CPU counters went backwards — the
    /// counters reset (guest reboot) and `cur` must become the new
    /// baseline instead of producing nonsense rates.
    fn from_delta(prev: &MachineStats, cur: &MachineStats) -> Option<Self> {
        if cur.monotonic_ms <= prev.monotonic_ms || cur.cpu_total_ticks <= prev.cpu_total_ticks {
            return None;
        }
        let dt = (cur.monotonic_ms - prev.monotonic_ms) as f64 / 1000.0;
        let total_ticks = (cur.cpu_total_ticks - prev.cpu_total_ticks) as f64;
        let busy_ticks = cur.cpu_busy_ticks.saturating_sub(prev.cpu_busy_ticks) as f64;
        let rate =
            |cur_bytes: u64, prev_bytes: u64| cur_bytes.saturating_sub(prev_bytes) as f64 / dt;

        let memory_used = cur
            .memory_total_bytes
            .saturating_sub(cur.memory_available_bytes);
        Some(Self {
            cpu_percent: (busy_ticks / total_ticks * 100.0).min(100.0),
            online_cpus: cur.online_cpus,
            loadavg1: cur.loadavg1,
            memory_total_bytes: cur.memory_total_bytes,
            memory_used_bytes: memory_used,
            memory_used_percent: if cur.memory_total_bytes == 0 {
                0.0
            } else {
                memory_used as f64 / cur.memory_total_bytes as f64 * 100.0
            },
            memory_psi_full_avg10: cur.memory_psi_full_avg10,
            disk_read_bytes_per_sec: rate(cur.disk_read_bytes, prev.disk_read_bytes),
            disk_write_bytes_per_sec: rate(cur.disk_written_bytes, prev.disk_written_bytes),
            net_rx_bytes_per_sec: rate(cur.net_rx_bytes, prev.net_rx_bytes),
            net_tx_bytes_per_sec: rate(cur.net_tx_bytes, prev.net_tx_bytes),
        })
    }

    fn render(&self) -> String {
        let psi = if self.memory_psi_full_avg10 < 0.0 {
            "n/a".to_owned()
        } else {
            format!("{:.2}%", self.memory_psi_full_avg10)
        };
        format!(
            "ArcBox System VM\n\
             \n\
             CPU     {:>6.1}%  of {} cpus   load {:.2}\n\
             Memory  {:>6.1}%  {} / {}   pressure {}\n\
             Disk    R {}/s   W {}/s\n\
             Net     ↓ {}/s   ↑ {}/s\n",
            self.cpu_percent,
            self.online_cpus,
            self.loadavg1,
            self.memory_used_percent,
            fmt_bytes(self.memory_used_bytes),
            fmt_bytes(self.memory_total_bytes),
            psi,
            fmt_bytes(self.disk_read_bytes_per_sec as u64),
            fmt_bytes(self.disk_write_bytes_per_sec as u64),
            fmt_bytes(self.net_rx_bytes_per_sec as u64),
            fmt_bytes(self.net_tx_bytes_per_sec as u64),
        )
    }
}

/// Binary-scaled human size ("3.2 GiB").
fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(monotonic_ms: u64, busy: u64, total: u64) -> MachineStats {
        MachineStats {
            monotonic_ms,
            cpu_busy_ticks: busy,
            cpu_total_ticks: total,
            online_cpus: 4,
            loadavg1: 0.5,
            memory_total_bytes: 8 * 1024 * 1024 * 1024,
            memory_available_bytes: 6 * 1024 * 1024 * 1024,
            memory_psi_full_avg10: 0.5,
            disk_read_bytes: 1000,
            disk_written_bytes: 2000,
            net_rx_bytes: 3000,
            net_tx_bytes: 4000,
        }
    }

    #[test]
    fn rates_come_from_deltas_over_guest_time() {
        let prev = sample(10_000, 100, 1000);
        let mut cur = sample(12_000, 150, 1200); // +2s, 50/200 busy
        cur.disk_read_bytes = 1000 + 2048;
        cur.net_tx_bytes = 4000 + 1024;

        let c = ComputedStats::from_delta(&prev, &cur).unwrap();
        assert!((c.cpu_percent - 25.0).abs() < f64::EPSILON);
        assert!((c.disk_read_bytes_per_sec - 1024.0).abs() < f64::EPSILON);
        assert!((c.net_tx_bytes_per_sec - 512.0).abs() < f64::EPSILON);
        assert!((c.memory_used_percent - 25.0).abs() < 0.01);
    }

    #[test]
    fn counter_reset_asks_for_a_new_baseline() {
        // Guest rebooted: monotonic clock and ticks both went backwards.
        let prev = sample(500_000, 4000, 50_000);
        let cur = sample(3_000, 10, 100);
        assert!(ComputedStats::from_delta(&prev, &cur).is_none());
    }

    #[test]
    fn bytes_format_scales() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2.0 KiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
