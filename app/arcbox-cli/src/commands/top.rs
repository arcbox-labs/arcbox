//! Live resource monitor for the System VM (`abctl top`).
//!
//! Subscribes to `StatsService.Watch` and renders one refreshed frame per
//! sample. Samples carry cumulative counters; the rates shown are deltas
//! between consecutive samples over the guest's monotonic clock, so a
//! stalled stream never fabricates activity.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::Future;
use std::io::{self, IsTerminal};

use anyhow::{Context, Result, bail};
use arcbox_cli::terminal::RawModeGuard;
use arcbox_connect::v1 as pb;
use arcbox_connect::v1::StatsServiceClient;
use arcbox_connect::v1::{ContainerStats, MachineStats};
use clap::Args;
use tokio::io::AsyncReadExt;

use super::OutputFormat;
use crate::connect;

/// Arguments for `abctl top`.
#[derive(Debug, Args)]
pub struct TopArgs {
    /// Print one computed sample and exit (also used for non-interactive output).
    #[arg(long)]
    pub once: bool,
}

pub async fn execute(args: TopArgs, format: OutputFormat) -> Result<()> {
    let (transport, config) = connect::daemon(&super::resolve_grpc_socket_path());
    let client = StatsServiceClient::new(transport, config);
    let mut stream = client
        .watch(pb::StatsWatchRequest {
            machine_id: String::new(),
            ..Default::default()
        })
        .await
        .context("subscribing to machine stats")?;

    let mode = TopMode::new(
        args.once,
        format,
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
    );
    let _raw_mode = matches!(mode, TopMode::Live)
        .then(RawModeGuard::new)
        .transpose()?;
    let quit = wait_for_quit(tokio::io::stdin(), tokio::signal::ctrl_c());
    tokio::pin!(quit);
    let mut previous: Option<MachineStats> = None;
    loop {
        let message = if matches!(mode, TopMode::Live) {
            tokio::select! {
                biased;
                result = &mut quit => {
                    result?;
                    return Ok(());
                }
                message = stream.message::<pb::MachineStats>() => message?,
            }
        } else {
            stream.message::<pb::MachineStats>().await?
        };
        let sample: MachineStats = match message {
            Some(item) => item.to_owned_message(),
            None => bail!("stats stream ended (daemon shutting down?)"),
        };
        // Compute against the prior sample (if any) before it becomes the
        // new baseline. A first sample or a counter reset yields None and
        // simply rebaselines. `MachineStats` owns a container Vec, so this
        // borrows rather than copies.
        let computed = previous
            .as_ref()
            .and_then(|prev| ComputedStats::from_delta(prev, &sample));
        previous = Some(sample);
        let Some(computed) = computed else {
            continue;
        };

        match format {
            OutputFormat::Json | OutputFormat::Quiet => {
                println!("{}", serde_json::to_string_pretty(&computed)?);
            }
            OutputFormat::Table => {
                write_table(&mut io::stdout().lock(), &computed, mode)?;
            }
        }
        if matches!(mode, TopMode::Snapshot) {
            return Ok(());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopMode {
    Snapshot,
    Live,
}

impl TopMode {
    fn new(once: bool, format: OutputFormat, stdin_tty: bool, stdout_tty: bool) -> Self {
        if once
            || !stdin_tty
            || !stdout_tty
            || matches!(format, OutputFormat::Json | OutputFormat::Quiet)
        {
            Self::Snapshot
        } else {
            Self::Live
        }
    }
}

async fn wait_for_quit<R, F>(mut input: R, interrupt: F) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    F: Future<Output = io::Result<()>>,
{
    let mut key = [0];
    tokio::pin!(interrupt);
    loop {
        tokio::select! {
            biased;
            read = input.read(&mut key) => match read.context("reading terminal input")? {
                0 => return Ok(()),
                _ if matches!(key[0], b'q' | b'Q' | b'\x03') => return Ok(()),
                _ => {}
            },
            result = &mut interrupt => {
                result.context("waiting for Ctrl-C")?;
                return Ok(());
            }
        }
    }
}

fn write_table(
    output: &mut impl io::Write,
    stats: &ComputedStats,
    mode: TopMode,
) -> io::Result<()> {
    if matches!(mode, TopMode::Live) {
        output.write_all(b"\x1b[2J\x1b[H")?;
    }
    output.write_all(stats.render().as_bytes())?;
    if matches!(mode, TopMode::Live) {
        output.write_all(b"\nq quit | Ctrl-C quit\n")?;
    }
    output.flush()
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
    containers: Vec<ComputedContainer>,
}

/// Per-container rates and gauges, derived from the same two samples.
#[derive(Debug, serde::Serialize)]
struct ComputedContainer {
    name: String,
    /// Percent of one core (may exceed 100 for a multi-threaded container),
    /// matching `docker stats`.
    cpu_percent: f64,
    memory_current_bytes: u64,
    /// 0 means unlimited.
    memory_limit_bytes: u64,
    disk_read_bytes_per_sec: f64,
    disk_write_bytes_per_sec: f64,
    net_rx_bytes_per_sec: f64,
    net_tx_bytes_per_sec: f64,
    pids: u32,
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
            containers: computed_containers(prev, cur, dt),
        })
    }

    fn render(&self) -> String {
        let psi = if self.memory_psi_full_avg10 < 0.0 {
            "n/a".to_owned()
        } else {
            format!("{:.2}%", self.memory_psi_full_avg10)
        };
        let mut out = format!(
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
        );
        if !self.containers.is_empty() {
            // Header and rows share the same width spec so columns stay
            // aligned; the size/rate cells are pre-formatted into "a/b"
            // strings (worst case ~"1023.9 MiB/1023.9 MiB") and
            // right-aligned as a whole.
            let _ = writeln!(
                out,
                "\n{:<24} {:>7} {:>21} {:>21} {:>21} {:>5}",
                "CONTAINER", "CPU%", "MEM", "DISK R/W/s", "NET ↓/↑/s", "PIDS"
            );
            for c in &self.containers {
                let mem = if c.memory_limit_bytes == 0 {
                    fmt_bytes(c.memory_current_bytes)
                } else {
                    format!(
                        "{}/{}",
                        fmt_bytes(c.memory_current_bytes),
                        fmt_bytes(c.memory_limit_bytes)
                    )
                };
                let disk = format!(
                    "{}/{}",
                    fmt_bytes(c.disk_read_bytes_per_sec as u64),
                    fmt_bytes(c.disk_write_bytes_per_sec as u64)
                );
                let net = format!(
                    "{}/{}",
                    fmt_bytes(c.net_rx_bytes_per_sec as u64),
                    fmt_bytes(c.net_tx_bytes_per_sec as u64)
                );
                let _ = writeln!(
                    out,
                    "{:<24} {:>6.1}% {:>21} {:>21} {:>21} {:>5}",
                    truncate(&c.name, 24),
                    c.cpu_percent,
                    mem,
                    disk,
                    net,
                    c.pids,
                );
            }
        }
        out
    }
}

/// Joins each current container with its previous sample by ID, computes
/// per-container rates, and sorts by CPU descending (top-style). A
/// container with no prior sample (just started) reports 0% CPU until the
/// next frame gives it a baseline.
fn computed_containers(prev: &MachineStats, cur: &MachineStats, dt: f64) -> Vec<ComputedContainer> {
    let previous: HashMap<&str, &ContainerStats> =
        prev.containers.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut computed: Vec<ComputedContainer> = cur
        .containers
        .iter()
        .map(|c| {
            let before = previous.get(c.id.as_str());
            let cpu_percent = before
                .filter(|p| c.cpu_usage_usec > p.cpu_usage_usec)
                .map_or(0.0, |p| {
                    (c.cpu_usage_usec - p.cpu_usage_usec) as f64 / (dt * 1_000_000.0) * 100.0
                });
            let rate = |cur_b: u64, prev_b: Option<u64>| {
                prev_b.map_or(0.0, |pb| cur_b.saturating_sub(pb) as f64 / dt)
            };
            ComputedContainer {
                name: if c.name.is_empty() {
                    short_id(&c.id)
                } else {
                    c.name.clone()
                },
                cpu_percent,
                memory_current_bytes: c.memory_current_bytes,
                memory_limit_bytes: c.memory_limit_bytes,
                disk_read_bytes_per_sec: rate(c.disk_read_bytes, before.map(|p| p.disk_read_bytes)),
                disk_write_bytes_per_sec: rate(
                    c.disk_written_bytes,
                    before.map(|p| p.disk_written_bytes),
                ),
                net_rx_bytes_per_sec: rate(c.net_rx_bytes, before.map(|p| p.net_rx_bytes)),
                net_tx_bytes_per_sec: rate(c.net_tx_bytes, before.map(|p| p.net_tx_bytes)),
                pids: c.pids,
            }
        })
        .collect();
    computed.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent));
    computed
}

/// Docker-style 12-character short ID.
fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

/// Truncates a display string to `width` columns, ellipsizing when longer.
fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_owned()
    } else {
        let kept: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{kept}…")
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
            containers: vec![],
            ..Default::default()
        }
    }

    fn container(id: &str, cpu_usec: u64, mem: u64) -> ContainerStats {
        ContainerStats {
            id: id.to_owned(),
            name: String::new(),
            cpu_usage_usec: cpu_usec,
            memory_current_bytes: mem,
            memory_limit_bytes: 0,
            disk_read_bytes: 0,
            disk_written_bytes: 0,
            pids: 3,
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            ..Default::default()
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

    #[test]
    fn container_cpu_from_usec_delta_and_sorted_desc() {
        let mut prev = sample(10_000, 100, 1000);
        let mut cur = sample(12_000, 150, 1200); // +2s
        // busy: 1s of CPU over 2s = 50% of one core.
        prev.containers = vec![container("busy", 0, 100), container("idle", 0, 50)];
        cur.containers = vec![
            container("idle", 0, 50),          // no CPU movement
            container("busy", 1_000_000, 100), // +1s cpu
        ];

        let c = ComputedStats::from_delta(&prev, &cur).unwrap();
        // Sorted CPU-descending: the busy one leads.
        assert_eq!(c.containers[0].name, "busy");
        assert!((c.containers[0].cpu_percent - 50.0).abs() < 0.01);
        assert!((c.containers[1].cpu_percent - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn container_network_rate_from_deltas() {
        let mut prev = sample(10_000, 100, 1000);
        let mut cur = sample(12_000, 150, 1200); // +2s
        let mut p = container("net", 0, 100);
        p.net_rx_bytes = 1000;
        p.net_tx_bytes = 2000;
        prev.containers = vec![p];
        let mut n = container("net", 0, 100);
        n.net_rx_bytes = 1000 + 4096; // +2 KiB/s
        n.net_tx_bytes = 2000 + 1024; // +512 B/s
        cur.containers = vec![n];

        let c = ComputedStats::from_delta(&prev, &cur).unwrap();
        assert!((c.containers[0].net_rx_bytes_per_sec - 2048.0).abs() < 0.001);
        assert!((c.containers[0].net_tx_bytes_per_sec - 512.0).abs() < 0.001);
    }

    #[test]
    fn newly_started_container_reports_zero_cpu_until_baseline() {
        let prev = sample(10_000, 100, 1000);
        let mut cur = sample(12_000, 150, 1200);
        cur.containers = vec![container("fresh", 5_000_000, 128)];

        let c = ComputedStats::from_delta(&prev, &cur).unwrap();
        // No prior sample for "fresh": CPU% is 0, not a huge spike.
        assert_eq!(c.containers.len(), 1);
        assert!((c.containers[0].cpu_percent - 0.0).abs() < f64::EPSILON);
        assert_eq!(c.containers[0].name, "fresh");
    }

    #[test]
    fn empty_name_falls_back_to_short_id() {
        let id = "0a1b2c3d4e5f00112233445566778899aabbccddeeff00112233445566778899";
        let prev = sample(10_000, 100, 1000);
        let mut cur = sample(12_000, 150, 1200);
        cur.containers = vec![container(id, 0, 64)];

        let c = ComputedStats::from_delta(&prev, &cur).unwrap();
        assert_eq!(c.containers[0].name, "0a1b2c3d4e5f");
    }

    #[test]
    fn live_mode_requires_interactive_table_io() {
        assert_eq!(
            TopMode::new(false, OutputFormat::Table, true, true),
            TopMode::Live
        );
        assert_eq!(
            TopMode::new(true, OutputFormat::Table, true, true),
            TopMode::Snapshot
        );
        assert_eq!(
            TopMode::new(false, OutputFormat::Table, false, true),
            TopMode::Snapshot
        );
        assert_eq!(
            TopMode::new(false, OutputFormat::Table, true, false),
            TopMode::Snapshot
        );
        assert_eq!(
            TopMode::new(false, OutputFormat::Json, true, true),
            TopMode::Snapshot
        );
    }

    #[tokio::test]
    async fn q_exits_the_input_loop_cleanly() {
        use tokio::io::AsyncWriteExt;

        let (mut writer, reader) = tokio::io::duplex(8);
        writer.write_all(b"xq").await.unwrap();

        wait_for_quit(reader, std::future::pending()).await.unwrap();
    }

    #[tokio::test]
    async fn interrupt_exits_the_input_loop_cleanly() {
        let (_writer, reader) = tokio::io::duplex(1);

        wait_for_quit(reader, std::future::ready(Ok::<(), std::io::Error>(())))
            .await
            .unwrap();
    }

    #[test]
    fn snapshot_table_has_no_terminal_control_bytes() {
        let stats =
            ComputedStats::from_delta(&sample(10_000, 100, 1000), &sample(12_000, 150, 1200))
                .unwrap();
        let mut output = Vec::new();

        write_table(&mut output, &stats, TopMode::Snapshot).unwrap();

        assert!(!output.contains(&0x1b));
        assert!(!String::from_utf8(output).unwrap().contains("q quit"));
    }

    #[test]
    fn live_table_exposes_controls() {
        let stats =
            ComputedStats::from_delta(&sample(10_000, 100, 1000), &sample(12_000, 150, 1200))
                .unwrap();
        let mut output = Vec::new();

        write_table(&mut output, &stats, TopMode::Live).unwrap();

        assert!(output.starts_with(b"\x1b[2J\x1b[H"));
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("q quit | Ctrl-C quit")
        );
    }
}
