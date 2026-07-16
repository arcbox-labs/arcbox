//! `WatchStats` streaming handler: samples machine-level resource counters
//! and pushes one frame per tick to the host.
//!
//! The host opens this stream only while a stats subscriber exists (the
//! desktop monitor, `abctl top`), so the sampling cost is zero when nobody
//! is watching. Parsing lives in the platform-neutral [`crate::stats`]
//! module; this file owns the `/proc` reads and the frame writing.

use std::time::Duration;

use anyhow::Result;
use prost::Message as _;
use tokio::io::AsyncWrite;

use arcbox_protocol::agent::{MachineStats, WatchStatsRequest};

use crate::rpc::{MessageType, write_message};
use crate::stats::{
    parse_cpu_ticks, parse_diskstats, parse_loadavg1, parse_meminfo, parse_net_dev,
    parse_psi_full_avg10, parse_uptime_ms,
};

/// Default watch window when the request leaves `timeout_ms` at 0.
const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Default sample cadence when the request leaves `interval_ms` at 0.
const DEFAULT_INTERVAL: Duration = Duration::from_millis(1000);

/// Fastest cadence the agent will sample at, whatever the host asks for —
/// guest self-protection against a misbehaving subscriber.
const MIN_INTERVAL: Duration = Duration::from_millis(200);

/// Handles one `WatchStats` request, streaming one sample per tick until
/// the window elapses or the peer goes away (write error).
///
/// Every frame doubles as a keepalive; a tick whose `/proc` reads fail is
/// skipped (the host tolerates gaps and reconnects on sustained silence).
pub(super) async fn handle_watch_stats<S>(
    stream: &mut S,
    req: WatchStatsRequest,
    trace_id: &str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let window = if req.timeout_ms == 0 {
        DEFAULT_WINDOW
    } else {
        Duration::from_millis(u64::from(req.timeout_ms))
    };
    let interval = if req.interval_ms == 0 {
        DEFAULT_INTERVAL
    } else {
        Duration::from_millis(u64::from(req.interval_ms)).max(MIN_INTERVAL)
    };

    tracing::info!(
        trace_id = %trace_id,
        window_secs = window.as_secs(),
        interval_ms = interval.as_millis(),
        "stats watch opened"
    );

    let started = tokio::time::Instant::now();
    let mut warned_unreadable = false;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // An immediate first sample: the subscriber gets its baseline for rate
    // deltas without waiting a full interval.
    loop {
        ticker.tick().await;
        if started.elapsed() >= window {
            // End of window: return to the connection loop, which accepts
            // the host's next WatchStats request on this same connection.
            return Ok(());
        }
        match read_machine_stats() {
            Some(sample) => {
                write_message(
                    stream,
                    MessageType::MachineStats,
                    trace_id,
                    &sample.encode_to_vec(),
                )
                .await?;
            }
            None if !warned_unreadable => {
                warned_unreadable = true;
                tracing::warn!(trace_id = %trace_id, "machine stats unreadable; skipping ticks");
            }
            None => {}
        }
    }
}

/// One pass over `/proc`, assembled into a [`MachineStats`] frame.
///
/// `None` when any mandatory source is unreadable; PSI is optional (kernels
/// without `CONFIG_PSI` report a negative gauge).
fn read_machine_stats() -> Option<MachineStats> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let loadavg = std::fs::read_to_string("/proc/loadavg").ok()?;
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let diskstats = std::fs::read_to_string("/proc/diskstats").unwrap_or_default();
    let net_dev = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let psi = std::fs::read_to_string("/proc/pressure/memory").ok();

    let (cpu_busy_ticks, cpu_total_ticks) = parse_cpu_ticks(&stat)?;
    let (memory_total_bytes, memory_available_bytes) = parse_meminfo(&meminfo)?;
    let (disk_read_bytes, disk_written_bytes) = parse_diskstats(&diskstats);
    let (net_rx_bytes, net_tx_bytes) = parse_net_dev(&net_dev);

    Some(MachineStats {
        monotonic_ms: parse_uptime_ms(&uptime)?,
        cpu_busy_ticks,
        cpu_total_ticks,
        online_cpus: std::thread::available_parallelism().map_or(0, |n| n.get() as u32),
        loadavg1: parse_loadavg1(&loadavg)?,
        memory_total_bytes,
        memory_available_bytes,
        memory_psi_full_avg10: psi
            .as_deref()
            .and_then(parse_psi_full_avg10)
            .unwrap_or(-1.0),
        disk_read_bytes,
        disk_written_bytes,
        net_rx_bytes,
        net_tx_bytes,
    })
}
