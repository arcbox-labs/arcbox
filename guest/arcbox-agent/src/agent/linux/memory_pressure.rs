//! `WatchMemoryPressure` streaming handler: samples in-guest memory signals
//! and pushes pressure events to the host.
//!
//! The host opens this stream only while the idle balloon is shrunk, so the
//! 1s sampling cost exists only in that state. Detection logic lives in the
//! platform-neutral [`crate::memory_pressure`] module; this file owns the
//! `/proc` reads and the frame writing.

use std::time::Duration;

use anyhow::Result;
use prost::Message as _;
use tokio::io::AsyncWrite;

use arcbox_protocol::agent::memory_pressure_event::Reason;
use arcbox_protocol::agent::{MemoryPressureEvent, WatchMemoryPressureRequest};

use crate::memory_pressure::{
    PressureDetector, PressureSignal, PressureThresholds, parse_mem_available,
    parse_workingset_refaults,
};
use crate::rpc::{MessageType, write_message};

/// Interval between `/proc` samples while a watch is open.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Default watch window when the request leaves `timeout_ms` at 0.
const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Default keepalive cadence when the request leaves `keepalive_ms` at 0.
const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(10);

/// One `/proc` sample: available bytes and the cumulative refault counter.
fn read_sample() -> Option<(u64, u64)> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let vmstat = std::fs::read_to_string("/proc/vmstat").ok()?;
    Some((
        parse_mem_available(&meminfo)?,
        parse_workingset_refaults(&vmstat)?,
    ))
}

/// Handles one `WatchMemoryPressure` request, streaming events until the
/// window elapses or the peer goes away (write error).
pub(super) async fn handle_watch_memory_pressure<S>(
    stream: &mut S,
    req: WatchMemoryPressureRequest,
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
    let keepalive = if req.keepalive_ms == 0 {
        DEFAULT_KEEPALIVE
    } else {
        Duration::from_millis(u64::from(req.keepalive_ms))
    };
    let mut detector = PressureDetector::new(PressureThresholds {
        min_available_bytes: req.min_available_bytes,
        max_refault_rate: req.max_refault_rate,
    });

    tracing::info!(
        trace_id = %trace_id,
        window_secs = window.as_secs(),
        min_available_bytes = req.min_available_bytes,
        max_refault_rate = req.max_refault_rate,
        "Memory pressure watch opened"
    );

    // Ack frame: tells the host the watch is established (and doubles as
    // the first keepalive).
    write_event(stream, trace_id, Reason::Keepalive, 0, 0).await?;

    let started = tokio::time::Instant::now();
    let mut last_keepalive = started;
    let mut previous: Option<(tokio::time::Instant, u64)> = None;
    let mut warned_unreadable = false;
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let now = ticker.tick().await;
        if started.elapsed() >= window {
            write_event(stream, trace_id, Reason::WindowElapsed, 0, 0).await?;
            return Ok(());
        }

        let Some((available, refaults)) = read_sample() else {
            // Without readable signals there is nothing to evaluate — but
            // keepalives must continue: they mean "agent alive", and their
            // absence makes the host restore full memory (fail open).
            if !warned_unreadable {
                warned_unreadable = true;
                tracing::warn!(trace_id = %trace_id, "memory pressure signals unreadable");
            }
            if now.duration_since(last_keepalive) >= keepalive {
                last_keepalive = now;
                write_event(stream, trace_id, Reason::Keepalive, 0, 0).await?;
            }
            continue;
        };

        let refault_rate = match previous {
            Some((at, count)) => {
                let elapsed = now.duration_since(at).as_secs_f64();
                if elapsed > 0.0 {
                    (refaults.saturating_sub(count) as f64 / elapsed) as u64
                } else {
                    0
                }
            }
            None => 0,
        };
        previous = Some((now, refaults));

        match detector.evaluate(available, refault_rate) {
            Some(signal) => {
                let reason = match signal {
                    PressureSignal::LowAvailable => Reason::LowAvailable,
                    PressureSignal::RefaultSpike => Reason::RefaultSpike,
                };
                tracing::info!(
                    trace_id = %trace_id,
                    available_bytes = available,
                    refault_rate,
                    reason = ?reason,
                    "Memory pressure detected"
                );
                last_keepalive = now;
                write_event(stream, trace_id, reason, available, refault_rate).await?;
            }
            None if now.duration_since(last_keepalive) >= keepalive => {
                last_keepalive = now;
                write_event(stream, trace_id, Reason::Keepalive, available, refault_rate).await?;
            }
            None => {}
        }
    }
}

async fn write_event<S>(
    stream: &mut S,
    trace_id: &str,
    reason: Reason,
    available_bytes: u64,
    refault_rate: u64,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let event = MemoryPressureEvent {
        reason: reason as i32,
        available_bytes,
        refault_rate,
    };
    write_message(
        stream,
        MessageType::MemoryPressureEvent,
        trace_id,
        &event.encode_to_vec(),
    )
    .await
}
