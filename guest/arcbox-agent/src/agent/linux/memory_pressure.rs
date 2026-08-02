//! `WatchMemoryPressure` streaming handler: samples in-guest memory signals
//! and pushes pressure events to the host.
//!
//! The host opens this stream only while the idle balloon is shrunk, so the
//! 1s sampling cost exists only in that state. Detection logic lives in the
//! platform-neutral [`crate::memory_pressure`] module; this file owns the
//! `/proc` reads and the frame writing.

use std::time::Duration;

use anyhow::Result;
use buffa::Message as _;
use tokio::io::AsyncWrite;

use arcbox_connect::v1::memory_pressure_event::Reason;
use arcbox_connect::v1::{MemoryPressureEvent, WatchMemoryPressureRequest};

use crate::memory_pressure::{
    PSI_WINDOW_US, PressureDetector, PressureSignal, PressureThresholds, parse_mem_available,
    parse_workingset_refaults, psi_stall_threshold_us,
};
use crate::rpc::{MessageType, write_message};

/// Interval between `/proc` samples while a watch is open.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Default watch window when the request leaves `timeout_ms` at 0.
const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Default keepalive cadence when the request leaves `keepalive_ms` at 0.
const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(10);

/// An event observed by the PSI trigger thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsiEvent {
    /// The kernel reported the stall threshold crossed.
    Stall,
    /// Poll timeout: time for a keepalive (and a floor check).
    Tick,
    /// The trigger fd failed; PSI watching cannot continue.
    Lost,
}

/// A registered trigger on `/proc/pressure/memory`, delivering
/// [`PsiEvent`]s from a dedicated blocking poll thread.
///
/// While the trigger is armed and the guest is quiet, the agent wakes only
/// on the poll timeout (keepalive cadence) — versus every second in the
/// sampling fallback — and the kernel itself decides when stall time
/// crosses the threshold.
struct PsiTrigger {
    events: tokio::sync::mpsc::Receiver<PsiEvent>,
}

impl PsiTrigger {
    /// Registers a `full <stall_us> <window>` trigger and spawns the poll
    /// thread. Fails on kernels without `CONFIG_PSI` (or with PSI disabled),
    /// in which case the caller stays on the sampling path.
    fn open(stall_us: u32, tick: Duration) -> std::io::Result<Self> {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/pressure/memory")?;
        // "full": all non-idle tasks stalled simultaneously — a single
        // thrashing task still accrues it, while plain heavy I/O does not.
        //
        // The registration must reach the kernel as ONE write(2): psi_write
        // parses each write as a complete trigger spec (`write!` on an
        // unbuffered File would issue one syscall per format fragment and
        // the first, "full ", fails with EINVAL). It must also be
        // NUL-terminated — the kernel replaces the last written byte with
        // a NUL before parsing, per the PSI docs' `strlen + 1` example.
        let trigger = format!("full {stall_us} {PSI_WINDOW_US}\0");
        file.write_all(trigger.as_bytes())?;

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let tick_ms = i32::try_from(tick.as_millis()).unwrap_or(i32::MAX);
        std::thread::spawn(move || {
            let fd = file.as_raw_fd();
            loop {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLPRI,
                    revents: 0,
                };
                // SAFETY: pfd is a valid pollfd for the duration of the call;
                // `file` (and thus fd) lives for the whole loop.
                let n = unsafe { libc::poll(&mut pfd, 1, tick_ms) };
                if n < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    // A signal is not a lost trigger; a spurious Lost would
                    // make the host fail open and undo the shrink.
                    continue;
                }
                let event = match n {
                    0 => PsiEvent::Tick,
                    n if n > 0 && pfd.revents & libc::POLLERR == 0 => PsiEvent::Stall,
                    _ => PsiEvent::Lost,
                };
                // Receiver dropped (watch ended) or trigger lost: exit; the
                // fd closes with `file`.
                if tx.blocking_send(event).is_err() || event == PsiEvent::Lost {
                    return;
                }
            }
        });
        Ok(Self { events: rx })
    }

    async fn next(&mut self) -> PsiEvent {
        self.events.recv().await.unwrap_or(PsiEvent::Lost)
    }
}

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

        let was_armed = detector.is_armed();
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

        let signal = detector.evaluate(available, refault_rate);
        if !was_armed && detector.is_armed() {
            tracing::info!(
                trace_id = %trace_id,
                available_bytes = available,
                elapsed_secs = started.elapsed().as_secs(),
                "memory pressure detector armed (guest settled after shrink)"
            );
            last_keepalive = now;
            write_event(stream, trace_id, Reason::Settled, available, refault_rate).await?;

            // Armed: upgrade to a kernel PSI trigger when the kernel has
            // one. The trigger is registered only now, so inflation-phase
            // stall never feeds it, and the sampling loop below is fully
            // replaced (keepalives ride the poll timeout).
            let stall_us = psi_stall_threshold_us(req.psi_full_stall_us);
            match PsiTrigger::open(stall_us, keepalive) {
                Ok(psi) => {
                    tracing::info!(
                        trace_id = %trace_id,
                        stall_us,
                        "PSI trigger armed; sampling paused"
                    );
                    return watch_armed_psi(
                        stream,
                        psi,
                        req.min_available_bytes,
                        window,
                        started,
                        trace_id,
                    )
                    .await;
                }
                Err(e) => {
                    // Mode selection is a load-bearing observability event:
                    // ops must be able to tell which detection path runs.
                    tracing::info!(
                        trace_id = %trace_id,
                        "PSI unavailable ({e}); staying on the sampling path"
                    );
                }
            }
        }
        match signal {
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

/// Armed-phase loop over a PSI trigger: the agent sleeps in the poll
/// thread and wakes only on kernel stall events or the keepalive tick
/// (which doubles as a coarse `MemAvailable` floor check).
async fn watch_armed_psi<S>(
    stream: &mut S,
    mut psi: PsiTrigger,
    min_available_bytes: u64,
    window: Duration,
    started: tokio::time::Instant,
    trace_id: &str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    loop {
        if started.elapsed() >= window {
            write_event(stream, trace_id, Reason::WindowElapsed, 0, 0).await?;
            return Ok(());
        }
        match psi.next().await {
            PsiEvent::Stall => {
                let available = read_sample().map_or(0, |(available, _)| available);
                tracing::info!(
                    trace_id = %trace_id,
                    available_bytes = available,
                    "Memory pressure detected (PSI full-stall trigger)"
                );
                write_event(stream, trace_id, Reason::LowAvailable, available, 0).await?;
            }
            PsiEvent::Tick => {
                // Unreadable signals must not trip the floor — a keepalive
                // still means "agent alive", matching the sampling path.
                let Some((available, _)) = read_sample() else {
                    write_event(stream, trace_id, Reason::Keepalive, 0, 0).await?;
                    continue;
                };
                if min_available_bytes > 0 && available < min_available_bytes {
                    tracing::info!(
                        trace_id = %trace_id,
                        available_bytes = available,
                        "Memory pressure detected (available floor, PSI mode)"
                    );
                    write_event(stream, trace_id, Reason::LowAvailable, available, 0).await?;
                } else {
                    write_event(stream, trace_id, Reason::Keepalive, available, 0).await?;
                }
            }
            PsiEvent::Lost => {
                // Ending the watch makes the host fail open (restore full),
                // which is the safe direction when pressure can no longer
                // be observed.
                anyhow::bail!("PSI trigger lost");
            }
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
        reason: reason.into(),
        available_bytes,
        refault_rate,
        ..Default::default()
    };
    write_message(
        stream,
        MessageType::MemoryPressureEvent,
        trace_id,
        &event.encode_to_vec(),
    )
    .await
}
