//! Serial port read loops for VM console and agent log output.

use std::sync::Arc;
use std::time::Duration;

use crate::machine::MachineManager;

use super::DEFAULT_MACHINE_NAME;

/// Base polling interval (ms) when serial output is actively being produced.
const SERIAL_ACTIVE_INTERVAL_MS: u64 = 100;

/// Maximum number of doublings for idle backoff (100ms → 1600ms).
const SERIAL_MAX_IDLE_SHIFT: u32 = 4;

/// Adaptive serial read loop for both hvc0 (console) and hvc1 (agent log).
///
/// Merges the two previously independent 200ms polling loops into a single
/// loop with exponential backoff: 100ms when active, doubling up to 1600ms
/// when idle. This reduces daemon wakeups from ~10/s to ~1/s at idle.
pub(super) async fn serial_read_adaptive(machine_manager: Arc<MachineManager>) {
    const MAX_LINE_BUF: usize = 64 * 1024;

    let mut console_buf = String::new();
    let mut agent_buf = String::new();
    let mut idle_streak: u32 = 0;

    loop {
        let mut had_output = false;

        // Read hvc0 (console)
        if let Ok(output) = machine_manager.read_console_output(DEFAULT_MACHINE_NAME) {
            if process_serial_output(&mut console_buf, &output, "Guest", true, MAX_LINE_BUF) {
                had_output = true;
            }
        } else {
            // Console read failed — VM likely stopped
            flush_line_buf(&mut console_buf, "Guest", true);
            flush_line_buf(&mut agent_buf, "Agent", false);
            tracing::debug!("Serial read loop stopped: console read failed");
            break;
        }

        // Read hvc1 (agent log)
        if let Ok(output) = machine_manager.read_agent_log_output(DEFAULT_MACHINE_NAME) {
            if process_serial_output(&mut agent_buf, &output, "Agent", false, MAX_LINE_BUF) {
                had_output = true;
            }
        }
        // Agent log failure is non-fatal — console may still work.

        if had_output {
            idle_streak = 0;
        } else {
            idle_streak = idle_streak.saturating_add(1);
        }

        // Adaptive delay: 100ms when active, doubling up to 1600ms when idle.
        let delay_ms = SERIAL_ACTIVE_INTERVAL_MS * (1u64 << idle_streak.min(SERIAL_MAX_IDLE_SHIFT));
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

/// Process raw serial output into line-buffered log messages.
///
/// Returns `true` if any non-empty output was received.
fn process_serial_output(
    line_buf: &mut String,
    output: &str,
    label: &str,
    level_info: bool,
    max_buf: usize,
) -> bool {
    let trimmed = output.trim_matches('\0');
    if trimmed.is_empty() {
        return false;
    }

    line_buf.push_str(trimmed);

    if line_buf.len() > max_buf {
        tracing::warn!("{label}: line buffer overflow, flushing");
        line_buf.clear();
        return true;
    }

    while let Some(pos) = line_buf.find('\n') {
        let line = line_buf[..pos].trim_end().to_owned();
        line_buf.drain(..=pos);
        if line.is_empty() {
            continue;
        }
        if level_info {
            tracing::info!("{label}: {line}");
        } else {
            tracing::debug!("{label}: {line}");
        }
    }

    true
}

/// Flush any remaining partial line from a serial buffer.
fn flush_line_buf(line_buf: &mut String, label: &str, level_info: bool) {
    let trailing = line_buf.trim().to_owned();
    if !trailing.is_empty() {
        if level_info {
            tracing::info!("{label}: {trailing}");
        } else {
            tracing::debug!("{label}: {trailing}");
        }
    }
    line_buf.clear();
}
