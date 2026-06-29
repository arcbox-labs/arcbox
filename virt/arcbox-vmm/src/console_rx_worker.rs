//! Interactive debug-console RX worker thread.
//!
//! Reads operator keystrokes from the debug-console Unix socket and injects
//! them into the guest virtio-console RX queue, then raises `INT_VRING` and
//! force-exits WFI-idle vCPUs so a guest shell sees the input promptly — the
//! same delivery scheme the vsock/net RX workers use.
//!
//! Output flows the other way for free: the console device mirrors guest TX
//! bytes to the same socket from `process_queue`, so an operator attached with
//! `socat - UNIX-CONNECT:<sock>` gets a bidirectional console.
//!
//! This is a debug aid gated behind `VmmConfig::debug_console_socket`; it is
//! not part of the normal boot path. Polling (rather than `kevent`) keeps it
//! dead simple — console I/O is human-paced, so a 10 ms tick is imperceptible.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arcbox_virtio::console::{ConsoleIo, SocketConsole};

use crate::device::{DeviceManager, DeviceType};

/// VirtIO MMIO interrupt status bit for "used ring updated".
const INT_VRING: u32 = 1;

/// Poll cadence — fast enough that keystrokes feel instant, idle cost is nil.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Resources for the debug-console RX worker thread.
pub struct ConsoleRxWorkerContext {
    /// Device manager owning the console device.
    pub device_manager: Arc<DeviceManager>,
    /// The debug-console socket backend (operator input source). Shares the
    /// same `Arc` set as the console device's output `io`.
    pub socket: Arc<Mutex<SocketConsole>>,
    /// VM shutdown flag.
    pub running: Arc<AtomicBool>,
    /// Force-exit all vCPUs from `hv_vcpu_run` (thread-safe).
    pub exit_vcpus: Arc<dyn Fn() + Send + Sync>,
}

/// Main loop for the debug-console RX worker thread.
pub fn console_rx_worker_loop(ctx: ConsoleRxWorkerContext) {
    tracing::info!("debug-console RX worker started");
    let mut buf = [0u8; 1024];

    while ctx.running.load(Ordering::Relaxed) {
        // `SocketConsole::read` accepts a pending client and returns operator
        // bytes (non-blocking, 0 when idle or unconnected).
        let n = match ctx.socket.lock() {
            Ok(mut s) => s.read(&mut buf).unwrap_or(0),
            Err(_) => 0,
        };

        // Inject fresh bytes (n > 0) or flush input buffered from a prior tick
        // against descriptors the guest has since posted (n == 0).
        if ctx.device_manager.console_inject_input(&buf[..n]) {
            ctx.device_manager
                .raise_interrupt_for(DeviceType::VirtioConsole, INT_VRING);
            (ctx.exit_vcpus)();
        }

        std::thread::sleep(POLL_INTERVAL);
    }

    tracing::info!("debug-console RX worker stopped");
}
