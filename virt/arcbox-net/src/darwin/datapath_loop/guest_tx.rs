use std::collections::VecDeque;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::darwin::egress::HostEgress;
use crate::darwin::inbound_relay::InboundCommand;
use crate::darwin::tcp_bridge::TcpBridge;
use crate::datapath::FrameBuf;

use super::fd::{FdWrapper, fd_write};
use super::intercept::process_inbound_cmd;

/// Hard cap on write_queue depth. Frames beyond this are dropped to prevent
/// unbounded memory growth when the guest FD is blocked (VM paused, VZ socket
/// buffer full). Increased from 2048 to 8192 to match 8 MB socket buffers.
const WRITE_QUEUE_HARD_CAP: usize = 8192;

/// Maximum number of reply frames to drain per call, preventing a single
/// drain from starving other `select!` branches under high traffic.
const DRAIN_REPLY_BATCH: usize = 64;

/// Maximum number of inbound listener commands to drain per common-tail pass.
///
/// Batching prevents command draining from monopolizing the event loop while
/// still guaranteeing forward progress when `cmd_rx.recv()` is starved.
const DRAIN_CMD_BATCH: usize = 64;

/// Non-blocking drain of the reply channel. Delivers pending proxy
/// responses (DNS, UDP, ICMP) to the guest without blocking the event loop.
///
/// Limits each call to `DRAIN_REPLY_BATCH` frames to avoid starving other
/// `select!` branches.
pub(super) fn drain_reply_rx(
    reply_rx: &mut mpsc::Receiver<Vec<u8>>,
    frame_sink: Option<&std::sync::Arc<dyn crate::direct_rx::FrameSink>>,
    guest_async: &AsyncFd<FdWrapper>,
    write_queue: &mut VecDeque<FrameBuf>,
) {
    for _ in 0..DRAIN_REPLY_BATCH {
        match reply_rx.try_recv() {
            Ok(reply_frame) => {
                send_to_guest(frame_sink, guest_async, &reply_frame, write_queue);
            }
            Err(_) => break,
        }
    }
}

/// Non-blocking drain of inbound listener commands.
///
/// Prevents starvation of `cmd_rx.recv()` in the biased `select!` loop when
/// the guest FD readable branch is continuously ready.
pub(super) fn drain_cmd_rx(
    cmd_rx: &mut mpsc::Receiver<InboundCommand>,
    tcp_bridge: &mut TcpBridge,
    egress: &mut HostEgress,
    guest_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    guest_mac: Option<[u8; 6]>,
) {
    for _ in 0..DRAIN_CMD_BATCH {
        match cmd_rx.try_recv() {
            Ok(cmd) => {
                process_inbound_cmd(cmd, tcp_bridge, egress, guest_ip, gateway_ip, guest_mac);
            }
            Err(_) => break,
        }
    }
}

/// Sends a frame to the guest via the frame sink (if present) or falls
/// back to the socketpair write path.
///
/// When `frame_sink` is `Some`, the frame is sent through the crossbeam
/// channel to the RX injection thread, bypassing the socketpair entirely.
/// When `None`, falls back to `enqueue_or_write` for VZ-backend or
/// early-boot compatibility.
pub(super) fn send_to_guest(
    frame_sink: Option<&std::sync::Arc<dyn crate::direct_rx::FrameSink>>,
    guest_async: &AsyncFd<FdWrapper>,
    frame_data: &[u8],
    write_queue: &mut VecDeque<FrameBuf>,
) {
    if let Some(sink) = frame_sink {
        let _ = sink.send(frame_data.to_vec());
        return;
    }
    // Fallback: socketpair (VZ backend or during early boot).
    enqueue_or_write(
        guest_async,
        FrameBuf::from(frame_data.to_vec()),
        write_queue,
    );
}

/// Attempts a direct non-blocking write; queues the frame on `WouldBlock`.
///
/// If the write queue is non-empty, the frame is appended directly to
/// preserve ordering.
pub(super) fn enqueue_or_write(
    guest_async: &AsyncFd<FdWrapper>,
    frame: FrameBuf,
    write_queue: &mut VecDeque<FrameBuf>,
) {
    if !write_queue.is_empty() {
        if write_queue.len() < WRITE_QUEUE_HARD_CAP {
            write_queue.push_back(frame);
        } else {
            tracing::debug!("Write queue full ({WRITE_QUEUE_HARD_CAP}), dropping frame");
        }
        return;
    }
    let fd = guest_async.get_ref().as_raw_fd();
    match fd_write(fd, &frame) {
        Ok(n) if n >= frame.len() => {}
        Ok(n) => {
            // SOCK_DGRAM: short write should never happen — invariant violation.
            tracing::error!(
                "Guest write: short datagram ({n}/{} bytes), dropping frame",
                frame.len(),
            );
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            write_queue.push_back(frame);
        }
        Err(e) => {
            tracing::warn!("Guest write error: {}", e);
        }
    }
}
