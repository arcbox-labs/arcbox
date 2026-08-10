//! Guest-bound frame sink for the datapath loop.
//!
//! All frames destined for the guest go through [`GuestTx`], classified by
//! delivery semantics:
//!
//! - [`DeliveryClass::Reliable`] — TCP-shim frames (handshake, data, ACK,
//!   FIN, RST). The shim terminates TCP and never retransmits payload, so a
//!   dropped frame is a permanent sequence gap: the guest dup-ACKs forever
//!   and the connection stalls. These frames are **never dropped** — when
//!   the socketpair is full they queue, and the event loop gates bulk
//!   production ([`GuestTx::has_backlog`]) so host sockets stop being read,
//!   which propagates backpressure to the remote sender through the host
//!   kernel's TCP receive window.
//! - [`DeliveryClass::Lossy`] — datagram-semantics frames (ARP, DHCP, DNS,
//!   UDP, ICMP replies). The protocol above recovers from loss; bounded
//!   queue overflow drops them.
//!
//! # Queue-then-flush
//!
//! [`GuestTx::send`] only enqueues; [`GuestTx::flush`] issues the syscalls.
//! Everything queued within one event-loop iteration therefore leaves in a
//! single batched `sendmsg_x` instead of one `write(2)` per frame — the
//! iteration produces bursts (a fast-path poll returns every frame read
//! from every host socket, a guest read burst produces one ACK per frame),
//! and at 1500-byte frames a 10 Gbps link is ~833K frames/s, i.e. ~833K
//! syscalls/s before batching (ABX-313). The event loop flushes on every
//! iteration, so a frame never waits for a later wakeup.
//!
//! # macOS socketpair overflow semantics
//!
//! When the VZ side of the `SOCK_DGRAM` socketpair stops draining (guest RX
//! ring full, VM paused), `write(2)` fails with `ENOBUFS` — not `EAGAIN` —
//! because AF_UNIX datagram sends append directly to the peer's receive
//! buffer. kqueue write-readiness does not reliably signal the transition
//! back to writable in that state, so an ENOBUFS-blocked queue is drained by
//! a short retry timer ([`NOBUFS_RETRY_DELAY`]) instead of
//! `AsyncFd::writable()`; an `EAGAIN`-blocked queue uses write-readiness.
//!
//! `sendmsg_x` reports only how many datagrams it accepted, never an errno
//! once it accepted at least one, so [`GuestTx::flush`] hands the first
//! refusal to a single `write(2)` — that call carries the errno the
//! blocked-state machine above needs.

use std::collections::VecDeque;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Duration;

use arcbox_xnu_net::BatchDgram;
use tokio::sync::mpsc;

use crate::darwin::egress::HostEgress;
use crate::darwin::inbound_relay::InboundCommand;
use crate::darwin::tcp_bridge::TcpBridge;
use crate::datapath::FrameBuf;
use crate::direct_rx::FrameSink;

use super::fd::fd_write;
use super::intercept::process_inbound_cmd;

/// Cap on queued [`DeliveryClass::Lossy`] frames. Datagram replies are small
/// and loss-recoverable; bounding them keeps a stalled guest FD from growing
/// the queue without bound. Reliable frames are not capped: the bulk
/// producer (fast-path host-socket reads) is gated on
/// [`GuestTx::has_backlog`], bounding it to one event-loop iteration, while
/// the remaining reliable producers (ACKs, handshake frames, RSTs) are
/// reactive — they only emit in response to guest activity, which itself
/// stops when the guest FD is wedged. This is a deliberate
/// memory-vs-correctness tradeoff: a dropped TCP-shim frame is a permanent
/// connection stall, and `queue_high_water` records how close the practical
/// bound comes.
pub(super) const LOSSY_QUEUE_CAP: usize = 1024;

/// Retry interval for a queue blocked on `ENOBUFS`. The VZ reader drains the
/// socketpair continuously, so capacity typically returns within
/// microseconds; 1 ms bounds the added latency without spinning the loop.
pub(super) const NOBUFS_RETRY_DELAY: Duration = Duration::from_millis(1);

/// Maximum number of reply frames to drain per call, preventing a single
/// drain from starving other `select!` branches under high traffic.
const DRAIN_REPLY_BATCH: usize = 64;

/// Maximum number of inbound listener commands to drain per common-tail pass.
///
/// Batching prevents command draining from monopolizing the event loop while
/// still guaranteeing forward progress when `cmd_rx.recv()` is starved.
const DRAIN_CMD_BATCH: usize = 64;

/// Delivery semantics of a guest-bound frame. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeliveryClass {
    /// TCP-shim frame: must never be dropped (no retransmitter exists).
    Reliable,
    /// Datagram-semantics frame: may be dropped under overload.
    Lossy,
}

/// Why the guest FD rejected the last write, and therefore which event
/// resumes draining.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteBlock {
    /// `EAGAIN` — resume on `AsyncFd::writable()`.
    WouldBlock,
    /// `ENOBUFS` — resume on the [`NOBUFS_RETRY_DELAY`] timer.
    NoBufs,
}

/// Counters for guest-bound frame delivery. Reliable frames have no drop
/// path by construction; everything that can go wrong is counted here.
#[derive(Debug, Default)]
pub(super) struct GuestTxStats {
    /// Lossy frames dropped at [`LOSSY_QUEUE_CAP`].
    pub lossy_dropped: u64,
    /// `ENOBUFS` write failures (frame queued, not dropped).
    pub enobufs_events: u64,
    /// `EAGAIN` write failures (frame queued, not dropped).
    pub would_block_events: u64,
    /// Short datagram writes — a `SOCK_DGRAM` invariant violation; the
    /// frame is dropped because a partial L2 frame is unrecoverable.
    pub short_writes: u64,
    /// Write failures with unexpected errnos (frame dropped; the link is
    /// assumed dead, e.g. `EPIPE` during shutdown).
    pub io_errors: u64,
    /// `FrameSink::send` rejections on the inject-thread path (frame
    /// dropped). TODO(ABX-420): give the HV inject path the same lossless
    /// contract as the socketpair path.
    pub sink_send_failures: u64,
    /// Bulk-production passes skipped because a backlog was pending.
    pub gated_polls: u64,
    /// High-water mark of the pending queue.
    pub queue_high_water: usize,
    /// Frames successfully written to the guest FD (or inject sink).
    pub tx_frames: u64,
    /// Write syscalls issued to the guest FD (batched and single combined).
    /// `tx_frames / tx_syscalls` is the realised batching factor — the
    /// number ABX-313 exists to move.
    pub tx_syscalls: u64,
}

/// Outcome of a single non-blocking write attempt.
enum WriteOutcome {
    /// Frame fully written, or unrecoverably consumed (short write / fatal
    /// errno — both counted in [`GuestTxStats`]).
    Consumed,
    /// FD full; the frame must be preserved and retried.
    Blocked(WriteBlock),
}

/// Sink for all guest-bound frames: owns the pending queue, the optional
/// inject-thread [`FrameSink`], and the blocked-state machine that decides
/// how draining resumes (write-readiness vs. retry timer).
pub(super) struct GuestTx {
    /// Inject-thread sink (HV backend). When set, frames bypass the
    /// socketpair entirely.
    frame_sink: Option<Arc<dyn FrameSink>>,
    /// Frames awaiting delivery, in order. Emptied by [`GuestTx::flush`]
    /// unless the guest FD refuses them.
    queue: VecDeque<FrameBuf>,
    /// Pre-allocated `msghdr_x`/`iovec` arrays for the batched write.
    batch: BatchDgram,
    /// Why the last write failed, if a backlog is pending.
    blocked: Option<WriteBlock>,
    /// Delivery counters.
    pub(super) stats: GuestTxStats,
}

impl GuestTx {
    /// Creates a sink. `frame_sink` routes frames to the RX inject thread
    /// when present (HV backend); otherwise frames go to the socketpair.
    pub(super) fn new(frame_sink: Option<Arc<dyn FrameSink>>) -> Self {
        Self {
            frame_sink,
            queue: VecDeque::new(),
            batch: BatchDgram::new(),
            blocked: None,
            stats: GuestTxStats::default(),
        }
    }

    /// True when frames the guest FD refused are still pending. Bulk
    /// producers (fast-path host-socket reads) must be gated on this so the
    /// backlog stays bounded and backpressure reaches the remote sender.
    ///
    /// Only meaningful **after** a [`flush`](Self::flush): between a
    /// [`send`](Self::send) and the next flush the queue holds frames that
    /// have not been offered to the FD yet, which is not backpressure.
    pub(super) fn has_backlog(&self) -> bool {
        !self.queue.is_empty()
    }

    /// True when draining can additionally resume on `AsyncFd::writable()`
    /// (`EAGAIN`-blocked). The retry timer remains armed as a fallback —
    /// kqueue write-readiness has not proven trustworthy for a datagram
    /// socketpair, and a missed edge here would wedge all guest-bound
    /// traffic permanently.
    pub(super) fn awaits_writable(&self) -> bool {
        self.has_backlog() && self.blocked == Some(WriteBlock::WouldBlock)
    }

    /// True when the [`NOBUFS_RETRY_DELAY`] timer should drive drain
    /// attempts: any pending backlog, regardless of which errno blocked it.
    pub(super) fn awaits_retry(&self) -> bool {
        self.has_backlog()
    }

    /// Queues one frame for the guest; [`flush`](Self::flush) delivers it.
    ///
    /// Takes ownership so the frame moves into the queue (or into the inject
    /// channel) without a copy. Reliable frames are never dropped here;
    /// lossy frames are dropped (and counted) once [`LOSSY_QUEUE_CAP`]
    /// frames are pending.
    pub(super) fn send(&mut self, frame: Vec<u8>, class: DeliveryClass) {
        if let Some(sink) = &self.frame_sink {
            // Inject-thread path (HV): bounded channel, drop-on-full.
            // TODO(ABX-420): reliable frames need the lossless contract on
            // this path too; count failures so post-mortems can see them.
            if sink.send(frame) {
                self.stats.tx_frames += 1;
            } else {
                self.stats.sink_send_failures += 1;
                tracing::debug!("Guest frame sink full, frame dropped ({class:?})");
            }
            return;
        }

        if class == DeliveryClass::Lossy && self.queue.len() >= LOSSY_QUEUE_CAP {
            self.stats.lossy_dropped += 1;
            tracing::debug!("Lossy queue cap ({LOSSY_QUEUE_CAP}) reached, dropping frame");
            return;
        }
        self.queue.push_back(FrameBuf::from(frame));
        self.stats.queue_high_water = self.stats.queue_high_water.max(self.queue.len());
    }

    /// Writes the pending queue to `guest_fd` until it empties or the FD
    /// blocks, updating the blocked state accordingly.
    ///
    /// Two phases: batched `sendmsg_x` while more than one frame is pending,
    /// then single `write(2)`s. The second phase both handles the tail and
    /// is what classifies a refusal — see the module docs.
    pub(super) fn flush(&mut self, guest_fd: RawFd) {
        self.blocked = None;

        while self.queue.len() > 1 {
            let sent = self.try_write_batch(guest_fd);
            if sent == 0 {
                break;
            }
            self.queue.drain(..sent);
        }

        // Pop before writing (`try_write` needs `&mut self` for counters);
        // a blocked frame is pushed back to the front, preserving order.
        while let Some(frame) = self.queue.pop_front() {
            match self.try_write(guest_fd, &frame) {
                WriteOutcome::Consumed => {}
                WriteOutcome::Blocked(block) => {
                    self.blocked = Some(block);
                    self.queue.push_front(frame);
                    break;
                }
            }
        }
    }

    /// Offers the head of the queue to one `sendmsg_x`, returning how many
    /// frames it accepted.
    ///
    /// `0` means the caller must fall back to a single write: a batch that
    /// accepted nothing reports no usable errno (and one that accepted some
    /// reports none at all), while the blocked-state machine needs to tell
    /// `EAGAIN` from `ENOBUFS`.
    fn try_write_batch(&mut self, guest_fd: RawFd) -> usize {
        let Self {
            queue,
            batch,
            stats,
            ..
        } = self;
        stats.tx_syscalls += 1;
        match batch.send_batch_iter(guest_fd, queue.iter().map(|frame| &**frame)) {
            Ok(sent) => {
                stats.tx_frames += sent as u64;
                sent
            }
            Err(_) => 0,
        }
    }

    /// Attempts one non-blocking write of `frame` to `guest_fd`.
    fn try_write(&mut self, guest_fd: RawFd, frame: &[u8]) -> WriteOutcome {
        self.stats.tx_syscalls += 1;
        match fd_write(guest_fd, frame) {
            Ok(n) if n >= frame.len() => {
                self.stats.tx_frames += 1;
                WriteOutcome::Consumed
            }
            Ok(n) => {
                // SOCK_DGRAM delivers whole datagrams or fails — a short
                // write indicates a broken invariant. The partial frame is
                // unrecoverable; drop it rather than corrupt L2 boundaries.
                self.stats.short_writes += 1;
                tracing::error!(
                    "Guest write: short datagram ({n}/{} bytes), dropping frame",
                    frame.len(),
                );
                WriteOutcome::Consumed
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.stats.would_block_events += 1;
                WriteOutcome::Blocked(WriteBlock::WouldBlock)
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                // Peer receive buffer full (VZ not draining). Backpressure,
                // not loss — the frame stays queued.
                self.stats.enobufs_events += 1;
                WriteOutcome::Blocked(WriteBlock::NoBufs)
            }
            Err(e) => {
                self.stats.io_errors += 1;
                tracing::warn!("Guest write error: {e}");
                WriteOutcome::Consumed
            }
        }
    }

    /// Logs a delivery-counter snapshot. Called from the maintenance tick;
    /// a backlog that persists across consecutive reports indicates a
    /// wedged drain, and `tx_frames` advancing while a connection is
    /// stalled means frames vanish beyond the socketpair (post-mortem
    /// signals, see ABX-420). `rx_frames` counts guest→host frames read by
    /// the loop, to spot one-directional freezes.
    pub(super) fn log_stats(&self, rx_frames: u64) {
        let s = &self.stats;
        tracing::info!(
            queue_len = self.queue.len(),
            blocked = ?self.blocked,
            tx_frames = s.tx_frames,
            tx_syscalls = s.tx_syscalls,
            rx_frames,
            enobufs = s.enobufs_events,
            would_block = s.would_block_events,
            lossy_dropped = s.lossy_dropped,
            short_writes = s.short_writes,
            io_errors = s.io_errors,
            sink_send_failures = s.sink_send_failures,
            gated_polls = s.gated_polls,
            queue_high_water = s.queue_high_water,
            "guest-tx delivery counters"
        );
    }
}

/// Non-blocking drain of the reply channel. Queues pending proxy responses
/// (DNS, UDP, ICMP) for the guest without blocking the event loop.
///
/// Limits each call to `DRAIN_REPLY_BATCH` frames to avoid starving other
/// `select!` branches.
pub(super) fn drain_reply_rx(reply_rx: &mut mpsc::Receiver<Vec<u8>>, guest_tx: &mut GuestTx) {
    for _ in 0..DRAIN_REPLY_BATCH {
        match reply_rx.try_recv() {
            Ok(reply_frame) => {
                guest_tx.send(reply_frame, DeliveryClass::Lossy);
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
