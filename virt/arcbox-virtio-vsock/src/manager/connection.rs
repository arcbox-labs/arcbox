use std::num::Wrapping;
use std::os::unix::io::OwnedFd;

use super::RxOps;

/// Unique identifier for a host↔guest vsock connection.
///
/// The vsock protocol identifies connections by the 4-tuple
/// `(src_cid, src_port, dst_cid, dst_port)`. Since host CID is always 2
/// and guest CID is always 3, the pair `(host_port, guest_port)` suffices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockConnectionId {
    pub host_port: u32,
    pub guest_port: u32,
}

/// Default host-side TX buffer size (also advertised as `buf_alloc` to guest).
pub const TX_BUFFER_SIZE: u32 = 64 * 1024;

/// Bytes consumed since the last credit packet before we send a proactive
/// `CREDIT_UPDATE`.
///
/// Chosen as 4 KB (one page) so the guest sees a refreshed fwd_cnt roughly
/// every page of drained traffic. A coarser threshold (e.g. 3/4 of
/// `TX_BUFFER_SIZE` = 48 KB) stalls the guest TX path on bursts between
/// the window size and the threshold: the guest exhausts its view of our
/// free buffer and blocks waiting for a credit packet we haven't sent yet.
/// A finer threshold would just spam credit-only packets without reducing
/// stall probability meaningfully.
pub const CREDIT_UPDATE_THRESHOLD: u32 = 4096;

/// `OP_SHUTDOWN` flag: peer will not receive any more data.
pub const VSOCK_SHUTDOWN_F_RECEIVE: u32 = 1 << 0;

/// `OP_SHUTDOWN` flag: peer will not send any more data.
pub const VSOCK_SHUTDOWN_F_SEND: u32 = 1 << 1;

/// Mask of both shutdown flags — equivalent to `RST` when set.
pub const VSOCK_SHUTDOWN_F_BOTH: u32 = VSOCK_SHUTDOWN_F_RECEIVE | VSOCK_SHUTDOWN_F_SEND;

/// A single host↔guest vsock connection.
///
/// Owns the internal end of the socketpair. When this entry is removed from
/// the manager (or the manager is dropped), `OwnedFd::drop` closes the fd.
///
/// The state machine is implicit:
/// - `connect == false`: handshake in progress
/// - `connect == true`: data transfer enabled
/// - `rx_queue` contains `RxOps::RESET`: connection is being torn down
pub struct VsockConnection {
    pub id: VsockConnectionId,
    pub internal_fd: OwnedFd,
    /// Fired by vCPU thread's poll_vsock_rx after OP_REQUEST is written to
    /// guest memory. The daemon blocks on this before returning the fd —
    /// guarantees the guest will see the OP_REQUEST and respond (RST or
    /// RESPONSE) so the daemon's read won't hang indefinitely.
    pub injected_notify: Option<std::sync::mpsc::Sender<()>>,
    pub guest_cid: u64,

    /// Whether the connection handshake is complete.
    pub connect: bool,

    /// Per-connection pending RX operations (bitmask priority queue).
    pub rx_queue: RxOps,

    // -- Credit flow control --
    /// Total bytes forwarded from host tx_buf to the actual host stream.
    /// Sent to guest in every packet so it knows how much host buffer is free.
    pub fwd_cnt: Wrapping<u32>,

    /// `fwd_cnt` value at the time of the last credit update sent to guest.
    /// Used to decide when a proactive CreditUpdate is warranted.
    last_fwd_cnt: Wrapping<u32>,

    /// Guest's advertised buffer allocation (extracted from every incoming pkt).
    pub peer_buf_alloc: u32,

    /// Guest's forwarded count (extracted from every incoming packet).
    pub peer_fwd_cnt: Wrapping<u32>,

    /// Total bytes sent TO the guest via RX virtqueue.
    pub rx_cnt: Wrapping<u32>,

    /// Set when a `CREDIT_REQUEST` packet has been enqueued for the peer and
    /// the peer has not yet answered with a `CREDIT_UPDATE`. Keeps us from
    /// spamming repeated credit requests each time we see a low-credit RW —
    /// one in-flight at a time is enough to refresh our view.
    credit_request_pending: bool,

    /// Set when the peer sent `OP_SHUTDOWN` with `F_RECEIVE` — it won't
    /// accept any more data. We must stop emitting `RW` for this connection
    /// but keep the fd open so pending peer→host data can still drain.
    peer_no_recv: bool,
}

impl VsockConnection {
    /// Creates a new connection for a host-initiated connect (OP_REQUEST).
    pub fn new_local_init(
        id: VsockConnectionId,
        guest_cid: u64,
        fd: OwnedFd,
        injected_notify: std::sync::mpsc::Sender<()>,
    ) -> Self {
        let mut conn = Self {
            id,
            internal_fd: fd,
            guest_cid,
            connect: false,
            injected_notify: Some(injected_notify),
            rx_queue: RxOps::default(),
            fwd_cnt: Wrapping(0),
            last_fwd_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            credit_request_pending: false,
            peer_no_recv: false,
        };
        // Enqueue OP_REQUEST to be sent to guest on the next RX fill.
        conn.rx_queue.enqueue(RxOps::REQUEST);
        conn
    }

    /// Returns the number of bytes the guest can still receive.
    ///
    /// `peer_buf_alloc - (rx_cnt - peer_fwd_cnt)` = total guest buffer minus
    /// bytes currently in-flight (sent but not yet consumed by the guest).
    pub fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    /// Updates peer credit state from an incoming guest packet. Also clears
    /// any in-flight `CREDIT_REQUEST` marker: the peer has just told us the
    /// fresh state, so whatever we asked about is answered.
    pub fn update_peer_credit(&mut self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc = buf_alloc;
        self.peer_fwd_cnt = Wrapping(fwd_cnt);
        self.credit_request_pending = false;
    }

    /// Enqueues a `CREDIT_REQUEST` op if peer credit has fallen below half
    /// the peer's advertised buffer and no request is already in flight.
    ///
    /// Call from the RX path after sending data the peer now has to process.
    /// Sending the request proactively — rather than only when credit hits
    /// zero — means we refresh our (possibly stale) view of `peer_fwd_cnt`
    /// before we actually deplete our window, avoiding a full TX stall.
    pub fn maybe_request_credit(&mut self) {
        if self.credit_request_pending || self.peer_buf_alloc == 0 {
            return;
        }
        let half = (self.peer_buf_alloc / 2) as usize;
        if self.peer_avail_credit() < half {
            self.rx_queue.enqueue(RxOps::CREDIT_REQUEST);
            self.credit_request_pending = true;
        }
    }

    /// Marks a `CREDIT_REQUEST` as in-flight without going through the
    /// `RxOps` queue. Used when the caller emits the request packet directly
    /// in the RW-with-zero-credit fallback path — we still want the pending
    /// flag set so `maybe_request_credit` doesn't duplicate us.
    pub fn note_credit_request_sent(&mut self) {
        self.credit_request_pending = true;
    }

    /// True iff we're waiting on the peer for a credit update.
    #[must_use]
    pub fn credit_request_pending(&self) -> bool {
        self.credit_request_pending
    }

    /// Peer sent `OP_SHUTDOWN` with `F_RECEIVE`. Record the half-close so the
    /// RX injection path stops trying to deliver more `RW` packets.
    pub fn mark_peer_no_recv(&mut self) {
        self.peer_no_recv = true;
    }

    /// True iff the peer has half-closed its receive side.
    #[must_use]
    pub const fn peer_no_recv(&self) -> bool {
        self.peer_no_recv
    }

    /// Whether we may send more data to the peer. False once the handshake
    /// hasn't completed or the peer has told us it won't accept more.
    #[must_use]
    pub const fn accepts_data(&self) -> bool {
        self.connect && !self.peer_no_recv
    }

    /// Called after data is written to the host stream (from guest OP_RW).
    /// Advances `fwd_cnt` and enqueues a CreditUpdate if buffer is getting low.
    pub fn advance_fwd_cnt(&mut self, bytes: u32) {
        self.fwd_cnt += Wrapping(bytes);

        // Proactive credit update once enough has been drained that the peer's
        // in-flight window is meaningfully stale.
        let consumed = (self.fwd_cnt - self.last_fwd_cnt).0;
        if consumed >= CREDIT_UPDATE_THRESHOLD {
            self.rx_queue.enqueue(RxOps::CREDIT_UPDATE);
        }
    }

    /// Records bytes sent to the guest and returns the new rx_cnt.
    pub fn record_rx(&mut self, bytes: u32) {
        self.rx_cnt += Wrapping(bytes);
    }

    /// Marks that a CreditUpdate was sent to the guest (syncs last_fwd_cnt).
    pub fn mark_credit_sent(&mut self) {
        self.last_fwd_cnt = self.fwd_cnt;
    }
}
