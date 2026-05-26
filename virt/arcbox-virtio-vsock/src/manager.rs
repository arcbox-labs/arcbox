//! Host-side vsock connection manager for the HV (Hypervisor.framework) backend.
//!
//! Implements a connection state machine inspired by vhost-device-vsock's
//! `VsockConnection`. Each connection tracks:
//! - A bitmask-based RX priority queue (`RxOps`) for pending host→guest ops
//! - Credit flow control (`fwd_cnt`, `peer_buf_alloc`, `peer_fwd_cnt`, `rx_cnt`)
//! - Connection lifecycle (`connect` flag)
//!
//! The manager maintains a `backend_rxq` — a FIFO of connections with pending
//! RX operations. The VMM's `poll_vsock_rx` drains this queue, filling guest
//! RX descriptors from the highest-priority pending operation per connection.

use std::collections::{HashMap, VecDeque};
use std::num::Wrapping;
#[cfg(test)]
use std::os::unix::io::FromRawFd;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::VsockHostConnections;

// ============================================================================
// RxOps: Per-connection pending RX operation bitmask
// ============================================================================

/// Pending RX operations for a single connection, stored as a u8 bitmask.
///
/// Dequeued in fixed priority order (lowest bit = highest priority).
/// Each operation type can only be pending once at a time.
#[derive(Debug, Clone, Copy, Default)]
pub struct RxOps(u8);

impl RxOps {
    // Priority order (lowest bit wins): Request > Rw > Response > CreditUpdate > Reset > CreditRequest
    pub const REQUEST: u8 = 0x01;
    pub const RW: u8 = 0x02;
    pub const RESPONSE: u8 = 0x04;
    pub const CREDIT_UPDATE: u8 = 0x08;
    pub const RESET: u8 = 0x10;
    pub const CREDIT_REQUEST: u8 = 0x20;

    /// Returns true if any operation is pending.
    pub fn pending(&self) -> bool {
        self.0 != 0
    }

    /// Enqueues an operation (sets bit).
    pub fn enqueue(&mut self, op: u8) {
        self.0 |= op;
    }

    /// Dequeues the highest-priority pending operation (clears bit).
    /// Returns the operation bitmask, or 0 if nothing pending.
    pub fn dequeue(&mut self) -> u8 {
        if self.0 == 0 {
            return 0;
        }
        // Lowest set bit = highest priority.
        let op = self.0 & self.0.wrapping_neg();
        self.0 &= !op;
        op
    }

    /// Peeks at the highest-priority pending operation without removing it.
    pub fn peek(&self) -> u8 {
        if self.0 == 0 {
            return 0;
        }
        self.0 & self.0.wrapping_neg()
    }
}

// ============================================================================
// VsockConnectionId
// ============================================================================

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

// ============================================================================
// VsockConnection: Per-connection state machine
// ============================================================================

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

// ============================================================================
// VsockConnectionManager
// ============================================================================

/// Manages all active host-initiated vsock connections for the HV backend.
///
/// Thread-safe: wrapped in `Arc<Mutex<>>` and shared between the daemon
/// threads (which call `allocate`) and vCPU threads (which call `poll`
/// methods via `VsockHostConnections` trait).
pub struct VsockConnectionManager {
    connections: HashMap<VsockConnectionId, VsockConnection>,
    /// FIFO of connection IDs with pending RX operations.
    /// Consumed by `poll_vsock_rx` → `recv_pkt`.
    pub backend_rxq: VecDeque<VsockConnectionId>,
    /// Monotonically increasing counter for ephemeral host port allocation.
    next_host_port: AtomicU32,
}

impl VsockConnectionManager {
    /// Starting ephemeral port. Each connection gets the next value.
    const EPHEMERAL_PORT_BASE: u32 = 50_000;

    /// Creates a new empty connection manager.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            backend_rxq: VecDeque::new(),
            next_host_port: AtomicU32::new(Self::EPHEMERAL_PORT_BASE),
        }
    }

    /// Allocates a new connection to `guest_port`, returning a unique ID.
    ///
    /// The `internal_fd` is the internal end of a socketpair; the external
    /// end was returned to the daemon caller. Ownership of `internal_fd`
    /// transfers to the manager — it will be closed automatically when the
    /// connection is removed.
    ///
    /// Enqueues `RxOps::REQUEST` and pushes to `backend_rxq` so the next
    /// `poll_vsock_rx` sends OP_REQUEST to the guest.
    /// Allocates a new connection to `guest_port`, returning the ID and a
    /// receiver that signals when the connection is established (OP_RESPONSE)
    /// or rejected (OP_RST). The daemon should wait on this receiver before
    /// using the socketpair for data transfer.
    /// Allocates a new connection. Returns the ID and a receiver that fires
    /// when the vCPU thread has injected the OP_REQUEST into guest memory.
    /// The daemon MUST wait on this receiver before using the fd.
    pub fn allocate(
        &mut self,
        guest_port: u32,
        guest_cid: u64,
        internal_fd: OwnedFd,
    ) -> (VsockConnectionId, std::sync::mpsc::Receiver<()>) {
        let host_port = self.next_host_port.fetch_add(1, Ordering::Relaxed);
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let conn = VsockConnection::new_local_init(id, guest_cid, internal_fd, tx);
        self.connections.insert(id, conn);
        // Signal that this connection has a pending RX op (OP_REQUEST).
        self.backend_rxq.push_back(id);
        tracing::info!(
            "VsockConnectionManager: allocated connection guest_port={} host_port={} — \
             OP_REQUEST enqueued",
            guest_port,
            host_port,
        );
        (id, rx)
    }

    /// Returns a snapshot of all connected (id, raw_fd) pairs for polling.
    ///
    /// The caller uses these to `libc::read` from each fd and, if data is
    /// available, enqueue `RxOps::RW` and push to `backend_rxq`.
    pub fn connected_fds(&self) -> Vec<(VsockConnectionId, RawFd)> {
        self.connections
            .values()
            .filter(|c| c.connect)
            .map(|c| (c.id, c.internal_fd.as_raw_fd()))
            .collect()
    }

    /// Returns a mutable reference to a connection.
    pub fn get_mut(&mut self, id: &VsockConnectionId) -> Option<&mut VsockConnection> {
        self.connections.get_mut(id)
    }

    /// Returns a reference to a connection.
    pub fn get(&self, id: &VsockConnectionId) -> Option<&VsockConnection> {
        self.connections.get(id)
    }

    /// Enqueues a data-available RX op for a connected stream.
    pub fn enqueue_rw(&mut self, id: VsockConnectionId) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.rx_queue.enqueue(RxOps::RW);
            self.backend_rxq.push_back(id);
        }
    }

    /// Enqueues a reset for a connection (e.g., when host stream closes).
    pub fn enqueue_reset(&mut self, id: VsockConnectionId) {
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.rx_queue.enqueue(RxOps::RESET);
            self.backend_rxq.push_back(id);
        }
    }

    /// Removes a connection and closes its fd.
    pub fn remove(&mut self, id: &VsockConnectionId) {
        if let Some(mut conn) = self.connections.remove(id) {
            // Best-effort: notify the receiver (if still alive) that this
            // connection is being torn down.
            if let Some(tx) = conn.injected_notify.take() {
                let _ = tx.send(());
            }
            // OwnedFd dropped here, closing the socketpair.
            // Remove from backend_rxq too.
            self.backend_rxq.retain(|qid| qid != id);
            tracing::info!(
                "VsockConnectionManager: removed connection guest_port={} host_port={} — fd closed",
                id.guest_port,
                id.host_port,
            );
        }
    }

    /// Returns IDs of connections that have pending RX ops but are NOT
    /// already in the `backend_rxq`. Used after TX processing to pick up
    /// newly-enqueued ops (e.g., CreditUpdate after guest OP_CREDIT_REQUEST).
    pub fn connections_with_pending_rx(&self) -> Vec<VsockConnectionId> {
        let in_queue: std::collections::HashSet<_> = self.backend_rxq.iter().copied().collect();
        self.connections
            .values()
            .filter(|c| c.rx_queue.pending() && !in_queue.contains(&c.id))
            .map(|c| c.id)
            .collect()
    }

    /// Returns the number of active connections.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Returns `true` if there are no active connections.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

impl VsockHostConnections for VsockConnectionManager {
    fn fd_for(&self, guest_port: u32, host_port: u32) -> Option<RawFd> {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        self.connections
            .get(&id)
            .filter(|c| c.connect)
            .map(|c| c.internal_fd.as_raw_fd())
    }

    fn mark_connected(&mut self, guest_port: u32, host_port: u32) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.connect = true;
            tracing::info!("VsockConnectionManager: connection {:?} now Connected", id,);
        } else {
            tracing::warn!(
                "VsockConnectionManager: mark_connected for unknown connection \
                 guest_port={} host_port={}",
                guest_port,
                host_port,
            );
        }
    }

    fn remove_connection(&mut self, guest_port: u32, host_port: u32) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        self.remove(&id);
    }

    fn update_peer_credit(
        &mut self,
        guest_port: u32,
        host_port: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.update_peer_credit(buf_alloc, fwd_cnt);
        }
    }

    fn advance_fwd_cnt(&mut self, guest_port: u32, host_port: u32, bytes: u32) -> bool {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.advance_fwd_cnt(bytes);
            if conn.rx_queue.pending() {
                self.backend_rxq.push_back(id);
                return true;
            }
        }
        false
    }

    fn enqueue_credit_update(&mut self, guest_port: u32, host_port: u32) {
        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if let Some(conn) = self.connections.get_mut(&id) {
            conn.rx_queue.enqueue(RxOps::CREDIT_UPDATE);
            self.backend_rxq.push_back(id);
        }
    }

    fn handle_shutdown(&mut self, guest_port: u32, host_port: u32, flags: u32) {
        // Both bits set (or flags==0, which is spec-invalid but treated as
        // worst case) → full teardown, matching the default trait impl.
        if flags == 0 || flags & VSOCK_SHUTDOWN_F_BOTH == VSOCK_SHUTDOWN_F_BOTH {
            self.remove_connection(guest_port, host_port);
            return;
        }

        let id = VsockConnectionId {
            host_port,
            guest_port,
        };
        if flags & VSOCK_SHUTDOWN_F_RECEIVE != 0 {
            if let Some(conn) = self.connections.get_mut(&id) {
                conn.mark_peer_no_recv();
            }
        }
        // `VSOCK_SHUTDOWN_F_SEND`: guest will not send any more data. Propagate
        // the half-close to the daemon-side fd by shutting down the write side
        // of the internal socketpair end — the daemon's `read(fds[0])` then
        // returns EOF. The reverse direction (daemon→guest writes) stays open
        // so the host can drain any in-flight bytes and finish the session.
        //
        // Without this, the daemon's RawFdStream poll_read never observes the
        // guest's half-close and `copy_bidirectional` stalls forever. This
        // manifests as `docker run <image>` (foreground attach) hanging after
        // the container exits: dockerd closes its end of attach, the guest
        // agent sends OP_SHUTDOWN F_SEND, but the daemon-side bridge never
        // learns about it and the Docker CLI waits indefinitely for EOF.
        if flags & VSOCK_SHUTDOWN_F_SEND != 0 {
            if let Some(conn) = self.connections.get(&id) {
                let fd = conn.internal_fd.as_raw_fd();
                // SAFETY: `fd` is borrowed from an `OwnedFd` held by the
                // connection map; it remains valid for the duration of this
                // call.
                let r = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
                if r != 0 {
                    let err = std::io::Error::last_os_error();
                    // ENOTCONN / EINVAL are benign — peer already tore down,
                    // or the write side was already shut (repeat F_SEND).
                    // Match the pattern used by the daemon-side shutdown in
                    // `rpc/arcbox-transport/src/vsock/stream.rs`.
                    if !matches!(err.raw_os_error(), Some(libc::ENOTCONN | libc::EINVAL)) {
                        tracing::warn!(
                            guest_port,
                            host_port,
                            "shutdown(internal_fd, SHUT_WR) for F_SEND failed: {}",
                            err,
                        );
                    }
                }
            }
        }
    }
}

impl Default for VsockConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds: [libc::c_int; 2] = [0; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn rx_ops_priority_order() {
        let mut ops = RxOps::default();
        ops.enqueue(RxOps::RESET);
        ops.enqueue(RxOps::REQUEST);
        ops.enqueue(RxOps::RW);
        ops.enqueue(RxOps::CREDIT_UPDATE);

        // Dequeue in priority order: Request → Rw → CreditUpdate → Reset
        assert_eq!(ops.dequeue(), RxOps::REQUEST);
        assert_eq!(ops.dequeue(), RxOps::RW);
        assert_eq!(ops.dequeue(), RxOps::CREDIT_UPDATE);
        assert_eq!(ops.dequeue(), RxOps::RESET);
        assert_eq!(ops.dequeue(), 0);
    }

    #[test]
    fn rx_ops_dedup() {
        let mut ops = RxOps::default();
        ops.enqueue(RxOps::RW);
        ops.enqueue(RxOps::RW);
        ops.enqueue(RxOps::RW);

        assert_eq!(ops.dequeue(), RxOps::RW);
        assert_eq!(ops.dequeue(), 0); // Only one dequeue despite 3 enqueues.
    }

    #[test]
    fn allocate_unique_host_ports() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal1) = make_socketpair();
        let (_, internal2) = make_socketpair();

        let (id1, _rx1) = mgr.allocate(1024, 3, internal1);
        let (id2, _rx2) = mgr.allocate(1024, 3, internal2);

        assert_ne!(id1.host_port, id2.host_port);
        assert_eq!(id1.guest_port, 1024);
        assert_eq!(id2.guest_port, 1024);
        assert_eq!(mgr.len(), 2);
    }

    #[test]
    fn allocate_enqueues_request() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        // Should be in backend_rxq.
        assert_eq!(mgr.backend_rxq.len(), 1);
        assert_eq!(mgr.backend_rxq[0], id);

        // Connection should have Request pending.
        let conn = mgr.get(&id).unwrap();
        assert_eq!(conn.rx_queue.peek(), RxOps::REQUEST);
        assert!(!conn.connect);
    }

    #[test]
    fn connected_fds_only_returns_connected() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal1) = make_socketpair();
        let (_, internal2) = make_socketpair();

        let (id1, _rx1) = mgr.allocate(1024, 3, internal1);
        let (_id2, _rx2) = mgr.allocate(1024, 3, internal2);

        assert!(mgr.connected_fds().is_empty());

        mgr.mark_connected(id1.guest_port, id1.host_port);
        let fds = mgr.connected_fds();
        assert_eq!(fds.len(), 1);
        assert_eq!(fds[0].0, id1);
    }

    #[test]
    fn remove_closes_fd() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let fd_raw = internal.as_raw_fd();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        mgr.mark_connected(id.guest_port, id.host_port);
        assert!(mgr.fd_for(1024, id.host_port).is_some());

        mgr.remove_connection(id.guest_port, id.host_port);
        assert!(mgr.fd_for(1024, id.host_port).is_none());
        assert_eq!(mgr.len(), 0);

        // Verify fd is actually closed (write should fail with EBADF).
        let ret = unsafe { libc::fcntl(fd_raw, libc::F_GETFD) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn credit_flow_control() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        // Simulate guest advertising 128KB buffer.
        let conn = mgr.get_mut(&id).unwrap();
        conn.update_peer_credit(128 * 1024, 0);
        assert_eq!(conn.peer_avail_credit(), 128 * 1024);

        // After sending 64KB to guest, available credit drops.
        conn.record_rx(64 * 1024);
        assert_eq!(conn.peer_avail_credit(), 64 * 1024);

        // Guest forwards 32KB.
        conn.update_peer_credit(128 * 1024, 32 * 1024);
        assert_eq!(conn.peer_avail_credit(), 96 * 1024);
    }

    #[test]
    fn fwd_cnt_triggers_credit_update() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        // Drain the initial REQUEST from rx_queue.
        let conn = mgr.get_mut(&id).unwrap();
        conn.rx_queue.dequeue();

        // Write past CREDIT_UPDATE_THRESHOLD (4 KB) → should trigger CreditUpdate.
        conn.advance_fwd_cnt(CREDIT_UPDATE_THRESHOLD);
        assert_eq!(conn.rx_queue.peek(), RxOps::CREDIT_UPDATE);
    }

    #[test]
    fn fwd_cnt_below_threshold_does_not_trigger_credit_update() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);
        let conn = mgr.get_mut(&id).unwrap();
        conn.rx_queue.dequeue();

        // One byte below threshold must NOT enqueue an update.
        conn.advance_fwd_cnt(CREDIT_UPDATE_THRESHOLD - 1);
        assert!(!conn.rx_queue.pending());
    }

    #[test]
    fn maybe_request_credit_fires_below_half_window() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);
        let conn = mgr.get_mut(&id).unwrap();
        conn.rx_queue.dequeue(); // drain REQUEST

        conn.update_peer_credit(8192, 0);
        conn.record_rx(5000); // avail = 8192 - 5000 = 3192, below half (4096)
        conn.maybe_request_credit();

        assert_eq!(conn.rx_queue.peek(), RxOps::CREDIT_REQUEST);
        assert!(conn.credit_request_pending());
    }

    #[test]
    fn maybe_request_credit_noop_above_half_window() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);
        let conn = mgr.get_mut(&id).unwrap();
        conn.rx_queue.dequeue();

        conn.update_peer_credit(8192, 0);
        conn.record_rx(3000); // avail = 5192, above half (4096)
        conn.maybe_request_credit();

        assert!(!conn.rx_queue.pending());
        assert!(!conn.credit_request_pending());
    }

    #[test]
    fn maybe_request_credit_dedupes_while_pending() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);
        let conn = mgr.get_mut(&id).unwrap();
        conn.rx_queue.dequeue();

        conn.update_peer_credit(8192, 0);
        conn.record_rx(5000);
        conn.maybe_request_credit();
        // Dequeue the first request so we can see if a duplicate fires.
        conn.rx_queue.dequeue();

        conn.record_rx(100); // still below half, still pending
        conn.maybe_request_credit();

        assert!(!conn.rx_queue.pending(), "second request would be a dup");
    }

    #[test]
    fn update_peer_credit_clears_pending_flag() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);
        let conn = mgr.get_mut(&id).unwrap();
        conn.rx_queue.dequeue();

        conn.update_peer_credit(8192, 0);
        conn.record_rx(5000);
        conn.maybe_request_credit();
        assert!(conn.credit_request_pending());

        // Peer answers with a fresh fwd_cnt; pending should clear. The
        // already-enqueued CREDIT_REQUEST op stays in rx_queue — sending it
        // is harmless (peer just replies with another CREDIT_UPDATE) and not
        // worth a bit-clearing helper on RxOps.
        conn.update_peer_credit(8192, 5000);
        assert!(!conn.credit_request_pending());

        // Drain the stale CREDIT_REQUEST to simulate the next RX tick.
        assert_eq!(conn.rx_queue.dequeue(), RxOps::CREDIT_REQUEST);

        // Now that we're at full credit, maybe_request_credit stays quiet.
        conn.maybe_request_credit();
        assert!(!conn.rx_queue.pending());
        assert!(!conn.credit_request_pending());
    }

    #[test]
    fn shutdown_both_bits_removes_connection() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);
        assert!(mgr.get(&id).is_some());

        mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_BOTH);
        assert!(mgr.get(&id).is_none());
    }

    #[test]
    fn shutdown_receive_bit_marks_half_close() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_RECEIVE);
        let conn = mgr.get(&id).expect("conn must survive half-close");
        assert!(conn.peer_no_recv());
        assert!(!conn.accepts_data() || !conn.connect); // connect=false initially
    }

    #[test]
    fn shutdown_send_bit_only_is_informational() {
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_SEND);
        let conn = mgr.get(&id).expect("conn must survive");
        assert!(
            !conn.peer_no_recv(),
            "F_SEND alone does not block host→peer RW"
        );
    }

    #[test]
    fn shutdown_send_bit_propagates_eof_to_daemon_fd() {
        // Regression for ABX-372: F_SEND half-close must translate into a
        // SHUT_WR on the internal socketpair end so the daemon-side fd reads
        // EOF. Without this, the Docker attach bridge (`copy_bidirectional`)
        // stalls forever after the container exits.
        use std::io::Read;
        use std::os::fd::IntoRawFd;

        let mut mgr = VsockConnectionManager::new();
        let (daemon_end, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        // Wrap the daemon end in a blocking `UnixStream` for `read`.
        let mut daemon_stream =
            unsafe { std::os::unix::net::UnixStream::from_raw_fd(daemon_end.into_raw_fd()) };
        // Bound the read so a regression doesn't hang the test runner.
        daemon_stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        // Before the half-close, the daemon's read blocks. After F_SEND
        // handling, it must return 0 (EOF).
        mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_SEND);

        let mut buf = [0u8; 8];
        let n = daemon_stream
            .read(&mut buf)
            .expect("read on daemon fd should not error");
        assert_eq!(n, 0, "daemon fd must read EOF after F_SEND propagation");

        // Reverse direction stays open: daemon can still write to the peer.
        use std::io::Write;
        daemon_stream
            .write_all(b"still-alive")
            .expect("daemon→internal write should still succeed");
    }

    #[test]
    fn shutdown_flags_zero_removes_connection_conservatively() {
        // flags=0 is spec-invalid; worst-case interpretation is full close.
        let mut mgr = VsockConnectionManager::new();
        let (_, internal) = make_socketpair();
        let (id, _rx) = mgr.allocate(1024, 3, internal);

        mgr.handle_shutdown(id.guest_port, id.host_port, 0);
        assert!(mgr.get(&id).is_none());
    }
}
