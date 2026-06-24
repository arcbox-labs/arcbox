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

mod connection;
mod host_connections;
mod ops;

#[cfg(test)]
mod tests;

pub use connection::{
    CREDIT_UPDATE_THRESHOLD, TX_BUFFER_SIZE, VSOCK_SHUTDOWN_F_BOTH, VSOCK_SHUTDOWN_F_RECEIVE,
    VSOCK_SHUTDOWN_F_SEND, VsockConnection, VsockConnectionId,
};
pub use ops::RxOps;

use std::collections::{HashMap, VecDeque};
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Wakeup hook invoked when host→guest RX work appears from outside the
/// injection driver (new connection, handshake completion, credit grants).
///
/// The VMM installs a callback that wakes its vsock-io worker so injection
/// runs immediately instead of waiting for the next natural vCPU exit —
/// without it, an idle guest adds ~100 ms per host→guest leg.
pub type VsockDoorbell = Arc<dyn Fn() + Send + Sync>;

/// Manages all active host-initiated vsock connections for the HV backend.
///
/// Thread-safe: wrapped in `Arc<Mutex<>>` and shared between the daemon
/// threads (which call `allocate`) and vCPU threads (which call `poll`
/// methods via `VsockHostConnections` trait).
pub struct VsockConnectionManager {
    pub(super) connections: HashMap<VsockConnectionId, VsockConnection>,
    /// FIFO of connection IDs with pending RX operations.
    /// Consumed by `poll_vsock_rx` → `recv_pkt`.
    pub backend_rxq: VecDeque<VsockConnectionId>,
    /// Monotonically increasing counter for ephemeral host port allocation.
    next_host_port: AtomicU32,
    /// Rung when RX work appears from producer paths (allocate, handshake
    /// completion, credit grants). NOT rung from the injection driver's own
    /// enqueues (`enqueue_rw`/`enqueue_reset` and in-loop re-pushes) — the
    /// driver is already awake there, and ringing on its re-pushes would
    /// spin it while the guest catches up.
    doorbell: Option<VsockDoorbell>,
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
            doorbell: None,
        }
    }

    /// Installs the doorbell rung when new host→guest RX work appears.
    pub fn set_doorbell(&mut self, doorbell: VsockDoorbell) {
        self.doorbell = Some(doorbell);
    }

    pub(super) fn ring_doorbell(&self) {
        if let Some(doorbell) = &self.doorbell {
            doorbell();
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
        self.ring_doorbell();
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

impl Default for VsockConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}
