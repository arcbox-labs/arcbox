//! Vsock connection state — used by the in-process loopback path.

use crate::addr::VsockAddr;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state.
    Idle,
    /// Connection requested.
    Connecting,
    /// Connected.
    Connected,
    /// Shutting down.
    Closing,
    /// Closed.
    Closed,
}

/// A vsock connection.
#[derive(Debug)]
#[allow(dead_code)]
pub struct VsockConnection {
    /// Local address.
    pub local: VsockAddr,
    /// Remote address.
    pub remote: VsockAddr,
    /// Connection state.
    pub state: ConnectionState,
    /// Receive buffer.
    rx_buf: Vec<u8>,
    /// Transmit buffer.
    tx_buf: Vec<u8>,
    /// Buffer allocation (credit).
    pub(crate) buf_alloc: u32,
    /// Forward count.
    pub(crate) fwd_cnt: u32,
    /// Peer buffer allocation.
    pub(crate) peer_buf_alloc: u32,
    /// Peer forward count.
    pub(crate) peer_fwd_cnt: u32,
}

impl VsockConnection {
    /// Creates a new connection.
    #[must_use]
    pub fn new(local: VsockAddr, remote: VsockAddr) -> Self {
        Self {
            local,
            remote,
            state: ConnectionState::Idle,
            rx_buf: Vec::with_capacity(64 * 1024),
            tx_buf: Vec::with_capacity(64 * 1024),
            buf_alloc: 64 * 1024,
            fwd_cnt: 0,
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
        }
    }

    /// Returns bytes available to send.
    #[must_use]
    pub fn tx_available(&self) -> usize {
        self.tx_buf.len()
    }

    /// Returns bytes available to receive.
    #[must_use]
    pub fn rx_available(&self) -> usize {
        self.rx_buf.len()
    }

    /// Enqueues data for transmission.
    pub fn enqueue_tx(&mut self, data: &[u8]) {
        self.tx_buf.extend_from_slice(data);
    }

    /// Dequeues transmitted data.
    pub fn dequeue_tx(&mut self, max_len: usize) -> Vec<u8> {
        let len = max_len.min(self.tx_buf.len());
        self.tx_buf.drain(..len).collect()
    }

    /// Enqueues received data.
    pub fn enqueue_rx(&mut self, data: &[u8]) {
        self.rx_buf.extend_from_slice(data);
        self.fwd_cnt = self.fwd_cnt.wrapping_add(data.len() as u32);
    }

    /// Dequeues received data.
    pub fn dequeue_rx(&mut self, max_len: usize) -> Vec<u8> {
        let len = max_len.min(self.rx_buf.len());
        self.rx_buf.drain(..len).collect()
    }

    /// Updates peer credit info.
    pub const fn update_peer_credit(&mut self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc = buf_alloc;
        self.peer_fwd_cnt = fwd_cnt;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_connection_state() {
        let conn = VsockConnection::new(VsockAddr::new(3, 1000), VsockAddr::new(2, 80));
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.tx_available(), 0);
        assert_eq!(conn.rx_available(), 0);
    }

    #[test]
    fn test_vsock_connection_buffers() {
        let mut conn = VsockConnection::new(VsockAddr::new(3, 1000), VsockAddr::new(2, 80));

        conn.enqueue_tx(b"hello");
        assert_eq!(conn.tx_available(), 5);
        let data = conn.dequeue_tx(3);
        assert_eq!(&data, b"hel");
        assert_eq!(conn.tx_available(), 2);

        conn.enqueue_rx(b"world");
        assert_eq!(conn.rx_available(), 5);
        let data = conn.dequeue_rx(10);
        assert_eq!(&data, b"world");
        assert_eq!(conn.rx_available(), 0);
    }
}
