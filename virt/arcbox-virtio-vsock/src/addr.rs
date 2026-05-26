//! Vsock address type + host-side connection-manager trait.

use std::os::unix::io::RawFd;

/// Well-known CID for the host.
pub const HOST_CID: u64 = 2;

/// Reserved CID — must not be used by guests.
pub const RESERVED_CID: u64 = 1;

/// Vsock address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockAddr {
    /// Context Identifier.
    pub cid: u64,
    /// Port number.
    pub port: u32,
}

impl VsockAddr {
    /// Creates a new vsock address.
    #[must_use]
    pub const fn new(cid: u64, port: u32) -> Self {
        Self { cid, port }
    }

    /// Returns the host address for a given port.
    #[must_use]
    pub const fn host(port: u32) -> Self {
        Self::new(HOST_CID, port)
    }
}

/// Abstracts host-side vsock connection tracking for the HV backend.
///
/// The VZ backend handles connections natively via Virtualization.framework.
/// For the HV backend, a concrete `VsockConnectionManager` (in arcbox-vmm)
/// implements this trait and is shared with `VirtioVsock` via `bind_connections`.
pub trait VsockHostConnections: Send + Sync {
    /// Returns the host fd for a connection identified by (`guest_port`, `host_port`).
    fn fd_for(&self, guest_port: u32, host_port: u32) -> Option<RawFd>;

    /// Marks a connection as established (called when `OP_RESPONSE` is received).
    fn mark_connected(&mut self, guest_port: u32, host_port: u32);

    /// Removes a connection and closes the associated fd (called on `OP_RST`).
    fn remove_connection(&mut self, guest_port: u32, host_port: u32);

    /// Updates peer credit state from an incoming guest packet.
    /// Called for every TX packet to keep credit info in sync.
    fn update_peer_credit(
        &mut self,
        _guest_port: u32,
        _host_port: u32,
        _buf_alloc: u32,
        _fwd_cnt: u32,
    ) {
    }

    /// Advances `fwd_cnt` after writing guest data to the host stream.
    /// Returns `true` if the host has pending RX data as a result (`CreditUpdate`).
    fn advance_fwd_cnt(&mut self, _guest_port: u32, _host_port: u32, _bytes: u32) -> bool {
        false
    }

    /// Enqueues a `CreditUpdate` to be sent on the next RX fill.
    fn enqueue_credit_update(&mut self, _guest_port: u32, _host_port: u32) {}

    /// Handles a guest-originated `OP_SHUTDOWN` with its flags bitmask.
    ///
    /// Per the vsock spec, `flags` carries two bits:
    /// - `VSOCK_SHUTDOWN_F_RECEIVE` (bit 0) — peer won't receive more data.
    /// - `VSOCK_SHUTDOWN_F_SEND` (bit 1) — peer won't send more data.
    ///
    /// The default behaviour mirrors `RST` (full teardown), which is correct
    /// when both bits are set; concrete managers override to handle half-close
    /// cases that should preserve the connection.
    fn handle_shutdown(&mut self, guest_port: u32, host_port: u32, _flags: u32) {
        self.remove_connection(guest_port, host_port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_addr_new() {
        let addr = VsockAddr::new(3, 1234);
        assert_eq!(addr.cid, 3);
        assert_eq!(addr.port, 1234);
    }

    #[test]
    fn test_vsock_addr_host() {
        let addr = VsockAddr::host(8080);
        assert_eq!(addr.cid, HOST_CID);
        assert_eq!(addr.cid, 2);
        assert_eq!(addr.port, 8080);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_vsock_addr_clone_copy() {
        let addr = VsockAddr::new(10, 5000);
        let cloned = addr.clone();
        let copied = addr;

        assert_eq!(cloned.cid, 10);
        assert_eq!(copied.port, 5000);
    }

    #[test]
    fn test_vsock_addr_eq() {
        let addr1 = VsockAddr::new(3, 1234);
        let addr2 = VsockAddr::new(3, 1234);
        let addr3 = VsockAddr::new(3, 5678);

        assert_eq!(addr1, addr2);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn test_vsock_addr_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(VsockAddr::new(3, 1234));
        set.insert(VsockAddr::new(3, 1234)); // Duplicate
        set.insert(VsockAddr::new(4, 1234));

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_vsock_constants() {
        assert_eq!(HOST_CID, 2);
        assert_eq!(RESERVED_CID, 1);
    }
}
