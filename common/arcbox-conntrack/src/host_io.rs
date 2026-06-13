//! Host-side network I/O abstraction for the NAT engine.

use std::io;

/// Trait for host-side network I/O.
///
/// This abstracts the actual mechanism used to send/receive packets on the host
/// network interface. Implementations may use utun, vmnet.framework, raw sockets,
/// TAP devices, or other mechanisms.
///
/// Methods take `&self` because the underlying I/O (file descriptor read/write)
/// is inherently thread-safe for datagram sockets.
pub trait HostNetIO: Send + Sync {
    /// Sends a raw IP packet to the host network stack.
    fn send_packet(&self, packet: &[u8]) -> io::Result<usize>;

    /// Receives a raw IP packet from the host network stack.
    ///
    /// Returns 0 if no data is available (non-blocking).
    fn recv_packet(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Returns true if there is data available to read.
    fn has_data(&self) -> bool;

    /// Returns the name/identifier of this I/O backend.
    fn name(&self) -> &str;
}
