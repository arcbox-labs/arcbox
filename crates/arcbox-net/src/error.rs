//! Error types for the network stack.

use thiserror::Error;

/// Result type alias for network operations.
pub type Result<T> = std::result::Result<T, NetError>;

/// Errors that can occur during network operations.
#[derive(Debug, Error)]
pub enum NetError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Interface error.
    #[error("interface error: {0}")]
    Interface(String),

    /// Address allocation error.
    #[error("address allocation error: {0}")]
    AddressAllocation(String),

    /// Port forwarding error.
    #[error("port forwarding error: {0}")]
    PortForward(String),

    /// DNS error.
    #[error("DNS error: {0}")]
    Dns(String),

    /// DHCP error.
    #[error("DHCP error: {0}")]
    Dhcp(String),

    /// Backend error.
    #[error("backend error: {0}")]
    Backend(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Netlink error (Linux only).
    #[error("netlink error: {0}")]
    Netlink(String),

    /// Bridge error (Linux only).
    #[error("bridge error: {0}")]
    Bridge(String),

    /// TAP device error (Linux only).
    #[error("TAP error: {0}")]
    Tap(String),

    /// Firewall error (Linux only).
    #[error("firewall error: {0}")]
    Firewall(String),

    /// NAT error.
    #[error("NAT error: {0}")]
    Nat(String),

    /// Datapath error.
    #[error("datapath error: {0}")]
    Datapath(String),

    /// Ring buffer error.
    #[error("ring buffer error: {0}")]
    RingBuffer(String),

    /// Packet pool error.
    #[error("packet pool error: {0}")]
    PacketPool(String),

    /// Connection tracking error.
    #[error("connection tracking error: {0}")]
    ConnTrack(String),

    /// Checksum error.
    #[error("checksum error: {0}")]
    Checksum(String),
}
