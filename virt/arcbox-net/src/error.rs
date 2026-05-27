//! Error types for the network stack.

use arcbox_error::CommonError;
use thiserror::Error;

/// Result type alias for network operations.
pub type Result<T> = std::result::Result<T, NetError>;

/// Errors that can occur during network operations.
#[derive(Debug, Error)]
pub enum NetError {
    /// Common errors shared across `ArcBox` crates.
    #[error(transparent)]
    Common(#[from] CommonError),

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

    /// Backend error.
    #[error("backend error: {0}")]
    Backend(String),

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

    /// mDNS error.
    #[error("mDNS error: {0}")]
    Mdns(String),
}

impl From<std::io::Error> for NetError {
    fn from(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

#[cfg(target_os = "macos")]
impl From<arcbox_vmnet::VmnetError> for NetError {
    fn from(err: arcbox_vmnet::VmnetError) -> Self {
        match err {
            arcbox_vmnet::VmnetError::Config(msg) => {
                Self::Common(CommonError::config(format!("vmnet: {msg}")))
            }
            arcbox_vmnet::VmnetError::Io(io) => Self::Common(CommonError::from(io)),
        }
    }
}

impl NetError {
    /// Creates a configuration error.
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Common(CommonError::config(msg))
    }

    /// Creates an I/O error.
    #[must_use]
    pub fn io(err: std::io::Error) -> Self {
        Self::Common(CommonError::from(err))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn vmnet_config_error_keeps_origin_prefix() {
        let err: NetError =
            arcbox_vmnet::VmnetError::config("bridge mode requires interface name").into();
        let s = err.to_string();
        assert!(
            s.contains("vmnet: bridge mode requires interface name"),
            "missing origin prefix: {s}"
        );
    }

    #[test]
    fn vmnet_io_error_passes_through() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: NetError = arcbox_vmnet::VmnetError::Io(io).into();
        match err {
            NetError::Common(common) if common.is_io() => {}
            other => panic!("expected Common(io), got {other:?}"),
        }
    }
}
