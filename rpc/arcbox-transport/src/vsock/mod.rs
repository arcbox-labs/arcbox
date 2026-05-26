//! Virtio socket (vsock) transport.
//!
//! Provides high-performance communication between host and guest VM.
//!
//! ## Platform Support
//!
//! - **Linux**: Uses `AF_VSOCK` socket family directly via nix crate.
//!   Standard `bind()` and `connect()` operations work as expected.
//!
//! - **macOS**: Uses Virtualization.framework (`VZVirtioSocketDevice`).
//!   Requires integration with the hypervisor layer:
//!   - For connections: Use [`VsockTransport::from_raw_fd()`] with an fd
//!     obtained from `VirtioSocketDevice::connect()`.
//!   - For listening: Use [`VsockListener::from_channel()`] with a channel
//!     connected to `VirtioSocketListener::accept()`.
//!
//! ## CID (Context ID) Values
//!
//! - `VMADDR_CID_HYPERVISOR` (0): Reserved for hypervisor
//! - `VMADDR_CID_LOCAL` (1): Local communication
//! - `VMADDR_CID_HOST` (2): Host (from guest perspective)
//! - 3+: Guest VMs
//!
//! ## macOS Usage Example
//!
//! ```rust,ignore
//! use arcbox_vz::{VirtualMachine, VirtioSocketDevice};
//! use arcbox_transport::vsock::{VsockListener, VsockTransport, VsockAddr, IncomingVsockConnection};
//! use tokio::sync::mpsc;
//!
//! // Get socket device from running VM
//! let vm: VirtualMachine = /* ... */;
//! let device = &vm.socket_devices()[0];
//!
//! // === Connecting to guest ===
//! let conn = device.connect(1024).await?;
//! let fd = conn.into_raw_fd();
//! let transport = VsockTransport::from_raw_fd(fd, VsockAddr::new(cid, 1024))?;
//!
//! // === Listening for guest connections ===
//! let mut vz_listener = device.listen(1024)?;
//! let (tx, rx) = mpsc::unbounded_channel();
//!
//! // Bridge VZ listener to transport layer
//! tokio::spawn(async move {
//!     loop {
//!         match vz_listener.accept().await {
//!             Ok(conn) => {
//!                 let incoming = IncomingVsockConnection {
//!                     fd: conn.into_raw_fd(),
//!                     source_port: conn.source_port(),
//!                     destination_port: conn.destination_port(),
//!                 };
//!                 if tx.send(incoming).is_err() {
//!                     break;
//!                 }
//!             }
//!             Err(_) => break,
//!         }
//!     }
//! });
//!
//! let mut listener = VsockListener::from_channel(1024, rx);
//! let transport = listener.accept().await?;
//! ```

mod addr;
pub mod blocking;
#[cfg(target_os = "macos")]
pub(crate) mod darwin;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
mod listener;
pub(crate) mod stream;
mod transport;

pub use addr::{DEFAULT_AGENT_PORT, VsockAddr};
pub use blocking::BlockingVsockTransport;
#[cfg(target_os = "macos")]
pub use darwin::IncomingVsockConnection;
pub use listener::VsockListener;
pub use transport::{VsockReceiver, VsockSender, VsockTransport};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;

    #[test]
    fn test_vsock_addr() {
        let addr = VsockAddr::new(3, 1234);
        assert_eq!(addr.cid, 3);
        assert_eq!(addr.port, 1234);

        let host = VsockAddr::host(DEFAULT_AGENT_PORT);
        assert_eq!(host.cid, VsockAddr::CID_HOST);
        assert_eq!(host.port, DEFAULT_AGENT_PORT);
    }

    #[test]
    fn test_vsock_transport_not_connected() {
        let transport = VsockTransport::new(VsockAddr::host(1234));
        assert!(!transport.is_connected());
    }

    #[test]
    fn test_into_split_not_connected() {
        let transport = VsockTransport::new(VsockAddr::host(1234));
        assert!(transport.into_split().is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_vsock_listener_from_channel() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::unbounded_channel();
        let listener = VsockListener::from_channel(1024, rx);
        assert_eq!(listener.port(), 1024);

        let conn = IncomingVsockConnection {
            fd: 42,
            source_port: 2000,
            destination_port: 1024,
        };
        assert!(tx.send(conn).is_ok());
    }
}
