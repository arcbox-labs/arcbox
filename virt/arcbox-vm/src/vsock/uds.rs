//! The transitional [`Vsock`] over Firecracker's hybrid-vsock Unix socket.
//!
//! Firecracker exposes a Unix domain socket that proxies host-initiated
//! connections to guest vsock ports behind a `CONNECT {port}` handshake
//! (see the parent module docs). Until the Firecracker adapter's handle
//! exposes [`Vsock`] itself, this is how the manager dials the guest; it
//! goes away with the last `vsock_uds_path` field.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use arcbox_vm_driver::{IoMode, Vsock, VsockConn};
use async_trait::async_trait;

use crate::error::VmmError;

/// Transitional [`Vsock`] over Firecracker's hybrid-vsock Unix socket.
///
/// Dials by running the `CONNECT {port}` handshake on the wrapped
/// `uds_path`. Firecracker closes the proxied connection without an `OK`
/// when the guest has no listener on the port yet; that is the port's
/// `ConnectionRefused`, so callers retry it. Goes away once the Firecracker
/// driver's handle exposes [`Vsock`] itself.
pub struct UdsVsock(pub PathBuf);

#[async_trait]
impl Vsock for UdsVsock {
    async fn dial(&self, port: u32) -> arcbox_vm_driver::Result<VsockConn> {
        match super::try_vsock_handshake(&self.0, port).await {
            Ok(stream) => Ok(VsockConn {
                fd: OwnedFd::from(stream.into_std()?),
                mode: IoMode::Async,
            }),
            Err(VmmError::Vsock(message)) if message.contains("connection closed") => {
                Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, message).into())
            }
            Err(error) => Err(arcbox_vm_driver::Error::Driver {
                driver: "firecracker",
                message: match error {
                    VmmError::Vsock(message) => message,
                    other => other.to_string(),
                },
                source: None,
            }),
        }
    }
}
