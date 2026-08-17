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

/// Transitional [`Vsock`] over Firecracker's hybrid-vsock Unix socket.
///
/// Dials by running the `CONNECT {port}` handshake on the wrapped
/// `uds_path` — the adapter's own [`arcbox_fc_driver::vsock::dial_uds`],
/// which already answers the port's `ConnectionRefused` when Firecracker
/// closes the proxied connection because the guest has no listener on the
/// port yet, so callers retry it. Goes away once the manager takes the
/// capability from the Firecracker driver's handle.
pub struct UdsVsock(pub PathBuf);

#[async_trait]
impl Vsock for UdsVsock {
    async fn dial(&self, port: u32) -> arcbox_vm_driver::Result<VsockConn> {
        let stream = arcbox_fc_driver::vsock::dial_uds(&self.0, port).await?;
        Ok(VsockConn {
            fd: OwnedFd::from(stream.into_std()?),
            mode: IoMode::Async,
        })
    }
}
