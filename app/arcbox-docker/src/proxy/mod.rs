//! Smart proxy for forwarding Docker API requests to guest dockerd.
//!
//! Provides HTTP/1.1 client over vsock to forward requests, with support
//! for streaming responses and HTTP upgrades (attach, exec, BuildKit).

mod connector;
mod fallback;
mod forward;
mod port_bindings;
mod stream;
mod upgrade;
mod upload;

pub use connector::VsockConnector;
pub use fallback::proxy_fallback;
pub use forward::{proxy_to_guest, proxy_to_guest_stream, proxy_to_guest_stream_for_role};
pub use port_bindings::{PortBindingInfo, parse_port_bindings};
pub use stream::RawFdStream;
pub use upgrade::proxy_with_upgrade;
pub use upload::{proxy_streaming_upload, proxy_streaming_upload_for_role};

use crate::error::Result;
use crate::routing::UtilityVmRole;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Timeout for the HTTP/1.1 handshake with guest dockerd.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Abstraction over guest connection establishment.
///
/// Production code connects via vsock ([`VsockConnector`]); integration tests
/// can connect via Unix socket. Both produce a [`TokioIo<RawFdStream>`]
/// because [`RawFdStream`] wraps any pollable file descriptor.
pub trait GuestConnector: Send + Sync + 'static {
    /// Opens a new connection to guest dockerd.
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<TokioIo<RawFdStream>>> + Send + '_>>;

    /// Opens a new connection to guest dockerd for a utility VM role.
    ///
    /// Single-VM connectors can ignore the role by using the default
    /// implementation. Dual-stack connectors should route `Native` to the HV
    /// utility VM and `Rosetta` to the VZ/Rosetta utility VM.
    fn connect_for(
        &self,
        _role: UtilityVmRole,
    ) -> Pin<Box<dyn Future<Output = Result<TokioIo<RawFdStream>>> + Send + '_>> {
        self.connect()
    }
}
