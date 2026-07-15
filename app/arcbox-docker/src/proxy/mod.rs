//! Smart proxy for forwarding Docker API requests to guest dockerd.
//!
//! Provides HTTP/1.1 client over vsock to forward requests, with support
//! for streaming responses and HTTP upgrades (attach, exec, BuildKit).

mod connector;
mod fallback;
mod forward;
mod headers;
mod session;
mod state;
mod upgrade;
mod upload;
mod uri;

pub use connector::VsockConnector;
pub(crate) use fallback::invalidate_on_guest_error;
pub use fallback::proxy_fallback;
pub use forward::{proxy_to_guest_pooled, proxy_to_guest_stream_pooled};
pub use session::GuestHttpClient;
pub use state::{ActivityHook, ProxyState};
pub use upgrade::proxy_with_upgrade;
pub use upload::proxy_streaming_upload;

use crate::error::Result;
pub use arcbox_transport::vsock::{VsockShutdown, VsockStream};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Timeout for the HTTP/1.1 handshake with guest dockerd.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Abstraction over guest connection establishment.
///
/// Production code connects via vsock ([`VsockConnector`]); integration tests
/// can connect via Unix socket. Both produce a [`TokioIo<VsockStream>`]
/// because [`VsockStream`] wraps any pollable file descriptor.
pub trait GuestConnector: Send + Sync + 'static {
    /// Opens a new connection to guest dockerd.
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<TokioIo<VsockStream>>> + Send + '_>>;
}
