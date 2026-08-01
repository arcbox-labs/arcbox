//! Sandbox gRPC service implementations.
//!
//! The proto is split along the control-plane / data-plane seam (CORE-57)
//! and these impls follow it one-to-one, so a cloud deployment can serve
//! them from different processes:
//!
//! - [`control`] — lifecycle, events, published ports (control plane)
//! - [`process`] — executions (data plane)
//! - [`filesystem`] — file transfer (data plane)
//!
//! Checkpoint/restore lives in the sibling `snapshot` module.
//!
//! All three route to the `arcbox-agent` in the target guest VM over the
//! port-1024 vsock binary-frame protocol; the shared helpers below are what
//! they have in common.

mod control;
mod filesystem;
mod process;

use std::time::Duration;

use arcbox_protocol::sandbox_v1::PortProtocol;
use tokio_stream::{Stream, StreamExt as _};
use tonic::Status;

pub use control::SandboxServiceImpl;
pub use filesystem::SandboxFilesystemServiceImpl;
pub use process::SandboxProcessServiceImpl;

/// Idle interval after which a server stream emits a keepalive frame, so
/// proxies and load balancers never see a silent connection (CORE-55).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Interleave keepalive items whenever `stream` stays idle for
/// [`KEEPALIVE_INTERVAL`].
fn with_keepalive<S, T>(stream: S, keepalive: fn() -> T) -> impl Stream<Item = Result<T, Status>>
where
    S: Stream<Item = Result<T, Status>>,
{
    stream
        .timeout(KEEPALIVE_INTERVAL)
        .map(move |item| item.unwrap_or_else(|_elapsed| Ok(keepalive())))
}

/// Map the public port protocol onto the host-side exposure key
/// (`UNSPECIFIED` defaults to TCP).
fn protocol_key(protocol: PortProtocol) -> &'static str {
    match protocol {
        PortProtocol::Udp => "udp",
        _ => "tcp",
    }
}

/// Map the public port protocol onto the host↔guest wire enum.
///
/// The vsock payloads carry their own protocol enum so the published
/// contract is never imported by the internal wire (CORE-57).
fn wire_protocol(protocol: PortProtocol) -> arcbox_protocol::v1::SandboxPortProtocol {
    match protocol {
        PortProtocol::Udp => arcbox_protocol::v1::SandboxPortProtocol::Udp,
        _ => arcbox_protocol::v1::SandboxPortProtocol::Tcp,
    }
}
