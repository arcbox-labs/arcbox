//! The sandbox API, served over Connect.
//!
//! These are the same four services the proto splits along the
//! control-plane / data-plane seam (CORE-57), but they are served through
//! `connectrpc` rather than tonic, so one set of handlers answers Connect
//! (HTTP POST, JSON or binary protobuf), gRPC, and gRPC-Web on a single
//! endpoint (CORE-53):
//!
//! - [`control`] — lifecycle, events, published ports (control plane)
//! - [`process`] — executions (data plane)
//! - [`filesystem`] — file transfer (data plane)
//! - [`snapshot`] — checkpoint / restore
//!
//! All four route to the `arcbox-agent` in the target guest VM over the
//! port-1024 vsock binary-frame protocol. Their request and response types
//! are buffa-generated (`arcbox-connect`) because that is what `connectrpc`
//! binds to, while the vsock payloads stay prost (`arcbox-protocol`);
//! [`bridge`] is the crossing, and its module docs explain why it is a
//! decode rather than a conversion table.

pub(crate) mod bridge;
mod control;
mod filesystem;
mod icon;
mod process;
mod snapshot;

use std::sync::Arc;
use std::time::Duration;

use arcbox_core::Runtime;
use arcbox_core::vm_lifecycle::DEFAULT_MACHINE_NAME;
use connectrpc::{ConnectError, RequestContext};
use tokio_stream::{Stream, StreamExt as _};

pub use control::SandboxServiceImpl;
pub use filesystem::SandboxFilesystemServiceImpl;
pub use icon::IconServiceImpl;
pub use process::SandboxProcessServiceImpl;
pub use snapshot::SandboxSnapshotServiceImpl;

use crate::grpc::SharedRuntime;

/// Idle interval after which a server stream emits a keepalive frame, so
/// proxies and load balancers never see a silent connection (CORE-55).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Interleave keepalive items whenever `stream` stays idle for
/// [`KEEPALIVE_INTERVAL`].
fn with_keepalive<S, T>(
    stream: S,
    keepalive: fn() -> T,
) -> impl Stream<Item = Result<T, ConnectError>>
where
    S: Stream<Item = Result<T, ConnectError>>,
{
    stream
        .timeout(KEEPALIVE_INTERVAL)
        .map(move |item| item.unwrap_or_else(|_elapsed| Ok(keepalive())))
}

/// Extension trait for obtaining the runtime from a deferred handle.
///
/// The gRPC services have the same need but answer with `tonic::Status`;
/// the message and the `UNAVAILABLE`/`Unavailable` code are deliberately
/// identical so a client sees one behaviour whichever surface it uses.
pub(crate) trait ConnectRuntimeExt {
    /// Returns the runtime, or `Unavailable` if it hasn't been initialized.
    fn ready(&self) -> Result<&Arc<Runtime>, ConnectError>;
}

impl ConnectRuntimeExt for SharedRuntime {
    fn ready(&self) -> Result<&Arc<Runtime>, ConnectError> {
        self.get()
            .ok_or_else(|| ConnectError::unavailable("daemon is starting, runtime not ready yet"))
    }
}

/// Extension trait for extracting routing metadata from a Connect request.
pub(crate) trait ContextExt {
    /// Returns the target machine name, defaulting to the System VM.
    fn machine_id(&self) -> Result<String, ConnectError>;
}

impl ContextExt for RequestContext {
    /// Reads the optional `x-machine` header.
    ///
    /// "Which local VM to target" is a host-local concept with no meaning in
    /// a multi-tenant cloud, so it is transport metadata a local client MAY
    /// set — never part of the product contract (CORE-54). Absent, requests
    /// go to the System VM, which is the only machine a sandbox client has.
    fn machine_id(&self) -> Result<String, ConnectError> {
        match self.header("x-machine") {
            None => Ok(DEFAULT_MACHINE_NAME.to_owned()),
            Some(value) => match value.to_str() {
                Ok("") => Ok(DEFAULT_MACHINE_NAME.to_owned()),
                Ok(s) => Ok(s.to_string()),
                Err(_) => Err(ConnectError::invalid_argument(
                    "invalid x-machine header: must be valid UTF-8",
                )),
            },
        }
    }
}

/// Map the public port protocol onto the host-side exposure key
/// (`UNSPECIFIED` defaults to TCP).
///
/// Takes the prost enum: handler bodies work in the internal representation
/// from [`bridge::wire_request`] onwards, so the public buffa twin never
/// reaches this far.
fn protocol_key(protocol: arcbox_protocol::sandbox_v1::PortProtocol) -> &'static str {
    use arcbox_protocol::sandbox_v1::PortProtocol;
    match protocol {
        PortProtocol::Udp => "udp",
        _ => "tcp",
    }
}

/// Map the public port protocol onto the host↔guest wire enum.
///
/// The vsock payloads carry their own protocol enum so the published
/// contract is never imported by the internal wire (CORE-57).
fn wire_protocol(
    protocol: arcbox_protocol::sandbox_v1::PortProtocol,
) -> arcbox_protocol::v1::SandboxPortProtocol {
    use arcbox_protocol::sandbox_v1::PortProtocol;
    match protocol {
        PortProtocol::Udp => arcbox_protocol::v1::SandboxPortProtocol::Udp,
        _ => arcbox_protocol::v1::SandboxPortProtocol::Tcp,
    }
}

/// Registers every sandbox service on a Connect router.
///
/// Kept here rather than in the daemon so that adding a fifth sandbox
/// service is one edit next to the impls, not a silent omission at the
/// call site.
#[must_use]
pub fn router(runtime: SharedRuntime) -> connectrpc::Router {
    connectrpc::Router::new()
        .add_service(Arc::new(SandboxServiceImpl::new(Arc::clone(&runtime))))
        .add_service(Arc::new(SandboxProcessServiceImpl::new(Arc::clone(
            &runtime,
        ))))
        .add_service(Arc::new(SandboxFilesystemServiceImpl::new(Arc::clone(
            &runtime,
        ))))
        .add_service(Arc::new(SandboxSnapshotServiceImpl::new(runtime)))
        // The daemon's own services migrate onto this router one at a time
        // (CORE-68); Icon is the first.
        .add_service(Arc::new(IconServiceImpl::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(header: Option<&str>) -> RequestContext {
        let mut headers = http::HeaderMap::new();
        if let Some(value) = header {
            headers.insert("x-machine", value.parse().expect("valid header value"));
        }
        RequestContext::new(headers)
    }

    /// `x-machine` is optional transport metadata (CORE-54): absent or
    /// empty must resolve to the System VM, not an error.
    #[test]
    fn machine_id_defaults_to_the_system_vm() {
        assert_eq!(
            ctx_with(None).machine_id().expect("absent header is valid"),
            DEFAULT_MACHINE_NAME
        );
        assert_eq!(
            ctx_with(Some(""))
                .machine_id()
                .expect("empty header is valid"),
            DEFAULT_MACHINE_NAME
        );
        assert_eq!(
            ctx_with(Some("other-vm"))
                .machine_id()
                .expect("explicit header is valid"),
            "other-vm"
        );
    }
}
