//! The daemon's API, served over Connect.
//!
//! One set of handlers answers Connect (HTTP POST, JSON or binary
//! protobuf), gRPC, and gRPC-Web on a single endpoint (CORE-53).
//!
//! The sandbox half keeps the control-plane / data-plane split the proto
//! draws (CORE-57), so a cloud deployment can serve the two from different
//! processes:
//!
//! - [`control`] — sandbox lifecycle, events, published ports
//! - [`process`] — executions (data plane)
//! - [`filesystem`] — file transfer (data plane)
//! - [`snapshot`] — checkpoint / restore
//!
//! The rest are the daemon's own services, migrating off tonic one at a
//! time (CORE-68): [`icon`], [`kubernetes`], [`machine`], [`migration`],
//! [`stats`], [`system`].
//!
//! Request and response types are buffa-generated (`arcbox-connect`)
//! because that is what `connectrpc` binds to, while the host↔guest vsock
//! payloads stay prost (`arcbox-protocol`); [`bridge`] is the crossing, and
//! its module docs explain why it is a decode rather than a conversion
//! table.

pub(crate) mod bridge;
mod control;
mod filesystem;
mod icon;
mod kubernetes;
mod machine;
#[cfg(target_os = "macos")]
mod macos;
mod migration;
mod process;
mod snapshot;
mod stats;
mod system;

use std::sync::Arc;
use std::time::Duration;

use std::sync::OnceLock;

use arcbox_core::Runtime;
use arcbox_core::vm_lifecycle::DEFAULT_MACHINE_NAME;
use connectrpc::{ConnectError, RequestContext};
use tokio_stream::{Stream, StreamExt as _};

pub use control::SandboxServiceImpl;
pub use filesystem::SandboxFilesystemServiceImpl;
pub use icon::IconServiceImpl;
pub use kubernetes::KubernetesServiceImpl;
pub use machine::MachineServiceImpl;
#[cfg(target_os = "macos")]
pub use macos::MacosServiceImpl;
pub use migration::MigrationServiceImpl;
pub use process::SandboxProcessServiceImpl;
pub use snapshot::SandboxSnapshotServiceImpl;
pub use stats::StatsServiceImpl;
pub use system::{SetupState, SystemServiceImpl};

/// Shared handle to a runtime that may not be initialized yet.
///
/// Services are registered before the runtime exists, so each RPC calls
/// `runtime.ready()`, which answers `Unavailable` while the daemon is still
/// downloading assets or starting the VM.
pub type SharedRuntime = Arc<OnceLock<Arc<Runtime>>>;

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

/// Drives a `!Send` macOS VM future to completion on a dedicated blocking
/// thread.
///
/// Virtualization.framework operations hold ObjC handles (and the VM's
/// dispatch queue) across await and are not `Send`, but handler futures must
/// be `Send` — that was true under tonic and is equally true under
/// connectrpc. Running the future via a transient current-thread runtime
/// inside `spawn_blocking` keeps that `!Send` state off the server's worker
/// threads; the booted VM (which is `Send + Sync`) outlives the transient
/// runtime.
#[cfg(target_os = "macos")]
pub(crate) async fn run_macos_blocking<T, Fut, F>(f: F) -> Result<T, ConnectError>
where
    T: Send + 'static,
    Fut: std::future::Future<Output = arcbox_core::Result<T>>,
    F: FnOnce() -> Fut + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ConnectError::internal(format!("macOS runtime: {e}")))?
            .block_on(f())
            .map_err(|e| ConnectError::internal(e.to_string()))
    })
    .await
    .map_err(|e| ConnectError::internal(format!("macOS task join: {e}")))?
}

/// Extension trait for obtaining the runtime from a deferred handle.
///
/// The message and the `Unavailable` code match what the tonic services
/// answered before CORE-68, so clients that predate the migration see the
/// same not-ready behaviour they always did.
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
fn protocol_key(protocol: arcbox_connect::sandbox_v1::PortProtocol) -> &'static str {
    use arcbox_connect::sandbox_v1::PortProtocol;
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
    protocol: arcbox_connect::sandbox_v1::PortProtocol,
) -> arcbox_connect::v1::SandboxPortProtocol {
    use arcbox_connect::sandbox_v1::PortProtocol;
    match protocol {
        PortProtocol::Udp => arcbox_connect::v1::SandboxPortProtocol::Udp,
        _ => arcbox_connect::v1::SandboxPortProtocol::Tcp,
    }
}

/// Registers every Connect-served service on one router.
///
/// Kept here rather than in the daemon so that adding a service is one edit
/// next to the impls, not a silent omission at the call site — and because
/// registration is what decides whether a path is served at all: the router
/// answers exactly what it was given, and an omission 404s at runtime.
#[must_use]
pub fn router(runtime: SharedRuntime) -> connectrpc::Router {
    let clone = || Arc::clone(&runtime);
    let router = connectrpc::Router::new()
        .add_service(Arc::new(SandboxServiceImpl::new(clone())))
        .add_service(Arc::new(SandboxProcessServiceImpl::new(clone())))
        .add_service(Arc::new(SandboxFilesystemServiceImpl::new(clone())))
        .add_service(Arc::new(SandboxSnapshotServiceImpl::new(clone())))
        // The daemon's own services, all on Connect since CORE-68.
        .add_service(Arc::new(IconServiceImpl::new()))
        .add_service(Arc::new(StatsServiceImpl::new(clone())))
        .add_service(Arc::new(KubernetesServiceImpl::new(clone())))
        .add_service(Arc::new(MigrationServiceImpl::new(clone())))
        .add_service(Arc::new(MachineServiceImpl::new(clone())));
    #[cfg(target_os = "macos")]
    let router = router.add_service(Arc::new(MacosServiceImpl::new(clone())));
    router
}

/// Registers the services plus the ones needing extra state the router
/// helper above cannot reach.
///
/// `SystemService` is separate because it also observes the setup state and
/// the early runtime handle — it must answer while `shared_runtime` is still
/// empty, which is the whole point of a diagnostics RPC.
#[must_use]
pub fn router_with_system(runtime: SharedRuntime, system: SystemServiceImpl) -> connectrpc::Router {
    router(runtime).add_service(Arc::new(system))
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
