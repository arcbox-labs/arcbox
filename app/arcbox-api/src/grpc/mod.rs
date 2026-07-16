//! gRPC service implementations.
//!
//! This module implements the gRPC services defined in `arcbox-protocol`.
//! Core service types are imported from `arcbox_protocol::v1`, with the
//! corresponding service traits from `arcbox_grpc::v1`. Sandbox-related
//! APIs use `arcbox_protocol::sandbox_v1` and sandbox service traits
//! re-exported from `arcbox_grpc` (non-`v1`).

mod icon;
mod kubernetes;
mod machine;
#[cfg(target_os = "macos")]
mod macos;
mod sandbox;
mod snapshot;
mod stats;

pub use icon::IconServiceImpl;
pub use kubernetes::KubernetesServiceImpl;
pub use machine::MachineServiceImpl;
#[cfg(target_os = "macos")]
pub use macos::MacosServiceImpl;
pub use sandbox::SandboxServiceImpl;
pub use snapshot::SandboxSnapshotServiceImpl;
pub use stats::StatsServiceImpl;

use std::sync::{Arc, OnceLock};

use arcbox_core::Runtime;
use tonic::Status;

/// Drives a `!Send` macOS VM future to completion on a dedicated blocking thread.
///
/// Virtualization.framework operations hold ObjC handles (and the VM's dispatch
/// queue) across await and are not `Send`, but tonic requires handler futures to be
/// `Send`. Running the future via a transient current-thread runtime inside
/// `spawn_blocking` keeps that `!Send` state off the gRPC worker threads; the booted
/// VM (which is `Send + Sync`) outlives the transient runtime.
#[cfg(target_os = "macos")]
async fn run_macos_blocking<T, Fut, F>(f: F) -> Result<T, Status>
where
    T: Send + 'static,
    Fut: std::future::Future<Output = arcbox_core::Result<T>>,
    F: FnOnce() -> Fut + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Status::internal(format!("macOS runtime: {e}")))?
            .block_on(f())
            .map_err(|e| Status::internal(e.to_string()))
    })
    .await
    .map_err(|e| Status::internal(format!("macOS task join: {e}")))?
}

/// Shared handle to a runtime that may not be initialized yet.
///
/// Services are registered with tonic before the runtime exists.
/// Each RPC method calls `runtime.ready()` which returns `UNAVAILABLE`
/// while the daemon is still downloading assets / starting the VM.
pub type SharedRuntime = Arc<OnceLock<Arc<Runtime>>>;

/// Extension trait for obtaining the runtime from a deferred handle.
pub(crate) trait SharedRuntimeExt {
    /// Returns the runtime, or `UNAVAILABLE` if it hasn't been initialized yet.
    fn ready(&self) -> Result<&Arc<Runtime>, Status>;
}

impl SharedRuntimeExt for SharedRuntime {
    fn ready(&self) -> Result<&Arc<Runtime>, Status> {
        self.get()
            .ok_or_else(|| Status::unavailable("daemon is starting, runtime not ready yet"))
    }
}

/// Extension trait for extracting routing metadata from gRPC requests.
trait RequestExt {
    /// Returns the target machine name from the `x-machine` metadata header.
    fn machine_id(&self) -> Result<String, Status>;
}

impl<T> RequestExt for tonic::Request<T> {
    fn machine_id(&self) -> Result<String, Status> {
        match self.metadata().get("x-machine") {
            None => Err(Status::invalid_argument(
                "missing x-machine metadata header",
            )),
            Some(value) => match value.to_str() {
                Ok(s) => Ok(s.to_string()),
                Err(_) => Err(Status::invalid_argument(
                    "invalid x-machine metadata header: must be valid UTF-8",
                )),
            },
        }
    }
}
