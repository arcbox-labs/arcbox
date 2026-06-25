//! Shared daemon state threaded through all lifecycle phases.
//!
//! The startup sequence produces progressively richer context types:
//!
//! ```text
//! Startup::prepare_host()          → EarlyContext   (no lock, no runtime)
//! Startup::acquire_daemon_lease()  → DaemonContext  (lock held, no runtime yet)
//! Startup::boot_runtime()          → Arc<Runtime>   (also fills SharedRuntime for gRPC)
//! ```
//!
//! This encoding makes it a compile error to access the daemon lock
//! before it has been acquired, or to skip the lock phase entirely.

use std::path::PathBuf;
use std::sync::Arc;

use arcbox_api::{SetupState, SharedRuntime};
use arcbox_constants::paths::HostLayout;
use tokio_util::sync::CancellationToken;

use crate::startup::DaemonLock;

/// Pre-lock context produced by the startup pipeline.
///
/// Contains everything needed to start the gRPC SystemService (so
/// clients can observe progress), but the daemon lock has not been
/// acquired yet. Consumed by the daemon lease phase to produce a
/// [`DaemonContext`].
pub struct EarlyContext {
    pub layout: HostLayout,
    pub shared_runtime: SharedRuntime,
    pub setup_state: Arc<SetupState>,
    pub shutdown: CancellationToken,
    pub dns_domain: String,
    pub dns_port: u16,
    pub docker_integration: bool,
    pub vm_args: VmArgs,
}

/// Daemon-wide context available after the exclusive lock is held.
///
/// `daemon_lock` is guaranteed to be valid — there is no construction
/// path that skips lock acquisition.
pub struct DaemonContext {
    pub layout: HostLayout,
    /// Exclusive lock held for the daemon's lifetime.
    /// Held via RAII — the flock is released when this value drops.
    #[allow(dead_code)] // held for drop semantics
    pub daemon_lock: DaemonLock,
    /// Shared with gRPC services. Empty after `acquire_lock`, filled by `init_runtime`.
    pub shared_runtime: SharedRuntime,
    pub setup_state: Arc<SetupState>,
    pub shutdown: CancellationToken,
    pub dns_domain: String,
    pub dns_port: u16,
    pub docker_integration: bool,
    pub vm_args: VmArgs,
}

/// VM-related CLI arguments, deferred until `init_runtime`.
pub struct VmArgs {
    pub guest_docker_vsock_port: Option<u32>,
    pub kernel: Option<PathBuf>,
}

/// Handles to spawned services for drain-on-shutdown.
pub struct ServiceHandles {
    pub dns: tokio::task::JoinHandle<()>,
    pub docker: tokio::task::JoinHandle<()>,
    pub grpc: tokio::task::JoinHandle<()>,
    pub kubernetes_proxy: Option<tokio::task::JoinHandle<()>>,
}
