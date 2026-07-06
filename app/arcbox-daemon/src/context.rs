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
use arcbox_constants::paths::{ArcboxProfile, HostLayout};
use tokio_util::sync::CancellationToken;

use crate::startup::DaemonLock;

/// Daemon lock shared between the startup pipeline and `main`.
///
/// Filled by the lease phase; kept alive by [`StartupHandles`] so the
/// flock survives the startup future being dropped on a signal.
pub type SharedDaemonLock = Arc<std::sync::OnceLock<Arc<DaemonLock>>>;

/// Handles created before the startup pipeline runs and shared with it.
///
/// A shutdown signal can arrive while the pipeline is still building the
/// daemon. `main` holds a clone so the interrupt path can reach whatever
/// the pipeline has published so far: the runtime (for a bounded stop of a
/// VM that keeps booting in its lifecycle tasks even after the startup
/// future is dropped), the cancellation token (for services that are
/// already running), and the daemon lock (dropping the startup future
/// would otherwise release the flock while this process still tears down
/// its VM, letting a concurrent daemon boot into the same resources).
#[derive(Clone)]
pub struct StartupHandles {
    pub shared_runtime: SharedRuntime,
    /// Filled right after runtime construction, before the VM boots.
    pub early_runtime: SharedRuntime,
    pub setup_state: Arc<SetupState>,
    pub shutdown: CancellationToken,
    /// Filled by the lease phase. Held here (not only in the pipeline's
    /// context) so the exclusive flock lives until process exit even when
    /// the startup future is cancelled mid-flight.
    pub daemon_lock: SharedDaemonLock,
}

impl StartupHandles {
    pub fn new(setup_state: Arc<SetupState>) -> Self {
        Self {
            shared_runtime: Arc::new(std::sync::OnceLock::new()),
            early_runtime: Arc::new(std::sync::OnceLock::new()),
            setup_state,
            shutdown: CancellationToken::new(),
            daemon_lock: Arc::new(std::sync::OnceLock::new()),
        }
    }
}

/// Pre-lock context produced by the startup pipeline.
///
/// Contains everything needed to start the gRPC SystemService (so
/// clients can observe progress), but the daemon lock has not been
/// acquired yet. Consumed by the daemon lease phase to produce a
/// [`DaemonContext`].
pub struct EarlyContext {
    pub profile: ArcboxProfile,
    pub layout: HostLayout,
    pub shared_runtime: SharedRuntime,
    /// Filled as soon as the runtime is constructed, before the VM boots.
    /// Diagnostics only (`GetVirtioDebug`) — a stuck boot must stay
    /// observable while `shared_runtime` is still empty.
    pub early_runtime: SharedRuntime,
    pub setup_state: Arc<SetupState>,
    pub shutdown: CancellationToken,
    /// Empty slot the lease phase publishes the acquired lock into.
    pub daemon_lock_slot: SharedDaemonLock,
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
    pub profile: ArcboxProfile,
    pub layout: HostLayout,
    /// Exclusive lock held for the daemon's lifetime.
    /// Held via RAII — the flock is released when the last clone drops;
    /// `StartupHandles` holds a sibling clone so a cancelled startup
    /// future cannot release it early.
    pub daemon_lock: Arc<DaemonLock>,
    /// Shared with gRPC services. Empty after `acquire_lock`, filled by `init_runtime`.
    pub shared_runtime: SharedRuntime,
    /// Filled by `init_runtime` right after runtime construction, before
    /// the VM boots. Diagnostics only (`GetVirtioDebug`).
    pub early_runtime: SharedRuntime,
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
    /// `--no-linux-vm`: forces `config.vm.autostart = false` in `init_runtime`.
    pub no_linux_vm: bool,
}

/// Handles to spawned services for drain-on-shutdown.
pub struct ServiceHandles {
    pub dns: tokio::task::JoinHandle<()>,
    /// Docker API server task; `None` in VM-host-only mode.
    pub docker: Option<tokio::task::JoinHandle<()>>,
    pub grpc: tokio::task::JoinHandle<()>,
    pub kubernetes_proxy: Option<tokio::task::JoinHandle<()>>,
}
