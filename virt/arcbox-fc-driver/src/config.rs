//! Node-wide Firecracker knobs: which binaries to run and how the VMM
//! process itself is configured.
//!
//! Nothing here is per-VM. What a VM is made of is the port's
//! [`VmSpec`](arcbox_vm_driver::VmSpec); how one VMM process is confined
//! (uid, gid, chroot base, namespaces) is its
//! [`IsolationSpec`](arcbox_vm_driver::IsolationSpec). This is what a
//! composition root reads from its own config file and hands to the
//! driver once.

use std::path::PathBuf;
use std::time::Duration;

/// How the driver runs Firecracker on this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcDriverConfig {
    /// The `firecracker` binary.
    pub firecracker_binary: PathBuf,
    /// The `jailer` binary; required for
    /// [`IsolationSpec::Jailer`](arcbox_vm_driver::IsolationSpec::Jailer),
    /// unused otherwise.
    pub jailer_binary: Option<PathBuf>,
    /// Firecracker's log level (`Error`, `Warning`, `Info`, `Debug`,
    /// `Trace`); Firecracker's own default when `None`.
    pub log_level: Option<String>,
    /// Disable seccomp filtering (reduces isolation; testing only).
    pub no_seccomp: bool,
    /// A custom seccomp filter BPF file.
    pub seccomp_filter: Option<PathBuf>,
    /// Maximum HTTP API payload size in bytes.
    pub http_api_max_payload_size: Option<usize>,
    /// MMDS in-memory store size limit in bytes.
    pub mmds_size_limit: Option<usize>,
    /// How long a spawn waits for the API socket to appear.
    pub socket_timeout: Duration,
    /// Jailer resource limits in `rlimit` form (`"fsize=2048"`), applied to
    /// every jailed VMM.
    pub resource_limits: Vec<String>,
}

impl FcDriverConfig {
    /// The socket wait a fresh config carries: five seconds, matching
    /// fc-sdk's own default so the boot handoff bound stays stable across
    /// SDK upgrades.
    pub const DEFAULT_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

    /// A config that runs `firecracker_binary` directly with Firecracker's
    /// defaults: no jailer, default log level, seccomp on, no API or MMDS
    /// size overrides, a five-second socket wait, no resource limits.
    pub fn new(firecracker_binary: impl Into<PathBuf>) -> Self {
        Self {
            firecracker_binary: firecracker_binary.into(),
            jailer_binary: None,
            log_level: None,
            no_seccomp: false,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout: Self::DEFAULT_SOCKET_TIMEOUT,
            resource_limits: Vec::new(),
        }
    }
}
