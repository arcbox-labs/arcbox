use crate::machine::{MachineInfo, MachineState};
use std::path::PathBuf;
use std::time::Duration;

use super::{
    DEFAULT_HEALTH_CHECK_INTERVAL_SECS, DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_RETRIES,
    DEFAULT_STARTUP_TIMEOUT_SECS,
};

/// Extended VM lifecycle state.
///
/// This extends the basic `MachineState` with additional states
/// for lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLifecycleState {
    /// VM does not exist yet.
    NotExist,
    /// VM is being created.
    Creating,
    /// VM created but not started.
    Created,
    /// VM is starting up.
    Starting,
    /// VM is running and agent is ready.
    Running,
    /// VM is idle (no recent activity).
    Idle,
    /// VM is stopping.
    Stopping,
    /// VM has stopped.
    Stopped,
    /// VM failed to start or crashed.
    Failed,
}

impl VmLifecycleState {
    /// Returns true if VM is in a state where it can accept commands.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Running | Self::Idle)
    }

    /// Returns true if VM needs to be started.
    #[must_use]
    pub const fn needs_start(&self) -> bool {
        matches!(
            self,
            Self::NotExist | Self::Created | Self::Stopped | Self::Failed
        )
    }

    /// Returns the state name for logging.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotExist => "not_exist",
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Idle => "idle",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}

impl From<MachineState> for VmLifecycleState {
    fn from(state: MachineState) -> Self {
        match state {
            MachineState::Created => Self::Created,
            MachineState::Starting => Self::Starting,
            MachineState::Running => Self::Running,
            MachineState::Stopping => Self::Stopping,
            MachineState::Stopped => Self::Stopped,
        }
    }
}

/// VM lifecycle configuration.
#[derive(Debug, Clone)]
pub struct VmLifecycleConfig {
    /// Enable auto-stop after idle timeout.
    pub auto_stop: bool,
    /// Idle timeout before entering idle state.
    pub idle_timeout: Duration,
    /// Startup timeout for VM boot.
    pub startup_timeout: Duration,
    /// Health check interval.
    pub health_check_interval: Duration,
    /// Maximum retry attempts for recovery.
    pub max_retries: u32,
    /// Default VM configuration.
    pub default_vm: DefaultVmConfig,
    /// Skip VM check (for testing only).
    /// When true, `ensure_ready()` returns immediately with a mock CID.
    pub skip_vm_check: bool,
    /// Guest docker API vsock port propagated via kernel cmdline.
    pub guest_docker_vsock_port: Option<u32>,
    /// macOS hypervisor backend this lifecycle's machine will use.
    ///
    /// Defaults to the System VM default ([`arcbox_vmm::VmBackend::default`],
    /// currently `Vz` — Apple-managed and stable). Switch to `Hv` (custom VMM
    /// + FEX) via the System VM backend control.
    pub backend: arcbox_vmm::VmBackend,
}

impl Default for VmLifecycleConfig {
    fn default() -> Self {
        Self {
            auto_stop: true,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            startup_timeout: Duration::from_secs(DEFAULT_STARTUP_TIMEOUT_SECS),
            health_check_interval: Duration::from_secs(DEFAULT_HEALTH_CHECK_INTERVAL_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            default_vm: DefaultVmConfig::default(),
            skip_vm_check: false,
            guest_docker_vsock_port: None,
            backend: arcbox_vmm::VmBackend::default(),
        }
    }
}

/// Default VM configuration.
#[derive(Debug, Clone)]
pub struct DefaultVmConfig {
    /// Number of vCPUs (default: host core count).
    pub cpus: u32,
    /// Memory in MB (default: half of host RAM, clamped to 512–16384).
    pub memory_mb: u64,
    /// Disk size in GB (default: 50).
    pub disk_gb: u64,
    /// Path to kernel image (if None, use `BootAssetProvider`).
    pub kernel: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Enable Rosetta for x86 emulation (Apple Silicon only).
    pub rosetta: bool,
}

impl Default for DefaultVmConfig {
    fn default() -> Self {
        Self {
            cpus: arcbox_hypervisor::default_vm_cpu_count(),
            memory_mb: arcbox_hypervisor::default_vm_memory_size() / (1024 * 1024),
            disk_gb: 50,
            kernel: None,
            cmdline: None,
            rosetta: cfg!(target_arch = "aarch64"),
        }
    }
}

/// Boot parameters for the default VM, resolved from config + boot assets.
///
/// Produced by [`VmLifecycleManager::resolve_desired_boot`] and consumed both
/// when creating the machine and when checking an existing machine for drift,
/// so the two paths can never disagree about the desired kernel/cmdline.
pub(super) struct DesiredBoot {
    /// Resolved kernel image path.
    pub(super) kernel: String,
    /// Final kernel command line (after quiet-strip, earlycon, and vsock port).
    pub(super) cmdline: String,
    /// EROFS rootfs image path (read-only vda).
    pub(super) rootfs_image: PathBuf,
}

/// Returns the first daemon-overridable field that differs between a persisted
/// machine and the desired default-VM config, or `None` if it is up to date.
///
/// Centralizing drift detection keeps every overridable field checked in one
/// place and in sync with what [`VmLifecycleManager::create_default_machine`]
/// produces: kernel and cmdline are compared against the same resolved
/// [`DesiredBoot`] the machine would be created with, so a change to `--kernel`
/// or any cmdline-injected override (e.g. the guest docker vsock port) forces a
/// recreate instead of silently reusing a stale VM.
pub(super) fn machine_drift_reason(
    persisted: &MachineInfo,
    want: &DefaultVmConfig,
    boot: &DesiredBoot,
) -> Option<&'static str> {
    if persisted.cpus != want.cpus {
        Some("cpus")
    } else if persisted.memory_mb != want.memory_mb {
        Some("memory_mb")
    } else if persisted.kernel.as_deref() != Some(boot.kernel.as_str()) {
        Some("kernel")
    } else if persisted.cmdline.as_deref() != Some(boot.cmdline.as_str()) {
        Some("cmdline")
    } else {
        None
    }
}
