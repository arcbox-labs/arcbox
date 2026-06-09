//! Automatic VM lifecycle management.
//!
//! This module provides transparent VM management for container operations.
//! Users never need to manually manage VMs - the lifecycle manager automatically
//! creates, starts, stops, and recovers VMs as needed.
//!
//! ## Design Goals
//!
//! - **Transparent**: Users only run `docker run`, VM is invisible
//! - **Eager**: Default VM boots during runtime initialization
//! - **Fast**: Cold start <1.5s, warm <500ms
//! - **Resilient**: Auto-recovery from crashes
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │              VmLifecycleManager                      │
//! │  ┌─────────────┐ ┌─────────────┐ ┌───────────────┐  │
//! │  │StateManager │ │HealthMonitor│ │BootAssetProv │  │
//! │  └─────────────┘ └─────────────┘ └───────────────┘  │
//! └─────────────────────────────────────────────────────┘
//!                        │
//!                        ▼
//!              ┌─────────────────┐
//!              │  MachineManager │
//!              └─────────────────┘
//! ```

mod health;
mod recovery;
#[cfg(target_os = "macos")]
mod serial;

use crate::boot_assets::BootAssetProvider;
use crate::error::{CoreError, Result};
use crate::event::{Event, EventBus};
use crate::machine::{MachineConfig, MachineInfo, MachineManager, MachineState};
use arcbox_constants::cmdline::GUEST_DOCKER_VSOCK_PORT_KEY;
use arcbox_error::CommonError;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

/// Default machine name used for container operations.
pub const DEFAULT_MACHINE_NAME: &str = "default";

/// Default startup timeout in seconds.
const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 30;

/// Default health check interval in seconds.
const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

/// Default idle timeout in seconds (5 minutes).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// Maximum retry attempts for recovery.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Minimum balloon target in MB when VM is idle.
/// Below this, the guest may become unstable.
const IDLE_BALLOON_TARGET_MB: u64 = 128;

/// Delay before shrinking balloon after entering idle state.
const BALLOON_SHRINK_DELAY_SECS: u64 = 10;

/// Persistent guest dockerd data image name.
const DOCKER_DATA_IMAGE_NAME: &str = "docker.img";
/// Persistent guest dockerd data image size (8 TiB sparse file).
///
/// This is the virtual size of the block device. The host file is sparse and
/// only consumes actual disk space for written blocks. 8 TiB matches OrbStack
/// and prevents users from hitting artificial limits.
const DOCKER_DATA_IMAGE_SIZE_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;

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

/// State transition events.
#[derive(Debug, Clone)]
pub enum VmEvent {
    /// Request to create VM.
    Create,
    /// VM creation completed.
    Created,
    /// Request to start VM.
    Start,
    /// Agent became ready.
    AgentReady,
    /// VM became idle (no activity for `idle_timeout`).
    IdleTimeout,
    /// Activity detected, exit idle state.
    Activity,
    /// Request to stop VM.
    Stop,
    /// VM stopped successfully.
    Stopped,
    /// Force stop VM.
    ForceStop,
    /// VM crashed or failed.
    Failure(String),
    /// Retry after failure.
    Retry,
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
    /// Defaults to `Hv` so the native utility VM keeps running on the
    /// custom HV-framework path. The rosetta utility VM overrides this
    /// to `Vz` so it can host the Rosetta share.
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
            backend: arcbox_vmm::VmBackend::Hv,
        }
    }
}

/// Default VM configuration.
#[derive(Debug, Clone)]
pub struct DefaultVmConfig {
    /// Number of vCPUs (default: host cores / 2, min: 2).
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
        let host_cpus = std::thread::available_parallelism().map_or(4, |n| n.get() as u32);

        Self {
            cpus: (host_cpus / 2).max(2),
            memory_mb: arcbox_hypervisor::default_vm_memory_size() / (1024 * 1024),
            disk_gb: 50,
            kernel: None,
            cmdline: None,
            rosetta: cfg!(target_arch = "aarch64"),
        }
    }
}

// Note: BootAssetProvider and BootAssets are now in crate::boot_assets module.

pub use health::HealthMonitor;
pub use recovery::{BackoffStrategy, RecoveryAction, RecoveryPolicy};

/// VM lifecycle manager.
///
/// Provides transparent VM management for container operations.
/// Users never need to manually manage VMs.
///
/// ## Usage
///
/// ```ignore
/// let manager = VmLifecycleManager::new(machine_manager, event_bus, data_dir, config)?;
///
/// // Ensure VM is ready before any container operation
/// let agent = manager.ensure_ready().await?;
///
/// // Use agent for container operations
/// agent.create_container(...).await?;
/// ```
pub struct VmLifecycleManager {
    /// Machine name this manager operates on. Set at construction time.
    /// Defaults to [`DEFAULT_MACHINE_NAME`] for the native utility VM;
    /// dual-VM setups override it (e.g. `"rosetta"`).
    machine_name: String,
    /// Filename used for this machine's persistent dockerd data image,
    /// relative to `<data_dir>/<DATA>/`. Defaults to `docker.img`; the
    /// rosetta lifecycle uses `docker-rosetta.img` to keep its image
    /// strictly separate.
    data_image_filename: String,
    /// Machine manager for VM operations.
    machine_manager: Arc<MachineManager>,
    /// Event bus.
    event_bus: EventBus,
    /// Current lifecycle state.
    state: RwLock<VmLifecycleState>,
    /// Health monitor.
    health_monitor: Arc<HealthMonitor>,
    /// Boot asset provider.
    boot_assets: Arc<BootAssetProvider>,
    /// Recovery policy.
    recovery: RecoveryPolicy,
    /// Configuration.
    config: VmLifecycleConfig,
    /// Data directory.
    data_dir: PathBuf,
    /// Mutex for serializing state transitions.
    transition_lock: Mutex<()>,
    /// Timestamp of last activity (epoch millis, for idle detection).
    last_activity_ms: AtomicU64,
    /// Whether balloon is currently shrunk for idle state.
    balloon_shrunk: std::sync::atomic::AtomicBool,
    /// Whether Kubernetes is holding the VM in the active state.
    kubernetes_hold: std::sync::atomic::AtomicBool,
}

impl VmLifecycleManager {
    fn ensure_sparse_block_image(path: &std::path::Path, size_bytes: u64) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CoreError::config(format!(
                    "failed to create block image directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        let file_exists = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| {
                CoreError::config(format!(
                    "failed to open block image '{}': {}",
                    path.display(),
                    e
                ))
            })?;

        let current_len = file.metadata().map_err(|e| {
            CoreError::config(format!(
                "failed to stat block image '{}': {}",
                path.display(),
                e
            ))
        })?;

        if current_len.len() < size_bytes {
            // Pre-allocate a bounded initial chunk on macOS (APFS) to reduce
            // double-CoW amplification (Btrfs CoW + APFS CoW) for the working
            // set. The full virtual size is set via `set_len` below, but we
            // never ask APFS to physically reserve all of it — at 8 TiB that
            // would either fail outright or, on a large disk, consume the
            // entire requested capacity. The bounded cap matches the previous
            // default working set and is best-effort; failures are ignored.
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::io::AsRawFd;
                /// Upper bound on initial APFS preallocation, in bytes.
                const APFS_PREALLOC_CAP_BYTES: u64 = 64 * 1024 * 1024 * 1024;
                let prealloc_target = size_bytes.min(APFS_PREALLOC_CAP_BYTES);
                if current_len.len() < prealloc_target {
                    let fd = file.as_raw_fd();
                    // fstore_t: fst_flags, fst_posmode, fst_offset, fst_length, fst_bytesalloc
                    #[repr(C)]
                    #[allow(clippy::struct_field_names)] // mirrors macOS fstore_t C struct
                    struct FStore {
                        fst_flags: u32,
                        fst_posmode: i32,
                        fst_offset: i64,
                        fst_length: i64,
                        fst_bytesalloc: i64,
                    }
                    const F_ALLOCATEALL: u32 = 0x00000004;
                    const F_PEOFPOSMODE: i32 = 3;
                    const F_PREALLOCATE: libc::c_int = 42;
                    let mut store = FStore {
                        fst_flags: F_ALLOCATEALL,
                        fst_posmode: F_PEOFPOSMODE,
                        fst_offset: 0,
                        #[allow(clippy::cast_possible_wrap)]
                        fst_length: prealloc_target as i64,
                        fst_bytesalloc: 0,
                    };
                    // Best-effort: if pre-allocation fails (e.g. not enough disk
                    // space), fall through to ftruncate which creates a sparse file.
                    let ret = unsafe { libc::fcntl(fd, F_PREALLOCATE, &mut store) };
                    if ret == 0 {
                        tracing::info!(
                            path = %path.display(),
                            allocated_bytes = store.fst_bytesalloc,
                            "pre-allocated docker data image (APFS)"
                        );
                    }
                }
            }

            file.set_len(size_bytes).map_err(|e| {
                CoreError::config(format!(
                    "failed to resize block image '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        }

        if !file_exists {
            tracing::info!(
                path = %path.display(),
                size_bytes,
                "created persistent docker data image"
            );
        }

        Ok(())
    }

    /// Creates a new VM lifecycle manager for the default native machine.
    pub fn new(
        machine_manager: Arc<MachineManager>,
        event_bus: EventBus,
        data_dir: PathBuf,
        config: VmLifecycleConfig,
    ) -> Result<Self> {
        Self::for_machine(
            String::from(DEFAULT_MACHINE_NAME),
            String::from(DOCKER_DATA_IMAGE_NAME),
            machine_manager,
            event_bus,
            data_dir,
            config,
        )
    }

    /// Creates a new VM lifecycle manager bound to a specific machine name
    /// and persistent data image. Used to build per-role lifecycles (e.g.
    /// the secondary VZ Rosetta VM) that must not share state with the
    /// default native machine.
    pub fn for_machine(
        machine_name: String,
        data_image_filename: String,
        machine_manager: Arc<MachineManager>,
        event_bus: EventBus,
        data_dir: PathBuf,
        config: VmLifecycleConfig,
    ) -> Result<Self> {
        let boot_assets = Arc::new(
            BootAssetProvider::new(data_dir.join("boot"))?
                .with_kernel(config.default_vm.kernel.clone().unwrap_or_default())?,
        );

        let health_monitor = Arc::new(HealthMonitor::new(
            config.health_check_interval,
            config.max_retries,
        ));

        let recovery = RecoveryPolicy::new(config.max_retries, BackoffStrategy::default());

        let initial_state = if let Some(info) = machine_manager.get(&machine_name) {
            VmLifecycleState::from(info.state)
        } else {
            VmLifecycleState::NotExist
        };

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(Self {
            machine_name,
            data_image_filename,
            machine_manager,
            event_bus,
            state: RwLock::new(initial_state),
            health_monitor,
            boot_assets,
            recovery,
            config,
            data_dir,
            transition_lock: Mutex::new(()),
            last_activity_ms: AtomicU64::new(now_ms),
            balloon_shrunk: std::sync::atomic::AtomicBool::new(false),
            kubernetes_hold: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Returns the machine name this lifecycle manager owns.
    #[must_use]
    pub fn machine_name(&self) -> &str {
        &self.machine_name
    }

    /// Returns the absolute path of this machine's persistent dockerd
    /// data image.
    #[must_use]
    pub fn data_image_path(&self) -> PathBuf {
        self.data_dir
            .join(arcbox_constants::paths::host::DATA)
            .join(&self.data_image_filename)
    }

    /// Returns the current lifecycle state.
    pub async fn state(&self) -> VmLifecycleState {
        *self.state.read().await
    }

    /// Returns true if the VM is running and ready.
    pub async fn is_running(&self) -> bool {
        self.state.read().await.is_ready()
    }

    /// Ensures a VM is ready for container operations.
    ///
    /// This is the main entry point for all container commands.
    /// It handles:
    /// - Creating VM if not exists
    /// - Starting VM if stopped
    /// - Waiting for agent ready
    /// - Health verification
    ///
    /// # Returns
    /// CID for agent communication.
    ///
    /// # Errors
    /// Returns an error if VM cannot be started or agent is not ready.
    pub async fn ensure_ready(&self) -> Result<u32> {
        self.ensure_ready_with_timeout(self.config.startup_timeout)
            .await
    }

    /// Ensures VM is ready with custom timeout.
    pub async fn ensure_ready_with_timeout(&self, timeout: Duration) -> Result<u32> {
        // Skip VM check for testing.
        if self.config.skip_vm_check {
            tracing::debug!("ensure_ready: skipping VM check (test mode)");
            // Register a mock machine so that container operations work.
            let mock_cid = 3;
            self.machine_manager
                .register_mock_machine(&self.machine_name, mock_cid)?;
            // Return a mock CID for testing.
            return Ok(mock_cid);
        }

        // Serialize state transitions
        let _lock = self.transition_lock.lock().await;

        let current_state = *self.state.read().await;

        tracing::debug!("ensure_ready: current state = {:?}", current_state);

        // If already running, just return CID
        if current_state.is_ready() {
            // Record activity timestamp.
            self.record_activity();

            // Exit idle state and restore balloon if shrunk.
            if current_state == VmLifecycleState::Idle {
                *self.state.write().await = VmLifecycleState::Running;
                self.restore_balloon();
            }

            return self.get_cid().await;
        }

        // Need to start VM
        if current_state.needs_start() {
            self.start_default_vm(timeout).await?;
        }

        // Wait for agent to be ready
        self.wait_for_agent(timeout).await?;

        // Reset recovery counter on success
        self.recovery.reset();
        self.health_monitor.reset();

        self.get_cid().await
    }

    /// Gets the CID for the default machine.
    async fn get_cid(&self) -> Result<u32> {
        self.machine_manager
            .get_cid(&self.machine_name)
            .ok_or_else(|| CoreError::Machine("default machine has no CID".to_string()))
    }

    /// Starts the default VM.
    async fn start_default_vm(&self, timeout: Duration) -> Result<()> {
        let current_state = *self.state.read().await;
        let existing_machine = self.machine_manager.get(&self.machine_name);
        let machine_exists = existing_machine.is_some();

        // Detect a stale persisted machine whose cpus/memory or kernel no
        // longer matches the desired default_vm config. The kernel comparison
        // is against the resolved desired kernel path — the custom `--kernel`
        // override if set, otherwise the versioned boot-asset cache path — not
        // merely the boot-asset version string. Comparing only the version
        // string let a `--kernel` override that kept the same boot-asset
        // version slip through, silently reusing the old VM with the stale
        // persisted kernel.
        let desired_kernel = self
            .boot_assets
            .config()
            .custom_kernel
            .clone()
            .unwrap_or_else(|| self.boot_assets.config().version_cache_dir().join("kernel"));
        let desired_kernel = desired_kernel.to_string_lossy();
        let config_drifted = existing_machine.as_ref().is_some_and(|m| {
            let hw_changed = m.cpus != self.config.default_vm.cpus
                || m.memory_mb != self.config.default_vm.memory_mb;
            let kernel_changed = m.kernel.as_deref() != Some(desired_kernel.as_ref());
            hw_changed || kernel_changed
        });

        if config_drifted {
            let m = existing_machine.as_ref().unwrap();
            tracing::warn!(
                persisted_cpus = m.cpus,
                persisted_memory = m.memory_mb,
                persisted_kernel = m.kernel.as_deref().unwrap_or("none"),
                desired_cpus = self.config.default_vm.cpus,
                desired_memory = self.config.default_vm.memory_mb,
                desired_kernel = %desired_kernel,
                "default machine config drifted from desired defaults; recreating"
            );
            let _ = self.machine_manager.remove(&self.machine_name, true);
        }

        // Recreate if state says "not exist", machine record is missing, or
        // the persisted config drifted from desired defaults.
        if current_state == VmLifecycleState::NotExist || !machine_exists || config_drifted {
            if current_state != VmLifecycleState::NotExist && !machine_exists {
                tracing::warn!(
                    state = current_state.as_str(),
                    "default machine missing while lifecycle state indicates existing VM; recreating"
                );
            }
            *self.state.write().await = VmLifecycleState::Creating;

            match self.create_default_machine().await {
                Ok(()) => {
                    *self.state.write().await = VmLifecycleState::Created;
                    self.event_bus.publish(Event::MachineCreated {
                        name: self.machine_name.clone(),
                    });
                }
                Err(e) => {
                    *self.state.write().await = VmLifecycleState::Failed;
                    return Err(e);
                }
            }
        }

        // Start VM
        *self.state.write().await = VmLifecycleState::Starting;

        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            match self.machine_manager.start(&self.machine_name).await {
                Ok(()) => {
                    tracing::info!("Default VM started successfully");
                    *self.state.write().await = VmLifecycleState::Running;
                    self.event_bus.publish(Event::MachineStarted {
                        name: self.machine_name.clone(),
                    });

                    // Install host route for container subnets via bridge NIC.
                    // Non-blocking: retries transient failures (helper not ready,
                    // bridge FDB not populated) but does not gate VM readiness.
                    #[cfg(all(target_os = "macos", feature = "vmnet"))]
                    if let Some(bridge) = self.machine_manager.vmnet_bridge_name(&self.machine_name)
                    {
                        // vmnet path: bridge name is known instantly, only need
                        // helper retry (1-2 attempts for XPC readiness).
                        drop(tokio::spawn(async move {
                            if let Err(e) =
                                crate::route_reconciler::ensure_route_for_bridge(&bridge).await
                            {
                                tracing::warn!(error = %e, "failed to install container route (vmnet)");
                            }
                        }));
                    }

                    #[cfg(all(target_os = "macos", not(feature = "vmnet")))]
                    if let Some(mac) = self.machine_manager.bridge_mac(&self.machine_name) {
                        // Non-vmnet path: scan kernel FDB to discover bridge
                        // (retries up to ~10s for FDB learning).
                        drop(tokio::spawn(async move {
                            if let Err(e) =
                                crate::route_reconciler::ensure_route_with_retry(&mac).await
                            {
                                tracing::warn!(error = %e, "failed to install container route");
                            }
                        }));
                    }

                    return Ok(());
                }
                Err(e) => {
                    if is_not_found_error(&e) {
                        tracing::warn!(
                            "default machine disappeared before start; recreating and retrying"
                        );
                        *self.state.write().await = VmLifecycleState::Creating;
                        match self.create_default_machine().await {
                            Ok(()) => {
                                *self.state.write().await = VmLifecycleState::Created;
                                self.event_bus.publish(Event::MachineCreated {
                                    name: self.machine_name.clone(),
                                });
                                continue;
                            }
                            Err(create_err) => {
                                *self.state.write().await = VmLifecycleState::Failed;
                                return Err(create_err);
                            }
                        }
                    }

                    tracing::warn!("Failed to start VM: {}", e);

                    // Check if we should retry.
                    // Avoid wrapping "VM error: ..." multiple times when propagating.
                    let recovery_error = match &e {
                        CoreError::Vm(msg) => msg.as_str(),
                        _ => &e.to_string(),
                    };
                    match self.recovery.handle_failure(recovery_error) {
                        RecoveryAction::RetryAfter(delay) => {
                            if tokio::time::Instant::now() + delay > deadline {
                                *self.state.write().await = VmLifecycleState::Failed;
                                return Err(CoreError::Vm(format!(
                                    "VM startup timeout after {} retries",
                                    self.recovery.retry_count()
                                )));
                            }

                            tracing::info!("Retrying VM start in {:?}", delay);
                            tokio::time::sleep(delay).await;
                        }
                        RecoveryAction::GiveUp(err) => {
                            *self.state.write().await = VmLifecycleState::Failed;
                            return Err(CoreError::Vm(err));
                        }
                    }
                }
            }
        }
    }

    /// Creates the default machine with EROFS rootfs and no initramfs.
    ///
    /// Block devices:
    /// - vda: rootfs.erofs (read-only)
    /// - vdb: docker-data.img (read-write)
    async fn create_default_machine(&self) -> Result<()> {
        let assets = self.boot_assets.get_assets().await?;
        let mut cmdline = self
            .config
            .default_vm
            .cmdline
            .clone()
            .unwrap_or(assets.cmdline);

        // Strip "quiet" so kernel boot messages are visible on the serial console.
        cmdline = cmdline
            .split_whitespace()
            .filter(|t| *t != "quiet")
            .collect::<Vec<_>>()
            .join(" ");

        // Ensure earlycon is present for early boot diagnostics via virtio console.
        if !cmdline
            .split_whitespace()
            .any(|t| t.starts_with("earlycon"))
        {
            cmdline.push_str(" earlycon");
        }

        // Inject guest docker vsock port if configured.
        if let Some(port) = self.config.guest_docker_vsock_port {
            if !cmdline
                .split_whitespace()
                .any(|token| token.starts_with(GUEST_DOCKER_VSOCK_PORT_KEY))
            {
                cmdline.push(' ');
                cmdline.push_str(GUEST_DOCKER_VSOCK_PORT_KEY);
                cmdline.push_str(&port.to_string());
            }
        }

        // Block devices: vda = EROFS rootfs (read-only), vdb = Docker data (read-write).
        let mut block_devices = vec![crate::vm::BlockDeviceConfig {
            path: assets.rootfs_image.to_string_lossy().to_string(),
            read_only: true,
        }];

        // Attach persistent Docker data disk.
        let docker_data_image = self.data_image_path();
        Self::ensure_sparse_block_image(&docker_data_image, DOCKER_DATA_IMAGE_SIZE_BYTES)?;

        // Don't inject docker_data_device into cmdline — let the agent
        // auto-detect. It prefers /dev/arcboxhvc1 (HVC fast path) when
        // available, falling back to /dev/vdb (VirtIO block).

        block_devices.push(crate::vm::BlockDeviceConfig {
            path: docker_data_image.to_string_lossy().to_string(),
            read_only: false,
        });

        let config = MachineConfig {
            name: self.machine_name.clone(),
            cpus: self.config.default_vm.cpus,
            memory_mb: self.config.default_vm.memory_mb,
            disk_gb: self.config.default_vm.disk_gb,
            kernel: Some(assets.kernel.to_string_lossy().to_string()),
            cmdline: Some(cmdline),
            block_devices,
            distro: None,
            distro_version: None,
            backend: self.config.backend,
            enable_rosetta: self.config.default_vm.rosetta,
        };

        tracing::info!(
            "Creating default machine: cpus={}, memory={}MB, kernel={}, rootfs={}",
            config.cpus,
            config.memory_mb,
            config.kernel.as_deref().unwrap_or("default"),
            assets.rootfs_image.display(),
        );

        self.machine_manager.create(config).await?;

        Ok(())
    }

    /// Waits for the agent to become ready.
    async fn wait_for_agent(&self, timeout: Duration) -> Result<()> {
        tracing::debug!("Waiting for agent to become ready...");

        let mm = Arc::clone(&self.machine_manager);
        let machine_name = self.machine_name.clone();

        // Run the entire probe loop on a blocking thread. On macOS HV backend,
        // the agent transport is AF_UNIX socketpair → BlockingVsockTransport.
        // Rapid connect/teardown of these fds stalls the tokio kqueue reactor's
        // timer wheel, so neither tokio::time::sleep nor tokio::time::timeout
        // can be used reliably inside this loop. spawn_blocking isolates the
        // probe from the async runtime entirely.
        let probe_result = tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + timeout;
            let poll_interval = Duration::from_millis(100);

            while std::time::Instant::now() < deadline {
                // Console output (best-effort, non-blocking).
                #[cfg(target_os = "macos")]
                if let Ok(output) = mm.read_console_output(&machine_name) {
                    let trimmed = output.trim_matches('\0');
                    if !trimmed.is_empty() {
                        tracing::info!("{}", trimmed.trim_end());
                    }
                }

                // connect_agent → AF_UNIX detected → BlockingVsockTransport.
                // ping_blocking uses libc::poll with 5s deadline — no tokio.
                match mm.connect_agent(&machine_name) {
                    Ok(mut agent) => match agent.ping_blocking() {
                        Ok(_) => return Ok(()),
                        Err(e) => tracing::debug!("Agent ping failed: {e}"),
                    },
                    Err(e) => tracing::debug!("Agent connection failed: {e}"),
                }

                std::thread::sleep(poll_interval);
            }

            Err(CoreError::Vm("timeout waiting for agent".to_string()))
        })
        .await
        .map_err(|e| CoreError::Vm(format!("probe task panicked: {e}")))?;

        probe_result?;

        // Back on async context — do async follow-up work.
        tracing::info!("Agent is ready");
        self.health_monitor.record_success();
        #[cfg(target_os = "macos")]
        {
            let mm = Arc::clone(&self.machine_manager);
            tokio::spawn(serial::serial_read_adaptive(mm));
        }

        Ok(())
    }

    /// Records activity, updating the last-activity timestamp.
    fn record_activity(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_activity_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Enables or disables the Kubernetes lifecycle hold.
    pub async fn set_kubernetes_hold(&self, active: bool) {
        self.kubernetes_hold.store(active, Ordering::Relaxed);
        self.record_activity();

        if active {
            self.restore_balloon();
            let mut state = self.state.write().await;
            if *state == VmLifecycleState::Idle {
                *state = VmLifecycleState::Running;
            }
        }
    }

    /// Returns seconds since last activity.
    fn idle_seconds(&self) -> u64 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(last) / 1000
    }

    /// Shrinks the balloon to reclaim guest memory during idle.
    ///
    /// Sets the balloon target to `IDLE_BALLOON_TARGET_MB` so the guest
    /// returns memory to the host, reducing idle footprint.
    #[cfg(target_os = "macos")]
    fn shrink_balloon(&self) {
        if self.balloon_shrunk.load(Ordering::Relaxed) {
            return;
        }

        let target_bytes = IDLE_BALLOON_TARGET_MB * 1024 * 1024;
        if let Some(info) = self.machine_manager.get(&self.machine_name) {
            match self
                .machine_manager
                .vm_manager()
                .set_balloon_target(&info.vm_id, target_bytes)
            {
                Ok(()) => {
                    self.balloon_shrunk.store(true, Ordering::Relaxed);
                    tracing::info!("Balloon shrunk to {}MB for idle VM", IDLE_BALLOON_TARGET_MB);
                }
                Err(e) => {
                    tracing::debug!("Failed to shrink balloon: {}", e);
                }
            }
        }
    }

    /// Restores the balloon to the full configured memory size.
    ///
    /// Called when the VM exits idle state (new container activity).
    #[cfg(target_os = "macos")]
    fn restore_balloon(&self) {
        if !self.balloon_shrunk.load(Ordering::Relaxed) {
            return;
        }

        if let Some(info) = self.machine_manager.get(&self.machine_name) {
            let full_bytes = info.memory_mb * 1024 * 1024;
            match self
                .machine_manager
                .vm_manager()
                .set_balloon_target(&info.vm_id, full_bytes)
            {
                Ok(()) => {
                    self.balloon_shrunk.store(false, Ordering::Relaxed);
                    tracing::info!("Balloon restored to {}MB", info.memory_mb);
                }
                Err(e) => {
                    tracing::debug!("Failed to restore balloon: {}", e);
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn shrink_balloon(&self) {}

    #[cfg(not(target_os = "macos"))]
    fn restore_balloon(&self) {}

    /// Starts the idle monitor background task.
    ///
    /// This task periodically checks if the VM has been idle for longer than
    /// `idle_timeout` and transitions to Idle state, shrinking the balloon.
    pub fn start_idle_monitor(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let idle_timeout = this.config.idle_timeout;
        let shutdown = this.health_monitor.shutdown_token();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(BALLOON_SHRINK_DELAY_SECS);
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(check_interval) => {}
                }

                let state = *this.state.read().await;
                if state != VmLifecycleState::Running {
                    continue;
                }

                let idle_secs = this.idle_seconds();
                if this.kubernetes_hold.load(Ordering::Relaxed) {
                    continue;
                }
                if idle_secs >= idle_timeout.as_secs() {
                    *this.state.write().await = VmLifecycleState::Idle;
                    this.shrink_balloon();
                    tracing::info!("VM entered idle state after {}s of inactivity", idle_secs);
                    this.event_bus.publish(Event::MachineIdle {
                        name: this.machine_name.clone(),
                    });
                }
            }
        });
    }

    /// Gracefully stops the VM.
    ///
    /// # Errors
    /// Returns an error if the VM cannot be stopped.
    pub async fn shutdown(&self) -> Result<()> {
        let _lock = self.transition_lock.lock().await;

        let current_state = *self.state.read().await;

        if !current_state.is_ready() && current_state != VmLifecycleState::Starting {
            // VM is not running, nothing to do
            return Ok(());
        }

        *self.state.write().await = VmLifecycleState::Stopping;

        // Stop health monitor
        self.health_monitor.stop();

        // Stop the machine (graceful first, then force-stop fallback).
        let stop_result = match self.machine_manager.graceful_stop(
            DEFAULT_MACHINE_NAME,
            Duration::from_secs(arcbox_constants::timeouts::HOST_SHUTDOWN_TIMEOUT_SECS),
        ) {
            Ok(true) => Ok(()),
            Ok(false) => {
                tracing::warn!(
                    "Graceful stop timed out for '{}', falling back to force stop",
                    DEFAULT_MACHINE_NAME
                );
                self.machine_manager.stop(&self.machine_name)
            }
            Err(e) => {
                tracing::warn!(
                    "Graceful stop failed for '{}': {}, falling back to force stop",
                    DEFAULT_MACHINE_NAME,
                    e
                );
                self.machine_manager.stop(&self.machine_name)
            }
        };

        match stop_result {
            Ok(()) => {
                *self.state.write().await = VmLifecycleState::Stopped;
                tracing::info!("Default VM stopped");
                self.event_bus.publish(Event::MachineStopped {
                    name: self.machine_name.clone(),
                });
                Ok(())
            }
            Err(e) => {
                *self.state.write().await = VmLifecycleState::Failed;
                Err(e)
            }
        }
    }

    /// Forces VM termination.
    ///
    /// Does not take `transition_lock` — force stop must succeed even when
    /// a graceful shutdown holds the lock (blocked in a sync VM stop call).
    ///
    /// # Errors
    /// Returns an error if the VM cannot be terminated.
    pub async fn force_stop(&self) -> Result<()> {
        self.health_monitor.stop();

        let _ = self.machine_manager.remove(&self.machine_name, true);

        *self.state.write().await = VmLifecycleState::NotExist;
        self.event_bus.publish(Event::MachineStopped {
            name: self.machine_name.clone(),
        });

        Ok(())
    }

    /// Returns the configuration.
    pub const fn config(&self) -> &VmLifecycleConfig {
        &self.config
    }

    /// Returns the boot asset provider.
    pub const fn boot_assets(&self) -> &Arc<BootAssetProvider> {
        &self.boot_assets
    }

    /// Returns the resolved default VM configuration used by lifecycle.
    #[must_use]
    pub fn default_vm_config(&self) -> DefaultVmConfig {
        self.config.default_vm.clone()
    }

    /// Returns the health monitor.
    pub const fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health_monitor
    }

    /// Returns the machine info for the default machine.
    pub fn default_machine_info(&self) -> Option<MachineInfo> {
        self.machine_manager.get(&self.machine_name)
    }
}

const fn is_not_found_error(err: &CoreError) -> bool {
    matches!(err, CoreError::Common(CommonError::NotFound(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_state_is_ready() {
        assert!(!VmLifecycleState::NotExist.is_ready());
        assert!(!VmLifecycleState::Creating.is_ready());
        assert!(!VmLifecycleState::Created.is_ready());
        assert!(!VmLifecycleState::Starting.is_ready());
        assert!(VmLifecycleState::Running.is_ready());
        assert!(VmLifecycleState::Idle.is_ready());
        assert!(!VmLifecycleState::Stopping.is_ready());
        assert!(!VmLifecycleState::Stopped.is_ready());
        assert!(!VmLifecycleState::Failed.is_ready());
    }

    #[test]
    fn test_lifecycle_state_needs_start() {
        assert!(VmLifecycleState::NotExist.needs_start());
        assert!(!VmLifecycleState::Creating.needs_start());
        assert!(VmLifecycleState::Created.needs_start());
        assert!(!VmLifecycleState::Starting.needs_start());
        assert!(!VmLifecycleState::Running.needs_start());
        assert!(!VmLifecycleState::Idle.needs_start());
        assert!(!VmLifecycleState::Stopping.needs_start());
        assert!(VmLifecycleState::Stopped.needs_start());
        assert!(VmLifecycleState::Failed.needs_start());
    }

    #[test]
    fn test_default_config() {
        let config = VmLifecycleConfig::default();
        assert!(config.auto_stop);
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn test_default_vm_config() {
        let config = DefaultVmConfig::default();
        assert!(config.cpus >= 2);
        // Default memory is half of host RAM, clamped to [512, 16384] MB.
        let expected_mb = arcbox_hypervisor::default_vm_memory_size() / (1024 * 1024);
        assert_eq!(config.memory_mb, expected_mb);
        assert!(config.memory_mb >= 512);
        assert!(config.memory_mb <= 16384);
        assert_eq!(config.disk_gb, 50);
    }
}
