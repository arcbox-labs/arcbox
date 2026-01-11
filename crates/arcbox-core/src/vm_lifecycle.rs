//! Automatic VM lifecycle management.
//!
//! This module provides transparent VM management for container operations.
//! Users never need to manually manage VMs - the lifecycle manager automatically
//! creates, starts, stops, and recovers VMs as needed.
//!
//! ## Design Goals
//!
//! - **Transparent**: Users only run `docker run`, VM is invisible
//! - **Lazy**: VM starts on first container command, not daemon startup
//! - **Fast**: Cold start <1.5s, warm <50ms
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

use crate::boot_assets::{BootAssetConfig, BootAssetProvider, BootAssets};
use crate::error::{CoreError, Result};
use crate::machine::{MachineConfig, MachineInfo, MachineManager, MachineState};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

// =============================================================================
// Constants
// =============================================================================

/// Default machine name used for container operations.
pub const DEFAULT_MACHINE_NAME: &str = "default";

/// Default agent port for vsock communication.
pub const DEFAULT_AGENT_PORT: u32 = 1024;

/// Default startup timeout in seconds.
const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 30;

/// Default health check interval in seconds.
const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

/// Default idle timeout in seconds (5 minutes).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// Maximum retry attempts for recovery.
const DEFAULT_MAX_RETRIES: u32 = 3;

// =============================================================================
// VM Lifecycle State
// =============================================================================

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
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Running | Self::Idle)
    }

    /// Returns true if VM needs to be started.
    #[must_use]
    pub fn needs_start(&self) -> bool {
        matches!(self, Self::NotExist | Self::Created | Self::Stopped | Self::Failed)
    }

    /// Returns the state name for logging.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
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
    /// VM became idle (no activity for idle_timeout).
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

// =============================================================================
// Configuration
// =============================================================================

/// VM lifecycle configuration.
#[derive(Debug, Clone)]
pub struct VmLifecycleConfig {
    /// Enable auto-start on first container command.
    pub auto_start: bool,
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
}

impl Default for VmLifecycleConfig {
    fn default() -> Self {
        Self {
            auto_start: true,
            auto_stop: true,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            startup_timeout: Duration::from_secs(DEFAULT_STARTUP_TIMEOUT_SECS),
            health_check_interval: Duration::from_secs(DEFAULT_HEALTH_CHECK_INTERVAL_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            default_vm: DefaultVmConfig::default(),
        }
    }
}

/// Default VM configuration.
#[derive(Debug, Clone)]
pub struct DefaultVmConfig {
    /// Number of vCPUs (default: host cores / 2, min: 2).
    pub cpus: u32,
    /// Memory in MB (default: 2048).
    pub memory_mb: u64,
    /// Disk size in GB (default: 50).
    pub disk_gb: u64,
    /// Path to kernel image (if None, use BootAssetProvider).
    pub kernel: Option<PathBuf>,
    /// Path to initramfs (if None, use BootAssetProvider).
    pub initramfs: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Enable Rosetta for x86 emulation (Apple Silicon only).
    pub rosetta: bool,
}

impl Default for DefaultVmConfig {
    fn default() -> Self {
        let host_cpus = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(4);

        Self {
            cpus: (host_cpus / 2).max(2),
            memory_mb: 2048,
            disk_gb: 50,
            kernel: None,
            initramfs: None,
            cmdline: None,
            rosetta: cfg!(target_arch = "aarch64"),
        }
    }
}

// Note: BootAssetProvider and BootAssets are now in crate::boot_assets module.

// =============================================================================
// Health Monitor
// =============================================================================

/// Health monitor for VM.
///
/// Continuously monitors VM health via agent ping.
/// Reports failures after consecutive failures exceed threshold.
pub struct HealthMonitor {
    /// Health check interval.
    interval: Duration,
    /// Maximum consecutive failures before reporting unhealthy.
    max_failures: u32,
    /// Current failure count.
    failures: AtomicU32,
    /// Shutdown signal.
    shutdown: CancellationToken,
}

impl HealthMonitor {
    /// Creates a new health monitor.
    pub fn new(interval: Duration, max_failures: u32) -> Self {
        Self {
            interval,
            max_failures,
            failures: AtomicU32::new(0),
            shutdown: CancellationToken::new(),
        }
    }

    /// Returns the shutdown token for stopping the monitor.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Resets the failure counter.
    pub fn reset(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    /// Returns true if the VM is considered healthy.
    pub fn is_healthy(&self) -> bool {
        self.failures.load(Ordering::SeqCst) < self.max_failures
    }

    /// Records a successful health check.
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    /// Records a failed health check.
    ///
    /// Returns true if the failure threshold has been exceeded.
    pub fn record_failure(&self) -> bool {
        let failures = self.failures.fetch_add(1, Ordering::SeqCst) + 1;
        failures >= self.max_failures
    }

    /// Stops the health monitor.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }
}

// =============================================================================
// Recovery Policy
// =============================================================================

/// Backoff strategy for recovery retries.
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Fixed delay between retries.
    Fixed(Duration),
    /// Exponential backoff with maximum.
    Exponential {
        /// Initial delay.
        initial: Duration,
        /// Maximum delay.
        max: Duration,
    },
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self::Exponential {
            initial: Duration::from_millis(500),
            max: Duration::from_secs(10),
        }
    }
}

/// Recovery action after failure.
#[derive(Debug)]
pub enum RecoveryAction {
    /// Retry after the specified delay.
    RetryAfter(Duration),
    /// Give up and report the error.
    GiveUp(String),
}

/// Recovery policy for VM failures.
pub struct RecoveryPolicy {
    /// Maximum retry attempts.
    max_retries: u32,
    /// Backoff strategy.
    backoff: BackoffStrategy,
    /// Current retry count.
    retries: AtomicU32,
}

impl RecoveryPolicy {
    /// Creates a new recovery policy.
    pub fn new(max_retries: u32, backoff: BackoffStrategy) -> Self {
        Self {
            max_retries,
            backoff,
            retries: AtomicU32::new(0),
        }
    }

    /// Handles a failure and returns the recovery action.
    pub fn handle_failure(&self, error: &str) -> RecoveryAction {
        let retries = self.retries.fetch_add(1, Ordering::SeqCst);

        if retries >= self.max_retries {
            return RecoveryAction::GiveUp(error.to_string());
        }

        let delay = match &self.backoff {
            BackoffStrategy::Fixed(d) => *d,
            BackoffStrategy::Exponential { initial, max } => {
                let delay = *initial * 2u32.pow(retries);
                delay.min(*max)
            }
        };

        RecoveryAction::RetryAfter(delay)
    }

    /// Resets the retry counter.
    pub fn reset(&self) {
        self.retries.store(0, Ordering::SeqCst);
    }

    /// Returns the current retry count.
    pub fn retry_count(&self) -> u32 {
        self.retries.load(Ordering::SeqCst)
    }
}

// =============================================================================
// VM Lifecycle Manager
// =============================================================================

/// VM lifecycle manager.
///
/// Provides transparent VM management for container operations.
/// Users never need to manually manage VMs.
///
/// ## Usage
///
/// ```ignore
/// let manager = VmLifecycleManager::new(machine_manager, config);
///
/// // Ensure VM is ready before any container operation
/// let agent = manager.ensure_ready().await?;
///
/// // Use agent for container operations
/// agent.create_container(...).await?;
/// ```
pub struct VmLifecycleManager {
    /// Machine manager for VM operations.
    machine_manager: Arc<MachineManager>,
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
}

impl VmLifecycleManager {
    /// Creates a new VM lifecycle manager.
    pub fn new(
        machine_manager: Arc<MachineManager>,
        data_dir: PathBuf,
        config: VmLifecycleConfig,
    ) -> Self {
        let boot_assets = Arc::new(
            BootAssetProvider::new(data_dir.join("boot"))
                .with_kernel(config.default_vm.kernel.clone().unwrap_or_default())
                .with_initramfs(config.default_vm.initramfs.clone().unwrap_or_default()),
        );

        let health_monitor = Arc::new(HealthMonitor::new(
            config.health_check_interval,
            config.max_retries,
        ));

        let recovery = RecoveryPolicy::new(config.max_retries, BackoffStrategy::default());

        // Check if default machine already exists
        let initial_state = if machine_manager.get(DEFAULT_MACHINE_NAME).is_some() {
            let info = machine_manager.get(DEFAULT_MACHINE_NAME).unwrap();
            VmLifecycleState::from(info.state)
        } else {
            VmLifecycleState::NotExist
        };

        Self {
            machine_manager,
            state: RwLock::new(initial_state),
            health_monitor,
            boot_assets,
            recovery,
            config,
            data_dir,
            transition_lock: Mutex::new(()),
        }
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
        // Serialize state transitions
        let _lock = self.transition_lock.lock().await;

        let current_state = *self.state.read().await;

        tracing::debug!("ensure_ready: current state = {:?}", current_state);

        // If already running, just return CID
        if current_state.is_ready() {
            // Record activity to exit idle state
            if current_state == VmLifecycleState::Idle {
                *self.state.write().await = VmLifecycleState::Running;
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
            .get_cid(DEFAULT_MACHINE_NAME)
            .ok_or_else(|| CoreError::Machine("default machine has no CID".to_string()))
    }

    /// Starts the default VM.
    async fn start_default_vm(&self, timeout: Duration) -> Result<()> {
        let current_state = *self.state.read().await;

        // Create VM if not exists
        if current_state == VmLifecycleState::NotExist {
            *self.state.write().await = VmLifecycleState::Creating;

            match self.create_default_machine().await {
                Ok(()) => {
                    *self.state.write().await = VmLifecycleState::Created;
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
            match self.machine_manager.start(DEFAULT_MACHINE_NAME) {
                Ok(()) => {
                    tracing::info!("Default VM started successfully");
                    *self.state.write().await = VmLifecycleState::Running;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Failed to start VM: {}", e);

                    // Check if we should retry
                    match self.recovery.handle_failure(&e.to_string()) {
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

    /// Creates the default machine with configured settings.
    async fn create_default_machine(&self) -> Result<()> {
        // Get boot assets
        let assets = self.boot_assets.get_assets().await?;

        let config = MachineConfig {
            name: DEFAULT_MACHINE_NAME.to_string(),
            cpus: self.config.default_vm.cpus,
            memory_mb: self.config.default_vm.memory_mb,
            disk_gb: self.config.default_vm.disk_gb,
            kernel: Some(assets.kernel.to_string_lossy().to_string()),
            initrd: Some(assets.initramfs.to_string_lossy().to_string()),
            cmdline: self.config.default_vm.cmdline.clone().or(Some(assets.cmdline)),
        };

        tracing::info!(
            "Creating default machine: cpus={}, memory={}MB, kernel={}",
            config.cpus,
            config.memory_mb,
            config.kernel.as_deref().unwrap_or("default")
        );

        self.machine_manager.create(config)?;

        Ok(())
    }

    /// Waits for the agent to become ready.
    async fn wait_for_agent(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        let poll_interval = Duration::from_millis(100);

        tracing::debug!("Waiting for agent to become ready...");

        while tokio::time::Instant::now() < deadline {
            #[cfg(target_os = "macos")]
            if std::env::var("ARCBOX_ENABLE_CONSOLE").as_deref() == Ok("1") {
                match self
                    .machine_manager
                    .read_console_output(DEFAULT_MACHINE_NAME)
                {
                    Ok(output) => {
                        let trimmed = output.trim_matches('\0');
                        if !trimmed.is_empty() {
                            tracing::info!("Guest console: {}", trimmed.trim_end());
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Console read failed: {}", e);
                    }
                }
            }

            // Try to connect to agent
            match self.machine_manager.connect_agent(DEFAULT_MACHINE_NAME) {
                Ok(mut agent) => {
                    // Try to ping agent
                    match agent.ping().await {
                        Ok(_response) => {
                            tracing::info!("Agent is ready");
                            self.health_monitor.record_success();
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::debug!("Agent ping failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Agent connection failed: {}", e);
                }
            }

            tokio::time::sleep(poll_interval).await;
        }

        Err(CoreError::Vm("timeout waiting for agent".to_string()))
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

        // Stop the machine
        match self.machine_manager.stop(DEFAULT_MACHINE_NAME) {
            Ok(()) => {
                *self.state.write().await = VmLifecycleState::Stopped;
                tracing::info!("Default VM stopped");
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
    /// # Errors
    /// Returns an error if the VM cannot be terminated.
    pub async fn force_stop(&self) -> Result<()> {
        let _lock = self.transition_lock.lock().await;

        // Stop health monitor
        self.health_monitor.stop();

        // Force stop by removing and recreating
        let _ = self.machine_manager.remove(DEFAULT_MACHINE_NAME, true);

        *self.state.write().await = VmLifecycleState::NotExist;

        Ok(())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &VmLifecycleConfig {
        &self.config
    }

    /// Returns the boot asset provider.
    pub fn boot_assets(&self) -> &Arc<BootAssetProvider> {
        &self.boot_assets
    }

    /// Returns the health monitor.
    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health_monitor
    }

    /// Returns the machine info for the default machine.
    pub fn default_machine_info(&self) -> Option<MachineInfo> {
        self.machine_manager.get(DEFAULT_MACHINE_NAME)
    }
}

// =============================================================================
// Tests
// =============================================================================

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
        assert!(config.auto_start);
        assert!(config.auto_stop);
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn test_default_vm_config() {
        let config = DefaultVmConfig::default();
        assert!(config.cpus >= 2);
        assert_eq!(config.memory_mb, 2048);
        assert_eq!(config.disk_gb, 50);
    }

    #[test]
    fn test_recovery_policy_fixed_backoff() {
        let policy = RecoveryPolicy::new(3, BackoffStrategy::Fixed(Duration::from_millis(100)));

        // First failure: retry
        match policy.handle_failure("test error") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            _ => panic!("expected RetryAfter"),
        }

        // Second failure: retry
        match policy.handle_failure("test error") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            _ => panic!("expected RetryAfter"),
        }

        // Third failure: retry
        match policy.handle_failure("test error") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            _ => panic!("expected RetryAfter"),
        }

        // Fourth failure: give up
        match policy.handle_failure("test error") {
            RecoveryAction::GiveUp(_) => {}
            _ => panic!("expected GiveUp"),
        }
    }

    #[test]
    fn test_recovery_policy_exponential_backoff() {
        let policy = RecoveryPolicy::new(
            5,
            BackoffStrategy::Exponential {
                initial: Duration::from_millis(100),
                max: Duration::from_secs(1),
            },
        );

        // First failure: 100ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(100)),
            _ => panic!("expected RetryAfter"),
        }

        // Second failure: 200ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(200)),
            _ => panic!("expected RetryAfter"),
        }

        // Third failure: 400ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(400)),
            _ => panic!("expected RetryAfter"),
        }

        // Fourth failure: 800ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_millis(800)),
            _ => panic!("expected RetryAfter"),
        }

        // Fifth failure: capped at 1000ms
        match policy.handle_failure("test") {
            RecoveryAction::RetryAfter(d) => assert_eq!(d, Duration::from_secs(1)),
            _ => panic!("expected RetryAfter"),
        }

        // Sixth failure: give up
        match policy.handle_failure("test") {
            RecoveryAction::GiveUp(_) => {}
            _ => panic!("expected GiveUp"),
        }
    }

    #[test]
    fn test_recovery_policy_reset() {
        let policy = RecoveryPolicy::new(2, BackoffStrategy::Fixed(Duration::from_millis(100)));

        // First failure
        let _ = policy.handle_failure("test");
        assert_eq!(policy.retry_count(), 1);

        // Reset
        policy.reset();
        assert_eq!(policy.retry_count(), 0);
    }

    #[test]
    fn test_health_monitor() {
        let monitor = HealthMonitor::new(Duration::from_secs(5), 3);

        assert!(monitor.is_healthy());

        // First failure
        assert!(!monitor.record_failure());
        assert!(monitor.is_healthy());

        // Second failure
        assert!(!monitor.record_failure());
        assert!(monitor.is_healthy());

        // Third failure - threshold exceeded
        assert!(monitor.record_failure());
        assert!(!monitor.is_healthy());

        // Reset
        monitor.reset();
        assert!(monitor.is_healthy());
    }

    #[test]
    fn test_health_monitor_success_resets() {
        let monitor = HealthMonitor::new(Duration::from_secs(5), 3);

        // Two failures
        monitor.record_failure();
        monitor.record_failure();

        // Success resets
        monitor.record_success();
        assert!(monitor.is_healthy());

        // Need 3 more failures to exceed threshold
        assert!(!monitor.record_failure());
        assert!(!monitor.record_failure());
        assert!(monitor.record_failure());
    }
}
