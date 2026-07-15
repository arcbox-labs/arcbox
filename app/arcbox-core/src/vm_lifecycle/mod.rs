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
//! The lifecycle is an event-driven hierarchical state machine (`machine.rs`,
//! built on `statig`) owned by a single actor task (`actor.rs`). The facade
//! ([`VmLifecycleManager`]) translates public calls into actor commands over an
//! `mpsc` channel and serves reads from a lock-free `watch` channel; slow I/O
//! (create/start/agent-wait/stop) runs in sub-tasks (`boot.rs`) so a force stop
//! can always preempt.
//!
//! ```text
//! VmLifecycleManager ──commands──▶ LifecycleActor ⟳ statig VmLifecycle
//!         ▲                          │        │
//!         └────── watch state ───────┘        └──spawn──▶ boot/stop sub-task
//!                                                              │
//!                                          MachineManager ◀────┘
//! ```

mod actor;
mod boot;
mod health;
mod machine;
mod recovery;
#[cfg(target_os = "macos")]
mod serial;
#[cfg(test)]
mod tests;
mod types;

use crate::boot_assets::BootAssetProvider;
use crate::error::{CoreError, Result};
use crate::event::EventBus;
use crate::machine::{MachineInfo, MachineManager};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

use actor::{Command, LifecycleActor, LifecycleShared};

/// Default machine name used for container operations.
pub const DEFAULT_MACHINE_NAME: &str = "default";

/// Default startup timeout in seconds.
///
/// Generous enough to cover a cold guest boot (erofs rootfs + large docker.img
/// mount) even when the host daemon is CPU/I/O constrained. A tight 30s budget
/// raced the cold-boot path and produced "timeout waiting for agent" loops.
const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 90;

/// Default health check interval in seconds.
const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

/// Default idle timeout in seconds (5 minutes).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

/// Maximum retry attempts for recovery.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Minimum balloon target in MB when VM is idle.
/// Below this, the guest may become unstable.
const IDLE_BALLOON_TARGET_MB: u64 = 128;

/// Interval of the actor's idle ticker, and thereby the delay before the
/// balloon shrinks once the idle timeout has elapsed.
const BALLOON_SHRINK_DELAY_SECS: u64 = 10;

/// Persistent guest dockerd data image name.
const DOCKER_DATA_IMAGE_NAME: &str = "docker.img";
/// Persistent guest dockerd data image size (8 TiB sparse file).
///
/// This is the virtual size of the block device. The host file is sparse and
/// only consumes actual disk space for written blocks. 8 TiB matches OrbStack
/// and prevents users from hitting artificial limits.
const DOCKER_DATA_IMAGE_SIZE_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;

pub use health::HealthMonitor;
pub use recovery::{BackoffStrategy, RecoveryAction, RecoveryPolicy};
pub use types::{DefaultVmConfig, VmLifecycleConfig, VmLifecycleState};

/// Deferred actor state, consumed when the actor is first started.
///
/// The constructors are synchronous and may run outside a tokio runtime (e.g.
/// `Runtime::new` in tests), where `tokio::spawn` would panic — so the actor is
/// spawned lazily from the first async facade call instead.
struct ActorSeed {
    /// Receiving half of the facade's command channel.
    commands: mpsc::UnboundedReceiver<Command>,
    /// Publishing half of the state channel.
    state_tx: watch::Sender<VmLifecycleState>,
}

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
/// let cid = manager.ensure_ready().await?;
/// ```
pub struct VmLifecycleManager {
    /// State shared with the lifecycle actor and its boot/stop sub-tasks.
    shared: Arc<LifecycleShared>,
    /// Commands to the lifecycle actor.
    cmd_tx: mpsc::UnboundedSender<Command>,
    /// Public lifecycle state, published by the actor after every transition.
    state_rx: watch::Receiver<VmLifecycleState>,
    /// One-shot actor startup latch; see [`ActorSeed`].
    actor: OnceLock<()>,
    /// Actor state handed to `tokio::spawn` on first use.
    seed: Mutex<Option<ActorSeed>>,
}

impl VmLifecycleManager {
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

        // Seed the backend from the persisted machine so a prior switch survives
        // daemon restarts; fall back to the config default on first boot.
        let seeded_backend = machine_manager
            .get(&machine_name)
            .map_or(config.backend, |info| info.backend);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let shared = Arc::new(LifecycleShared {
            machine_name,
            data_image_filename,
            data_dir,
            machine_manager,
            event_bus,
            boot_assets,
            recovery,
            health_monitor,
            config,
            backend: AtomicU8::new(seeded_backend as u8),
            restart_generation: AtomicU64::new(0),
            last_activity_ms: AtomicU64::new(now_ms),
            balloon_shrunk: AtomicBool::new(false),
            kubernetes_hold: AtomicBool::new(false),
        });

        // The machine always boots its state graph from `NotExist`; whether a
        // boot must (re)create the machine is derived from the machine
        // registry at boot time, so no persisted-state seeding is needed (all
        // persisted states map to non-ready states after crash recovery).
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (state_tx, state_rx) = watch::channel(VmLifecycleState::NotExist);

        Ok(Self {
            shared,
            cmd_tx,
            state_rx,
            actor: OnceLock::new(),
            seed: Mutex::new(Some(ActorSeed {
                commands: cmd_rx,
                state_tx,
            })),
        })
    }

    /// Spawns the lifecycle actor on first use.
    ///
    /// Must be called from a tokio runtime context; every caller is an async
    /// facade method, which guarantees that.
    fn ensure_actor(&self) {
        self.actor.get_or_init(|| {
            let seed = self
                .seed
                .lock()
                .expect("lifecycle actor seed lock poisoned")
                .take();
            if let Some(seed) = seed {
                let actor =
                    LifecycleActor::new(Arc::clone(&self.shared), seed.commands, seed.state_tx);
                drop(tokio::spawn(actor.run()));
            }
        });
    }

    /// Sends `command` to the actor and awaits its reply.
    async fn request<T>(
        &self,
        command: Command,
        reply_rx: oneshot::Receiver<Result<T>>,
    ) -> Result<T> {
        self.ensure_actor();
        self.cmd_tx
            .send(command)
            .map_err(|_| CoreError::Vm("VM lifecycle actor terminated".to_string()))?;
        reply_rx
            .await
            .map_err(|_| CoreError::Vm("VM lifecycle actor terminated".to_string()))?
    }

    /// Returns the machine name this lifecycle manager owns.
    #[must_use]
    pub fn machine_name(&self) -> &str {
        &self.shared.machine_name
    }

    /// Returns the current VM incarnation counter, bumped on every stop.
    ///
    /// The Docker proxy compares this against the value it last verified
    /// against to detect a System VM restart (e.g. a backend switch) and reset
    /// its cached readiness + pooled connections before the next request.
    #[must_use]
    pub fn restart_generation(&self) -> u64 {
        self.shared
            .restart_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Returns the absolute path of this machine's persistent dockerd
    /// data image.
    #[must_use]
    pub fn data_image_path(&self) -> PathBuf {
        self.shared
            .data_dir
            .join(arcbox_constants::paths::host::DATA)
            .join(&self.shared.data_image_filename)
    }

    /// Returns the current lifecycle state.
    #[allow(clippy::unused_async, reason = "public API compatibility")]
    pub async fn state(&self) -> VmLifecycleState {
        *self.state_rx.borrow()
    }

    /// Returns true if the VM is running and ready.
    #[allow(clippy::unused_async, reason = "public API compatibility")]
    pub async fn is_running(&self) -> bool {
        self.state_rx.borrow().is_ready()
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
        self.ensure_ready_with_timeout(self.shared.config.startup_timeout)
            .await
    }

    /// Ensures VM is ready with custom timeout.
    pub async fn ensure_ready_with_timeout(&self, timeout: Duration) -> Result<u32> {
        // Skip VM check for testing.
        if self.shared.config.skip_vm_check {
            tracing::debug!("ensure_ready: skipping VM check (test mode)");
            // Register a mock machine so that container operations work.
            let mock_cid = 3;
            self.shared
                .machine_manager
                .register_mock_machine(&self.shared.machine_name, mock_cid)?;
            // Return a mock CID for testing.
            return Ok(mock_cid);
        }

        let (reply, reply_rx) = oneshot::channel();
        self.request(Command::EnsureReady { timeout, reply }, reply_rx)
            .await
    }

    /// Records external activity (e.g. a proxied Docker API request),
    /// resetting the idle clock and exiting idle if the VM is there.
    ///
    /// Cheap and non-blocking — safe to call on every request. Unlike
    /// [`Self::ensure_ready`] it never boots a stopped VM.
    pub fn note_activity(&self) {
        self.shared.record_activity();
        if *self.state_rx.borrow() == VmLifecycleState::Idle {
            // Exit idle so the balloon is restored to full memory.
            let _ = self.cmd_tx.send(Command::Activity);
        }
    }

    /// Enables or disables the Kubernetes lifecycle hold.
    #[allow(clippy::unused_async, reason = "public API compatibility")]
    pub async fn set_kubernetes_hold(&self, active: bool) {
        self.shared
            .kubernetes_hold
            .store(active, std::sync::atomic::Ordering::Relaxed);
        self.shared.record_activity();

        if active {
            // Exit idle (restoring the balloon) so the hold takes effect
            // immediately.
            self.ensure_actor();
            let _ = self.cmd_tx.send(Command::Activity);
        }
    }

    /// Gracefully stops the VM.
    ///
    /// # Errors
    /// Returns an error if the VM cannot be stopped.
    pub async fn shutdown(&self) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.request(Command::Shutdown { reply }, reply_rx).await
    }

    /// Forces VM termination, preempting any in-flight boot or graceful stop.
    ///
    /// # Errors
    /// Returns an error if the VM cannot be terminated.
    pub async fn force_stop(&self) -> Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.request(Command::ForceStop { reply }, reply_rx).await
    }

    /// Returns the System VM's current hypervisor backend.
    #[must_use]
    pub fn backend(&self) -> arcbox_vmm::VmBackend {
        self.shared.backend()
    }

    /// Sets the hypervisor backend used on the next (re)boot of the System VM.
    ///
    /// Does not stop or restart a running VM; to apply immediately the caller
    /// must force a recreate (see `Runtime::switch_system_vm_backend`).
    pub fn set_backend(&self, backend: arcbox_vmm::VmBackend) {
        self.shared
            .backend
            .store(backend as u8, std::sync::atomic::Ordering::Release);
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &VmLifecycleConfig {
        &self.shared.config
    }

    /// Returns the boot asset provider.
    #[must_use]
    pub fn boot_assets(&self) -> &Arc<BootAssetProvider> {
        &self.shared.boot_assets
    }

    /// Returns the resolved default VM configuration used by lifecycle.
    #[must_use]
    pub fn default_vm_config(&self) -> DefaultVmConfig {
        self.shared.config.default_vm.clone()
    }

    /// Returns the health monitor.
    #[must_use]
    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.shared.health_monitor
    }

    /// Returns the machine info for the default machine.
    pub fn default_machine_info(&self) -> Option<MachineInfo> {
        self.shared.machine_manager.get(&self.shared.machine_name)
    }
}
