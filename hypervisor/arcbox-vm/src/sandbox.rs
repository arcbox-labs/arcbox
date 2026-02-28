//! `SandboxManager` — orchestrates sandbox microVM lifecycle.
//!
//! A sandbox is a short-lived, strongly-isolated microVM decoupled from its
//! workload: when the initial `cmd` process exits the sandbox transitions back
//! to `Ready` rather than stopping, and continues accepting `Run` calls until
//! an explicit `Stop`/`Remove` or TTL expiry.
//!
//! `create_sandbox` returns immediately with state `"starting"`.  The VM boots
//! in a background task which broadcasts a `"ready"` event on success.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use fc_sdk::VmBuilder;
use fc_sdk::process::{FirecrackerProcessBuilder, JailerProcessBuilder};
use fc_sdk::types::{BootSource, Drive, NetworkInterface, Vsock};
use nix::unistd::{Gid, Uid, chown};
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::VmmConfig;
use crate::error::{Result, VmmError};
use crate::network::{NetworkAllocation, NetworkManager};
use crate::snapshot::SnapshotCatalog;
use crate::vsock::{self, ExecInputMsg, OutputChunk, StartCommand};

/// Unique sandbox identifier (UUID string).
pub type SandboxId = String;

// =============================================================================
// State
// =============================================================================

/// Lifecycle state of a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxState {
    /// Firecracker process spawned; VM still booting.
    Starting,
    /// VM booted and ready to accept workloads (or last workload exited).
    Ready,
    /// A workload (cmd / Run) is currently executing inside the VM.
    Running,
    /// `Stop` called; draining workload and shutting down VM.
    Stopping,
    /// VM has shut down cleanly.
    Stopped,
    /// Unrecoverable error occurred.
    Failed,
}

impl std::fmt::Display for SandboxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxState::Starting => write!(f, "starting"),
            SandboxState::Ready => write!(f, "ready"),
            SandboxState::Running => write!(f, "running"),
            SandboxState::Stopping => write!(f, "stopping"),
            SandboxState::Stopped => write!(f, "stopped"),
            SandboxState::Failed => write!(f, "failed"),
        }
    }
}

// =============================================================================
// Spec types (input to SandboxManager methods)
// =============================================================================

/// Network configuration supplied at sandbox creation time.
#[derive(Debug, Clone, Default)]
pub struct SandboxNetworkSpec {
    /// `"tap"` (default) or `"none"`.
    pub mode: String,
}

/// A single bind-mount into the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxMountSpec {
    pub source: String,
    pub target: String,
    pub readonly: bool,
}

/// Full sandbox creation parameters.
#[derive(Debug, Clone, Default)]
pub struct SandboxSpec {
    /// Caller-supplied ID; auto-generated (UUID) when `None` or empty.
    pub id: Option<String>,
    /// Arbitrary key-value metadata (filtering, listing).
    pub labels: HashMap<String, String>,
    /// Kernel image path (empty = daemon default).
    pub kernel: String,
    /// Root filesystem image path (empty = daemon default).
    pub rootfs: String,
    /// Kernel command-line arguments (empty = daemon default).
    pub boot_args: String,
    /// Number of vCPUs (0 = daemon default).
    pub vcpus: u32,
    /// Memory in MiB (0 = daemon default).
    pub memory_mib: u64,
    /// OCI image reference (empty = use rootfs directly; reserved for future use).
    pub image: String,
    /// Initial command launched automatically after boot (empty = none).
    pub cmd: Vec<String>,
    /// Environment variables for the initial command.
    pub env: HashMap<String, String>,
    /// Working directory for the initial command.
    pub working_dir: String,
    /// User to run the initial command as.
    pub user: String,
    /// Bind mounts into the sandbox.
    pub mounts: Vec<SandboxMountSpec>,
    /// Network configuration.
    pub network: SandboxNetworkSpec,
    /// Auto-destroy TTL in seconds (0 = no limit).
    pub ttl_seconds: u32,
    /// SSH public key injected via MMDS (None = no SSH setup).
    pub ssh_public_key: Option<String>,
}

/// Parameters to restore a sandbox from a checkpoint.
#[derive(Debug, Clone, Default)]
pub struct RestoreSandboxSpec {
    /// Caller-supplied ID (None = auto-generate).
    pub id: Option<String>,
    /// Source checkpoint/snapshot ID.
    pub snapshot_id: String,
    /// Labels to assign to the restored sandbox.
    pub labels: HashMap<String, String>,
    /// Assign a fresh TAP + IP to the restored sandbox.
    pub network_override: bool,
    /// Auto-destroy TTL in seconds (0 = no limit).
    pub ttl_seconds: u32,
}

// =============================================================================
// Runtime instance
// =============================================================================

/// Per-sandbox runtime state.
pub struct SandboxInstance {
    /// Unique identifier.
    pub id: SandboxId,
    /// User-supplied labels.
    pub labels: HashMap<String, String>,
    /// Original creation spec.
    pub spec: SandboxSpec,
    /// Current lifecycle state.
    pub state: SandboxState,
    /// Handle to the Firecracker process.
    pub process: Option<fc_sdk::FirecrackerProcess>,
    /// Post-boot API handle (present once the VM has booted).
    pub vm: Option<Arc<fc_sdk::Vm>>,
    /// Allocated network resources.
    pub network: Option<NetworkAllocation>,
    /// Directory holding the VM's runtime files (socket, logs, metrics).
    pub vm_dir: PathBuf,
    /// Path to the Firecracker vsock Unix domain socket (host side).
    /// `None` until the VM is booted.
    pub vsock_uds_path: Option<PathBuf>,
    /// When the sandbox record was created.
    pub created_at: DateTime<Utc>,
    /// When the sandbox first became ready.
    pub ready_at: Option<DateTime<Utc>>,
    /// When the last workload exited.
    pub last_exited_at: Option<DateTime<Utc>>,
    /// Exit code of the last workload.
    pub last_exit_code: Option<i32>,
    /// Human-readable error (only set when state == `Failed`).
    pub error: Option<String>,
}

impl SandboxInstance {
    fn new(
        id: SandboxId,
        spec: SandboxSpec,
        network: Option<NetworkAllocation>,
        vm_dir: PathBuf,
    ) -> Self {
        Self {
            id,
            labels: spec.labels.clone(),
            spec,
            state: SandboxState::Starting,
            process: None,
            vm: None,
            network,
            vm_dir,
            vsock_uds_path: None,
            created_at: Utc::now(),
            ready_at: None,
            last_exited_at: None,
            last_exit_code: None,
            error: None,
        }
    }

    /// Path to the Firecracker API socket for this sandbox.
    pub fn socket_path(&self) -> PathBuf {
        self.vm_dir.join("firecracker.sock")
    }
}

// =============================================================================
// Public output types (returned to callers / gRPC layer)
// =============================================================================

/// Lightweight summary for `List` operations.
pub struct SandboxSummary {
    pub id: SandboxId,
    pub state: SandboxState,
    pub labels: HashMap<String, String>,
    /// Allocated IP address (empty when network mode is `"none"`).
    pub ip_address: String,
    pub created_at: DateTime<Utc>,
}

/// Detailed sandbox state for `Inspect`.
pub struct SandboxInfo {
    pub id: SandboxId,
    pub state: SandboxState,
    pub labels: HashMap<String, String>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub network: Option<SandboxNetworkInfo>,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub last_exited_at: Option<DateTime<Utc>>,
    pub last_exit_code: Option<i32>,
    pub error: Option<String>,
}

/// Network details within `SandboxInfo`.
pub struct SandboxNetworkInfo {
    pub ip_address: String,
    pub gateway: String,
    pub tap_name: String,
}

// =============================================================================
// Events
// =============================================================================

/// A sandbox lifecycle event broadcast to subscribers.
#[derive(Debug, Clone)]
pub struct SandboxEvent {
    pub sandbox_id: SandboxId,
    /// Action: `"created"` | `"ready"` | `"running"` | `"idle"` |
    ///         `"stopping"` | `"stopped"` | `"failed"` | `"removed"`
    pub action: String,
    /// Unix nanoseconds.
    pub timestamp_ns: i64,
    /// Extra context (e.g. `"exit_code"` on `"idle"`, `"error"` on `"failed"`).
    pub attributes: HashMap<String, String>,
}

impl SandboxEvent {
    fn new(sandbox_id: &str, action: &str) -> Self {
        Self {
            sandbox_id: sandbox_id.to_owned(),
            action: action.to_owned(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            attributes: HashMap::new(),
        }
    }

    fn with_attr(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_owned(), value.to_owned());
        self
    }
}

// =============================================================================
// Checkpoint / Restore output types
// =============================================================================

/// Info returned after a successful checkpoint.
pub struct CheckpointInfo {
    pub snapshot_id: String,
    pub snapshot_dir: String,
    pub created_at: String,
}

/// Lightweight checkpoint summary for `ListSnapshots`.
pub struct CheckpointSummary {
    pub id: String,
    /// ID of the sandbox that was checkpointed.
    pub sandbox_id: String,
    pub name: String,
    pub labels: HashMap<String, String>,
    pub snapshot_dir: String,
    pub created_at: String,
}

// =============================================================================
// SandboxManager
// =============================================================================

const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Manages the full lifecycle of multiple sandbox microVMs.
pub struct SandboxManager {
    instances: Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: Arc<NetworkManager>,
    snapshots: Arc<SnapshotCatalog>,
    config: Arc<VmmConfig>,
    events_tx: broadcast::Sender<SandboxEvent>,
}

impl SandboxManager {
    /// Create a new manager from the given configuration.
    pub fn new(config: VmmConfig) -> Result<Self> {
        let network = Arc::new(NetworkManager::new(
            &config.network.bridge,
            &config.network.cidr,
            &config.network.gateway,
            config.network.dns.clone(),
        )?);
        let snapshots = Arc::new(SnapshotCatalog::new(&config.firecracker.data_dir));
        let (events_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);

        Ok(Self {
            instances: Arc::new(RwLock::new(HashMap::new())),
            network,
            snapshots,
            config: Arc::new(config),
            events_tx,
        })
    }

    // =========================================================================
    // Core lifecycle
    // =========================================================================

    /// Create a sandbox and return immediately (state = `"starting"`).
    ///
    /// Boots the VM in a background task.  Subscribe to [`subscribe_events`]
    /// or poll [`inspect_sandbox`] to wait for state `"ready"`.
    ///
    /// Returns `(sandbox_id, ip_address)`.  The IP is pre-allocated even
    /// before the VM finishes booting.
    pub async fn create_sandbox(&self, mut spec: SandboxSpec) -> Result<(SandboxId, String)> {
        // Apply daemon defaults for fields not supplied by the caller.
        let defaults = &self.config.defaults;
        if spec.kernel.is_empty() {
            spec.kernel = defaults.kernel.clone();
        }
        if spec.rootfs.is_empty() {
            spec.rootfs = defaults.rootfs.clone();
        }
        if spec.boot_args.is_empty() {
            spec.boot_args = defaults.boot_args.clone();
        }
        if spec.vcpus == 0 {
            spec.vcpus = defaults.vcpus as u32;
        }
        if spec.memory_mib == 0 {
            spec.memory_mib = defaults.memory_mib;
        }
        if spec.network.mode.is_empty() {
            spec.network.mode = "tap".into();
        }

        let id = spec
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Uniqueness check.
        {
            let instances = self.instances.read().unwrap();
            if instances.contains_key(&id) {
                return Err(VmmError::AlreadyExists(id.clone()));
            }
        }

        // Allocate network resources.
        let net_alloc = if spec.network.mode == "none" {
            None
        } else {
            Some(self.network.allocate(&id)?)
        };

        let ip_address = net_alloc
            .as_ref()
            .map(|n| n.ip_address.to_string())
            .unwrap_or_default();

        // Create the VM working directory.
        let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
            .join("sandboxes")
            .join(&id);
        std::fs::create_dir_all(&vm_dir).map_err(VmmError::Io)?;

        // Insert instance in Starting state.
        let instance =
            SandboxInstance::new(id.clone(), spec.clone(), net_alloc.clone(), vm_dir.clone());
        {
            let mut instances = self.instances.write().unwrap();
            instances.insert(id.clone(), Arc::new(Mutex::new(instance)));
        }

        // Broadcast "created" event.
        let _ = self.events_tx.send(SandboxEvent::new(&id, "created"));

        // Spawn background boot task.
        {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let config = Arc::clone(&self.config);
            let events_tx = self.events_tx.clone();
            let id_clone = id.clone();
            let spec_clone = spec.clone();
            let net_alloc_clone = net_alloc.clone();
            tokio::spawn(async move {
                boot_sandbox(
                    id_clone,
                    spec_clone,
                    net_alloc_clone,
                    vm_dir,
                    instances,
                    network,
                    config,
                    events_tx,
                )
                .await;
            });
        }

        // Spawn TTL expiry task if requested.
        if spec.ttl_seconds > 0 {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let events_tx = self.events_tx.clone();
            let config2 = Arc::clone(&self.config);
            let id2 = id.clone();
            let ttl = spec.ttl_seconds;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl as u64)).await;
                remove_sandbox_impl(&id2, true, &instances, &network, &events_tx, &config2).await;
            });
        }

        info!(sandbox_id = %id, "sandbox create requested (async boot started)");
        Ok((id, ip_address))
    }

    /// Stop a sandbox gracefully.
    ///
    /// Sends Ctrl+Alt+Del to the guest and waits up to `timeout_seconds`
    /// (default 30 s) for the VM to shut down.
    pub async fn stop_sandbox(&self, id: &SandboxId, timeout_seconds: u32) -> Result<()> {
        let vm_handle = {
            let instance = self.get_instance(id)?;
            let mut inst = instance.lock().unwrap();
            match inst.state {
                SandboxState::Ready | SandboxState::Running | SandboxState::Starting => {}
                s => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "Starting, Ready, or Running".into(),
                        actual: s.to_string(),
                    });
                }
            }
            inst.state = SandboxState::Stopping;
            inst.vm.as_ref().map(Arc::clone)
        };

        let _ = self.events_tx.send(SandboxEvent::new(id, "stopping"));

        if let Some(vm) = vm_handle {
            let timeout = if timeout_seconds > 0 {
                timeout_seconds
            } else {
                30
            };
            // Ignore errors — VM may have already exited.
            let _ =
                tokio::time::timeout(Duration::from_secs(timeout as u64), vm.send_ctrl_alt_del())
                    .await;
        }

        {
            let instance = self.get_instance(id)?;
            let mut inst = instance.lock().unwrap();
            inst.state = SandboxState::Stopped;
        }

        let _ = self.events_tx.send(SandboxEvent::new(id, "stopped"));
        info!(sandbox_id = %id, "sandbox stopped");
        Ok(())
    }

    /// Forcibly destroy a sandbox and release all resources immediately.
    pub async fn remove_sandbox(&self, id: &SandboxId, force: bool) -> Result<()> {
        // Verify the sandbox exists.
        let state = {
            let instance = self.get_instance(id)?;
            instance.lock().unwrap().state
        };

        if !force && state == SandboxState::Running {
            return Err(VmmError::WrongState {
                id: id.clone(),
                expected: "non-running (pass force=true to override)".into(),
                actual: state.to_string(),
            });
        }

        remove_sandbox_impl(
            id,
            force,
            &self.instances,
            &self.network,
            &self.events_tx,
            &self.config,
        )
        .await;
        info!(sandbox_id = %id, "sandbox removed");
        Ok(())
    }

    /// Return the current state and metadata of a sandbox.
    pub fn inspect_sandbox(&self, id: &SandboxId) -> Result<SandboxInfo> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        Ok(inst_to_info(&inst))
    }

    /// List sandboxes, optionally filtered by state string and/or labels.
    pub fn list_sandboxes(
        &self,
        state_filter: Option<&str>,
        label_filter: &HashMap<String, String>,
    ) -> Vec<SandboxSummary> {
        self.instances
            .read()
            .unwrap()
            .values()
            .filter_map(|arc| {
                let inst = arc.lock().unwrap();
                // State filter.
                if let Some(sf) = state_filter
                    && !sf.is_empty()
                    && inst.state.to_string() != sf
                {
                    return None;
                }
                // Label filter: all supplied key-value pairs must match.
                for (k, v) in label_filter {
                    if inst.labels.get(k).map(String::as_str) != Some(v.as_str()) {
                        return None;
                    }
                }
                Some(SandboxSummary {
                    id: inst.id.clone(),
                    state: inst.state,
                    labels: inst.labels.clone(),
                    ip_address: inst
                        .network
                        .as_ref()
                        .map(|n| n.ip_address.to_string())
                        .unwrap_or_default(),
                    created_at: inst.created_at,
                })
            })
            .collect()
    }

    /// Subscribe to sandbox lifecycle events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SandboxEvent> {
        self.events_tx.subscribe()
    }

    // =========================================================================
    // Workload execution (requires guest agent via vsock)
    // =========================================================================

    /// Run a command inside a ready sandbox and stream its output.
    ///
    /// The sandbox must be in `Ready` state.  It transitions to `Running`
    /// immediately and back to `Ready` (emitting an `"idle"` event) when the
    /// command exits.
    ///
    /// Returns a channel receiver yielding [`OutputChunk`]s.  The final chunk
    /// has `stream == "exit"` and carries the process exit code.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_in_sandbox(
        &self,
        id: &SandboxId,
        cmd: Vec<String>,
        env: HashMap<String, String>,
        working_dir: String,
        user: String,
        tty: bool,
        tty_size: Option<(u16, u16)>,
        timeout_seconds: u32,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<OutputChunk>>> {
        let uds_path = self.require_ready_vsock(id)?;

        // Transition to Running.
        {
            let inst = self.get_instance(id)?;
            inst.lock().unwrap().state = SandboxState::Running;
        }
        let _ = self.events_tx.send(SandboxEvent::new(id, "running"));

        let start = StartCommand {
            cmd,
            env,
            working_dir,
            user,
            tty,
            tty_width: tty_size.map(|(w, _)| w).unwrap_or(80),
            tty_height: tty_size.map(|(_, h)| h).unwrap_or(24),
            timeout_seconds,
        };

        let inner_rx = vsock::run(&uds_path, start).await?;

        // Wrap the receiver to intercept MSG_EXIT and update state.
        let (wrapped_tx, wrapped_rx) = tokio::sync::mpsc::channel(64);
        let instances = Arc::clone(&self.instances);
        let events_tx = self.events_tx.clone();
        let sandbox_id = id.clone();
        tokio::spawn(async move {
            let mut inner_rx = inner_rx;
            while let Some(result) = inner_rx.recv().await {
                let send_result = match &result {
                    Ok(chunk) if chunk.stream == "exit" => {
                        let exit_code = chunk.exit_code;
                        if let Some(arc) = instances.read().unwrap().get(&sandbox_id).cloned() {
                            let mut inst = arc.lock().unwrap();
                            inst.state = SandboxState::Ready;
                            inst.last_exit_code = Some(exit_code);
                            inst.last_exited_at = Some(Utc::now());
                        }
                        let _ = events_tx.send(
                            SandboxEvent::new(&sandbox_id, "idle")
                                .with_attr("exit_code", &exit_code.to_string()),
                        );
                        wrapped_tx.send(result).await
                    }
                    _ => wrapped_tx.send(result).await,
                };
                if send_result.is_err() {
                    break;
                }
            }
        });

        Ok(wrapped_rx)
    }

    /// Start an interactive exec session inside a ready sandbox.
    ///
    /// The sandbox must be in `Ready` state.  It transitions to `Running`
    /// immediately and back to `Ready` when the session ends.
    ///
    /// Returns `(input_sender, output_receiver)`:
    /// - Push [`ExecInputMsg`]s (stdin bytes, TTY resize, EOF) into `input_sender`.
    /// - Read [`OutputChunk`]s from `output_receiver` for stdout, stderr, and exit.
    #[allow(clippy::too_many_arguments)]
    pub async fn exec_in_sandbox(
        &self,
        id: &SandboxId,
        cmd: Vec<String>,
        env: HashMap<String, String>,
        working_dir: String,
        user: String,
        tty: bool,
        tty_size: Option<(u16, u16)>,
        timeout_seconds: u32,
    ) -> Result<(
        tokio::sync::mpsc::Sender<ExecInputMsg>,
        tokio::sync::mpsc::Receiver<Result<OutputChunk>>,
    )> {
        let uds_path = self.require_ready_vsock(id)?;

        // Transition to Running.
        {
            let inst = self.get_instance(id)?;
            inst.lock().unwrap().state = SandboxState::Running;
        }
        let _ = self.events_tx.send(SandboxEvent::new(id, "running"));

        let start = StartCommand {
            cmd,
            env,
            working_dir,
            user,
            tty,
            tty_width: tty_size.map(|(w, _)| w).unwrap_or(80),
            tty_height: tty_size.map(|(_, h)| h).unwrap_or(24),
            timeout_seconds,
        };

        let (in_tx, inner_rx) = vsock::exec(&uds_path, start).await?;

        // Wrap the output receiver to intercept MSG_EXIT and update state.
        let (wrapped_tx, wrapped_rx) = tokio::sync::mpsc::channel(64);
        let instances = Arc::clone(&self.instances);
        let events_tx = self.events_tx.clone();
        let sandbox_id = id.clone();
        tokio::spawn(async move {
            let mut inner_rx = inner_rx;
            while let Some(result) = inner_rx.recv().await {
                let send_result = match &result {
                    Ok(chunk) if chunk.stream == "exit" => {
                        let exit_code = chunk.exit_code;
                        if let Some(arc) = instances.read().unwrap().get(&sandbox_id).cloned() {
                            let mut inst = arc.lock().unwrap();
                            inst.state = SandboxState::Ready;
                            inst.last_exit_code = Some(exit_code);
                            inst.last_exited_at = Some(Utc::now());
                        }
                        let _ = events_tx.send(
                            SandboxEvent::new(&sandbox_id, "idle")
                                .with_attr("exit_code", &exit_code.to_string()),
                        );
                        wrapped_tx.send(result).await
                    }
                    _ => wrapped_tx.send(result).await,
                };
                if send_result.is_err() {
                    break;
                }
            }
        });

        Ok((in_tx, wrapped_rx))
    }

    // =========================================================================
    // Checkpoint / Restore
    // =========================================================================

    /// Pause, checkpoint, and resume a sandbox.
    ///
    /// The sandbox must be in `Ready` state (no active workload).
    pub async fn checkpoint_sandbox(
        &self,
        sandbox_id: &SandboxId,
        name: String,
    ) -> Result<CheckpointInfo> {
        // Verify state and capture the kernel/rootfs paths for jailer re-staging.
        let (kernel_path, rootfs_path) = {
            let instance = self.get_instance(sandbox_id)?;
            let inst = instance.lock().unwrap();
            if inst.state != SandboxState::Ready {
                return Err(VmmError::WrongState {
                    id: sandbox_id.clone(),
                    expected: "Ready".into(),
                    actual: inst.state.to_string(),
                });
            }
            // Only needed for jailer mode; safe to capture regardless.
            (inst.spec.kernel.clone(), inst.spec.rootfs.clone())
        };

        let vm = self.get_vm_handle(sandbox_id)?;

        // Pause before snapshotting.
        vm.pause().await.map_err(VmmError::Sdk)?;

        let snapshot_id = Uuid::new_v4().to_string();

        // In jailer mode FC runs inside a chroot and can only write to paths
        // within that chroot.  We create a temporary snapshot directory inside
        // the chroot, pass the chroot-relative paths to FC, then move the
        // resulting files to the standard catalog location on the host.
        let (fc_vmstate_path, fc_mem_path, chroot_snap_dir_opt) =
            if let Some(ref jc) = self.config.firecracker.jailer {
                let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
                let cr = chroot_root(&self.config.firecracker.binary, base, sandbox_id);
                let chroot_snap = cr.join("snapshots").join(&snapshot_id);
                std::fs::create_dir_all(&chroot_snap).map_err(VmmError::Io)?;
                // Firecracker runs as jc.uid/jc.gid; chown the directory so it
                // can create the snapshot files.
                let uid = nix::unistd::Uid::from_raw(jc.uid);
                let gid = nix::unistd::Gid::from_raw(jc.gid);
                nix::unistd::chown(&chroot_snap, Some(uid), Some(gid))
                    .map_err(|e| VmmError::Process(format!("chown snapshot dir: {e}")))?;
                // Paths as seen by Firecracker inside the chroot.
                let fc_vmstate = format!("/snapshots/{snapshot_id}/vmstate");
                let fc_mem = format!("/snapshots/{snapshot_id}/mem");
                (fc_vmstate, fc_mem, Some(chroot_snap))
            } else {
                let snap_dir = self.snapshots.prepare_dir(sandbox_id, &snapshot_id)?;
                (
                    snap_dir.join("vmstate").to_str().unwrap().to_owned(),
                    snap_dir.join("mem").to_str().unwrap().to_owned(),
                    None,
                )
            };

        let snap_result = vm.create_snapshot(&fc_vmstate_path, &fc_mem_path).await;

        // Always resume regardless of snapshot success.
        let _ = vm.resume().await;

        snap_result.map_err(VmmError::Sdk)?;

        // If jailer mode, move snapshot files from chroot to the catalog dir.
        let (vmstate_path, mem_path) = if let Some(chroot_snap) = chroot_snap_dir_opt {
            let catalog_dir = self.snapshots.prepare_dir(sandbox_id, &snapshot_id)?;
            let dst_vmstate = catalog_dir.join("vmstate");
            let dst_mem = catalog_dir.join("mem");
            tokio::fs::rename(chroot_snap.join("vmstate"), &dst_vmstate)
                .await
                .map_err(VmmError::Io)?;
            if chroot_snap.join("mem").exists() {
                tokio::fs::rename(chroot_snap.join("mem"), &dst_mem)
                    .await
                    .map_err(VmmError::Io)?;
            }
            let _ = tokio::fs::remove_dir_all(&chroot_snap).await;
            (dst_vmstate, dst_mem)
        } else {
            let snap_dir = self.snapshots.prepare_dir(sandbox_id, &snapshot_id)?;
            (snap_dir.join("vmstate"), snap_dir.join("mem"))
        };

        // Store kernel/rootfs only in jailer mode — needed when restoring.
        let (snap_kernel, snap_rootfs) = if self.config.firecracker.jailer.is_some() {
            (Some(kernel_path), Some(rootfs_path))
        } else {
            (None, None)
        };

        let meta = self.snapshots.register(
            sandbox_id,
            Some(name),
            crate::config::SnapshotType::Full,
            vmstate_path,
            Some(mem_path),
            None,
            snap_kernel,
            snap_rootfs,
        )?;

        let snap_dir_path = meta
            .vmstate_path
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        info!(sandbox_id, snapshot_id = %meta.id, "sandbox checkpointed");
        Ok(CheckpointInfo {
            snapshot_id: meta.id,
            snapshot_dir: snap_dir_path,
            created_at: meta.created_at.to_rfc3339(),
        })
    }

    /// Restore a new sandbox from a previously created checkpoint.
    ///
    /// The restored sandbox starts in `Ready` state immediately.
    ///
    /// Returns `(sandbox_id, ip_address)`.
    pub async fn restore_sandbox(&self, spec: RestoreSandboxSpec) -> Result<(SandboxId, String)> {
        let new_id = spec
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Uniqueness check.
        {
            let instances = self.instances.read().unwrap();
            if instances.contains_key(&new_id) {
                return Err(VmmError::AlreadyExists(new_id.clone()));
            }
        }

        // Allocate network if requested.
        let net_alloc = if spec.network_override {
            Some(self.network.allocate(&new_id)?)
        } else {
            None
        };

        let ip_address = net_alloc
            .as_ref()
            .map(|n| n.ip_address.to_string())
            .unwrap_or_default();

        // Create working directory.
        let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
            .join("sandboxes")
            .join(&new_id);
        std::fs::create_dir_all(&vm_dir).map_err(VmmError::Io)?;
        let socket_path = vm_dir.join("firecracker.sock");

        // Locate checkpoint on disk.
        let snap_meta = self.snapshots.find_by_id(&spec.snapshot_id)?;
        let vmstate_str = snap_meta.vmstate_path.to_str().unwrap().to_owned();
        let mem_file = snap_meta.mem_path.as_ref().and_then(|p| {
            if p.exists() {
                Some(p.to_str().unwrap().to_owned())
            } else {
                None
            }
        });

        let fc_cfg = &self.config.firecracker;

        // Determine the actual host-side vsock UDS path FC will bind to on restore
        // and ensure the socket path is clear before spawning.
        //
        // - Jailer mode: each sandbox has its own chroot; FC sees `/run/firecracker.vsock`
        //   which maps to `{chroot_root}/run/firecracker.vsock` on the host. No conflict
        //   between sandboxes — we just ensure the `run/` directory exists.
        // - Direct mode: the vmstate stores the ABSOLUTE host path from the original
        //   sandbox. We must recreate that directory and delete any stale socket so FC
        //   can bind successfully.
        let (process, actual_vsock_path) = if let Some(ref jc) = fc_cfg.jailer {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, &new_id);
            // Ensure the `run/` directory exists inside the new chroot so FC can
            // create the vsock socket there on restore.
            let run_dir = cr.join("run");
            std::fs::create_dir_all(&run_dir).map_err(VmmError::Io)?;
            let vsock_path = cr.join("run/firecracker.vsock");
            let _ = std::fs::remove_file(&vsock_path);

            let mut jb =
                JailerProcessBuilder::new(&jc.binary, &fc_cfg.binary, &new_id, jc.uid, jc.gid);
            if let Some(ref base_dir) = jc.chroot_base_dir {
                jb = jb.chroot_base_dir(base_dir);
            }
            if let Some(ref ns) = jc.netns {
                jb = jb.netns(ns);
            }
            if jc.new_pid_ns {
                jb = jb.new_pid_ns(true);
            }
            if let Some(ref ver) = jc.cgroup_version {
                jb = jb.cgroup_version(ver);
            }
            if let Some(ref parent) = jc.parent_cgroup {
                jb = jb.parent_cgroup(parent);
            }
            for limit in &jc.resource_limits {
                jb = jb.resource_limit(limit);
            }
            if let Some(secs) = fc_cfg.socket_timeout_secs {
                jb = jb.socket_timeout(Duration::from_secs(secs));
            }
            let proc = jb
                .spawn()
                .await
                .map_err(|e| VmmError::Process(e.to_string()))?;
            (proc, vsock_path)
        } else {
            // Direct mode: the vmstate embeds the original sandbox's full vsock path.
            let original_vm_dir = PathBuf::from(&fc_cfg.data_dir)
                .join("sandboxes")
                .join(&snap_meta.vm_id);
            let original_vsock_path = original_vm_dir.join("firecracker.vsock");
            if let Err(e) = std::fs::create_dir_all(&original_vm_dir) {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(VmmError::Io(e));
                }
            }
            let _ = std::fs::remove_file(&original_vsock_path);

            let proc = FirecrackerProcessBuilder::new(&fc_cfg.binary, &socket_path)
                .id(&new_id)
                .spawn()
                .await
                .map_err(|e| VmmError::Process(e.to_string()))?;
            (proc, original_vsock_path)
        };

        // In jailer mode the restored FC process also runs inside a chroot and
        // cannot access the catalog's host-absolute paths.  Copy the snapshot
        // files into the new sandbox's chroot and use chroot-relative paths.
        let (effective_vmstate, effective_mem) = if let Some(ref jc) = fc_cfg.jailer {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, &new_id);
            let snap_in_chroot = cr.join("snapshots").join(&spec.snapshot_id);
            std::fs::create_dir_all(&snap_in_chroot).map_err(VmmError::Io)?;
            let uid = nix::unistd::Uid::from_raw(jc.uid);
            let gid = nix::unistd::Gid::from_raw(jc.gid);
            nix::unistd::chown(&snap_in_chroot, Some(uid), Some(gid))
                .map_err(|e| VmmError::Process(format!("chown snap dir: {e}")))?;

            // Stage kernel and rootfs into the new chroot (same layout as boot).
            if let (Some(k), Some(r)) = (
                snap_meta.kernel_path.as_deref(),
                snap_meta.rootfs_path.as_deref(),
            ) {
                stage_files_for_jailer(&cr, k, r, jc.uid, jc.gid).await?;
            }

            // Copy vmstate into chroot.
            let dst_vmstate = snap_in_chroot.join("vmstate");
            tokio::fs::copy(&snap_meta.vmstate_path, &dst_vmstate)
                .await
                .map_err(VmmError::Io)?;
            nix::unistd::chown(&dst_vmstate, Some(uid), Some(gid))
                .map_err(|e| VmmError::Process(format!("chown vmstate: {e}")))?;

            let effective_mem = if let Some(ref mf) = snap_meta.mem_path
                && mf.exists()
            {
                let dst_mem = snap_in_chroot.join("mem");
                tokio::fs::copy(mf, &dst_mem).await.map_err(VmmError::Io)?;
                nix::unistd::chown(&dst_mem, Some(uid), Some(gid))
                    .map_err(|e| VmmError::Process(format!("chown mem: {e}")))?;
                Some(format!("/snapshots/{}/mem", spec.snapshot_id))
            } else {
                None
            };

            (
                format!("/snapshots/{}/vmstate", spec.snapshot_id),
                effective_mem,
            )
        } else {
            (vmstate_str, mem_file)
        };

        // Build the restore parameters.
        let mut load_params = fc_sdk::types::SnapshotLoadParams {
            snapshot_path: effective_vmstate,
            mem_file_path: effective_mem,
            mem_backend: None,
            enable_diff_snapshots: None,
            track_dirty_pages: None,
            resume_vm: Some(true),
            network_overrides: vec![],
        };

        if let Some(ref net) = net_alloc {
            load_params.network_overrides = vec![fc_sdk::types::NetworkOverride {
                iface_id: "eth0".into(),
                host_dev_name: net.tap_name.clone(),
            }];
        }

        // In jailer mode, the actual socket path is inside the chroot; use the
        // path reported by the process handle instead of vm_dir's socket_path.
        let effective_socket = process.socket_path().to_owned();
        let vm = Arc::new(
            fc_sdk::restore(effective_socket.to_str().unwrap(), load_params)
                .await
                .map_err(VmmError::Sdk)?,
        );

        // Build and register the new sandbox instance.
        let restore_spec = SandboxSpec {
            id: Some(new_id.clone()),
            labels: spec.labels,
            ttl_seconds: spec.ttl_seconds,
            ..Default::default()
        };
        let mut instance =
            SandboxInstance::new(new_id.clone(), restore_spec, net_alloc.clone(), vm_dir);
        instance.process = Some(process);
        instance.vm = Some(vm);
        instance.vsock_uds_path = Some(actual_vsock_path);
        instance.state = SandboxState::Ready;
        instance.ready_at = Some(Utc::now());

        {
            let mut instances = self.instances.write().unwrap();
            instances.insert(new_id.clone(), Arc::new(Mutex::new(instance)));
        }

        let _ = self.events_tx.send(SandboxEvent::new(&new_id, "ready"));

        // TTL expiry task.
        if spec.ttl_seconds > 0 {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let events_tx = self.events_tx.clone();
            let config2 = Arc::clone(&self.config);
            let id2 = new_id.clone();
            let ttl = spec.ttl_seconds;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl as u64)).await;
                remove_sandbox_impl(&id2, true, &instances, &network, &events_tx, &config2).await;
            });
        }

        info!(
            sandbox_id = %new_id,
            snapshot_id = %spec.snapshot_id,
            "sandbox restored from checkpoint"
        );
        Ok((new_id, ip_address))
    }

    /// List checkpoints, optionally filtered by origin sandbox ID.
    pub fn list_checkpoints(&self, sandbox_id: Option<&str>) -> Result<Vec<CheckpointSummary>> {
        let infos = match sandbox_id {
            Some(sid) => self.snapshots.list(sid)?,
            None => self.snapshots.list_all()?,
        };
        Ok(infos
            .into_iter()
            .map(|s| CheckpointSummary {
                id: s.id,
                sandbox_id: s.vm_id,
                name: s.name.unwrap_or_default(),
                labels: HashMap::new(),
                snapshot_dir: s
                    .vmstate_path
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                created_at: s.created_at.to_rfc3339(),
            })
            .collect())
    }

    /// Delete a checkpoint by its ID.
    pub fn delete_checkpoint(&self, snapshot_id: &str) -> Result<()> {
        self.snapshots.delete_by_id(snapshot_id)
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    fn get_instance(&self, id: &SandboxId) -> Result<Arc<Mutex<SandboxInstance>>> {
        self.instances
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| VmmError::NotFound(id.clone()))
    }

    /// Verify the sandbox is `Ready` and return its vsock UDS path.
    fn require_ready_vsock(&self, id: &SandboxId) -> Result<PathBuf> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        match inst.state {
            SandboxState::Ready => {}
            s => {
                return Err(VmmError::WrongState {
                    id: id.clone(),
                    expected: "Ready".into(),
                    actual: s.to_string(),
                });
            }
        }
        inst.vsock_uds_path
            .clone()
            .ok_or_else(|| VmmError::Vsock(format!("sandbox {id} has no vsock configured")))
    }

    fn get_vm_handle(&self, id: &SandboxId) -> Result<Arc<fc_sdk::Vm>> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        inst.vm
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| VmmError::WrongState {
                id: id.clone(),
                expected: "Ready or Running (VM handle not yet available)".into(),
                actual: inst.state.to_string(),
            })
    }
}

// =============================================================================
// Background task: boot a sandbox VM
// =============================================================================

/// Spawned by `create_sandbox`; boots the Firecracker VM and updates state.
#[allow(clippy::too_many_arguments)]
async fn boot_sandbox(
    id: SandboxId,
    spec: SandboxSpec,
    net_alloc: Option<NetworkAllocation>,
    vm_dir: PathBuf,
    instances: Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: Arc<NetworkManager>,
    config: Arc<VmmConfig>,
    events_tx: broadcast::Sender<SandboxEvent>,
) {
    match do_boot(&id, &spec, net_alloc.as_ref(), &vm_dir, &config).await {
        Ok((process, vm, vsock_uds_path)) => {
            let ready_at = Utc::now();
            if let Some(arc) = instances.read().unwrap().get(&id).cloned() {
                let mut inst = arc.lock().unwrap();
                inst.process = Some(process);
                inst.vm = Some(vm);
                inst.vsock_uds_path = Some(vsock_uds_path);
                inst.state = SandboxState::Ready;
                inst.ready_at = Some(ready_at);
            }
            let _ = events_tx.send(SandboxEvent::new(&id, "ready"));
            info!(sandbox_id = %id, "sandbox booted and ready");
        }
        Err(e) => {
            if let Some(arc) = instances.read().unwrap().get(&id).cloned() {
                let mut inst = arc.lock().unwrap();
                inst.state = SandboxState::Failed;
                inst.error = Some(e.to_string());
            }
            // Release network on boot failure.
            if let Some(ref net) = net_alloc {
                network.release(net);
            }
            let _ =
                events_tx.send(SandboxEvent::new(&id, "failed").with_attr("error", &e.to_string()));
            error!(sandbox_id = %id, error = %e, "sandbox boot failed");
        }
    }
}

/// Compute the host-side absolute path to the jailer chroot root directory.
///
/// Returns `{chroot_base_dir}/{fc_binary_filename}/{id}/root`.
fn chroot_root(fc_binary: &str, chroot_base_dir: &str, id: &str) -> PathBuf {
    let exec_name = Path::new(fc_binary)
        .file_name()
        .expect("fc_binary must have a filename")
        .to_string_lossy();
    PathBuf::from(chroot_base_dir)
        .join(exec_name.as_ref())
        .join(id)
        .join("root")
}

/// Copy kernel and rootfs into the jailer chroot and set ownership.
///
/// Returns `(kernel_guest_path, rootfs_guest_path)` — paths relative to the
/// chroot root (e.g., `"/vmlinux"`, `"/rootfs.ext4"`).
async fn stage_files_for_jailer(
    chroot_root: &Path,
    kernel_src: &str,
    rootfs_src: &str,
    uid: u32,
    gid: u32,
) -> Result<(String, String)> {
    tokio::fs::create_dir_all(chroot_root)
        .await
        .map_err(VmmError::Io)?;

    let kernel_dst = chroot_root.join("vmlinux");
    let rootfs_dst = chroot_root.join("rootfs.ext4");

    tokio::fs::copy(kernel_src, &kernel_dst)
        .await
        .map_err(VmmError::Io)?;
    tokio::fs::copy(rootfs_src, &rootfs_dst)
        .await
        .map_err(VmmError::Io)?;

    let uid = Uid::from_raw(uid);
    let gid = Gid::from_raw(gid);
    chown(&kernel_dst, Some(uid), Some(gid))
        .map_err(|e| VmmError::Process(format!("chown kernel: {e}")))?;
    chown(&rootfs_dst, Some(uid), Some(gid))
        .map_err(|e| VmmError::Process(format!("chown rootfs: {e}")))?;

    Ok(("/vmlinux".to_string(), "/rootfs.ext4".to_string()))
}

/// Perform the actual Firecracker boot: spawn process, configure, start VM.
///
/// Returns `(FirecrackerProcess, Arc<Vm>, vsock_uds_path)` on success.
/// `vsock_uds_path` is the host-side absolute path to the vsock UDS socket.
async fn do_boot(
    id: &str,
    spec: &SandboxSpec,
    net_alloc: Option<&NetworkAllocation>,
    vm_dir: &Path,
    config: &VmmConfig,
) -> Result<(fc_sdk::FirecrackerProcess, Arc<fc_sdk::Vm>, PathBuf)> {
    let log_path = vm_dir.join("firecracker.log");
    let metrics_path = vm_dir.join("firecracker.metrics");
    // socket_path is used only for the direct (non-jailer) mode spawn.
    let socket_path = vm_dir.join("firecracker.sock");

    let fc_cfg = &config.firecracker;

    // Spawn the Firecracker process (direct or via Jailer).
    let process = if let Some(ref jc) = fc_cfg.jailer {
        let mut jb = JailerProcessBuilder::new(&jc.binary, &fc_cfg.binary, id, jc.uid, jc.gid);
        if let Some(ref base) = jc.chroot_base_dir {
            jb = jb.chroot_base_dir(base);
        }
        if let Some(ref ns) = jc.netns {
            jb = jb.netns(ns);
        }
        if jc.new_pid_ns {
            jb = jb.new_pid_ns(true);
        }
        if let Some(ref ver) = jc.cgroup_version {
            jb = jb.cgroup_version(ver);
        }
        if let Some(ref parent) = jc.parent_cgroup {
            jb = jb.parent_cgroup(parent);
        }
        for limit in &jc.resource_limits {
            jb = jb.resource_limit(limit);
        }
        if let Some(secs) = fc_cfg.socket_timeout_secs {
            jb = jb.socket_timeout(Duration::from_secs(secs));
        }
        jb.spawn()
            .await
            .map_err(|e| VmmError::Process(e.to_string()))?
    } else {
        let mut fb = FirecrackerProcessBuilder::new(&fc_cfg.binary, &socket_path).id(id);
        fb = fb.log_path(&log_path).metrics_path(&metrics_path);
        if let Some(ref level) = fc_cfg.log_level {
            fb = fb.log_level(level);
        }
        if fc_cfg.no_seccomp {
            fb = fb.no_seccomp(true);
        }
        if let Some(ref filter) = fc_cfg.seccomp_filter {
            fb = fb.seccomp_filter(filter);
        }
        if let Some(size) = fc_cfg.http_api_max_payload_size {
            fb = fb.http_api_max_payload_size(size);
        }
        if let Some(size) = fc_cfg.mmds_size_limit {
            fb = fb.mmds_size_limit(size);
        }
        if let Some(secs) = fc_cfg.socket_timeout_secs {
            fb = fb.socket_timeout(Duration::from_secs(secs));
        }
        fb.spawn()
            .await
            .map_err(|e| VmmError::Process(e.to_string()))?
    };

    // Determine kernel, rootfs, and vsock paths.
    //
    // In jailer mode the files must exist inside the chroot, and paths passed
    // to the FC API are relative to the chroot root.  In direct mode the
    // host-absolute paths from the spec are used as-is.
    let (kernel_path, rootfs_path, vsock_fc_path, vsock_host_path) =
        if let Some(ref jc) = fc_cfg.jailer {
            let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
            let cr = chroot_root(&fc_cfg.binary, base, id);
            let (k, r) =
                stage_files_for_jailer(&cr, &spec.kernel, &spec.rootfs, jc.uid, jc.gid).await?;
            // FC creates the vsock socket at this path inside the chroot.
            let vsock_host = cr.join("run/firecracker.vsock");
            (k, r, "/run/firecracker.vsock".to_string(), vsock_host)
        } else {
            let vsock_path = vm_dir.join("firecracker.vsock");
            (
                spec.kernel.clone(),
                spec.rootfs.clone(),
                vsock_path.to_str().unwrap().to_owned(),
                vsock_path,
            )
        };

    // Configure and boot the VM.
    let vcpu_count = NonZeroU64::new(spec.vcpus.max(1) as u64)
        .ok_or_else(|| VmmError::Config("vcpus must be > 0".into()))?;

    let mut builder = VmBuilder::new(process.socket_path())
        .boot_source(BootSource {
            kernel_image_path: kernel_path,
            boot_args: Some(spec.boot_args.clone()),
            initrd_path: None,
        })
        .machine_config(fc_sdk::types::MachineConfiguration {
            vcpu_count,
            mem_size_mib: spec.memory_mib as i64,
            smt: false,
            // Enable dirty-page tracking so checkpointing is always available.
            track_dirty_pages: true,
            cpu_template: None,
            huge_pages: None,
        })
        .drive(Drive {
            drive_id: "rootfs".into(),
            path_on_host: Some(rootfs_path),
            is_root_device: true,
            is_read_only: Some(false),
            partuuid: None,
            cache_type: fc_sdk::types::DriveCacheType::Unsafe,
            rate_limiter: None,
            io_engine: fc_sdk::types::DriveIoEngine::Sync,
            socket: None,
        });

    if let Some(net) = net_alloc {
        builder = builder.network_interface(NetworkInterface {
            iface_id: "eth0".into(),
            guest_mac: Some(net.mac_address.clone()),
            host_dev_name: net.tap_name.clone(),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
    }

    // Configure vsock device so the guest agent can receive connections.
    // vsock_fc_path is the path FC uses inside its own filesystem view;
    // vsock_host_path is the host-absolute path used to connect from the host.
    builder = builder.vsock(Vsock {
        // CID 3 is the conventional guest CID; each Firecracker process is
        // isolated so the same CID is safe across concurrent sandboxes.
        guest_cid: 3,
        uds_path: vsock_fc_path,
        vsock_id: None,
    });

    let vm = Arc::new(builder.start().await.map_err(VmmError::Sdk)?);
    Ok((process, vm, vsock_host_path))
}

// =============================================================================
// Background task: remove a sandbox
// =============================================================================

/// Shared implementation for `remove_sandbox` and TTL expiry tasks.
#[allow(clippy::type_complexity)]
async fn remove_sandbox_impl(
    id: &str,
    _force: bool,
    instances: &Arc<RwLock<HashMap<SandboxId, Arc<Mutex<SandboxInstance>>>>>,
    network: &Arc<NetworkManager>,
    events_tx: &broadcast::Sender<SandboxEvent>,
    config: &Arc<VmmConfig>,
) {
    let entry = instances.read().unwrap().get(id).cloned();
    let Some(arc) = entry else {
        return;
    };

    {
        let mut inst = arc.lock().unwrap();
        // Kill the Firecracker process.
        if let Some(ref mut proc) = inst.process
            && let Some(pid) = proc.pid()
        {
            // SAFETY: pid is a valid process ID obtained from the spawned child.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
        // Release network resources.
        if let Some(ref net) = inst.network {
            network.release(net);
        }
    }

    // Clean up the jailer chroot directory if applicable.
    if let Some(ref jc) = config.firecracker.jailer {
        let base = jc.chroot_base_dir.as_deref().unwrap_or("/srv/jailer");
        let chroot_dir = chroot_root(&config.firecracker.binary, base, id);
        // Remove {base}/{exec_name}/{id}/ (parent of "root/").
        if let Some(parent) = chroot_dir.parent()
            && let Err(e) = tokio::fs::remove_dir_all(parent).await
        {
            warn!(sandbox_id = %id, err = %e, "failed to remove jailer chroot dir");
        }
    }

    // Remove the sandbox working directory (sockets, logs, etc.).
    let vm_dir = PathBuf::from(&config.firecracker.data_dir)
        .join("sandboxes")
        .join(id);
    if let Err(e) = tokio::fs::remove_dir_all(&vm_dir).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(sandbox_id = %id, err = %e, "failed to remove sandbox dir");
        }
    }

    instances.write().unwrap().remove(id);
    let _ = events_tx.send(SandboxEvent::new(id, "removed"));
}

// =============================================================================
// Conversion helpers
// =============================================================================

fn inst_to_info(inst: &SandboxInstance) -> SandboxInfo {
    SandboxInfo {
        id: inst.id.clone(),
        state: inst.state,
        labels: inst.labels.clone(),
        vcpus: inst.spec.vcpus,
        memory_mib: inst.spec.memory_mib,
        network: inst.network.as_ref().map(|n| SandboxNetworkInfo {
            ip_address: n.ip_address.to_string(),
            gateway: n.gateway.to_string(),
            tap_name: n.tap_name.clone(),
        }),
        created_at: inst.created_at,
        ready_at: inst.ready_at,
        last_exited_at: inst.last_exited_at,
        last_exit_code: inst.last_exit_code,
        error: inst.error.clone(),
    }
}
