use super::*;
use serde::{Deserialize, Serialize};

pub type SandboxId = String;

pub(super) struct SandboxBootTask {
    pub(super) resource_handoff: Option<tokio::sync::oneshot::Receiver<()>>,
    pub(super) handle: tokio::task::JoinHandle<()>,
}

// State

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
            Self::Starting => write!(f, "starting"),
            Self::Ready => write!(f, "ready"),
            Self::Running => write!(f, "running"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// Spec types (input to SandboxManager methods)

/// Network configuration supplied at sandbox creation time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxNetworkSpec {
    /// `"tap"` (default) or `"none"`.
    pub mode: String,
}

/// A single bind-mount into the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxMountSpec {
    pub source: String,
    pub target: String,
    pub readonly: bool,
}

/// Full sandbox creation parameters.
///
/// The initial workload fields (`cmd`, `env`, `working_dir`, `user`) are
/// consumed by the boot task: a non-empty `cmd` is launched automatically
/// once the sandbox is ready, through the same path as `Run`.
/// `mounts`, `image`, and `ssh_public_key` are validated at the service
/// boundary (see the guest agent's `SandboxService::create`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
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

// Runtime instance

/// Per-sandbox runtime state.
pub struct SandboxInstance {
    /// Unique identifier.
    pub id: SandboxId,
    /// Durable lifecycle record generation.
    pub(super) record_generation: Option<Uuid>,
    /// User-supplied labels.
    pub labels: HashMap<String, String>,
    /// Original creation spec.
    pub spec: SandboxSpec,
    /// Current lifecycle state.
    pub state: SandboxState,
    /// Serializes Stop/Remove and failure cleanup for this generation.
    pub(super) cleanup_lock: Arc<tokio::sync::Mutex<()>>,
    /// In-flight boot, retained until Remove can cancel and join it.
    pub(super) boot_task: Option<SandboxBootTask>,
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
    /// How the last workload terminated.
    pub last_exit_status: Option<ExitStatus>,
    /// Human-readable error (only set when state == `Failed`).
    pub error: Option<String>,
    /// dm-snapshot CoW handle (present when snapshot-based rootfs is active).
    pub cow_handle: Option<CowHandle>,
    /// When this sandbox adopted a pre-warmed restore slot's resources
    /// (CORE-78), the slot id (`pool-<uuid>`) its jailer chroot and dm/CoW
    /// names are keyed by. `None` for resources created under the
    /// sandbox's own id.
    pub(super) pool_slot_id: Option<String>,
}

impl SandboxInstance {
    pub(super) fn new(
        id: SandboxId,
        spec: SandboxSpec,
        network: Option<NetworkAllocation>,
        vm_dir: PathBuf,
    ) -> Self {
        Self::new_inner(id, spec, network, vm_dir, None)
    }

    pub(super) fn new_with_generation(
        id: SandboxId,
        spec: SandboxSpec,
        network: Option<NetworkAllocation>,
        vm_dir: PathBuf,
        generation: Uuid,
    ) -> Self {
        Self::new_inner(id, spec, network, vm_dir, Some(generation))
    }

    fn new_inner(
        id: SandboxId,
        spec: SandboxSpec,
        network: Option<NetworkAllocation>,
        vm_dir: PathBuf,
        record_generation: Option<Uuid>,
    ) -> Self {
        Self {
            id,
            record_generation,
            labels: spec.labels.clone(),
            spec,
            state: SandboxState::Starting,
            cleanup_lock: Arc::new(tokio::sync::Mutex::new(())),
            boot_task: None,
            process: None,
            vm: None,
            network,
            vm_dir,
            vsock_uds_path: None,
            created_at: Utc::now(),
            ready_at: None,
            last_exited_at: None,
            last_exit_status: None,
            error: None,
            cow_handle: None,
            pool_slot_id: None,
        }
    }

    /// Path to the Firecracker API socket for this sandbox.
    pub fn socket_path(&self) -> PathBuf {
        self.vm_dir.join("firecracker.sock")
    }
}

// Public output types (returned to callers / gRPC layer)

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
    pub last_exit_status: Option<ExitStatus>,
    pub error: Option<String>,
}

/// Network details within `SandboxInfo`.
pub struct SandboxNetworkInfo {
    pub ip_address: String,
    pub gateway: String,
    pub tap_name: String,
}

// Events

/// The `action` values a [`SandboxEvent`] carries, in lifecycle order.
///
/// `action` stays a `String` on the event (it crosses the API as one), but
/// every emit site and match in this crate goes through these constants, so
/// renaming or adding an action is a change here — not a grep for string
/// literals whose miss surfaces as silently skipped teardown handling.
pub mod action {
    pub const CREATED: &str = "created";
    pub const READY: &str = "ready";
    pub const RUNNING: &str = "running";
    pub const IDLE: &str = "idle";
    pub const STOPPING: &str = "stopping";
    pub const STOPPED: &str = "stopped";
    pub const FAILED: &str = "failed";
    pub const REMOVED: &str = "removed";
}

/// A sandbox lifecycle event broadcast to subscribers.
#[derive(Debug, Clone)]
pub struct SandboxEvent {
    pub sandbox_id: SandboxId,
    /// One of the [`action`] constants.
    pub action: String,
    /// Unix nanoseconds.
    pub timestamp_ns: i64,
    /// Extra context (e.g. `"exit_code"` on `"idle"`, `"error"` on `"failed"`).
    pub attributes: HashMap<String, String>,
}

impl SandboxEvent {
    pub(super) fn new(sandbox_id: &str, action: &str) -> Self {
        Self {
            sandbox_id: sandbox_id.to_owned(),
            action: action.to_owned(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            attributes: HashMap::new(),
        }
    }

    pub(super) fn with_attr(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_owned(), value.to_owned());
        self
    }

    /// Whether this event marks the sandbox's teardown — nothing can run in
    /// it afterwards. A new terminal action must be added here, or torn-down
    /// sandboxes silently stop purging their executions.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.action.as_str(),
            action::STOPPED | action::FAILED | action::REMOVED
        )
    }
}

// Checkpoint / Restore output types

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

// SandboxManager
