use super::*;
use serde::{Deserialize, Serialize};

pub type ComputerId = String;

/// A sandbox's network as the boot flow carries it: the lease the guest
/// network reserved, the NIC it returned when it activated that lease, and
/// the addressing the guest is told to use over it.
///
/// The three travel together because all of them are needed at once and
/// none derives the others — the crash journal records the lease, the VM
/// spec boots the NIC, the kernel command line carries the identity, and
/// only the network knows which interface it built for which address or
/// what a guest on it sees.
#[derive(Clone)]
pub struct NetworkAttachment {
    /// The reserved address, and the cleanup token its generation ends on.
    pub lease: NetworkLease,
    /// The interface the driver attaches the guest's `eth0` to.
    pub nic: NicSpec,
    /// What the guest is told over that interface, from
    /// [`GuestNetwork::identity`](arcbox_vm_driver::net::GuestNetwork::identity)
    /// under the mode it was activated in.
    pub identity: NetworkIdentity,
    /// Whether this boot bakes the fixed invariant identity (CORE-81) into
    /// the guest's command line, which it does not when the caller supplied
    /// their own `ip=`.
    ///
    /// Carried beside the mode rather than confused with it: the host side
    /// of a cold boot is *always* activated
    /// [`AttachMode::Invariant`](arcbox_vm_driver::net::AttachMode::Invariant),
    /// so this flag says something about the guest, not about the datapath.
    pub invariant_identity: bool,
}

impl NetworkAttachment {
    /// This attachment as the crash journal records it.
    pub(crate) fn journaled(&self) -> super::reconcile::JournaledLease<'_> {
        super::reconcile::JournaledLease::cold_boot(&self.lease, self.invariant_identity)
    }
}

// State

/// Lifecycle state of a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxState {
    /// VMM prepared; VM still booting.
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
    /// `Pause` called; checkpointing state, then releasing the VM.
    Pausing,
    /// Checkpointed to disk with runtime resources released; the record,
    /// checkpoint, and disk overlay survive under the same id until
    /// `Resume` or `Remove` (CORE-21).
    Paused,
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
            Self::Pausing => write!(f, "pausing"),
            Self::Paused => write!(f, "paused"),
        }
    }
}

// Spec types (input to SandboxManager methods)

/// What happens when a sandbox's idle timeout expires (CORE-21).
///
/// Mirrors `arcbox.sandbox.v1.IdleAction`; `UNSPECIFIED` resolves to the
/// daemon default ([`IdleAction::Kill`]) at the service boundary, so this
/// type only carries effective policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleAction {
    /// Destroy the sandbox and release all resources (Remove semantics).
    #[default]
    Kill,
    /// Checkpoint to disk under the same id and release the VM.
    Pause,
}

/// A partial lifecycle update applied by `SetLifecycle` (CORE-60).
///
/// `None` fields are left unchanged, so each knob can be adjusted
/// independently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LifecycleUpdate {
    /// Replace the hard maximum lifetime: expire this many seconds from
    /// now (`Some(0)` removes the limit).
    pub ttl_seconds: Option<u32>,
    /// Replace the idle timeout (`Some(0)` disables idle detection).
    pub idle_timeout_seconds: Option<u32>,
    /// Replace the idle policy.
    pub on_idle: Option<IdleAction>,
}

/// Network configuration supplied at sandbox creation time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerNetworkSpec {
    /// `"tap"` (default) or `"none"`.
    pub mode: String,
}

/// A single bind-mount into the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerMountSpec {
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
pub struct ComputerSpec {
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
    pub mounts: Vec<ComputerMountSpec>,
    /// Network configuration.
    pub network: ComputerNetworkSpec,
    /// Auto-destroy TTL in seconds (0 = no limit).
    pub ttl_seconds: u32,
    /// SSH public key injected via MMDS (None = no SSH setup).
    pub ssh_public_key: Option<String>,
    /// Apply [`Self::on_idle`] after this many seconds without a running
    /// execution (0 = no idle detection). Re-armed on every `Ready` edge;
    /// file activity does NOT re-arm (CORE-21).
    pub idle_timeout_seconds: u32,
    /// What to do when the idle timeout expires.
    pub on_idle: IdleAction,
    /// The catalog template's pre-warmed snapshot, when the create resolved
    /// one (CORE-107). A boot-recipe input like `rootfs`: the create path
    /// restores it instead of cold-booting when eligible, and it rides the
    /// journaled effective spec so crash replay keeps working. `None` for
    /// non-catalog templates and warm-less catalog entries.
    pub template_warm: Option<TemplateWarmRef>,
    /// The catalog template's readiness probe (CORE-107): READY is withheld
    /// until it passes; expiry fails the boot. `None` = ready on
    /// exec-acceptance. Filled from the resolved template, never the request.
    pub ready_probe: Option<crate::template_catalog::ReadyProbeSpec>,
}

/// A template's pre-warmed boot-to-ready snapshot, threaded through
/// [`ComputerSpec`] (CORE-107).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateWarmRef {
    /// Snapshot id in the snapshot catalog.
    pub snapshot_id: String,
    /// Capture-time geometry; restore is eligible only on an exact match.
    pub vcpus: u32,
    pub memory_mib: u64,
}

/// Parameters to restore a sandbox from a checkpoint.
#[derive(Debug, Clone, Default)]
pub struct RestoreComputerSpec {
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

// Public output types (returned to callers / gRPC layer)

/// Lightweight summary for `List` operations.
pub struct SandboxSummary {
    pub id: ComputerId,
    pub state: SandboxState,
    pub labels: HashMap<String, String>,
    /// Allocated IP address (empty when network mode is `"none"`).
    pub ip_address: String,
    pub created_at: DateTime<Utc>,
    /// When the sandbox reached `Paused` (None otherwise).
    pub paused_at: Option<DateTime<Utc>>,
    /// On-disk footprint of retained pause state (checkpoint + overlay).
    pub storage_bytes: u64,
}

/// Detailed sandbox state for `Inspect`.
pub struct SandboxInfo {
    pub id: ComputerId,
    pub state: SandboxState,
    pub labels: HashMap<String, String>,
    pub vcpus: u32,
    pub memory_mib: u64,
    pub network: Option<ComputerNetworkInfo>,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub last_exited_at: Option<DateTime<Utc>>,
    pub last_exit_status: Option<ExitStatus>,
    pub error: Option<String>,
    /// When the sandbox reached `Paused` (None otherwise).
    pub paused_at: Option<DateTime<Utc>>,
    /// On-disk footprint of retained pause state (checkpoint + overlay).
    pub storage_bytes: u64,
    /// When the hard maximum lifetime fires (None = no limit).
    pub ttl_deadline: Option<DateTime<Utc>>,
    /// Idle timeout in seconds (0 = no idle detection).
    pub idle_timeout_seconds: u32,
    /// Action applied when the idle timeout expires.
    pub on_idle: IdleAction,
}

/// Network details within `SandboxInfo`.
pub struct ComputerNetworkInfo {
    pub ip_address: String,
    pub gateway: String,
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
    pub const PAUSING: &str = "pausing";
    pub const PAUSED: &str = "paused";
    pub const RESUMED: &str = "resumed";
}

/// A sandbox lifecycle event broadcast to subscribers.
#[derive(Debug, Clone)]
pub struct SandboxEvent {
    pub sandbox_id: ComputerId,
    /// One of the [`action`] constants.
    pub action: String,
    /// Unix nanoseconds.
    pub timestamp_ns: i64,
    /// Extra context (e.g. `"exit_code"` on `"idle"`, `"error"` on `"failed"`).
    pub attributes: HashMap<String, String>,
}

impl SandboxEvent {
    pub fn new(sandbox_id: &str, action: &str) -> Self {
        Self {
            sandbox_id: sandbox_id.to_owned(),
            action: action.to_owned(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or(0),
            attributes: HashMap::new(),
        }
    }

    pub fn with_attr(mut self, key: &str, value: &str) -> Self {
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
#[derive(Debug, Clone)]
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
