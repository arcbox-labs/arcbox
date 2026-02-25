use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::VmSpec;
use crate::network::NetworkAllocation;

/// Unique VM identifier (UUID string).
pub type VmId = String;

/// Lifecycle state of a single VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmState {
    /// Resources allocated; process not yet started.
    Created,
    /// Firecracker booted and guest is running.
    Running,
    /// Guest execution paused (snapshot-ready).
    Paused,
    /// Guest has shut down or was stopped.
    Stopped,
    /// An unrecoverable error occurred.
    Failed,
}

impl std::fmt::Display for VmState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmState::Created => write!(f, "created"),
            VmState::Running => write!(f, "running"),
            VmState::Paused => write!(f, "paused"),
            VmState::Stopped => write!(f, "stopped"),
            VmState::Failed => write!(f, "failed"),
        }
    }
}

/// Per-VM runtime state.
pub struct VmInstance {
    /// Unique identifier.
    pub id: VmId,
    /// Human-readable name.
    pub name: String,
    /// Original creation spec.
    pub spec: VmSpec,
    /// Current lifecycle state.
    pub state: VmState,
    /// Handle to the Firecracker process (present while the process is alive).
    pub process: Option<fc_sdk::FirecrackerProcess>,
    /// Post-boot API handle (present once the VM has booted).
    /// Wrapped in `Arc` so the manager can share the handle without re-constructing it.
    pub vm: Option<Arc<fc_sdk::Vm>>,
    /// Allocated network resources.
    pub network: Option<NetworkAllocation>,
    /// Path to the Firecracker API socket for this VM.
    pub socket_path: PathBuf,
    /// When the VM record was created.
    pub created_at: DateTime<Utc>,
    /// When the VM last transitioned to `Running`.
    pub started_at: Option<DateTime<Utc>>,
}

impl VmInstance {
    /// Create a new instance in the `Created` state.
    pub fn new(id: VmId, name: String, spec: VmSpec, socket_path: PathBuf) -> Self {
        Self {
            id,
            name,
            spec,
            state: VmState::Created,
            process: None,
            vm: None,
            network: None,
            socket_path,
            created_at: Utc::now(),
            started_at: None,
        }
    }
}

/// Lightweight summary for list operations.
#[derive(Debug, Clone)]
pub struct VmSummary {
    pub id: VmId,
    pub name: String,
    pub state: VmState,
    pub vcpus: u64,
    pub memory_mib: u64,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Detailed VM information for inspect operations.
#[derive(Debug, Clone)]
pub struct VmInfo {
    pub id: VmId,
    pub name: String,
    pub state: VmState,
    pub spec: VmSpec,
    pub network: Option<NetworkAllocation>,
    pub socket_path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
}

/// Metrics snapshot for a VM.
#[derive(Debug, Clone)]
pub struct VmMetrics {
    pub vm_id: VmId,
    /// Balloon target in MiB (None if no balloon device).
    pub balloon_target_mib: Option<i64>,
    /// Actual balloon size in MiB.
    pub balloon_actual_mib: Option<i64>,
}
