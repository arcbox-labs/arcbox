use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// VM snapshot state data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct VmSnapshotState {
    /// Target VM ID.
    pub(super) target_id: String,
    /// When the snapshot was captured.
    pub(super) captured_at: DateTime<Utc>,
    /// Whether the VM was paused during capture.
    pub(super) paused: bool,
    /// Number of vCPUs.
    pub(super) vcpu_count: u32,
    /// Memory size in bytes.
    pub(super) memory_size: u64,
    /// Device states.
    pub(super) devices: Vec<DeviceState>,
}

/// Device state in snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DeviceState {
    /// Device type.
    pub(super) device_type: String,
    /// Device-specific state data.
    pub(super) data: serde_json::Value,
}

/// Container checkpoint data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ContainerCheckpoint {
    /// Target container ID.
    pub(super) target_id: String,
    /// When the checkpoint was captured.
    pub(super) captured_at: DateTime<Utc>,
    /// Process tree (PIDs).
    pub(super) process_tree: Vec<u32>,
    /// Open file descriptors.
    pub(super) open_files: Vec<String>,
    /// Network state.
    pub(super) network_state: Option<serde_json::Value>,
}
