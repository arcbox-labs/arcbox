//! Snapshot and restore support for virtual machines and containers.

mod compression;
mod container;
mod error;
mod manager;
mod state;
mod util;
mod vm;

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use arcbox_hypervisor::{DeviceSnapshot, VcpuSnapshot, VmSnapshot};

pub use error::SnapshotError;
/// Callback type for reading guest memory into a caller-supplied buffer.
type MemoryReaderFn = Box<dyn FnOnce(&mut [u8]) -> Result<(), SnapshotError> + Send>;

/// Snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Snapshot ID.
    pub id: String,
    /// Snapshot name.
    pub name: String,
    /// Target (VM or container) ID.
    pub target_id: String,
    /// Target type.
    pub target_type: SnapshotTargetType,
    /// Creation time.
    pub created: DateTime<Utc>,
    /// Size in bytes.
    pub size: u64,
    /// Parent snapshot ID (for incremental).
    pub parent: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Snapshot state.
    pub state: SnapshotState,
}

/// Target type for snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotTargetType {
    /// Virtual machine.
    Vm,
    /// Container.
    Container,
}

/// Snapshot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotState {
    /// Snapshot is being created.
    Creating,
    /// Snapshot is ready.
    Ready,
    /// Snapshot is corrupted or invalid.
    Invalid,
}

/// Snapshot creation options.
#[derive(Debug, Clone, Default)]
pub struct SnapshotCreateOptions {
    /// Snapshot name (auto-generated if None).
    pub name: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Labels.
    pub labels: HashMap<String, String>,
    /// Parent snapshot for incremental (None for full snapshot).
    pub parent: Option<String>,
    /// Whether to pause the VM during snapshot.
    pub pause_vm: bool,
    /// Whether to compress memory dump.
    pub compress: bool,
}

/// VM snapshot context provided by the caller.
///
/// Since `SnapshotManager` doesn't own VMs, the caller must provide this context
/// with callbacks to interact with the VM.
pub struct VmSnapshotContext {
    /// vCPU snapshots.
    pub vcpu_snapshots: Vec<VcpuSnapshot>,
    /// Device snapshots.
    pub device_snapshots: Vec<DeviceSnapshot>,
    /// Memory size in bytes.
    pub memory_size: u64,
    /// Callback to read guest memory into a buffer.
    pub memory_reader: MemoryReaderFn,
}

/// Data needed to restore a VM from a snapshot.
///
/// Returned by `SnapshotManager::take_restore_data()` after calling `restore()`.
pub struct VmRestoreData {
    /// VM snapshot metadata and state.
    pub vm_snapshot: VmSnapshot,
    /// Guest memory content.
    pub memory: Vec<u8>,
}

impl VmRestoreData {
    /// Returns the vCPU snapshots.
    #[must_use]
    pub fn vcpu_snapshots(&self) -> &[VcpuSnapshot] {
        &self.vm_snapshot.vcpus
    }

    /// Returns the device snapshots.
    #[must_use]
    pub fn device_snapshots(&self) -> &[arcbox_hypervisor::DeviceSnapshot] {
        &self.vm_snapshot.devices
    }

    /// Returns the total memory size.
    #[must_use]
    pub const fn memory_size(&self) -> u64 {
        self.vm_snapshot.total_memory
    }

    /// Returns the memory data.
    #[must_use]
    pub fn memory(&self) -> &[u8] {
        &self.memory
    }

    /// Whether the snapshot was compressed.
    #[must_use]
    pub const fn was_compressed(&self) -> bool {
        self.vm_snapshot.compressed
    }
}

/// Snapshot manager.
///
/// Manages VM and container snapshots with support for incremental snapshots.
pub struct SnapshotManager {
    /// Base directory for snapshots.
    base_dir: PathBuf,
    /// In-memory cache of snapshot metadata.
    snapshots: std::sync::RwLock<HashMap<String, SnapshotInfo>>,
    /// Cache of restore data for recently restored snapshots.
    restore_cache: std::sync::RwLock<HashMap<String, VmRestoreData>>,
}

/// CRIU checkpoint options.
#[cfg(all(target_os = "linux", feature = "criu"))]
#[derive(Debug, Clone, Default)]
pub struct CriuCheckpointOptions {
    /// Leave the process running after checkpoint.
    pub leave_running: bool,
    /// Checkpoint file locks.
    pub file_locks: bool,
    /// Checkpoint established TCP connections.
    pub tcp_established: bool,
}
