use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::config::SnapshotType;
use crate::error::{Result, VmmError};

/// Metadata stored alongside each snapshot on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// Unique snapshot identifier.
    pub id: String,
    /// VM identifier this snapshot belongs to.
    pub vm_id: String,
    /// Optional human-readable label.
    pub name: Option<String>,
    pub snapshot_type: SnapshotType,
    /// Absolute path to the `vmstate` file.
    pub vmstate_path: PathBuf,
    /// Absolute path to the memory file (full snapshots only).
    pub mem_path: Option<PathBuf>,
    /// When the snapshot was created.
    pub created_at: DateTime<Utc>,
    /// Parent snapshot ID (diff chain).
    pub parent_id: Option<String>,
}

/// Info returned to callers / gRPC layer.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub id: String,
    pub vm_id: String,
    pub name: Option<String>,
    pub snapshot_type: SnapshotType,
    pub vmstate_path: PathBuf,
    pub mem_path: Option<PathBuf>,
    pub created_at: DateTime<Utc>,
}

impl From<&SnapshotMeta> for SnapshotInfo {
    fn from(m: &SnapshotMeta) -> Self {
        Self {
            id: m.id.clone(),
            vm_id: m.vm_id.clone(),
            name: m.name.clone(),
            snapshot_type: m.snapshot_type,
            vmstate_path: m.vmstate_path.clone(),
            mem_path: m.mem_path.clone(),
            created_at: m.created_at,
        }
    }
}

/// Manages the on-disk snapshot catalog for all VMs.
///
/// Layout:
/// ```text
/// {data_dir}/snapshots/{vm_id}/{snapshot_id}/
///     vmstate
///     mem          (full only)
///     meta.json
/// ```
pub struct SnapshotCatalog {
    root: PathBuf,
}

impl SnapshotCatalog {
    /// Create a new catalog rooted at `{data_dir}/snapshots`.
    pub fn new(data_dir: &str) -> Self {
        Self {
            root: PathBuf::from(data_dir).join("snapshots"),
        }
    }

    /// Register a freshly-created snapshot.
    pub fn register(
        &self,
        vm_id: &str,
        name: Option<String>,
        snapshot_type: SnapshotType,
        vmstate_path: PathBuf,
        mem_path: Option<PathBuf>,
        parent_id: Option<String>,
    ) -> Result<SnapshotMeta> {
        let id = Uuid::new_v4().to_string();
        let meta = SnapshotMeta {
            id: id.clone(),
            vm_id: vm_id.to_owned(),
            name,
            snapshot_type,
            vmstate_path,
            mem_path,
            created_at: Utc::now(),
            parent_id,
        };
        self.write_meta(&meta)?;
        info!(snapshot_id = %id, vm_id, "snapshot registered");
        Ok(meta)
    }

    /// List all snapshots for a VM, sorted by creation time (oldest first).
    pub fn list(&self, vm_id: &str) -> Result<Vec<SnapshotInfo>> {
        let dir = self.vm_dir(vm_id);
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut entries: Vec<SnapshotMeta> = std::fs::read_dir(&dir)
            .map_err(VmmError::Io)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| self.read_meta(&e.path()).ok())
            .collect();
        entries.sort_by_key(|m| m.created_at);
        Ok(entries.iter().map(SnapshotInfo::from).collect())
    }

    /// Look up a single snapshot by ID.
    pub fn get(&self, vm_id: &str, snapshot_id: &str) -> Result<SnapshotMeta> {
        let path = self.snapshot_dir(vm_id, snapshot_id);
        self.read_meta(&path)
    }

    /// Delete a snapshot directory from disk.
    pub fn delete(&self, vm_id: &str, snapshot_id: &str) -> Result<()> {
        let path = self.snapshot_dir(vm_id, snapshot_id);
        if !path.exists() {
            return Err(VmmError::Snapshot(format!(
                "snapshot {snapshot_id} not found for VM {vm_id}"
            )));
        }
        std::fs::remove_dir_all(&path).map_err(VmmError::Io)?;
        info!(snapshot_id, vm_id, "snapshot deleted");
        Ok(())
    }

    /// Return the canonical directory for a new snapshot (creates it).
    pub fn prepare_dir(&self, vm_id: &str, snapshot_id: &str) -> Result<PathBuf> {
        let dir = self.snapshot_dir(vm_id, snapshot_id);
        std::fs::create_dir_all(&dir).map_err(VmmError::Io)?;
        Ok(dir)
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    fn vm_dir(&self, vm_id: &str) -> PathBuf {
        self.root.join(vm_id)
    }

    fn snapshot_dir(&self, vm_id: &str, snapshot_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join(snapshot_id)
    }

    fn meta_path(dir: &Path) -> PathBuf {
        dir.join("meta.json")
    }

    fn write_meta(&self, meta: &SnapshotMeta) -> Result<()> {
        let dir = self.snapshot_dir(&meta.vm_id, &meta.id);
        std::fs::create_dir_all(&dir).map_err(VmmError::Io)?;
        let json = serde_json::to_string_pretty(meta)?;
        std::fs::write(Self::meta_path(&dir), json).map_err(VmmError::Io)?;
        Ok(())
    }

    fn read_meta(&self, dir: &Path) -> Result<SnapshotMeta> {
        let json = std::fs::read_to_string(Self::meta_path(dir)).map_err(VmmError::Io)?;
        let meta = serde_json::from_str(&json)?;
        Ok(meta)
    }
}
