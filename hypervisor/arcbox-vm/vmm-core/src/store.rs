use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{Result, VmmError};
use crate::instance::VmInstance;

/// Persisted VM record (a subset of `VmInstance` that survives daemon restarts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRecord {
    pub id: String,
    pub name: String,
    /// Spec used to create the VM.
    pub spec: crate::config::VmSpec,
    /// Serialised `VmState`.
    pub state: String,
    /// Firecracker process PID (used to re-attach on restart).
    pub pid: Option<u32>,
    /// Absolute path to the Firecracker API socket.
    pub socket_path: PathBuf,
    /// Network allocation JSON (optional — absent if network not yet allocated).
    pub network_json: Option<String>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 start timestamp.
    pub started_at: Option<String>,
}

/// Disk-backed VM metadata store.
///
/// Each VM is stored as `{data_dir}/vms/{vm_id}/meta.json`.
pub struct VmStore {
    root: PathBuf,
}

impl VmStore {
    /// Create a new store rooted at `{data_dir}/vms`.
    pub fn new(data_dir: &str) -> Self {
        Self {
            root: PathBuf::from(data_dir).join("vms"),
        }
    }

    /// Persist (create or overwrite) a VM record derived from `instance`.
    pub fn save(&self, instance: &VmInstance) -> Result<()> {
        let dir = self.vm_dir(&instance.id);
        std::fs::create_dir_all(&dir).map_err(VmmError::Io)?;

        let record = VmRecord {
            id: instance.id.clone(),
            name: instance.name.clone(),
            spec: instance.spec.clone(),
            state: format!("{:?}", instance.state),
            pid: instance.process.as_ref().and_then(|p| p.pid()),
            socket_path: instance.socket_path.clone(),
            network_json: instance
                .network
                .as_ref()
                .and_then(|n| serde_json::to_string(n).ok()),
            created_at: instance.created_at.to_rfc3339(),
            started_at: instance.started_at.map(|t| t.to_rfc3339()),
        };

        let json = serde_json::to_string_pretty(&record)?;
        std::fs::write(self.meta_path(&instance.id), json).map_err(VmmError::Io)?;
        debug!(vm_id = %instance.id, "VM record saved");
        Ok(())
    }

    /// Load all persisted VM records.
    pub fn load_all(&self) -> Result<Vec<VmRecord>> {
        if !self.root.exists() {
            return Ok(vec![]);
        }
        let mut records = vec![];
        for entry in std::fs::read_dir(&self.root).map_err(VmmError::Io)? {
            let entry = entry.map_err(VmmError::Io)?;
            if entry.path().is_dir() {
                match self.load_record_from_dir(&entry.path()) {
                    Ok(r) => records.push(r),
                    Err(e) => {
                        tracing::warn!(path = %entry.path().display(), error = %e, "skipping corrupt VM record")
                    }
                }
            }
        }
        Ok(records)
    }

    /// Load a single VM record by ID.
    pub fn load(&self, vm_id: &str) -> Result<VmRecord> {
        self.load_record_from_dir(&self.vm_dir(vm_id))
    }

    /// Delete the store entry for a VM.
    pub fn delete(&self, vm_id: &str) -> Result<()> {
        let dir = self.vm_dir(vm_id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(VmmError::Io)?;
        }
        debug!(vm_id, "VM record deleted");
        Ok(())
    }

    /// Return the VM-specific data directory (also used for sockets and logs).
    pub fn vm_dir(&self, vm_id: &str) -> PathBuf {
        self.root.join(vm_id)
    }

    // -------------------------------------------------------------------------

    fn meta_path(&self, vm_id: &str) -> PathBuf {
        self.vm_dir(vm_id).join("meta.json")
    }

    fn load_record_from_dir(&self, dir: &std::path::Path) -> Result<VmRecord> {
        let json = std::fs::read_to_string(dir.join("meta.json")).map_err(VmmError::Io)?;
        let record = serde_json::from_str(&json)?;
        Ok(record)
    }
}
