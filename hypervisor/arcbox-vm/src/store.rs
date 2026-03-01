use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{Result, VmmError};
use crate::instance::{VmInstance, VmState};

/// Persisted VM record (a subset of `VmInstance` that survives daemon restarts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRecord {
    pub id: String,
    pub name: String,
    /// Spec used to create the VM.
    pub spec: crate::config::VmSpec,
    /// VM lifecycle state.
    pub state: VmState,
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
            state: instance.state,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::VmInstance;

    fn make_instance(id: &str) -> VmInstance {
        VmInstance::new(
            id.to_owned(),
            format!("test-{id}"),
            crate::config::VmSpec::default(),
            PathBuf::from(format!("/tmp/{id}.sock")),
        )
    }

    #[test]
    fn test_load_all_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = VmStore::new(dir.path().to_str().unwrap());
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = VmStore::new(dir.path().to_str().unwrap());
        let inst = make_instance("vm-001");
        store.save(&inst).unwrap();
        let record = store.load("vm-001").unwrap();
        assert_eq!(record.id, "vm-001");
        assert_eq!(record.name, "test-vm-001");
        assert_eq!(record.state, VmState::Created);
    }

    #[test]
    fn test_save_multiple_and_load_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = VmStore::new(dir.path().to_str().unwrap());
        store.save(&make_instance("vm-a")).unwrap();
        store.save(&make_instance("vm-b")).unwrap();
        let records = store.load_all().unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_delete_removes_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = VmStore::new(dir.path().to_str().unwrap());
        store.save(&make_instance("del-me")).unwrap();
        store.delete("del-me").unwrap();
        assert!(store.load_all().unwrap().is_empty());
    }

    #[test]
    fn test_load_missing_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = VmStore::new(dir.path().to_str().unwrap());
        assert!(store.load("nonexistent").is_err());
    }
}
