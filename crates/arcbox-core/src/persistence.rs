//! Machine configuration persistence.
//!
//! Stores machine configurations to disk so they survive process restarts.

use crate::error::{CoreError, Result};
use crate::machine::{MachineInfo, MachineState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Persisted machine data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMachine {
    /// Machine name.
    pub name: String,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Disk size in GB.
    pub disk_gb: u64,
    /// Kernel path.
    #[serde(default)]
    pub kernel: Option<String>,
    /// Initrd path.
    #[serde(default)]
    pub initrd: Option<String>,
    /// Kernel command line.
    #[serde(default)]
    pub cmdline: Option<String>,
    /// Last known state.
    pub state: PersistedState,
    /// VM ID (for correlation).
    pub vm_id: String,
    /// Creation timestamp.
    #[serde(default = "default_created_at")]
    pub created_at: DateTime<Utc>,
}

/// Default creation time for backward compatibility with old configs.
fn default_created_at() -> DateTime<Utc> {
    Utc::now()
}

/// Persisted machine state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PersistedState {
    #[default]
    Created,
    Running,
    Stopped,
}

impl From<MachineState> for PersistedState {
    fn from(state: MachineState) -> Self {
        match state {
            MachineState::Created => Self::Created,
            MachineState::Starting | MachineState::Running => Self::Running,
            MachineState::Stopping | MachineState::Stopped => Self::Stopped,
        }
    }
}

impl From<PersistedState> for MachineState {
    fn from(state: PersistedState) -> Self {
        match state {
            PersistedState::Created => Self::Created,
            PersistedState::Running => Self::Stopped, // Assume stopped on restart
            PersistedState::Stopped => Self::Stopped,
        }
    }
}

impl From<&MachineInfo> for PersistedMachine {
    fn from(info: &MachineInfo) -> Self {
        Self {
            name: info.name.clone(),
            cpus: info.cpus,
            memory_mb: info.memory_mb,
            disk_gb: info.disk_gb,
            kernel: info.kernel.clone(),
            initrd: info.initrd.clone(),
            cmdline: info.cmdline.clone(),
            state: info.state.into(),
            vm_id: info.vm_id.to_string(),
            created_at: info.created_at,
        }
    }
}

/// Machine persistence manager.
pub struct MachinePersistence {
    /// Base directory for machine configs.
    base_dir: PathBuf,
}

impl MachinePersistence {
    /// Creates a new persistence manager.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Returns the config file path for a machine.
    fn config_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(name).join("config.toml")
    }

    /// Returns the machine directory path.
    fn machine_dir(&self, name: &str) -> PathBuf {
        self.base_dir.join(name)
    }

    /// Saves a machine configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be saved.
    pub fn save(&self, machine: &MachineInfo) -> Result<()> {
        let dir = self.machine_dir(&machine.name);
        fs::create_dir_all(&dir)?;

        let persisted = PersistedMachine::from(machine);
        let content = toml::to_string_pretty(&persisted).map_err(|e| {
            CoreError::Machine(format!("Failed to serialize config: {}", e))
        })?;

        fs::write(self.config_path(&machine.name), content)?;

        tracing::debug!("Saved machine config: {}", machine.name);
        Ok(())
    }

    /// Loads a machine configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be loaded.
    pub fn load(&self, name: &str) -> Result<PersistedMachine> {
        let path = self.config_path(name);
        let content = fs::read_to_string(&path).map_err(|e| {
            CoreError::NotFound(format!("Machine config not found: {}", e))
        })?;

        toml::from_str(&content).map_err(|e| {
            CoreError::Machine(format!("Failed to parse config: {}", e))
        })
    }

    /// Lists all saved machines.
    pub fn list(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.base_dir) else {
            return Vec::new();
        };

        entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter(|e| e.path().join("config.toml").exists())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect()
    }

    /// Loads all saved machines.
    pub fn load_all(&self) -> Vec<PersistedMachine> {
        self.list()
            .iter()
            .filter_map(|name| self.load(name).ok())
            .collect()
    }

    /// Removes a machine configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be removed.
    pub fn remove(&self, name: &str) -> Result<()> {
        let dir = self.machine_dir(name);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
            tracing::debug!("Removed machine config: {}", name);
        }
        Ok(())
    }

    /// Updates the state of a persisted machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be updated.
    pub fn update_state(&self, name: &str, state: MachineState) -> Result<()> {
        let mut machine = self.load(name)?;
        machine.state = state.into();

        let content = toml::to_string_pretty(&machine).map_err(|e| {
            CoreError::Machine(format!("Failed to serialize config: {}", e))
        })?;

        fs::write(self.config_path(name), content)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::VmId;
    use tempfile::TempDir;

    #[test]
    fn test_save_and_load() {
        let temp = TempDir::new().unwrap();
        let persistence = MachinePersistence::new(temp.path());

        let created_at = Utc::now();
        let info = MachineInfo {
            name: "test-vm".to_string(),
            state: MachineState::Created,
            vm_id: VmId::new(),
            cpus: 4,
            memory_mb: 4096,
            disk_gb: 50,
            kernel: Some("/path/to/kernel".to_string()),
            initrd: Some("/path/to/initrd".to_string()),
            cmdline: Some("console=ttyS0".to_string()),
            cid: None,
            created_at,
        };

        persistence.save(&info).unwrap();

        let loaded = persistence.load("test-vm").unwrap();
        assert_eq!(loaded.name, "test-vm");
        assert_eq!(loaded.cpus, 4);
        assert_eq!(loaded.memory_mb, 4096);
        assert_eq!(loaded.kernel, Some("/path/to/kernel".to_string()));
        assert_eq!(loaded.initrd, Some("/path/to/initrd".to_string()));
        assert_eq!(loaded.cmdline, Some("console=ttyS0".to_string()));
        // Check created_at is preserved (within 1 second tolerance)
        assert!((loaded.created_at - created_at).num_seconds().abs() < 1);
    }

    #[test]
    fn test_list() {
        let temp = TempDir::new().unwrap();
        let persistence = MachinePersistence::new(temp.path());

        // Create multiple machines
        for name in ["vm1", "vm2", "vm3"] {
            let info = MachineInfo {
                name: name.to_string(),
                state: MachineState::Created,
                vm_id: VmId::new(),
                cpus: 2,
                memory_mb: 2048,
                disk_gb: 20,
                kernel: None,
                initrd: None,
                cmdline: None,
                cid: None,
                created_at: Utc::now(),
            };
            persistence.save(&info).unwrap();
        }

        let machines = persistence.list();
        assert_eq!(machines.len(), 3);
        assert!(machines.contains(&"vm1".to_string()));
        assert!(machines.contains(&"vm2".to_string()));
        assert!(machines.contains(&"vm3".to_string()));
    }

    #[test]
    fn test_remove() {
        let temp = TempDir::new().unwrap();
        let persistence = MachinePersistence::new(temp.path());

        let info = MachineInfo {
            name: "test-vm".to_string(),
            state: MachineState::Created,
            vm_id: VmId::new(),
            cpus: 2,
            memory_mb: 2048,
            disk_gb: 20,
            kernel: None,
            initrd: None,
            cmdline: None,
            cid: None,
            created_at: Utc::now(),
        };

        persistence.save(&info).unwrap();
        assert!(persistence.load("test-vm").is_ok());

        persistence.remove("test-vm").unwrap();
        assert!(persistence.load("test-vm").is_err());
    }
}
