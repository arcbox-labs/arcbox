//! Machine configuration persistence.
//!
//! Stores machine configurations to disk so they survive process restarts.

use crate::error::{CoreError, Result};
use crate::machine::{MachineInfo, MachineState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
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
    /// Kernel command line.
    #[serde(default)]
    pub cmdline: Option<String>,
    /// Block devices (e.g., EROFS rootfs, Btrfs data disk).
    #[serde(default)]
    pub block_devices: Vec<crate::vm::BlockDeviceConfig>,
    /// Distribution name.
    #[serde(default)]
    pub distro: Option<String>,
    /// Distribution version.
    #[serde(default)]
    pub distro_version: Option<String>,
    /// Path to the disk image.
    #[serde(default)]
    pub disk_path: Option<String>,
    /// Path to the SSH private key.
    #[serde(default)]
    pub ssh_key_path: Option<String>,
    /// Last known IP address.
    #[serde(default)]
    pub ip_address: Option<String>,
    /// Last known state.
    pub state: PersistedState,
    /// VM ID (for correlation).
    pub vm_id: String,
    /// macOS hypervisor backend. Defaults to [`arcbox_vmm::VmBackend::default`]
    /// (`Vz`) for configs written before the field existed.
    #[serde(default)]
    pub backend: arcbox_vmm::VmBackend,
    /// Creation timestamp.
    #[serde(default = "default_created_at")]
    pub created_at: DateTime<Utc>,
    /// Last successful start timestamp.
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    /// Host directories shared into the machine.
    #[serde(default)]
    pub mounts: Vec<crate::machine::MachineMount>,
}

/// Default creation time for backward compatibility with old configs.
fn default_created_at() -> DateTime<Utc> {
    Utc::now()
}

/// Persisted machine state.
///
/// Records the last known state when the daemon wrote the config.
/// On reload, [`MachineState::from`] maps this to the *current* state
/// (e.g. `Running` → `Stopped` because the VM process is gone).
/// Use [`Self::needs_recovery`] to distinguish a clean stop from a
/// crash/daemon restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PersistedState {
    #[default]
    Created,
    Running,
    Stopped,
}

impl PersistedState {
    /// Returns `true` if the machine was running when the daemon last
    /// persisted state — meaning it was interrupted and may need recovery
    /// (e.g. networking re-registration, container reconciliation).
    #[must_use]
    pub const fn needs_recovery(self) -> bool {
        matches!(self, Self::Running)
    }
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
    /// Maps persisted state to current machine state on reload.
    ///
    /// A machine persisted as `Running` is mapped to `Stopped` because
    /// the VM process is no longer alive after a daemon restart. Use
    /// [`PersistedState::needs_recovery`] to detect this case and
    /// trigger recovery logic.
    fn from(state: PersistedState) -> Self {
        match state {
            PersistedState::Created => Self::Created,
            PersistedState::Running => Self::Stopped,
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
            cmdline: info.cmdline.clone(),
            block_devices: info.block_devices.clone(),
            distro: info.distro.clone(),
            distro_version: info.distro_version.clone(),
            disk_path: info
                .disk_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            ssh_key_path: info
                .ssh_key_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            ip_address: info.ip_address.clone(),
            state: info.state.into(),
            vm_id: info.vm_id.to_string(),
            backend: info.backend,
            created_at: info.created_at,
            started_at: info.started_at,
            mounts: info.mounts.clone(),
        }
    }
}

/// Writes `data` to `path` atomically via write-to-temp-then-rename.
///
/// A process crash or panic during the write leaves either the old file
/// or the new file intact — never a truncated/partial file.  This does
/// **not** call `fsync`; durability across power loss is not guaranteed.
fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| CoreError::config("config path has no parent directory"))?;

    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.flush()?;
    tmp.persist(path).map_err(|e| {
        std::io::Error::new(
            e.error.kind(),
            format!("failed to persist to '{}': {}", path.display(), e.error),
        )
    })?;

    Ok(())
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
        let content = toml::to_string_pretty(&persisted)
            .map_err(|e| CoreError::config(format!("failed to serialize config: {e}")))?;

        atomic_write(&self.config_path(&machine.name), content.as_bytes())?;

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
        let content = fs::read_to_string(&path)
            .map_err(|e| CoreError::not_found(format!("Machine config not found: {e}")))?;

        toml::from_str(&content).map_err(CoreError::from)
    }

    /// Lists all saved machines.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.base_dir) else {
            return Vec::new();
        };

        entries
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().is_dir())
            .filter(|e| e.path().join("config.toml").exists())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect()
    }

    /// Loads all saved machines.
    #[must_use]
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
        self.update(name, |machine| {
            machine.state = state.into();
        })
    }

    /// Updates the IP address of a persisted machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the IP cannot be updated.
    pub fn update_ip(&self, name: &str, ip: Option<&str>) -> Result<()> {
        self.update(name, |machine| {
            machine.ip_address = ip.map(ToString::to_string);
        })
    }

    /// Applies a mutation to a persisted machine config in a single
    /// load→mutate→write cycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be loaded or written.
    pub fn update(&self, name: &str, mutate: impl FnOnce(&mut PersistedMachine)) -> Result<()> {
        let mut machine = self.load(name)?;
        mutate(&mut machine);

        let content = toml::to_string_pretty(&machine)
            .map_err(|e| CoreError::config(format!("failed to serialize config: {e}")))?;

        atomic_write(&self.config_path(name), content.as_bytes())?;

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
            started_at: None,
            mounts: Vec::new(),
            state: MachineState::Created,
            vm_id: VmId::new(),
            cpus: 4,
            memory_mb: 4096,
            disk_gb: 50,
            kernel: Some("/path/to/kernel".to_string()),
            cmdline: Some("console=ttyS0".to_string()),
            block_devices: Vec::new(),
            distro: None,
            distro_version: None,
            disk_path: None,
            ssh_key_path: None,
            ip_address: None,
            cid: None,
            backend: arcbox_vmm::VmBackend::Hv,
            created_at,
        };

        persistence.save(&info).unwrap();

        let loaded = persistence.load("test-vm").unwrap();
        assert_eq!(loaded.name, "test-vm");
        assert_eq!(loaded.cpus, 4);
        assert_eq!(loaded.memory_mb, 4096);
        assert_eq!(loaded.kernel, Some("/path/to/kernel".to_string()));
        assert_eq!(loaded.cmdline, Some("console=ttyS0".to_string()));
        // The hypervisor backend must round-trip so a switch survives restart.
        assert_eq!(loaded.backend, arcbox_vmm::VmBackend::Hv);
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
                started_at: None,
                mounts: Vec::new(),
                state: MachineState::Created,
                vm_id: VmId::new(),
                cpus: 2,
                memory_mb: 2048,
                disk_gb: 20,
                kernel: None,
                cmdline: None,
                block_devices: Vec::new(),
                distro: None,
                distro_version: None,
                disk_path: None,
                ssh_key_path: None,
                ip_address: None,
                cid: None,
                backend: arcbox_vmm::VmBackend::default(),
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
            started_at: None,
            mounts: Vec::new(),
            state: MachineState::Created,
            vm_id: VmId::new(),
            cpus: 2,
            memory_mb: 2048,
            disk_gb: 20,
            kernel: None,
            cmdline: None,
            block_devices: Vec::new(),
            distro: None,
            distro_version: None,
            disk_path: None,
            ssh_key_path: None,
            ip_address: None,
            cid: None,
            backend: arcbox_vmm::VmBackend::default(),
            created_at: Utc::now(),
        };

        persistence.save(&info).unwrap();
        assert!(persistence.load("test-vm").is_ok());

        persistence.remove("test-vm").unwrap();
        assert!(persistence.load("test-vm").is_err());
    }

    #[test]
    fn test_update_batches_mutations() {
        let temp = TempDir::new().unwrap();
        let persistence = MachinePersistence::new(temp.path());

        let info = MachineInfo {
            name: "test-vm".to_string(),
            started_at: None,
            mounts: Vec::new(),
            state: MachineState::Created,
            vm_id: VmId::new(),
            cpus: 2,
            memory_mb: 2048,
            disk_gb: 20,
            kernel: None,
            cmdline: None,
            block_devices: Vec::new(),
            distro: None,
            distro_version: None,
            disk_path: None,
            ssh_key_path: None,
            ip_address: None,
            cid: None,
            backend: arcbox_vmm::VmBackend::default(),
            created_at: Utc::now(),
        };

        persistence.save(&info).unwrap();

        // Single update call sets both state and IP.
        persistence
            .update("test-vm", |m| {
                m.state = PersistedState::Running;
                m.ip_address = Some("10.0.2.15".to_string());
            })
            .unwrap();

        let loaded = persistence.load("test-vm").unwrap();
        assert_eq!(loaded.state, PersistedState::Running);
        assert_eq!(loaded.ip_address.as_deref(), Some("10.0.2.15"));
    }

    #[test]
    fn test_needs_recovery_detects_interrupted_running() {
        assert!(PersistedState::Running.needs_recovery());
        assert!(!PersistedState::Stopped.needs_recovery());
        assert!(!PersistedState::Created.needs_recovery());
    }

    #[test]
    fn test_persisted_running_maps_to_stopped_on_reload() {
        let temp = TempDir::new().unwrap();
        let persistence = MachinePersistence::new(temp.path());

        let info = MachineInfo {
            name: "crash-vm".to_string(),
            started_at: None,
            mounts: Vec::new(),
            state: MachineState::Running,
            vm_id: VmId::new(),
            cpus: 2,
            memory_mb: 2048,
            disk_gb: 20,
            kernel: None,
            cmdline: None,
            block_devices: Vec::new(),
            distro: None,
            distro_version: None,
            disk_path: None,
            ssh_key_path: None,
            ip_address: Some("10.0.2.15".to_string()),
            cid: None,
            backend: arcbox_vmm::VmBackend::default(),
            created_at: Utc::now(),
        };
        persistence.save(&info).unwrap();

        // Simulate daemon restart: load and check recovery flag.
        let loaded = persistence.load("crash-vm").unwrap();
        assert_eq!(loaded.state, PersistedState::Running);
        assert!(loaded.state.needs_recovery());

        // After recovery, MachineState maps Running → Stopped.
        let state: MachineState = loaded.state.into();
        assert_eq!(state, MachineState::Stopped);

        // Correcting the persisted state should stick.
        persistence
            .update_state("crash-vm", MachineState::Stopped)
            .unwrap();
        let reloaded = persistence.load("crash-vm").unwrap();
        assert_eq!(reloaded.state, PersistedState::Stopped);
        assert!(!reloaded.state.needs_recovery());
    }
}
