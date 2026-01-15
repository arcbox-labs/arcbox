//! Linux machine management.
//!
//! A "machine" is a high-level abstraction over a VM that provides
//! a Linux environment for running containers.

use crate::error::{CoreError, Result};
use crate::persistence::MachinePersistence;
use crate::vm::{SharedDirConfig, VmConfig, VmId, VmManager};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// Machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineState {
    /// Machine created but not started.
    Created,
    /// Machine is starting.
    Starting,
    /// Machine is running.
    Running,
    /// Machine is stopping.
    Stopping,
    /// Machine is stopped.
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_assign_cid_propagates_to_vm_config() {
        let temp_dir = tempdir().unwrap();
        let vm_manager = VmManager::new();
        let machine_manager = MachineManager::new(vm_manager, temp_dir.path().to_path_buf());

        let name = machine_manager
            .create(MachineConfig {
                name: "cid-test".to_string(),
                ..Default::default()
            })
            .unwrap();

        let (vm_id, cid) = machine_manager.assign_cid_for_start(&name).unwrap();
        assert_eq!(cid, 3);
        assert_eq!(
            machine_manager.vm_manager.guest_cid_for_test(&vm_id),
            Some(cid)
        );
    }

    #[test]
    fn test_register_mock_machine() {
        let temp_dir = tempdir().unwrap();
        let vm_manager = VmManager::new();
        let machine_manager = MachineManager::new(vm_manager, temp_dir.path().to_path_buf());

        // Register a mock machine.
        machine_manager
            .register_mock_machine("test-mock", 42)
            .unwrap();

        // Verify the machine exists.
        let machine = machine_manager.get("test-mock").expect("machine should exist");
        assert_eq!(machine.name, "test-mock");
        assert_eq!(machine.cid, Some(42));
        assert_eq!(machine.state, MachineState::Running);
    }

    #[test]
    fn test_register_mock_machine_idempotent() {
        let temp_dir = tempdir().unwrap();
        let vm_manager = VmManager::new();
        let machine_manager = MachineManager::new(vm_manager, temp_dir.path().to_path_buf());

        // Register twice should succeed (idempotent).
        machine_manager
            .register_mock_machine("test-idempotent", 10)
            .unwrap();
        machine_manager
            .register_mock_machine("test-idempotent", 20)
            .unwrap();

        // Should still have the first CID (not overwritten).
        let machine = machine_manager.get("test-idempotent").unwrap();
        assert_eq!(machine.cid, Some(10));
    }
}

/// Machine information.
#[derive(Debug, Clone)]
pub struct MachineInfo {
    /// Machine name.
    pub name: String,
    /// Machine state.
    pub state: MachineState,
    /// Underlying VM ID.
    pub vm_id: VmId,
    /// vsock CID for agent communication (assigned when VM starts).
    pub cid: Option<u32>,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Disk size in GB.
    pub disk_gb: u64,
    /// Kernel path.
    pub kernel: Option<String>,
    /// Initrd path.
    pub initrd: Option<String>,
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Machine configuration.
#[derive(Debug, Clone)]
pub struct MachineConfig {
    /// Machine name.
    pub name: String,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Disk size in GB.
    pub disk_gb: u64,
    /// Kernel path.
    pub kernel: Option<String>,
    /// Initrd path.
    pub initrd: Option<String>,
    /// Kernel command line.
    pub cmdline: Option<String>,
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            cpus: 4,
            memory_mb: 4096,
            disk_gb: 50,
            kernel: None,
            initrd: None,
            cmdline: None,
        }
    }
}

/// Machine manager.
pub struct MachineManager {
    machines: RwLock<HashMap<String, MachineInfo>>,
    vm_manager: VmManager,
    persistence: MachinePersistence,
    /// Data directory for VirtioFS sharing.
    data_dir: PathBuf,
}

impl MachineManager {
    /// Creates a new machine manager.
    #[must_use]
    pub fn new(vm_manager: VmManager, data_dir: PathBuf) -> Self {
        let machines_dir = data_dir.join("machines");
        let persistence = MachinePersistence::new(&machines_dir);

        // Create the default shared directory config for VirtioFS
        // This shares the data_dir (e.g., ~/.arcbox) with the guest at /arcbox
        let shared_dirs = vec![SharedDirConfig::new(
            data_dir.to_string_lossy().to_string(),
            "arcbox",
        )];

        // Load persisted machines
        let mut machines = HashMap::new();
        for persisted in persistence.load_all() {
            // Create a new VM ID since the old one is no longer valid
            let vm_config = VmConfig {
                cpus: persisted.cpus,
                memory_mb: persisted.memory_mb,
                kernel: persisted.kernel.clone(),
                initrd: persisted.initrd.clone(),
                cmdline: persisted.cmdline.clone(),
                shared_dirs: shared_dirs.clone(),
                ..Default::default()
            };

            // Try to create the underlying VM
            if let Ok(vm_id) = vm_manager.create(vm_config) {
                let info = MachineInfo {
                    name: persisted.name.clone(),
                    state: persisted.state.into(),
                    vm_id,
                    cid: None, // Will be assigned when VM starts
                    cpus: persisted.cpus,
                    memory_mb: persisted.memory_mb,
                    disk_gb: persisted.disk_gb,
                    kernel: persisted.kernel.clone(),
                    initrd: persisted.initrd.clone(),
                    cmdline: persisted.cmdline,
                    created_at: persisted.created_at,
                };
                machines.insert(persisted.name, info);
            }
        }

        tracing::info!("Loaded {} persisted machines", machines.len());

        Self {
            machines: RwLock::new(machines),
            vm_manager,
            persistence,
            data_dir,
        }
    }

    /// Creates a new machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be created.
    pub fn create(&self, config: MachineConfig) -> Result<String> {
        // Check if machine already exists
        if self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?
            .contains_key(&config.name)
        {
            return Err(CoreError::AlreadyExists(config.name));
        }

        // Create shared directory for container rootfs via VirtioFS
        // This shares data_dir (e.g., ~/.arcbox) with the guest at /arcbox
        let shared_dirs = vec![SharedDirConfig::new(
            self.data_dir.to_string_lossy().to_string(),
            "arcbox",
        )];

        // Create underlying VM
        let vm_config = VmConfig {
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            kernel: config.kernel.clone(),
            initrd: config.initrd.clone(),
            cmdline: config.cmdline.clone(),
            shared_dirs,
            ..Default::default()
        };
        let vm_id = self.vm_manager.create(vm_config)?;

        let info = MachineInfo {
            name: config.name.clone(),
            state: MachineState::Created,
            vm_id,
            cid: None, // Will be assigned when VM starts
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            disk_gb: config.disk_gb,
            kernel: config.kernel,
            initrd: config.initrd,
            cmdline: config.cmdline,
            created_at: Utc::now(),
        };

        // Persist the machine config
        self.persistence.save(&info)?;

        self.machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?
            .insert(config.name.clone(), info);

        Ok(config.name)
    }

    /// Starts a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be started.
    pub fn start(&self, name: &str) -> Result<()> {
        let (vm_id, cid) = self.assign_cid_for_start(name)?;

        // Start underlying VM
        self.vm_manager.start(&vm_id)?;

        // Update machine state
        {
            let mut machines = self
                .machines
                .write()
                .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

            if let Some(machine) = machines.get_mut(name) {
                machine.state = MachineState::Running;
                machine.cid = Some(cid);

                tracing::info!(
                    "Machine '{}' started with CID {}",
                    name,
                    machine.cid.unwrap()
                );
            }
        }

        // Update persisted state
        let _ = self.persistence.update_state(name, MachineState::Running);

        Ok(())
    }

    fn assign_cid_for_start(&self, name: &str) -> Result<(VmId, u32)> {
        let (vm_id, running_count) = {
            let machines = self
                .machines
                .read()
                .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

            let machine = machines
                .get(name)
                .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

            // Count running machines. CIDs 0, 1 are reserved, 2 is the host. We start from 3.
            let running_count = machines
                .values()
                .filter(|m| m.state == MachineState::Running && m.cid.is_some())
                .count() as u32;

            (machine.vm_id.clone(), running_count)
        };

        let cid = 3 + running_count;
        self.vm_manager.set_guest_cid(&vm_id, cid)?;

        Ok((vm_id, cid))
    }

    /// Gets the vsock CID for a running machine.
    #[must_use]
    pub fn get_cid(&self, name: &str) -> Option<u32> {
        self.machines.read().ok()?.get(name)?.cid
    }

    /// Connects to the agent on a running machine.
    ///
    /// Returns an `AgentClient` that can be used to communicate with the
    /// guest agent for container operations.
    ///
    /// # Errors
    /// Returns an error if the machine is not found, not running, or connection fails.
    #[cfg(target_os = "macos")]
    pub fn connect_agent(&self, name: &str) -> Result<crate::agent_client::AgentClient> {
        use crate::agent_client::{AgentClient, AGENT_PORT};

        let machines = self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::InvalidState(format!(
                "machine '{}' is not running",
                name
            )));
        }

        let cid = machine
            .cid
            .ok_or_else(|| CoreError::Machine("CID not assigned".to_string()))?;

        // Connect to the agent via vsock through the VM
        let fd = self.vm_manager.connect_vsock(&machine.vm_id, AGENT_PORT)?;

        AgentClient::from_fd(cid, fd)
    }

    /// Connects to the agent on a running machine (Linux).
    #[cfg(target_os = "linux")]
    pub fn connect_agent(&self, name: &str) -> Result<crate::agent_client::AgentClient> {
        use crate::agent_client::AgentClient;

        let machines = self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::InvalidState(format!(
                "machine '{}' is not running",
                name
            )));
        }

        let cid = machine
            .cid
            .ok_or_else(|| CoreError::Machine("CID not assigned".to_string()))?;

        // On Linux, AgentClient connects directly via AF_VSOCK
        Ok(AgentClient::new(cid))
    }

    /// Reads serial console output for a running machine (macOS only).
    #[cfg(target_os = "macos")]
    pub fn read_console_output(&self, name: &str) -> Result<String> {
        let machines = self
            .machines
            .read()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::InvalidState(format!(
                "machine '{}' is not running",
                name
            )));
        }

        self.vm_manager.read_console_output(&machine.vm_id)
    }

    /// Stops a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be stopped.
    pub fn stop(&self, name: &str) -> Result<()> {
        let mut machines = self
            .machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get_mut(name)
            .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

        // Stop underlying VM
        self.vm_manager.stop(&machine.vm_id)?;
        machine.state = MachineState::Stopped;

        // Update persisted state
        let _ = self.persistence.update_state(name, MachineState::Stopped);

        Ok(())
    }

    /// Gets machine information.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<MachineInfo> {
        self.machines.read().ok()?.get(name).cloned()
    }

    /// Lists all machines.
    #[must_use]
    pub fn list(&self) -> Vec<MachineInfo> {
        self.machines
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Removes a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the machine cannot be removed.
    pub fn remove(&self, name: &str, force: bool) -> Result<()> {
        let mut machines = self
            .machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get(name)
            .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

        // Check if machine is running
        if machine.state == MachineState::Running && !force {
            return Err(CoreError::InvalidState(
                "cannot remove running machine (use --force)".to_string(),
            ));
        }

        // Stop if running and force is set
        if machine.state == MachineState::Running {
            let vm_id = machine.vm_id.clone();
            drop(machines); // Release lock before stopping
            self.vm_manager.stop(&vm_id)?;
            machines = self
                .machines
                .write()
                .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;
        }

        // Get VM ID before removing
        let vm_id = machines
            .get(name)
            .map(|m| m.vm_id.clone())
            .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

        // Remove from VM manager
        self.vm_manager.remove(&vm_id)?;

        // Remove from machines map
        machines.remove(name);

        // Remove persisted config
        let _ = self.persistence.remove(name);

        tracing::info!("Removed machine '{}'", name);
        Ok(())
    }

    /// Registers a mock machine for testing purposes.
    ///
    /// This method creates a machine entry without creating an actual VM.
    /// The machine will be in Running state with a mock CID.
    ///
    /// # Note
    /// This is intended for unit testing only and should not be used in production.
    pub fn register_mock_machine(&self, name: &str, cid: u32) -> Result<()> {
        let mut machines = self
            .machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        if machines.contains_key(name) {
            return Ok(()); // Already registered
        }

        let info = MachineInfo {
            name: name.to_string(),
            state: MachineState::Running,
            vm_id: VmId::new(), // Fake VM ID
            cid: Some(cid),
            cpus: 4,
            memory_mb: 4096,
            disk_gb: 50,
            kernel: None,
            initrd: None,
            cmdline: None,
            created_at: Utc::now(),
        };

        machines.insert(name.to_string(), info);
        tracing::debug!("Registered mock machine '{}' with CID {}", name, cid);
        Ok(())
    }
}
