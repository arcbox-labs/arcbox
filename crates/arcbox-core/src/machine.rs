//! Linux machine management.
//!
//! A "machine" is a high-level abstraction over a VM that provides
//! a Linux environment for running containers.

use crate::error::{CoreError, Result};
use crate::persistence::MachinePersistence;
use crate::vm::{VmConfig, VmId, VmManager};
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

/// Machine information.
#[derive(Debug, Clone)]
pub struct MachineInfo {
    /// Machine name.
    pub name: String,
    /// Machine state.
    pub state: MachineState,
    /// Underlying VM ID.
    pub vm_id: VmId,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Disk size in GB.
    pub disk_gb: u64,
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
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            cpus: 4,
            memory_mb: 4096,
            disk_gb: 50,
        }
    }
}

/// Machine manager.
pub struct MachineManager {
    machines: RwLock<HashMap<String, MachineInfo>>,
    vm_manager: VmManager,
    persistence: MachinePersistence,
}

impl MachineManager {
    /// Creates a new machine manager.
    #[must_use]
    pub fn new(vm_manager: VmManager, data_dir: PathBuf) -> Self {
        let machines_dir = data_dir.join("machines");
        let persistence = MachinePersistence::new(&machines_dir);

        // Load persisted machines
        let mut machines = HashMap::new();
        for persisted in persistence.load_all() {
            // Create a new VM ID since the old one is no longer valid
            let vm_config = VmConfig {
                cpus: persisted.cpus,
                memory_mb: persisted.memory_mb,
                ..Default::default()
            };

            // Try to create the underlying VM
            if let Ok(vm_id) = vm_manager.create(vm_config) {
                let info = MachineInfo {
                    name: persisted.name.clone(),
                    state: persisted.state.into(),
                    vm_id,
                    cpus: persisted.cpus,
                    memory_mb: persisted.memory_mb,
                    disk_gb: persisted.disk_gb,
                };
                machines.insert(persisted.name, info);
            }
        }

        tracing::info!("Loaded {} persisted machines", machines.len());

        Self {
            machines: RwLock::new(machines),
            vm_manager,
            persistence,
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

        // Create underlying VM
        let vm_config = VmConfig {
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            ..Default::default()
        };
        let vm_id = self.vm_manager.create(vm_config)?;

        let info = MachineInfo {
            name: config.name.clone(),
            state: MachineState::Created,
            vm_id,
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            disk_gb: config.disk_gb,
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
        let mut machines = self
            .machines
            .write()
            .map_err(|_| CoreError::Machine("lock poisoned".to_string()))?;

        let machine = machines
            .get_mut(name)
            .ok_or_else(|| CoreError::NotFound(name.to_string()))?;

        // Start underlying VM
        self.vm_manager.start(&machine.vm_id)?;
        machine.state = MachineState::Running;

        // Update persisted state
        let _ = self.persistence.update_state(name, MachineState::Running);

        Ok(())
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
}
