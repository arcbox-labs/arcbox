//! Virtual machine management.

use crate::error::{CoreError, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use uuid::Uuid;

use arcbox_vmm::{Vmm, VmmConfig};

/// VM identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmId(String);

impl VmId {
    /// Creates a new VM ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Returns the ID as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for VmId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// VM state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// VM created but not started.
    Created,
    /// VM is starting.
    Starting,
    /// VM is running.
    Running,
    /// VM is stopping.
    Stopping,
    /// VM is stopped.
    Stopped,
}

/// VM information.
#[derive(Debug, Clone)]
pub struct VmInfo {
    /// VM ID.
    pub id: VmId,
    /// VM state.
    pub state: VmState,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
}

/// VM configuration.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Kernel path.
    pub kernel: Option<String>,
    /// Initrd path.
    pub initrd: Option<String>,
    /// Kernel command line.
    pub cmdline: Option<String>,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            cpus: 4,
            memory_mb: 4096,
            kernel: None,
            initrd: None,
            cmdline: None,
        }
    }
}

/// Internal VM entry with info, config, and runtime state.
struct VmEntry {
    info: VmInfo,
    config: VmConfig,
    vmm: Option<Vmm>,
}

/// VM manager.
pub struct VmManager {
    vms: RwLock<HashMap<VmId, VmEntry>>,
}

impl VmManager {
    /// Creates a new VM manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vms: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be created.
    pub fn create(&self, config: VmConfig) -> Result<VmId> {
        let id = VmId::new();
        let info = VmInfo {
            id: id.clone(),
            state: VmState::Created,
            cpus: config.cpus,
            memory_mb: config.memory_mb,
        };

        let entry = VmEntry {
            info,
            config,
            vmm: None,
        };

        self.vms
            .write()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?
            .insert(id.clone(), entry);

        tracing::info!("Created VM {}", id);
        Ok(id)
    }

    /// Starts a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be started.
    pub fn start(&self, id: &VmId) -> Result<()> {
        let mut vms = self
            .vms
            .write()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if entry.info.state != VmState::Created && entry.info.state != VmState::Stopped {
            return Err(CoreError::InvalidState(format!(
                "cannot start VM in state {:?}",
                entry.info.state
            )));
        }

        entry.info.state = VmState::Starting;

        // Convert our config to VMM config
        let vmm_config = VmmConfig {
            vcpu_count: entry.config.cpus,
            memory_size: entry.config.memory_mb * 1024 * 1024,
            kernel_path: entry
                .config
                .kernel
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_default(),
            kernel_cmdline: entry.config.cmdline.clone().unwrap_or_default(),
            initrd_path: entry.config.initrd.as_ref().map(PathBuf::from),
            enable_rosetta: false,
            serial_console: true,
            virtio_console: true,
        };

        // Create and start VMM
        let mut vmm = Vmm::new(vmm_config).map_err(|e| CoreError::Vm(e.to_string()))?;
        vmm.start().map_err(|e| CoreError::Vm(e.to_string()))?;

        entry.vmm = Some(vmm);
        entry.info.state = VmState::Running;

        tracing::info!("Started VM {}", id);
        Ok(())
    }

    /// Stops a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be stopped.
    pub fn stop(&self, id: &VmId) -> Result<()> {
        let mut vms = self
            .vms
            .write()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if entry.info.state != VmState::Running {
            return Err(CoreError::InvalidState(format!(
                "cannot stop VM in state {:?}",
                entry.info.state
            )));
        }

        entry.info.state = VmState::Stopping;

        // Stop the VMM
        if let Some(ref mut vmm) = entry.vmm {
            vmm.stop().map_err(|e| CoreError::Vm(e.to_string()))?;
        }

        entry.vmm = None;
        entry.info.state = VmState::Stopped;

        tracing::info!("Stopped VM {}", id);
        Ok(())
    }

    /// Pauses a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be paused.
    pub fn pause(&self, id: &VmId) -> Result<()> {
        let mut vms = self
            .vms
            .write()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if let Some(ref mut vmm) = entry.vmm {
            vmm.pause().map_err(|e| CoreError::Vm(e.to_string()))?;
        }

        Ok(())
    }

    /// Resumes a paused VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be resumed.
    pub fn resume(&self, id: &VmId) -> Result<()> {
        let mut vms = self
            .vms
            .write()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if let Some(ref mut vmm) = entry.vmm {
            vmm.resume().map_err(|e| CoreError::Vm(e.to_string()))?;
        }

        Ok(())
    }

    /// Gets VM information.
    #[must_use]
    pub fn get(&self, id: &VmId) -> Option<VmInfo> {
        self.vms.read().ok()?.get(id).map(|e| e.info.clone())
    }

    /// Lists all VMs.
    #[must_use]
    pub fn list(&self) -> Vec<VmInfo> {
        self.vms
            .read()
            .map(|vms| vms.values().map(|e| e.info.clone()).collect())
            .unwrap_or_default()
    }

    /// Removes a VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be removed.
    pub fn remove(&self, id: &VmId) -> Result<()> {
        let mut vms = self
            .vms
            .write()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if entry.info.state == VmState::Running {
            return Err(CoreError::InvalidState(
                "cannot remove running VM".to_string(),
            ));
        }

        vms.remove(id);
        tracing::info!("Removed VM {}", id);
        Ok(())
    }
}

impl Default for VmManager {
    fn default() -> Self {
        Self::new()
    }
}
