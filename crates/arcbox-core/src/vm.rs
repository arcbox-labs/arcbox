//! Virtual machine management.

use crate::error::{CoreError, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use uuid::Uuid;

use arcbox_vmm::{SharedDirConfig as VmmSharedDirConfig, Vmm, VmmConfig};

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

/// Shared directory configuration for VirtioFS.
#[derive(Debug, Clone)]
pub struct SharedDirConfig {
    /// Host path to share.
    pub host_path: String,
    /// Tag for mounting in guest (e.g., "share").
    pub tag: String,
    /// Whether the share is read-only.
    pub read_only: bool,
}

impl SharedDirConfig {
    /// Creates a new shared directory configuration.
    #[must_use]
    pub fn new(host_path: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            host_path: host_path.into(),
            tag: tag.into(),
            read_only: false,
        }
    }

    /// Sets the share as read-only.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }
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
    /// Shared directories for VirtioFS.
    pub shared_dirs: Vec<SharedDirConfig>,
    /// Enable networking.
    pub networking: bool,
    /// Enable vsock.
    pub vsock: bool,
    /// Guest CID for vsock connections (Linux).
    pub guest_cid: Option<u32>,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            cpus: 4,
            memory_mb: 4096,
            kernel: None,
            initrd: None,
            cmdline: None,
            shared_dirs: Vec::new(),
            networking: true,
            vsock: true,
            guest_cid: None,
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

    /// Sets the guest CID for an existing VM configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is running or not found.
    pub fn set_guest_cid(&self, id: &VmId, guest_cid: u32) -> Result<()> {
        let mut vms = self
            .vms
            .write()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if matches!(entry.info.state, VmState::Running | VmState::Starting) {
            return Err(CoreError::InvalidState(format!(
                "cannot set guest_cid while VM is {:?}",
                entry.info.state
            )));
        }

        entry.config.guest_cid = Some(guest_cid);
        Ok(())
    }

    fn build_vmm_config(entry: &VmEntry) -> VmmConfig {
        let shared_dirs: Vec<VmmSharedDirConfig> = entry
            .config
            .shared_dirs
            .iter()
            .map(|sd| VmmSharedDirConfig {
                host_path: PathBuf::from(&sd.host_path),
                tag: sd.tag.clone(),
                read_only: sd.read_only,
            })
            .collect();

        VmmConfig {
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
            shared_dirs,
            networking: entry.config.networking,
            vsock: entry.config.vsock,
            guest_cid: entry.config.guest_cid,
        }
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

        let vmm_config = Self::build_vmm_config(entry);

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

    /// Connects to a vsock port on a running VM.
    ///
    /// This establishes a vsock connection to the specified port number
    /// on the guest VM. The VM must be running.
    ///
    /// # Arguments
    /// * `id` - The VM ID
    /// * `port` - The port number to connect to (e.g., 1024 for agent)
    ///
    /// # Returns
    /// A file descriptor for the connection that can be used for I/O.
    ///
    /// # Errors
    /// Returns an error if the VM is not found, not running, or connection fails.
    pub fn connect_vsock(&self, id: &VmId, port: u32) -> Result<std::os::unix::io::RawFd> {
        let vms = self
            .vms
            .read()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if entry.info.state != VmState::Running {
            return Err(CoreError::InvalidState(format!(
                "cannot connect vsock: VM is {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::Vm("VMM not initialized".to_string()))?;

        vmm.connect_vsock(port)
            .map_err(|e| CoreError::Vm(format!("vsock connect failed: {}", e)))
    }

    /// Reads serial console output from a running VM (macOS only).
    #[cfg(target_os = "macos")]
    pub fn read_console_output(&self, id: &VmId) -> Result<String> {
        let vms = self
            .vms
            .read()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;

        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;

        if entry.info.state != VmState::Running {
            return Err(CoreError::InvalidState(format!(
                "cannot read console output: VM is {:?}",
                entry.info.state
            )));
        }

        let vmm = entry
            .vmm
            .as_ref()
            .ok_or_else(|| CoreError::Vm("VMM not initialized".to_string()))?;

        vmm.read_console_output()
            .map_err(|e| CoreError::Vm(format!("read console failed: {}", e)))
    }

    #[cfg(test)]
    pub(crate) fn guest_cid_for_test(&self, id: &VmId) -> Option<u32> {
        self.vms
            .read()
            .ok()?
            .get(id)
            .and_then(|entry| entry.config.guest_cid)
    }

    #[cfg(test)]
    pub(crate) fn build_vmm_config_for_test(&self, id: &VmId) -> Result<VmmConfig> {
        let vms = self
            .vms
            .read()
            .map_err(|_| CoreError::Vm("lock poisoned".to_string()))?;
        let entry = vms
            .get(id)
            .ok_or_else(|| CoreError::NotFound(id.to_string()))?;
        Ok(Self::build_vmm_config(entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_guest_cid_updates_vm_config() {
        let manager = VmManager::new();
        let mut config = VmConfig::default();
        config.guest_cid = None;

        let vm_id = manager.create(config).unwrap();

        manager.set_guest_cid(&vm_id, 7).unwrap();
        assert_eq!(manager.guest_cid_for_test(&vm_id), Some(7));
    }

    #[test]
    fn test_build_vmm_config_includes_guest_cid() {
        let manager = VmManager::new();
        let mut config = VmConfig::default();
        config.guest_cid = Some(9);

        let vm_id = manager.create(config).unwrap();
        let vmm_config = manager.build_vmm_config_for_test(&vm_id).unwrap();
        assert_eq!(vmm_config.guest_cid, Some(9));
    }
}

impl Default for VmManager {
    fn default() -> Self {
        Self::new()
    }
}
