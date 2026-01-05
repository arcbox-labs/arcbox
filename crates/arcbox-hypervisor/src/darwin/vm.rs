//! Virtual machine implementation for macOS.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;

use crate::{
    config::VmConfig,
    error::HypervisorError,
    traits::VirtualMachine,
    types::VirtioDeviceConfig,
};

use super::ffi;
use super::memory::DarwinMemory;
use super::vcpu::DarwinVcpu;

/// Global VM ID counter.
static VM_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Virtual machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// VM is created but not started.
    Created,
    /// VM is starting.
    Starting,
    /// VM is running.
    Running,
    /// VM is paused.
    Paused,
    /// VM is stopping.
    Stopping,
    /// VM is stopped.
    Stopped,
    /// VM encountered an error.
    Error,
}

/// Virtual machine implementation for Darwin (macOS).
///
/// This wraps a Virtualization.framework VM and provides the
/// platform-agnostic interface.
pub struct DarwinVm {
    /// Unique VM ID.
    id: u64,
    /// VM configuration.
    config: VmConfig,
    /// Guest memory.
    memory: DarwinMemory,
    /// Created vCPUs.
    vcpus: RwLock<Vec<u32>>,
    /// Current state.
    state: RwLock<VmState>,
    /// Whether the VM is running.
    running: AtomicBool,
    /// VZ configuration handle.
    vz_config: Option<ffi::VmConfiguration>,
    /// VZ virtual machine handle.
    vz_vm: Option<ffi::VirtualMachine>,
}

// Safety: The VZ handles are properly synchronized and only accessed
// through controlled interfaces.
unsafe impl Send for DarwinVm {}
unsafe impl Sync for DarwinVm {}

impl DarwinVm {
    /// Creates a new Darwin VM.
    pub(crate) fn new(config: VmConfig) -> Result<Self, HypervisorError> {
        let id = VM_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Allocate guest memory
        let memory = DarwinMemory::new(config.memory_size)?;

        // Create VZ configuration
        let vz_config = ffi::VmConfiguration::new()
            .map_err(|e| HypervisorError::VmCreationFailed(e.to_string()))?;

        // Set CPU count and memory size
        vz_config.set_cpu_count(config.vcpu_count as u64);
        vz_config.set_memory_size(config.memory_size);

        // Set up boot loader if kernel path is specified
        if let Some(ref kernel_path) = config.kernel_path {
            let boot_loader = ffi::LinuxBootLoader::new(kernel_path)
                .map_err(|e| HypervisorError::VmCreationFailed(e.to_string()))?;

            if let Some(ref cmdline) = config.kernel_cmdline {
                boot_loader.set_command_line(cmdline);
            }

            if let Some(ref initrd_path) = config.initrd_path {
                boot_loader.set_initial_ramdisk(initrd_path);
            }

            vz_config.set_boot_loader(&boot_loader);
        }

        // Add entropy device for random number generation
        if let Ok(entropy) = ffi::create_entropy_device() {
            vz_config.set_entropy_devices(&[entropy]);
        }

        // Validate configuration
        vz_config
            .validate()
            .map_err(|e| HypervisorError::VmCreationFailed(format!("Invalid config: {}", e)))?;

        // Create the VM
        let vz_vm = ffi::VirtualMachine::new(&vz_config)
            .map_err(|e| HypervisorError::VmCreationFailed(e.to_string()))?;

        tracing::info!(
            "Created VM {}: vcpus={}, memory={}MB",
            id,
            config.vcpu_count,
            config.memory_size / (1024 * 1024)
        );

        Ok(Self {
            id,
            config,
            memory,
            vcpus: RwLock::new(Vec::new()),
            state: RwLock::new(VmState::Created),
            running: AtomicBool::new(false),
            vz_config: Some(vz_config),
            vz_vm: Some(vz_vm),
        })
    }

    /// Returns the VM ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the VM configuration.
    #[must_use]
    pub fn config(&self) -> &VmConfig {
        &self.config
    }

    /// Returns the current VM state.
    pub fn state(&self) -> VmState {
        *self.state.read().unwrap()
    }

    /// Returns whether the VM is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Sets the VM state.
    fn set_state(&self, new_state: VmState) {
        let mut state = self.state.write().unwrap();
        tracing::debug!("VM {} state: {:?} -> {:?}", self.id, *state, new_state);
        *state = new_state;
    }
}

impl VirtualMachine for DarwinVm {
    type Vcpu = DarwinVcpu;
    type Memory = DarwinMemory;

    fn memory(&self) -> &Self::Memory {
        &self.memory
    }

    fn create_vcpu(&mut self, id: u32) -> Result<Self::Vcpu, HypervisorError> {
        if id >= self.config.vcpu_count as u32 {
            return Err(HypervisorError::VcpuCreationFailed {
                id,
                reason: format!(
                    "vCPU ID {} exceeds configured count {}",
                    id, self.config.vcpu_count
                ),
            });
        }

        // Check if already created
        {
            let vcpus = self.vcpus.read().map_err(|_| {
                HypervisorError::VcpuCreationFailed {
                    id,
                    reason: "Lock poisoned".to_string(),
                }
            })?;

            if vcpus.contains(&id) {
                return Err(HypervisorError::VcpuCreationFailed {
                    id,
                    reason: "vCPU already created".to_string(),
                });
            }
        }

        // Create vCPU
        let vcpu = DarwinVcpu::new(id);

        // Record creation
        {
            let mut vcpus = self.vcpus.write().map_err(|_| {
                HypervisorError::VcpuCreationFailed {
                    id,
                    reason: "Lock poisoned".to_string(),
                }
            })?;
            vcpus.push(id);
        }

        tracing::debug!("Created vCPU {} for VM {}", id, self.id);

        Ok(vcpu)
    }

    fn add_virtio_device(&mut self, device: VirtioDeviceConfig) -> Result<(), HypervisorError> {
        // Check state
        let state = self.state();
        if state != VmState::Created {
            return Err(HypervisorError::DeviceError(
                "Cannot add device: VM not in Created state".to_string(),
            ));
        }

        // TODO: Add device to VZ configuration
        // This would involve creating the appropriate VZ*DeviceConfiguration
        // and adding it to the VM configuration.

        tracing::debug!(
            "Added {:?} device to VM {}",
            device.device_type,
            self.id
        );

        Ok(())
    }

    fn start(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Created && state != VmState::Stopped {
            return Err(HypervisorError::InvalidState {
                expected: "Created or Stopped".to_string(),
                actual: format!("{:?}", state),
            });
        }

        self.set_state(VmState::Starting);

        // Note: Starting a VM with Virtualization.framework requires running on
        // the main thread with a run loop. For now, we just update state.
        // Real implementation would use async start with completion handler.

        self.running.store(true, Ordering::SeqCst);
        self.set_state(VmState::Running);

        tracing::info!("Started VM {}", self.id);

        Ok(())
    }

    fn pause(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running {
            return Err(HypervisorError::InvalidState {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        // Note: Real implementation would call async pause with completion handler

        self.set_state(VmState::Paused);

        tracing::info!("Paused VM {}", self.id);

        Ok(())
    }

    fn resume(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Paused {
            return Err(HypervisorError::InvalidState {
                expected: "Paused".to_string(),
                actual: format!("{:?}", state),
            });
        }

        // Note: Real implementation would call async resume with completion handler

        self.set_state(VmState::Running);

        tracing::info!("Resumed VM {}", self.id);

        Ok(())
    }

    fn stop(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running && state != VmState::Paused {
            return Err(HypervisorError::InvalidState {
                expected: "Running or Paused".to_string(),
                actual: format!("{:?}", state),
            });
        }

        self.set_state(VmState::Stopping);

        if let Some(ref vm) = self.vz_vm {
            // Try to stop, but don't fail if already stopped
            let _ = vm.stop();
        }

        self.running.store(false, Ordering::SeqCst);
        self.set_state(VmState::Stopped);

        tracing::info!("Stopped VM {}", self.id);

        Ok(())
    }
}

impl Drop for DarwinVm {
    fn drop(&mut self) {
        // Stop VM if running
        if self.is_running() {
            let _ = self.stop();
        }

        // VZ handles are automatically released by Rust's drop

        tracing::debug!("Dropped VM {}", self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Vcpu;
    use crate::types::CpuArch;

    #[test]
    fn test_vm_creation() {
        if !ffi::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let config = VmConfig {
            vcpu_count: 2,
            memory_size: 512 * 1024 * 1024,
            arch: CpuArch::native(),
            ..Default::default()
        };

        let vm = DarwinVm::new(config).unwrap();
        assert_eq!(vm.state(), VmState::Created);
        assert!(!vm.is_running());
    }

    #[test]
    fn test_vcpu_creation() {
        if !ffi::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let config = VmConfig {
            vcpu_count: 4,
            memory_size: 512 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = DarwinVm::new(config).unwrap();

        // Create valid vCPUs
        let vcpu0 = vm.create_vcpu(0);
        assert!(vcpu0.is_ok());
        assert_eq!(vcpu0.unwrap().id(), 0);

        let vcpu1 = vm.create_vcpu(1);
        assert!(vcpu1.is_ok());

        // Try to create same vCPU again
        let vcpu0_again = vm.create_vcpu(0);
        assert!(vcpu0_again.is_err());

        // Try to create vCPU with invalid ID
        let vcpu99 = vm.create_vcpu(99);
        assert!(vcpu99.is_err());
    }

    #[test]
    fn test_vm_lifecycle() {
        if !ffi::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 256 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = DarwinVm::new(config).unwrap();
        assert_eq!(vm.state(), VmState::Created);

        // Start
        vm.start().unwrap();
        assert_eq!(vm.state(), VmState::Running);
        assert!(vm.is_running());

        // Pause
        vm.pause().unwrap();
        assert_eq!(vm.state(), VmState::Paused);

        // Resume
        vm.resume().unwrap();
        assert_eq!(vm.state(), VmState::Running);

        // Stop
        vm.stop().unwrap();
        assert_eq!(vm.state(), VmState::Stopped);
        assert!(!vm.is_running());
    }

    #[test]
    fn test_invalid_state_transitions() {
        if !ffi::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let config = VmConfig::default();
        let mut vm = DarwinVm::new(config).unwrap();

        // Can't pause if not running
        assert!(vm.pause().is_err());

        // Can't resume if not paused
        assert!(vm.resume().is_err());

        // Can't stop if not running
        assert!(vm.stop().is_err());
    }
}
