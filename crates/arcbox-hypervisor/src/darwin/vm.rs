//! Virtual machine implementation for macOS.

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

use objc2::runtime::AnyObject;

use crate::{
    config::VmConfig,
    error::HypervisorError,
    traits::VirtualMachine,
    types::{VirtioDeviceConfig, VirtioDeviceType},
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
    /// Dispatch queue for VM operations.
    dispatch_queue: *mut AnyObject,
    /// Storage devices (raw pointers for VZ).
    storage_devices: Vec<*mut AnyObject>,
    /// Network devices.
    network_devices: Vec<*mut AnyObject>,
    /// Console device.
    console_device: Option<*mut AnyObject>,
    /// Serial port file descriptors (read, write).
    serial_fds: Option<(RawFd, RawFd)>,
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

        // Use main dispatch queue for VM operations
        // VZVirtualMachine requires all operations to be on its designated queue
        let dispatch_queue = ffi::get_main_queue();

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

        // Note: We don't validate or create VM yet - devices may be added later
        // The VM will be created in finalize_configuration()

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
            vz_vm: None,
            dispatch_queue,
            storage_devices: Vec::new(),
            network_devices: Vec::new(),
            console_device: None,
            serial_fds: None,
        })
    }

    /// Configures a serial console using PTY.
    ///
    /// Returns the path to the slave PTY device that can be used to connect.
    pub fn setup_serial_console(&mut self) -> Result<String, HypervisorError> {
        // Create a PTY pair
        let mut master_fd: libc::c_int = 0;
        let mut slave_fd: libc::c_int = 0;

        unsafe {
            let mut slave_name = [0u8; 256];
            let ret = libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                slave_name.as_mut_ptr() as *mut i8,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if ret != 0 {
                return Err(HypervisorError::DeviceError(
                    "Failed to create PTY".to_string(),
                ));
            }

            let slave_path = std::ffi::CStr::from_ptr(slave_name.as_ptr() as *const i8)
                .to_string_lossy()
                .into_owned();

            // Store FDs for later use
            self.serial_fds = Some((master_fd, master_fd)); // Use master for both read/write

            tracing::info!("Created serial console at {}", slave_path);

            // Create serial port attachment
            let read_handle = ffi::create_file_handle_for_reading(master_fd)
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
            let write_handle = ffi::create_file_handle_for_reading(master_fd)
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;

            let attachment = ffi::create_serial_port_attachment(read_handle, write_handle)
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;

            // Create console port configuration
            let port = ffi::create_console_port_configuration()
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
            ffi::set_console_port_attachment(port, attachment);
            ffi::set_console_port_name(port, "console");
            ffi::set_console_port_is_console(port, true);

            // Create console device and set ports
            let console = ffi::create_console_device()
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
            ffi::set_console_device_ports(console, &[port]);

            self.console_device = Some(console);

            Ok(slave_path)
        }
    }

    /// Finalizes configuration and creates the actual VZ VM.
    fn finalize_configuration(&mut self) -> Result<(), HypervisorError> {
        let vz_config = self.vz_config.as_ref().ok_or_else(|| {
            HypervisorError::VmCreationFailed("No VZ configuration".to_string())
        })?;

        // Set storage devices
        if !self.storage_devices.is_empty() {
            vz_config.set_storage_devices(&self.storage_devices);
        }

        // Set network devices
        if !self.network_devices.is_empty() {
            vz_config.set_network_devices(&self.network_devices);
        }

        // Set console device
        if let Some(console) = self.console_device {
            vz_config.set_console_devices(&[console]);
        }

        // Validate configuration
        vz_config
            .validate()
            .map_err(|e| HypervisorError::VmCreationFailed(format!("Invalid config: {}", e)))?;

        // Create the VM with dispatch queue
        let vz_vm = ffi::VirtualMachine::new_with_queue(vz_config, self.dispatch_queue)
            .map_err(|e| HypervisorError::VmCreationFailed(e.to_string()))?;

        self.vz_vm = Some(vz_vm);

        tracing::debug!("VM {} configuration finalized", self.id);

        Ok(())
    }

    /// Waits for the VM to reach a specific state.
    fn wait_for_state(&self, target: ffi::VZVirtualMachineState, timeout: Duration) -> Result<(), HypervisorError> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(10);

        loop {
            if let Some(ref vm) = self.vz_vm {
                let state = vm.state();
                if state == target {
                    return Ok(());
                }
                if state == ffi::VZVirtualMachineState::Error {
                    return Err(HypervisorError::VmError("VM entered error state".to_string()));
                }
            }

            if start.elapsed() > timeout {
                return Err(HypervisorError::Timeout("Timed out waiting for VM state".to_string()));
            }

            std::thread::sleep(poll_interval);
        }
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

        match device.device_type {
            VirtioDeviceType::Block => {
                // Create block device
                if let Some(ref path) = device.path {
                    let attachment = ffi::create_disk_attachment(path, device.read_only)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    let block_device = ffi::create_block_device(attachment)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    self.storage_devices.push(block_device);
                    tracing::debug!("Added block device: {}", path);
                }
            }
            VirtioDeviceType::Net => {
                // Create network device with NAT
                let attachment = ffi::create_nat_attachment()
                    .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                let network_device = ffi::create_network_device(attachment)
                    .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;

                // Set random MAC address
                if let Ok(mac) = ffi::create_random_mac() {
                    ffi::set_network_mac(network_device, mac);
                }

                self.network_devices.push(network_device);
                tracing::debug!("Added network device with NAT");
            }
            VirtioDeviceType::Console => {
                // Console is handled separately via setup_serial_console()
                tracing::debug!("Console device will be configured separately");
            }
            VirtioDeviceType::Fs => {
                // Create filesystem device
                if let (Some(path), Some(tag)) = (&device.path, &device.tag) {
                    let directory = ffi::create_shared_directory(path, device.read_only)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    let share = ffi::create_single_directory_share(directory)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    let fs_device = ffi::create_fs_device(tag, share)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;

                    // Add to directory sharing devices
                    if let Some(ref config) = self.vz_config {
                        config.set_directory_sharing_devices(&[fs_device]);
                    }
                    tracing::debug!("Added filesystem device: {} -> {}", tag, path);
                }
            }
            VirtioDeviceType::Vsock => {
                // Create vsock device
                let socket_device = ffi::create_socket_device()
                    .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                if let Some(ref config) = self.vz_config {
                    config.set_socket_devices(&[socket_device]);
                }
                tracing::debug!("Added vsock device");
            }
            VirtioDeviceType::Rng => {
                // Entropy device is already added in new()
                tracing::debug!("Entropy device already configured");
            }
            _ => {
                // Other device types (Balloon, Gpu) not yet supported on Darwin
                tracing::warn!("Device type {:?} not supported on Darwin", device.device_type);
            }
        }

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

        // Finalize configuration if VM hasn't been created yet
        if self.vz_vm.is_none() {
            self.finalize_configuration()?;
        }

        // Check if VM can start
        if let Some(ref vm) = self.vz_vm {
            tracing::debug!("Checking if VM {} can start...", self.id);

            let can_start = vm.can_start();
            tracing::debug!("VM {} can_start: {}", self.id, can_start);

            if !can_start {
                self.set_state(VmState::Error);
                return Err(HypervisorError::VmError("VM cannot start".to_string()));
            }

            tracing::debug!("Starting VM {} asynchronously...", self.id);

            // Start the VM asynchronously
            vm.start_async();

            tracing::debug!("Waiting for VM {} to reach Running state...", self.id);

            // Wait for VM to reach Running state
            match self.wait_for_state(ffi::VZVirtualMachineState::Running, Duration::from_secs(30)) {
                Ok(()) => {
                    self.running.store(true, Ordering::SeqCst);
                    self.set_state(VmState::Running);
                    tracing::info!("Started VM {}", self.id);
                    Ok(())
                }
                Err(e) => {
                    self.set_state(VmState::Error);
                    Err(e)
                }
            }
        } else {
            self.set_state(VmState::Error);
            Err(HypervisorError::VmError("No VZ VM instance".to_string()))
        }
    }

    fn pause(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running {
            return Err(HypervisorError::InvalidState {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        if let Some(ref vm) = self.vz_vm {
            if !vm.can_pause() {
                return Err(HypervisorError::VmError("VM cannot pause".to_string()));
            }

            vm.pause_async();

            // Wait for VM to reach Paused state
            self.wait_for_state(ffi::VZVirtualMachineState::Paused, Duration::from_secs(10))?;
        }

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

        if let Some(ref vm) = self.vz_vm {
            if !vm.can_resume() {
                return Err(HypervisorError::VmError("VM cannot resume".to_string()));
            }

            vm.resume_async();

            // Wait for VM to reach Running state
            self.wait_for_state(ffi::VZVirtualMachineState::Running, Duration::from_secs(10))?;
        }

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
            // Try graceful stop first
            if vm.can_request_stop() {
                let _ = vm.request_stop();
                // Give it a moment to stop gracefully
                std::thread::sleep(Duration::from_millis(500));
            }

            // Force stop if still running
            if vm.state() != ffi::VZVirtualMachineState::Stopped {
                let _ = vm.stop();
            }
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

        // Close serial FDs
        if let Some((read_fd, write_fd)) = self.serial_fds.take() {
            unsafe {
                libc::close(read_fd);
                if write_fd != read_fd {
                    libc::close(write_fd);
                }
            }
        }

        // Note: We're using the main queue now, so don't release it
        // If we switch to custom queues, uncomment:
        // if !self.dispatch_queue.is_null() {
        //     ffi::release_dispatch_queue(self.dispatch_queue);
        // }

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

        // Note: Actually starting the VM requires:
        // 1. The process to be signed with com.apple.security.virtualization entitlement
        // 2. Running on a thread with an active CFRunLoop
        //
        // For unit tests without proper signing, we can only verify state transitions
        // up to the point of calling start(). The full lifecycle test requires
        // a signed binary run from a GUI or properly configured CLI environment.

        // Attempt to start - will fail without entitlement or kernel
        match vm.start() {
            Ok(()) => {
                // If start succeeds, test full lifecycle
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
            Err(e) => {
                // Expected without proper signing/configuration
                println!("VM start failed (expected without entitlement): {}", e);
                // VM should be in Error or Starting state
                let state = vm.state();
                assert!(
                    state == VmState::Starting || state == VmState::Error,
                    "Unexpected state after failed start: {:?}",
                    state
                );
            }
        }
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
