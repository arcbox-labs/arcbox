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
    /// Serial port configuration (for serialPorts).
    serial_port: Option<*mut AnyObject>,
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

        // Create a custom serial queue for VM operations
        // VZVirtualMachine requires all operations to be called from its designated queue
        let dispatch_queue = ffi::create_dispatch_queue(&format!("com.arcbox.vm.{}", id));

        // Create VZ configuration
        let vz_config = ffi::VmConfiguration::new()
            .map_err(|e| HypervisorError::VmCreationFailed(e.to_string()))?;

        // Set CPU count and memory size
        vz_config.set_cpu_count(config.vcpu_count as u64);
        vz_config.set_memory_size(config.memory_size);

        // Set up generic platform for Linux VMs on Apple Silicon
        let platform = ffi::create_generic_platform()
            .map_err(|e| HypervisorError::VmCreationFailed(format!("Failed to create platform: {}", e)))?;
        vz_config.set_platform(platform);
        tracing::debug!("Set generic platform configuration");

        // Set up boot loader if kernel path is specified
        if let Some(ref kernel_path) = config.kernel_path {
            let boot_loader = ffi::LinuxBootLoader::new(kernel_path)
                .map_err(|e| HypervisorError::VmCreationFailed(format!("Failed to create boot loader: {}", e)))?;
            tracing::debug!("Created boot loader for kernel: {}", kernel_path);

            if let Some(ref cmdline) = config.kernel_cmdline {
                boot_loader.set_command_line(cmdline);
                tracing::debug!("Set kernel cmdline: {}", cmdline);
            }

            if let Some(ref initrd_path) = config.initrd_path {
                boot_loader.set_initial_ramdisk(initrd_path);
                tracing::debug!("Set initrd: {}", initrd_path);
            }

            vz_config.set_boot_loader(&boot_loader);
            tracing::debug!("Boot loader configured");
        }

        // Add entropy device for random number generation
        let entropy = ffi::create_entropy_device()
            .map_err(|e| HypervisorError::VmCreationFailed(format!("Failed to create entropy device: {}", e)))?;
        vz_config.set_entropy_devices(&[entropy]);
        tracing::debug!("Entropy device configured");

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
            serial_port: None,
            serial_fds: None,
        })
    }

    /// Configures a serial console using pipes.
    ///
    /// Returns "pipe" on success. Use `read_console_output()` to read output.
    /// Note: Console output may not work with all Linux kernels. Virtio console
    /// driver must be properly configured in the guest kernel.
    pub fn setup_serial_console(&mut self) -> Result<String, HypervisorError> {
        // Create two pipes: one for input to VM, one for output from VM
        // input_pipe: we write to [1], VM reads from [0]
        // output_pipe: VM writes to [1], we read from [0]
        let mut input_pipe: [libc::c_int; 2] = [0, 0];
        let mut output_pipe: [libc::c_int; 2] = [0, 0];

        unsafe {
            if libc::pipe(input_pipe.as_mut_ptr()) != 0 {
                return Err(HypervisorError::DeviceError(
                    "Failed to create input pipe".to_string(),
                ));
            }
            if libc::pipe(output_pipe.as_mut_ptr()) != 0 {
                libc::close(input_pipe[0]);
                libc::close(input_pipe[1]);
                return Err(HypervisorError::DeviceError(
                    "Failed to create output pipe".to_string(),
                ));
            }

            // Store FDs: (read_from_vm, write_to_vm)
            // read_from_vm = output_pipe[0] (we read VM output)
            // write_to_vm = input_pipe[1] (we send input to VM)
            self.serial_fds = Some((output_pipe[0], input_pipe[1]));

            tracing::info!("Created serial console pipes: input={}/{}, output={}/{}",
                input_pipe[0], input_pipe[1], output_pipe[0], output_pipe[1]);

            // Create serial port attachment
            // fileHandleForReading: VZ reads input to send to guest (from input_pipe[0])
            // fileHandleForWriting: VZ writes guest output (to output_pipe[1])
            let read_handle = ffi::create_file_handle_for_reading(input_pipe[0])
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
            let write_handle = ffi::create_file_handle_for_reading(output_pipe[1])
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
            let attachment = ffi::create_serial_port_attachment(read_handle, write_handle)
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;

            // Use VZVirtioConsoleDeviceSerialPortConfiguration with serialPorts
            let serial_port = ffi::create_virtio_serial_port_configuration(attachment)
                .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;

            self.serial_port = Some(serial_port);
            tracing::debug!("Serial port configured (will be added to serialPorts)");

            Ok("pipe".to_string())
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

        // Set serial ports (appears as hvc0 in guest)
        if let Some(serial_port) = self.serial_port {
            vz_config.set_serial_ports(&[serial_port]);
            tracing::debug!("Added serial port to configuration");
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
    ///
    /// This function polls the VM state directly (state property should be thread-safe to read).
    fn wait_for_state(&self, target: ffi::VZVirtualMachineState, timeout: Duration) -> Result<(), HypervisorError> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(100);

        loop {
            if let Some(ref vm) = self.vz_vm {
                // Read state directly - VZVirtualMachine.state should be thread-safe
                let state = vm.state();
                tracing::debug!("VM {} current state: {:?}, target: {:?}", self.id, state, target);

                if state == target {
                    return Ok(());
                }
                if state == ffi::VZVirtualMachineState::Error {
                    return Err(HypervisorError::VmError("VM entered error state".to_string()));
                }
            }

            if start.elapsed() > timeout {
                if let Some(ref vm) = self.vz_vm {
                    let state = vm.state();
                    return Err(HypervisorError::Timeout(format!(
                        "Timed out waiting for VM state {:?}, current state: {:?}",
                        target, state
                    )));
                }
                return Err(HypervisorError::Timeout("Timed out waiting for VM state".to_string()));
            }

            std::thread::sleep(poll_interval);
        }
    }

    /// Reads available console output from the PTY.
    ///
    /// Returns the output as a String. Returns an empty string if no output
    /// is available or if the console hasn't been set up.
    ///
    /// This is a non-blocking read that returns whatever data is currently
    /// available in the PTY buffer.
    pub fn read_console_output(&self) -> Result<String, HypervisorError> {
        let (read_fd, _) = self.serial_fds.ok_or_else(|| {
            HypervisorError::DeviceError("Console not configured".to_string())
        })?;

        tracing::debug!("read_console_output called, fd={}", read_fd);

        // Check if fd is valid
        unsafe {
            let flags = libc::fcntl(read_fd, libc::F_GETFL);
            if flags == -1 {
                let errno = *libc::__error();
                tracing::warn!("fcntl F_GETFL failed on fd {}: errno={}", read_fd, errno);
                return Ok(String::new());
            }

            // Use poll to check if data is available
            let mut pfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_result = libc::poll(&mut pfd, 1, 0);
            tracing::debug!("poll on fd {}: result={}, revents={:#x}", read_fd, poll_result, pfd.revents);

            // Set non-blocking mode for the read
            libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);

            let mut buffer = vec![0u8; 4096];
            let mut output = String::new();
            let mut total_bytes = 0isize;

            loop {
                let bytes_read = libc::read(
                    read_fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                );

                if bytes_read > 0 {
                    total_bytes += bytes_read;
                    if let Ok(s) = std::str::from_utf8(&buffer[..bytes_read as usize]) {
                        output.push_str(s);
                    }
                } else if bytes_read == 0 {
                    // EOF
                    break;
                } else {
                    // Error - check if it's EAGAIN/EWOULDBLOCK
                    let errno = *libc::__error();
                    if errno != libc::EAGAIN && errno != libc::EWOULDBLOCK {
                        tracing::warn!("Console read error on fd {}: errno={}", read_fd, errno);
                    }
                    break;
                }
            }

            // Log if we read any data
            if total_bytes > 0 {
                tracing::debug!("Read {} bytes from console fd {}", total_bytes, read_fd);
            }

            // Restore blocking mode
            libc::fcntl(read_fd, libc::F_SETFL, flags);

            Ok(output)
        }
    }

    /// Writes input to the console.
    ///
    /// This sends data to the guest's serial console input.
    pub fn write_console_input(&self, input: &str) -> Result<usize, HypervisorError> {
        let (master_fd, _) = self.serial_fds.ok_or_else(|| {
            HypervisorError::DeviceError("Console not configured".to_string())
        })?;

        unsafe {
            let bytes_written = libc::write(
                master_fd,
                input.as_ptr() as *const libc::c_void,
                input.len(),
            );

            if bytes_written < 0 {
                return Err(HypervisorError::DeviceError(format!(
                    "Failed to write to console: errno={}",
                    *libc::__error()
                )));
            }

            Ok(bytes_written as usize)
        }
    }

    /// Returns the path to the slave PTY device.
    ///
    /// This can be used with tools like `screen` or `minicom` to connect
    /// to the VM's serial console interactively.
    pub fn console_path(&self) -> Option<String> {
        self.serial_fds.map(|(master_fd, _)| {
            unsafe {
                let slave_name = libc::ptsname(master_fd);
                if !slave_name.is_null() {
                    std::ffi::CStr::from_ptr(slave_name)
                        .to_string_lossy()
                        .into_owned()
                } else {
                    String::new()
                }
            }
        }).filter(|s| !s.is_empty())
    }

    /// Connects to a vsock port on the guest.
    ///
    /// This establishes a vsock connection to the specified port number
    /// on the guest VM. The VM must be running and have a vsock device
    /// configured.
    ///
    /// # Arguments
    /// * `port` - The port number to connect to (e.g., 1024 for agent)
    ///
    /// # Returns
    /// A file descriptor for the connection that can be used for I/O.
    ///
    /// # Errors
    /// Returns an error if the VM is not running, no vsock device is
    /// configured, or the connection fails.
    pub fn connect_vsock(&self, port: u32) -> Result<std::os::unix::io::RawFd, HypervisorError> {
        // Check VM is running
        let state = self.state();
        if state != VmState::Running {
            return Err(HypervisorError::InvalidState {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        // Get the VZ VM's socket device
        let vz_vm = self.vz_vm.as_ref().ok_or_else(|| {
            HypervisorError::VmError("No VZ VM instance".to_string())
        })?;

        let socket_device = ffi::vm_first_socket_device(vz_vm.as_ptr()).ok_or_else(|| {
            HypervisorError::DeviceError("No vsock device configured".to_string())
        })?;

        // Connect to the port
        tracing::debug!("Connecting to vsock port {} on VM {}", port, self.id);

        let fd = ffi::vsock_connect_to_port(socket_device, self.dispatch_queue, port).map_err(|e| {
            HypervisorError::DeviceError(format!("vsock connect failed: {}", e))
        })?;

        tracing::debug!("Connected to vsock port {}, fd={}", port, fd);

        Ok(fd)
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

    // ========================================================================
    // IRQ Injection Interface (Darwin)
    //
    // NOTE: Apple's Virtualization.framework does NOT expose interrupt injection
    // APIs. VirtIO device interrupts are handled internally by the framework.
    //
    // For custom devices that need interrupt injection, consider:
    // 1. Using Hypervisor.framework directly (hv_vcpu_inject_extint)
    // 2. Using virtio-based signaling through existing VirtIO devices
    // 3. Using shared memory + polling as a fallback
    //
    // The methods below are stubs that log warnings when called.
    // ========================================================================

    /// Sets the IRQ line level (stub - not supported on Darwin).
    ///
    /// Darwin Virtualization.framework handles VirtIO interrupts internally.
    /// This method logs a warning and returns success to maintain API compatibility.
    pub fn set_irq_line(&self, gsi: u32, level: bool) -> Result<(), HypervisorError> {
        tracing::warn!(
            "set_irq_line(gsi={}, level={}) called on Darwin VM {} - \
            Virtualization.framework handles interrupts internally",
            gsi,
            level,
            self.id
        );
        // Return Ok to allow code that uses this to continue working,
        // but the interrupt won't actually be injected.
        Ok(())
    }

    /// Triggers an edge-triggered interrupt (stub - not supported on Darwin).
    pub fn trigger_edge_irq(&self, gsi: u32) -> Result<(), HypervisorError> {
        tracing::warn!(
            "trigger_edge_irq(gsi={}) called on Darwin VM {} - not supported",
            gsi,
            self.id
        );
        Ok(())
    }

    /// Registers an eventfd for IRQ injection (stub - not supported on Darwin).
    ///
    /// On Darwin, VirtIO devices use framework-managed interrupts.
    /// For custom interrupt handling, use vsock or shared memory.
    pub fn register_irqfd(
        &self,
        _eventfd: RawFd,
        gsi: u32,
        _resample_fd: Option<RawFd>,
    ) -> Result<(), HypervisorError> {
        tracing::warn!(
            "register_irqfd(gsi={}) called on Darwin VM {} - not supported, \
            use vsock or VirtIO for guest signaling",
            gsi,
            self.id
        );
        // Return error since this is a fundamental limitation
        Err(HypervisorError::DeviceError(
            "IRQFD not supported on Darwin Virtualization.framework".to_string(),
        ))
    }

    /// Unregisters an eventfd (stub - not supported on Darwin).
    pub fn unregister_irqfd(&self, _eventfd: RawFd, gsi: u32) -> Result<(), HypervisorError> {
        tracing::warn!(
            "unregister_irqfd(gsi={}) called on Darwin VM {} - not supported",
            gsi,
            self.id
        );
        Ok(())
    }
}

impl VirtualMachine for DarwinVm {
    type Vcpu = DarwinVcpu;
    type Memory = DarwinMemory;

    fn is_managed_execution(&self) -> bool {
        // Darwin Virtualization.framework manages vCPU execution internally
        true
    }

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

        // Create vCPU with VZ VM pointer for state queries.
        // On Virtualization.framework, vCPU execution is managed internally,
        // so the vCPU needs access to the VM's state for run() to work properly.
        let vz_vm_ptr = self.vz_vm.as_ref().map_or(std::ptr::null_mut(), |vm| vm.as_ptr());
        let vcpu = DarwinVcpu::new_managed(id, vz_vm_ptr);

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

        tracing::debug!(
            "Created vCPU {} for VM {} (managed execution, vz_vm={:?})",
            id,
            self.id,
            vz_vm_ptr
        );

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

        // Start the VM
        // All VZ operations must be dispatched to the VM's designated queue
        if let Some(ref vm) = self.vz_vm {
            tracing::debug!("Starting VM {} asynchronously...", self.id);

            // Start the VM asynchronously on its queue
            let queue = self.dispatch_queue;
            ffi::dispatch_sync_closure(queue, || {
                vm.start_async();
            });

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
                    // Check actual VM state for better error message
                    if let Some(ref vz) = self.vz_vm {
                        let state = vz.state();
                        tracing::error!("VM {} failed to start, current state: {:?}", self.id, state);
                    }
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
            let queue = self.dispatch_queue;
            ffi::dispatch_sync_closure(queue, || {
                vm.pause_async();
            });
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
            let queue = self.dispatch_queue;
            ffi::dispatch_sync_closure(queue, || {
                vm.resume_async();
            });
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
            // Check if VM can be stopped
            let can_stop = vm.can_stop();
            tracing::debug!("VM {} can_stop: {}", self.id, can_stop);

            if can_stop {
                // Use async stop API (macOS 12.0+)
                let queue = self.dispatch_queue;
                ffi::dispatch_sync_closure(queue, || {
                    vm.stop_async();
                });

                // Wait for VM to reach Stopped state
                match self.wait_for_state(ffi::VZVirtualMachineState::Stopped, Duration::from_secs(10)) {
                    Ok(()) => {
                        tracing::debug!("VM {} reached Stopped state", self.id);
                    }
                    Err(e) => {
                        tracing::warn!("VM {} stop wait failed: {}", self.id, e);
                        // Continue with cleanup even if wait fails
                    }
                }
            } else {
                tracing::warn!("VM {} cannot be stopped (canStop=false), forcing state change", self.id);
            }
        }

        self.running.store(false, Ordering::SeqCst);
        self.set_state(VmState::Stopped);

        tracing::info!("Stopped VM {}", self.id);

        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
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

        // Release the custom dispatch queue
        if !self.dispatch_queue.is_null() {
            ffi::release_dispatch_queue(self.dispatch_queue);
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
