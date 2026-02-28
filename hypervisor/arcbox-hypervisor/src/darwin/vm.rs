//! Virtual machine implementation for macOS.
//!
//! This module uses arcbox-vz for Virtualization.framework bindings.

use std::os::unix::io::RawFd;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader, MemoryBalloonDeviceConfiguration,
    NetworkDeviceConfiguration, SerialPortConfiguration, SharedDirectory, SingleDirectoryShare,
    SocketDeviceConfiguration, StorageDeviceConfiguration, VirtioFileSystemDeviceConfiguration,
    VirtualMachineConfiguration, VirtualMachineState,
};

use crate::{
    config::VmConfig,
    error::HypervisorError,
    traits::VirtualMachine,
    types::{DeviceSnapshot, VirtioDeviceConfig, VirtioDeviceType},
};

use super::memory::DarwinMemory;
use super::vcpu::DarwinVcpu;

/// Global VM ID counter.
static VM_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Reserved vsock port for IRQ signaling.
///
/// This port is used by the host to send IRQ signals to the guest.
/// The guest arcbox-agent listens on this port and handles incoming IRQ signals.
const VSOCK_IRQ_SIGNAL_PORT: u32 = 1025;

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
/// This wraps arcbox-vz types for Virtualization.framework and provides the
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
    /// VZ configuration builder (consumed when VM is built).
    vz_config: Option<VirtualMachineConfiguration>,
    /// VZ virtual machine handle (created from configuration).
    vz_vm: Option<arcbox_vz::VirtualMachine>,
    /// Serial port file descriptors (read, write).
    /// Read from VM output, write to VM input.
    serial_fds: Option<(RawFd, RawFd)>,
    /// Device configuration metadata for snapshots.
    ///
    /// Since Virtualization.framework doesn't expose device state, we store
    /// the original configuration to enable re-creation on restore.
    device_configs: Vec<VirtioDeviceConfig>,
    /// Vsock file descriptor for IRQ signaling (if established).
    ///
    /// Since Darwin's Virtualization.framework doesn't expose direct IRQ injection,
    /// we use vsock-based signaling as an alternative. The host sends IRQ signals
    /// through this connection, and the guest agent handles them.
    vsock_irq_fd: RwLock<Option<RawFd>>,
    /// Whether a balloon device has been configured.
    ///
    /// The balloon device configuration is stored here during VM setup
    /// and added to the VZ configuration in finalize_configuration().
    balloon_configured: bool,
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

        // Create VZ configuration using arcbox-vz API
        let mut vz_config = VirtualMachineConfiguration::new()
            .map_err(|e| HypervisorError::VmCreationFailed(e.to_string()))?;

        // Set CPU count and memory size
        vz_config.set_cpu_count(config.vcpu_count as usize);
        vz_config.set_memory_size(config.memory_size);

        // Set up generic platform for Linux VMs on Apple Silicon
        let platform = GenericPlatform::new().map_err(|e| {
            HypervisorError::VmCreationFailed(format!("Failed to create platform: {}", e))
        })?;
        if GenericPlatform::is_nested_virt_supported() {
            platform.set_nested_virt_enabled(true);
            tracing::info!("Nested virtualization enabled");
        }
        vz_config.set_platform(platform);
        tracing::debug!("Set generic platform configuration");

        // Set up boot loader if kernel path is specified
        if let Some(ref kernel_path) = config.kernel_path {
            let mut boot_loader = LinuxBootLoader::new(kernel_path).map_err(|e| {
                HypervisorError::VmCreationFailed(format!("Failed to create boot loader: {}", e))
            })?;
            tracing::debug!("Created boot loader for kernel: {}", kernel_path);

            if let Some(ref cmdline) = config.kernel_cmdline {
                boot_loader.set_command_line(cmdline);
                tracing::debug!("Set kernel cmdline: {}", cmdline);
            }

            if let Some(ref initrd_path) = config.initrd_path {
                boot_loader.set_initial_ramdisk(initrd_path);
                tracing::debug!("Set initrd: {}", initrd_path);
            }

            vz_config.set_boot_loader(boot_loader);
            tracing::debug!("Boot loader configured");
        }

        // Add entropy device for random number generation
        let entropy = EntropyDeviceConfiguration::new().map_err(|e| {
            HypervisorError::VmCreationFailed(format!("Failed to create entropy device: {}", e))
        })?;
        vz_config.add_entropy_device(entropy);
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
            serial_fds: None,
            device_configs: Vec::new(),
            vsock_irq_fd: RwLock::new(None),
            balloon_configured: false,
        })
    }

    /// Configures a serial console using pipes.
    ///
    /// Returns "pipe" on success. Use `read_console_output()` to read output.
    /// Note: Console output may not work with all Linux kernels. Virtio console
    /// driver must be properly configured in the guest kernel.
    pub fn setup_serial_console(&mut self) -> Result<String, HypervisorError> {
        // Use arcbox-vz's SerialPortConfiguration which handles pipe creation internally
        let serial_port = SerialPortConfiguration::virtio_console()
            .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;

        // Store FDs: (read_from_vm, write_to_vm)
        let read_fd = serial_port.read_fd().ok_or_else(|| {
            HypervisorError::DeviceError("Failed to get serial read fd".to_string())
        })?;
        let write_fd = serial_port.write_fd().ok_or_else(|| {
            HypervisorError::DeviceError("Failed to get serial write fd".to_string())
        })?;
        self.serial_fds = Some((read_fd, write_fd));

        tracing::info!(
            "Created serial console pipes: read_fd={}, write_fd={}",
            read_fd,
            write_fd
        );

        // Add serial port to configuration
        if let Some(ref mut vz_config) = self.vz_config {
            vz_config.add_serial_port(serial_port);
            tracing::debug!("Serial port configured (will be added to serialPorts)");
        }

        Ok("pipe".to_string())
    }

    /// Finalizes configuration and creates the actual VZ VM.
    fn finalize_configuration(&mut self) -> Result<(), HypervisorError> {
        let mut vz_config = self
            .vz_config
            .take()
            .ok_or_else(|| HypervisorError::VmCreationFailed("No VZ configuration".to_string()))?;

        // NOTE: Storage, network, serial, and other devices have already been added
        // via add_*_device methods during configuration phase.

        // Add balloon device if configured.
        if self.balloon_configured {
            let balloon = MemoryBalloonDeviceConfiguration::new().map_err(|e| {
                HypervisorError::DeviceError(format!(
                    "Failed to create balloon device configuration: {}",
                    e
                ))
            })?;
            vz_config.add_memory_balloon_device(balloon);
            tracing::debug!("Balloon device configured for VM {}", self.id);
        }

        // Build the VM. This validates configuration internally and creates
        // the VZVirtualMachine instance with a dedicated dispatch queue.
        let vz_vm = vz_config
            .build()
            .map_err(|e| HypervisorError::VmCreationFailed(format!("Failed to build VM: {}", e)))?;

        self.vz_vm = Some(vz_vm);

        tracing::debug!("VM {} configuration finalized", self.id);

        Ok(())
    }

    /// Waits for the VM to reach a specific state.
    ///
    /// Uses progressive backoff: starts with short spins then yields, avoiding
    /// the overhead of a fixed 100ms poll interval for fast transitions.
    fn wait_for_state(
        &self,
        target: VirtualMachineState,
        timeout: Duration,
    ) -> Result<(), HypervisorError> {
        let start = std::time::Instant::now();
        // Start with short intervals for fast state transitions, then back off.
        let mut poll_interval = Duration::from_millis(1);
        let max_interval = Duration::from_millis(50);

        loop {
            if let Some(ref vm) = self.vz_vm {
                let state = vm.state();
                tracing::debug!(
                    "VM {} current state: {:?}, target: {:?}",
                    self.id,
                    state,
                    target
                );

                if state == target {
                    return Ok(());
                }
                if state == VirtualMachineState::Error {
                    return Err(HypervisorError::VmError(
                        "VM entered error state".to_string(),
                    ));
                }
            }

            if start.elapsed() > timeout {
                if let Some(ref vm) = self.vz_vm {
                    let state = vm.state();
                    return Err(HypervisorError::timeout(format!(
                        "Timed out waiting for VM state {:?}, current state: {:?}",
                        target, state
                    )));
                }
                return Err(HypervisorError::timeout("Timed out waiting for VM state"));
            }

            std::thread::sleep(poll_interval);
            // Progressive backoff: 1ms → 2ms → 4ms → ... → 50ms cap.
            poll_interval = (poll_interval * 2).min(max_interval);
        }
    }

    /// Sends ACPI power button to guest and waits for shutdown.
    ///
    /// Returns `Ok(true)` if the VM reached `Stopped`, `Ok(false)` if graceful
    /// shutdown is unsupported or did not complete within `timeout`.
    pub fn request_stop_and_wait(&self, timeout: Duration) -> Result<bool, HypervisorError> {
        let vm = self
            .vz_vm
            .as_ref()
            .ok_or_else(|| HypervisorError::VmError("No VZ VM instance".to_string()))?;

        if !vm.can_request_stop() {
            tracing::debug!("VM {} cannot request graceful stop", self.id);
            return Ok(false);
        }

        vm.request_stop()
            .map_err(|e| HypervisorError::VmError(format!("Failed to request VM stop: {}", e)))?;

        match self.wait_for_state(VirtualMachineState::Stopped, timeout) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::warn!(
                    "VM {} did not stop gracefully within {:?}: {}",
                    self.id,
                    timeout,
                    e
                );
                Ok(false)
            }
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
        let (read_fd, _) = self
            .serial_fds
            .ok_or_else(|| HypervisorError::DeviceError("Console not configured".to_string()))?;

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
            tracing::debug!(
                "poll on fd {}: result={}, revents={:#x}",
                read_fd,
                poll_result,
                pfd.revents
            );

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
        let (master_fd, _) = self
            .serial_fds
            .ok_or_else(|| HypervisorError::DeviceError("Console not configured".to_string()))?;

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
        self.serial_fds
            .map(|(master_fd, _)| unsafe {
                let slave_name = libc::ptsname(master_fd);
                if !slave_name.is_null() {
                    std::ffi::CStr::from_ptr(slave_name)
                        .to_string_lossy()
                        .into_owned()
                } else {
                    String::new()
                }
            })
            .filter(|s| !s.is_empty())
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
            return Err(HypervisorError::VmStateError {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        // Get the VZ VM's socket devices using arcbox-vz API
        let vz_vm = self
            .vz_vm
            .as_ref()
            .ok_or_else(|| HypervisorError::VmError("No VZ VM instance".to_string()))?;

        let socket_devices = vz_vm.socket_devices();
        let socket_device = socket_devices.first().ok_or_else(|| {
            HypervisorError::DeviceError("No vsock device configured".to_string())
        })?;

        // Connect to the port using arcbox-vz's async connect
        tracing::debug!("Connecting to vsock port {} on VM {}", port, self.id);

        // Use tokio runtime to run async connect
        let rt = tokio::runtime::Handle::try_current().map_err(|_| {
            HypervisorError::DeviceError("No tokio runtime available for vsock connect".to_string())
        })?;

        // Use block_in_place to allow blocking in async context
        let connection = tokio::task::block_in_place(|| rt.block_on(socket_device.connect(port)))
            .map_err(|e| {
            HypervisorError::DeviceError(format!("vsock connect failed: {}", e))
        })?;

        // Get the raw fd and take ownership (prevents close on drop)
        let fd = connection.into_raw_fd();

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
    // For custom devices that need interrupt injection, we use vsock-based
    // signaling as an alternative. The host sends IRQ signals through a
    // vsock connection, and the guest agent handles them.
    //
    // Protocol: [opcode(1)] [gsi(4)] [level(1)]
    // - opcode 0x01: set_irq_line
    // - opcode 0x02: trigger_edge_irq
    // ========================================================================

    /// IRQ signal opcodes for vsock protocol.
    const IRQ_OPCODE_SET_LINE: u8 = 0x01;
    const IRQ_OPCODE_EDGE_TRIGGER: u8 = 0x02;

    /// Sets up vsock-based IRQ signaling.
    ///
    /// This establishes a vsock connection to the guest agent on the reserved
    /// IRQ signal port. Once established, `set_irq_line` and `trigger_edge_irq`
    /// will send signals through this connection.
    ///
    /// # Note
    /// The VM must be running and have a vsock device configured.
    /// The guest agent must be listening on `VSOCK_IRQ_SIGNAL_PORT`.
    pub fn setup_irq_signaling(&self) -> Result<(), HypervisorError> {
        // Check if already set up
        {
            let irq_fd = self.vsock_irq_fd.read().unwrap();
            if irq_fd.is_some() {
                tracing::debug!("IRQ signaling already set up for VM {}", self.id);
                return Ok(());
            }
        }

        tracing::info!(
            "Setting up vsock-based IRQ signaling for VM {} on port {}",
            self.id,
            VSOCK_IRQ_SIGNAL_PORT
        );

        let fd = self.connect_vsock(VSOCK_IRQ_SIGNAL_PORT)?;

        let mut irq_fd = self.vsock_irq_fd.write().unwrap();
        *irq_fd = Some(fd);

        tracing::info!("IRQ signaling established for VM {}, fd={}", self.id, fd);

        Ok(())
    }

    /// Tears down vsock-based IRQ signaling.
    pub fn teardown_irq_signaling(&self) {
        let mut irq_fd = self.vsock_irq_fd.write().unwrap();
        if let Some(fd) = irq_fd.take() {
            tracing::debug!("Closing IRQ signaling fd {} for VM {}", fd, self.id);
            unsafe {
                libc::close(fd);
            }
        }
    }

    /// Sends an IRQ signal through the vsock connection.
    ///
    /// Returns true if the signal was sent successfully, false if no IRQ
    /// signaling connection is established.
    fn send_irq_signal(&self, opcode: u8, gsi: u32, level: bool) -> bool {
        let irq_fd = self.vsock_irq_fd.read().unwrap();
        if let Some(fd) = *irq_fd {
            // Protocol: [opcode(1)] [gsi(4 LE)] [level(1)]
            let mut buf = [0u8; 6];
            buf[0] = opcode;
            buf[1..5].copy_from_slice(&gsi.to_le_bytes());
            buf[5] = u8::from(level);

            let written = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, 6) };

            if written == 6 {
                tracing::trace!(
                    "Sent IRQ signal: opcode={}, gsi={}, level={} on VM {}",
                    opcode,
                    gsi,
                    level,
                    self.id
                );
                return true;
            }
            tracing::warn!(
                "Failed to send IRQ signal on VM {}: wrote {} bytes instead of 6",
                self.id,
                written
            );
        }
        false
    }

    /// Sets the IRQ line level.
    ///
    /// If vsock-based IRQ signaling is established (via `setup_irq_signaling`),
    /// this sends a signal to the guest agent. Otherwise, it falls back to
    /// logging a warning since Virtualization.framework doesn't expose direct
    /// IRQ injection.
    pub fn set_irq_line(&self, gsi: u32, level: bool) -> Result<(), HypervisorError> {
        // Try vsock-based signaling first
        if self.send_irq_signal(Self::IRQ_OPCODE_SET_LINE, gsi, level) {
            return Ok(());
        }

        // Fall back to warning
        tracing::warn!(
            "set_irq_line(gsi={}, level={}) called on Darwin VM {} - \
            no IRQ signaling connection, call setup_irq_signaling() first",
            gsi,
            level,
            self.id
        );
        Ok(())
    }

    /// Triggers an edge-triggered interrupt.
    ///
    /// If vsock-based IRQ signaling is established, this sends a signal to
    /// the guest agent. Otherwise, it logs a warning.
    pub fn trigger_edge_irq(&self, gsi: u32) -> Result<(), HypervisorError> {
        // Try vsock-based signaling first (level is always true for edge-triggered)
        if self.send_irq_signal(Self::IRQ_OPCODE_EDGE_TRIGGER, gsi, true) {
            return Ok(());
        }

        // Fall back to warning
        tracing::warn!(
            "trigger_edge_irq(gsi={}) called on Darwin VM {} - \
            no IRQ signaling connection, call setup_irq_signaling() first",
            gsi,
            self.id
        );
        Ok(())
    }

    /// Registers an eventfd for IRQ injection.
    ///
    /// On Darwin, this is not supported. Use vsock-based signaling instead
    /// by calling `setup_irq_signaling()` and then `set_irq_line()`.
    pub fn register_irqfd(
        &self,
        _eventfd: RawFd,
        gsi: u32,
        _resample_fd: Option<RawFd>,
    ) -> Result<(), HypervisorError> {
        tracing::warn!(
            "register_irqfd(gsi={}) called on Darwin VM {} - not supported, \
            use setup_irq_signaling() + set_irq_line() for IRQ injection",
            gsi,
            self.id
        );
        Err(HypervisorError::DeviceError(
            "IRQFD not supported on Darwin - use vsock-based IRQ signaling".to_string(),
        ))
    }

    /// Unregisters an eventfd (not supported on Darwin).
    pub fn unregister_irqfd(&self, _eventfd: RawFd, gsi: u32) -> Result<(), HypervisorError> {
        tracing::warn!(
            "unregister_irqfd(gsi={}) called on Darwin VM {} - not supported",
            gsi,
            self.id
        );
        Ok(())
    }

    // ========================================================================
    // Memory Balloon Interface
    //
    // The VirtIO balloon device allows the host to dynamically manage guest
    // memory by "inflating" (reclaiming memory) or "deflating" (returning
    // memory). This helps achieve the <150MB idle memory target.
    // ========================================================================

    /// Returns whether a balloon device is configured for this VM.
    #[must_use]
    pub fn has_balloon_device(&self) -> bool {
        self.balloon_configured
    }

    /// Sets the target memory size for the balloon device.
    ///
    /// The balloon device will inflate or deflate to reach the target:
    /// - **Smaller target**: Balloon inflates, reclaiming memory from guest
    /// - **Larger target**: Balloon deflates, returning memory to guest
    ///
    /// # Arguments
    /// * `target_bytes` - Target memory size in bytes. Should be between
    ///   the minimum memory size and the VM's configured memory size.
    ///
    /// # Errors
    /// Returns an error if the VM is not running or no balloon device is configured.
    pub fn set_balloon_target_memory(&self, target_bytes: u64) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running {
            return Err(HypervisorError::VmStateError {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        if !self.balloon_configured {
            return Err(HypervisorError::DeviceError(
                "No balloon device configured".to_string(),
            ));
        }

        let vz_vm = self
            .vz_vm
            .as_ref()
            .ok_or_else(|| HypervisorError::DeviceError("VM not finalized".to_string()))?;

        let balloon = vz_vm.first_balloon_device().ok_or_else(|| {
            HypervisorError::DeviceError("No balloon device found on running VM".to_string())
        })?;

        balloon.set_target_memory_size(target_bytes);
        tracing::debug!(
            "VM {}: set balloon target memory to {} bytes ({}MB)",
            self.id,
            target_bytes,
            target_bytes / (1024 * 1024)
        );

        Ok(())
    }

    /// Gets the current target memory size from the balloon device.
    ///
    /// Returns the target memory size in bytes, or 0 if no balloon is configured
    /// or the VM is not running.
    #[must_use]
    pub fn get_balloon_target_memory(&self) -> u64 {
        if self.state() != VmState::Running || !self.balloon_configured {
            return 0;
        }

        self.vz_vm
            .as_ref()
            .and_then(|vm| vm.first_balloon_device())
            .map_or(0, |balloon| balloon.target_memory_size())
    }

    /// Returns the configured memory size for this VM.
    ///
    /// This is the maximum memory the guest can use when the balloon is fully deflated.
    #[must_use]
    pub fn configured_memory_size(&self) -> u64 {
        self.config.memory_size
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
            let vcpus = self
                .vcpus
                .read()
                .map_err(|_| HypervisorError::VcpuCreationFailed {
                    id,
                    reason: "Lock poisoned".to_string(),
                })?;

            if vcpus.contains(&id) {
                return Err(HypervisorError::VcpuCreationFailed {
                    id,
                    reason: "vCPU already created".to_string(),
                });
            }
        }

        // Create vCPU for managed execution.
        // On Virtualization.framework, vCPU execution is managed internally by the framework.
        // The vCPU struct is a lightweight handle that tracks vCPU ID and state.
        // NOTE: We pass null_mut() because arcbox-vz doesn't expose VM's raw pointer.
        // The VM state is queried through the DarwinVm's state() method instead.
        let vcpu = DarwinVcpu::new_managed(id, std::ptr::null_mut());

        // Record creation
        {
            let mut vcpus =
                self.vcpus
                    .write()
                    .map_err(|_| HypervisorError::VcpuCreationFailed {
                        id,
                        reason: "Lock poisoned".to_string(),
                    })?;
            vcpus.push(id);
        }

        tracing::debug!("Created vCPU {} for VM {} (managed execution)", id, self.id);

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

        // Get mutable reference to config
        let vz_config = self.vz_config.as_mut().ok_or_else(|| {
            HypervisorError::DeviceError("VZ configuration not available".to_string())
        })?;

        match device.device_type {
            VirtioDeviceType::Block => {
                // Create block device using arcbox-vz API
                if let Some(ref path) = device.path {
                    let storage_device =
                        StorageDeviceConfiguration::disk_image(path, device.read_only)
                            .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    vz_config.add_storage_device(storage_device);
                    tracing::debug!("Added block device: {}", path);
                }
            }
            VirtioDeviceType::Net => {
                let network_device = if let Some(fd) = device.net_fd {
                    // File-handle attachment: host owns the full network stack.
                    NetworkDeviceConfiguration::file_handle(fd)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?
                } else {
                    // Fallback to Apple's built-in NAT attachment.
                    NetworkDeviceConfiguration::nat()
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?
                };
                vz_config.add_network_device(network_device);
                tracing::debug!(
                    "Added network device (file_handle={})",
                    device.net_fd.is_some()
                );
            }
            VirtioDeviceType::Console => {
                // Console is handled separately via setup_serial_console()
                tracing::debug!("Console device will be configured separately");
            }
            VirtioDeviceType::Fs => {
                // Create filesystem device using arcbox-vz API
                if let (Some(path), Some(tag)) = (&device.path, &device.tag) {
                    let directory = SharedDirectory::new(path, device.read_only)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    let share = SingleDirectoryShare::new(directory)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    let mut fs_device = VirtioFileSystemDeviceConfiguration::new(tag)
                        .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                    fs_device.set_share(share);
                    vz_config.add_directory_share(fs_device);
                    tracing::debug!("Added filesystem device: {} -> {}", tag, path);
                }
            }
            VirtioDeviceType::Vsock => {
                // Create vsock device using arcbox-vz API
                let socket_device = SocketDeviceConfiguration::new()
                    .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                vz_config.add_socket_device(socket_device);
                tracing::debug!("Added vsock device");
            }
            VirtioDeviceType::Rng => {
                // Entropy device is already added in new()
                tracing::debug!("Entropy device already configured");
            }
            VirtioDeviceType::Balloon => {
                // Mark balloon as configured
                // NOTE: arcbox-vz does not yet support balloon device configuration
                self.balloon_configured = true;
                tracing::debug!("Balloon device configured (pending arcbox-vz support)");
            }
            _ => {
                // Other device types (Gpu) not yet supported on Darwin
                tracing::warn!(
                    "Device type {:?} not supported on Darwin",
                    device.device_type
                );
            }
        }

        tracing::debug!("Added {:?} device to VM {}", device.device_type, self.id);

        // Store device configuration for snapshot/restore
        self.device_configs.push(device);

        Ok(())
    }

    fn start(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Created && state != VmState::Stopped {
            return Err(HypervisorError::VmStateError {
                expected: "Created or Stopped".to_string(),
                actual: format!("{:?}", state),
            });
        }

        self.set_state(VmState::Starting);

        // Finalize configuration if VM hasn't been created yet
        if self.vz_vm.is_none() {
            // Enable serial console for boot diagnostics unless already configured.
            if self.serial_fds.is_none() {
                if let Err(err) = self.setup_serial_console() {
                    tracing::warn!("Failed to set up serial console: {}", err);
                }
            }
            self.finalize_configuration()?;
        }

        // Start the VM using arcbox-vz's async API
        if let Some(ref vm) = self.vz_vm {
            tracing::debug!("Starting VM {} asynchronously...", self.id);

            // Get tokio runtime handle for async operations
            let rt = tokio::runtime::Handle::try_current().map_err(|_| {
                self.set_state(VmState::Error);
                HypervisorError::VmError("No tokio runtime available for VM start".to_string())
            })?;

            // Start the VM using arcbox-vz's async start
            // Use block_in_place to allow blocking in async context
            tokio::task::block_in_place(|| rt.block_on(vm.start())).map_err(|e| {
                self.set_state(VmState::Error);
                HypervisorError::VmError(format!("Failed to start VM: {}", e))
            })?;

            tracing::debug!("Waiting for VM {} to reach Running state...", self.id);

            // Wait for VM to reach Running state
            match self.wait_for_state(VirtualMachineState::Running, Duration::from_secs(30)) {
                Ok(()) => {
                    self.running.store(true, Ordering::SeqCst);
                    self.set_state(VmState::Running);
                    tracing::info!("Started VM {}", self.id);
                    if let Some(path) = self.console_path() {
                        tracing::info!("Serial console attached at {}", path);
                    }
                    Ok(())
                }
                Err(e) => {
                    // Check actual VM state for better error message
                    if let Some(ref vz) = self.vz_vm {
                        let state = vz.state();
                        tracing::error!(
                            "VM {} failed to start, current state: {:?}",
                            self.id,
                            state
                        );
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
            return Err(HypervisorError::VmStateError {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        if let Some(ref vm) = self.vz_vm {
            // Get tokio runtime handle for async operations
            let rt = tokio::runtime::Handle::try_current().map_err(|_| {
                HypervisorError::VmError("No tokio runtime available for VM pause".to_string())
            })?;

            // Pause using arcbox-vz's async pause
            // Use block_in_place to allow blocking in async context
            tokio::task::block_in_place(|| rt.block_on(vm.pause()))
                .map_err(|e| HypervisorError::VmError(format!("Failed to pause VM: {}", e)))?;

            self.wait_for_state(VirtualMachineState::Paused, Duration::from_secs(10))?;
        }

        self.set_state(VmState::Paused);
        tracing::info!("Paused VM {}", self.id);

        Ok(())
    }

    fn resume(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Paused {
            return Err(HypervisorError::VmStateError {
                expected: "Paused".to_string(),
                actual: format!("{:?}", state),
            });
        }

        if let Some(ref vm) = self.vz_vm {
            // Get tokio runtime handle for async operations
            let rt = tokio::runtime::Handle::try_current().map_err(|_| {
                HypervisorError::VmError("No tokio runtime available for VM resume".to_string())
            })?;

            // Resume using arcbox-vz's async resume
            // Use block_in_place to allow blocking in async context
            tokio::task::block_in_place(|| rt.block_on(vm.resume()))
                .map_err(|e| HypervisorError::VmError(format!("Failed to resume VM: {}", e)))?;

            self.wait_for_state(VirtualMachineState::Running, Duration::from_secs(10))?;
        }

        self.set_state(VmState::Running);
        tracing::info!("Resumed VM {}", self.id);

        Ok(())
    }

    fn stop(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running && state != VmState::Paused {
            return Err(HypervisorError::VmStateError {
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
                // Get tokio runtime handle for async operations
                let rt = tokio::runtime::Handle::try_current().ok();

                if let Some(rt) = rt {
                    // Stop using arcbox-vz's async stop
                    // Use block_in_place to allow blocking in async context
                    match tokio::task::block_in_place(|| rt.block_on(vm.stop())) {
                        Ok(()) => {
                            tracing::debug!("VM {} stop completed", self.id);
                        }
                        Err(e) => {
                            tracing::warn!("VM {} stop failed: {}", self.id, e);
                            // Continue with cleanup even if stop fails
                        }
                    }
                } else {
                    // No runtime available, try graceful request_stop
                    if let Err(e) = vm.request_stop() {
                        tracing::warn!("VM {} request_stop failed: {}", self.id, e);
                    }
                }

                // Wait for VM to reach Stopped state
                match self.wait_for_state(VirtualMachineState::Stopped, Duration::from_secs(10)) {
                    Ok(()) => {
                        tracing::debug!("VM {} reached Stopped state", self.id);
                    }
                    Err(e) => {
                        tracing::warn!("VM {} stop wait failed: {}", self.id, e);
                        // Continue with cleanup even if wait fails
                    }
                }
            } else {
                tracing::warn!(
                    "VM {} cannot be stopped (canStop=false), forcing state change",
                    self.id
                );
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

    fn vcpu_count(&self) -> u32 {
        self.config.vcpu_count as u32
    }

    fn snapshot_devices(&self) -> Result<Vec<DeviceSnapshot>, HypervisorError> {
        // Darwin Virtualization.framework does not expose internal device state.
        // However, we store the device configuration metadata which allows:
        // 1. Verifying device configuration matches on restore
        // 2. Re-creating devices with the same configuration
        //
        // The `state` field contains serialized VirtioDeviceConfig.
        let mut snapshots = Vec::new();

        for (idx, config) in self.device_configs.iter().enumerate() {
            // Serialize the device configuration to JSON bytes
            let state = serde_json::to_vec(config).unwrap_or_default();

            let name = match config.device_type {
                VirtioDeviceType::Block => {
                    if let Some(ref path) = config.path {
                        format!(
                            "block-{}-{}",
                            idx,
                            path.rsplit('/').next().unwrap_or("disk")
                        )
                    } else {
                        format!("block-{}", idx)
                    }
                }
                VirtioDeviceType::Net => format!("net-{}", idx),
                VirtioDeviceType::Console => "console-0".to_string(),
                VirtioDeviceType::Fs => {
                    if let Some(ref tag) = config.tag {
                        format!("fs-{}", tag)
                    } else {
                        format!("fs-{}", idx)
                    }
                }
                VirtioDeviceType::Vsock => "vsock-0".to_string(),
                _ => format!("device-{}", idx),
            };

            snapshots.push(DeviceSnapshot {
                device_type: config.device_type,
                name,
                state,
            });
        }

        // Also record serial port if configured (not in device_configs)
        if self.serial_fds.is_some() {
            snapshots.push(DeviceSnapshot {
                device_type: VirtioDeviceType::Console,
                name: "serial-0".to_string(),
                state: Vec::new(), // Serial state is managed by guest
            });
        }

        tracing::debug!(
            "snapshot_devices: captured {} device configurations for VM {}",
            snapshots.len(),
            self.id
        );

        Ok(snapshots)
    }

    fn restore_devices(&mut self, snapshots: &[DeviceSnapshot]) -> Result<(), HypervisorError> {
        // Darwin Virtualization.framework does not support live device state restore.
        // However, we can validate that the snapshot device configuration matches
        // the current VM configuration.
        //
        // For actual device restore, the VM should be recreated with the same
        // configuration from the snapshot metadata.
        tracing::info!(
            "restore_devices: validating {} devices for VM {}",
            snapshots.len(),
            self.id
        );

        // Deserialize and validate device configurations
        let mut mismatches = Vec::new();

        for snapshot in snapshots {
            // Try to deserialize the stored configuration
            if !snapshot.state.is_empty() {
                if let Ok(stored_config) =
                    serde_json::from_slice::<VirtioDeviceConfig>(&snapshot.state)
                {
                    // Find matching device in current configuration
                    let matches = self.device_configs.iter().any(|current| {
                        current.device_type == stored_config.device_type
                            && current.path == stored_config.path
                            && current.tag == stored_config.tag
                    });

                    if !matches {
                        mismatches.push(format!(
                            "{:?} device '{}' (path={:?}, tag={:?})",
                            stored_config.device_type,
                            snapshot.name,
                            stored_config.path,
                            stored_config.tag
                        ));
                    }
                }
            }
        }

        if !mismatches.is_empty() {
            tracing::warn!(
                "restore_devices: {} device(s) in snapshot don't match current configuration: {:?}",
                mismatches.len(),
                mismatches
            );
        }

        // Verify device count by type
        let snapshot_blocks = snapshots
            .iter()
            .filter(|s| s.device_type == VirtioDeviceType::Block)
            .count();
        let snapshot_nets = snapshots
            .iter()
            .filter(|s| s.device_type == VirtioDeviceType::Net)
            .count();
        let current_blocks = self
            .device_configs
            .iter()
            .filter(|c| c.device_type == VirtioDeviceType::Block)
            .count();
        let current_nets = self
            .device_configs
            .iter()
            .filter(|c| c.device_type == VirtioDeviceType::Net)
            .count();

        if snapshot_blocks != current_blocks {
            tracing::warn!(
                "Block device count mismatch: snapshot has {}, current VM has {}",
                snapshot_blocks,
                current_blocks
            );
        }

        if snapshot_nets != current_nets {
            tracing::warn!(
                "Network device count mismatch: snapshot has {}, current VM has {}",
                snapshot_nets,
                current_nets
            );
        }

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

        // VZ handles and dispatch queue are automatically released by arcbox-vz's drop

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
        if !arcbox_vz::is_supported() {
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
        if !arcbox_vz::is_supported() {
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
        if !arcbox_vz::is_supported() {
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
        if !arcbox_vz::is_supported() {
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

    #[test]
    fn test_balloon_device_configuration() {
        if !arcbox_vz::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 512 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = DarwinVm::new(config).unwrap();

        // Initially no balloon device
        assert!(!vm.has_balloon_device());

        // Add balloon device
        let balloon_config = VirtioDeviceConfig::balloon();
        vm.add_virtio_device(balloon_config).unwrap();

        // Now balloon should be configured
        assert!(vm.has_balloon_device());
        assert_eq!(vm.configured_memory_size(), 512 * 1024 * 1024);

        // Before starting, balloon target memory should return 0
        // (no running VM to query)
        assert_eq!(vm.get_balloon_target_memory(), 0);
    }

    #[test]
    fn test_balloon_device_pending() {
        if !arcbox_vz::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        // NOTE: Balloon device configuration is pending arcbox-vz support.
        // Once arcbox-vz adds BalloonDeviceConfiguration, this test should
        // verify that the balloon device can be created and configured.
        println!("Balloon device test skipped: pending arcbox-vz support");
    }
}
