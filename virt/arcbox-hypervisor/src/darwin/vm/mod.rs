//! Virtual machine implementation for macOS.
//!
//! This module uses arcbox-vz for Virtualization.framework bindings.

use std::os::unix::io::RawFd;
use std::sync::{
    RwLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

use super::memory::DarwinMemory;
use crate::{config::VmConfig, error::HypervisorError, types::VirtioDeviceConfig};
use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader, LinuxRosettaDirectoryShare,
    MemoryBalloonDeviceConfiguration, RosettaAvailability, SerialPortConfiguration,
    VirtioFileSystemDeviceConfiguration, VirtualMachineConfiguration, VirtualMachineState,
};

mod drop;
#[cfg(test)]
mod tests;
mod virtual_machine;

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
    /// Console serial port file descriptors (hvc0): kernel/init output.
    console_fds: Option<(RawFd, RawFd)>,
    /// Agent log serial port file descriptors (hvc1): dedicated agent tracing channel.
    agent_log_fds: Option<(RawFd, RawFd)>,
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
    /// and added to the VZ configuration in `finalize_configuration()`.
    balloon_configured: bool,
    /// When true, `Drop` will skip calling `self.stop()`. Used when the
    /// guest has already halted and the VF stop path would crash.
    skip_stop_on_drop: bool,
}

// Safety: The VZ handles are properly synchronized and only accessed
// through controlled interfaces.
unsafe impl Send for DarwinVm {}
unsafe impl Sync for DarwinVm {}

impl DarwinVm {
    /// Marks this VM to skip calling `stop()` when dropped.
    ///
    /// Use when the guest has already halted (e.g. ACPI shutdown) and the
    /// Virtualization.framework stop path would crash. FDs and other
    /// resources are still released normally via Drop.
    pub fn set_skip_stop_on_drop(&mut self) {
        self.skip_stop_on_drop = true;
    }

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
            HypervisorError::VmCreationFailed(format!("Failed to create platform: {e}"))
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
                HypervisorError::VmCreationFailed(format!("Failed to create boot loader: {e}"))
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
            HypervisorError::VmCreationFailed(format!("Failed to create entropy device: {e}"))
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
            console_fds: None,
            agent_log_fds: None,
            device_configs: Vec::new(),
            vsock_irq_fd: RwLock::new(None),
            balloon_configured: false,
            skip_stop_on_drop: false,
        })
    }

    /// Configures dual serial console ports using pipes.
    ///
    /// Creates two VirtIO console ports:
    /// - Port 0 (`hvc0`): kernel/init console output
    /// - Port 1 (`hvc1`): dedicated agent log channel
    ///
    /// Returns "pipe" on success. Use `read_console_output()` and
    /// `read_agent_log_output()` to read from each port.
    pub fn setup_serial_console(&mut self) -> Result<String, HypervisorError> {
        let make_port =
            |label: &str| -> Result<(SerialPortConfiguration, RawFd, RawFd), HypervisorError> {
                let port = SerialPortConfiguration::virtio_console()
                    .map_err(|e| HypervisorError::DeviceError(e.to_string()))?;
                let read_fd = port.read_fd().ok_or_else(|| {
                    HypervisorError::DeviceError(format!("Failed to get {label} read fd"))
                })?;
                let write_fd = port.write_fd().ok_or_else(|| {
                    HypervisorError::DeviceError(format!("Failed to get {label} write fd"))
                })?;
                Ok((port, read_fd, write_fd))
            };

        // Port 0 (hvc0): kernel/init console
        let (console_port, console_read, console_write) = make_port("console")?;
        self.console_fds = Some((console_read, console_write));
        tracing::info!(
            "Console port (hvc0): read_fd={}, write_fd={}",
            console_read,
            console_write
        );

        // Port 1 (hvc1): agent log channel
        let (agent_log_port, agent_read, agent_write) = make_port("agent-log")?;
        self.agent_log_fds = Some((agent_read, agent_write));
        tracing::info!(
            "Agent log port (hvc1): read_fd={}, write_fd={}",
            agent_read,
            agent_write
        );

        // Add ports in order — array index determines hvc device number.
        if let Some(ref mut vz_config) = self.vz_config {
            vz_config.add_serial_port(console_port);
            vz_config.add_serial_port(agent_log_port);
            tracing::debug!("Dual serial ports configured (hvc0 + hvc1)");
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
                    "Failed to create balloon device configuration: {e}"
                ))
            })?;
            vz_config.add_memory_balloon_device(balloon);
            tracing::debug!("Balloon device configured for VM {}", self.id);
        }

        // Build the VM. This validates configuration internally and creates
        // the VZVirtualMachine instance with a dedicated dispatch queue.
        let vz_vm = vz_config
            .build()
            .map_err(|e| HypervisorError::VmCreationFailed(format!("Failed to build VM: {e}")))?;

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
                        "Timed out waiting for VM state {target:?}, current state: {state:?}"
                    )));
                }
                return Err(HypervisorError::timeout("Timed out waiting for VM state"));
            }

            std::thread::sleep(poll_interval);
            // Progressive backoff: 1ms → 2ms → 4ms → ... → 50ms cap.
            poll_interval = (poll_interval * 2).min(max_interval);
        }
    }

    /// Waits for the VM to reach the Stopped state within `timeout`.
    ///
    /// Returns `Ok(true)` if stopped, `Ok(false)` on timeout.
    pub fn wait_for_stopped(&self, timeout: Duration) -> Result<bool, HypervisorError> {
        match self.wait_for_state(VirtualMachineState::Stopped, timeout) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::warn!("VM {} did not stop within {:?}: {}", self.id, timeout, e);
                Ok(false)
            }
        }
    }

    /// Non-blocking read of all available data from a serial port file descriptor.
    fn read_serial_fd(read_fd: RawFd) -> String {
        // SAFETY: All fd operations use valid pipe fds from setup_serial_console().
        // Flags are saved and restored to avoid side effects.
        unsafe {
            let flags = libc::fcntl(read_fd, libc::F_GETFL);
            if flags == -1 {
                let errno = *libc::__error();
                tracing::warn!("fcntl F_GETFL failed on fd {}: errno={}", read_fd, errno);
                return String::new();
            }

            if libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                let errno = *libc::__error();
                tracing::warn!("fcntl F_SETFL failed on fd {}: errno={}", read_fd, errno);
                return String::new();
            }

            let mut buffer = vec![0u8; 4096];
            let mut output = String::new();

            loop {
                let bytes_read = libc::read(
                    read_fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                );

                if bytes_read > 0 {
                    if let Ok(s) = std::str::from_utf8(&buffer[..bytes_read as usize]) {
                        output.push_str(s);
                    }
                } else if bytes_read == 0 {
                    break;
                } else {
                    let errno = *libc::__error();
                    if errno != libc::EAGAIN && errno != libc::EWOULDBLOCK {
                        tracing::warn!("Serial read error on fd {}: errno={}", read_fd, errno);
                    }
                    break;
                }
            }

            if libc::fcntl(read_fd, libc::F_SETFL, flags) == -1 {
                let errno = *libc::__error();
                tracing::warn!(
                    "fcntl F_SETFL restore failed on fd {}: errno={}",
                    read_fd,
                    errno
                );
            }
            output
        }
    }

    /// Reads available console output (hvc0) from the guest.
    pub fn read_console_output(&self) -> Result<String, HypervisorError> {
        let (read_fd, _) = self
            .console_fds
            .ok_or_else(|| HypervisorError::DeviceError("Console not configured".to_string()))?;
        Ok(Self::read_serial_fd(read_fd))
    }

    /// Reads available agent log output (hvc1) from the guest.
    pub fn read_agent_log_output(&self) -> Result<String, HypervisorError> {
        let (read_fd, _) = self.agent_log_fds.ok_or_else(|| {
            HypervisorError::DeviceError("Agent log port not configured".to_string())
        })?;
        Ok(Self::read_serial_fd(read_fd))
    }

    /// Writes input to the console (hvc0).
    pub fn write_console_input(&self, input: &str) -> Result<usize, HypervisorError> {
        let (_, write_fd) = self
            .console_fds
            .ok_or_else(|| HypervisorError::DeviceError("Console not configured".to_string()))?;

        // SAFETY: write_fd is a valid pipe fd from setup_serial_console().
        unsafe {
            let bytes_written =
                libc::write(write_fd, input.as_ptr() as *const libc::c_void, input.len());

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
        self.console_fds
            .map(|(master_fd, _)| unsafe {
                let slave_name = libc::ptsname(master_fd);
                if slave_name.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(slave_name)
                        .to_string_lossy()
                        .into_owned()
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
                actual: format!("{state:?}"),
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

        // Connect to the port using arcbox-vz's blocking connect.
        tracing::debug!("Connecting to vsock port {} on VM {}", port, self.id);
        let connection = socket_device
            .connect_blocking(port, std::time::Duration::from_secs(10))
            .map_err(|e| HypervisorError::DeviceError(format!("vsock connect failed: {e}")))?;

        // Get the raw fd and take ownership (prevents close on drop)
        let fd = connection.into_raw_fd();

        tracing::debug!("Connected to vsock port {}, fd={}", port, fd);

        Ok(fd)
    }

    /// Returns the VM ID.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the VM configuration.
    #[must_use]
    pub const fn config(&self) -> &VmConfig {
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

    // Memory Balloon Interface
    //
    // The VirtIO balloon device allows the host to dynamically manage guest
    // memory by "inflating" (reclaiming memory) or "deflating" (returning
    // memory). This helps achieve the <150MB idle memory target.

    /// Returns whether a balloon device is configured for this VM.
    #[must_use]
    pub const fn has_balloon_device(&self) -> bool {
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
                actual: format!("{state:?}"),
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
            .and_then(arcbox_vz::VirtualMachine::first_balloon_device)
            .map_or(0, |balloon| balloon.target_memory_size())
    }

    /// Returns the configured memory size for this VM.
    ///
    /// This is the maximum memory the guest can use when the balloon is fully deflated.
    #[must_use]
    pub const fn configured_memory_size(&self) -> u64 {
        self.config.memory_size
    }

    /// Adds a Rosetta x86_64 translation directory share to the VM.
    ///
    /// Exposes Apple's Rosetta binary as a VirtioFS share (tag: "rosetta").
    /// The guest mounts this and registers the binary via binfmt_misc to
    /// transparently run x86_64 ELF binaries at near-native speed.
    ///
    /// No-op (with warning) if Rosetta is not available on the host.
    pub fn add_rosetta_share(&mut self) -> Result<(), HypervisorError> {
        let availability = LinuxRosettaDirectoryShare::availability();
        match availability {
            RosettaAvailability::NotSupported => {
                tracing::warn!("Rosetta not supported on this platform (Intel Mac or macOS < 13)");
                return Ok(());
            }
            RosettaAvailability::NotInstalled => {
                tracing::warn!(
                    "Rosetta not installed — run `softwareupdate --install-rosetta` to enable x86_64 support"
                );
                return Ok(());
            }
            RosettaAvailability::Supported => {}
        }

        let vz_config = self
            .vz_config
            .as_mut()
            .ok_or_else(|| HypervisorError::VmStateError {
                expected: "Created (config available)".to_string(),
                actual: "config already consumed".to_string(),
            })?;

        let rosetta_share = match LinuxRosettaDirectoryShare::new() {
            Ok(share) => share,
            Err(e) => {
                tracing::warn!("Failed to create Rosetta directory share: {e}");
                return Ok(());
            }
        };

        let mut fs_device = match VirtioFileSystemDeviceConfiguration::new("rosetta") {
            Ok(device) => device,
            Err(e) => {
                tracing::warn!("Failed to create Rosetta VirtioFS device: {e}");
                return Ok(());
            }
        };
        fs_device.set_share(rosetta_share);
        vz_config.add_directory_share(fs_device);

        tracing::info!("Added Rosetta x86_64 translation share (tag: rosetta)");
        Ok(())
    }
}
