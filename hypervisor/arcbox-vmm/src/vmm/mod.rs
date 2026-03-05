//! Main VMM implementation.
//!
//! The VMM (Virtual Machine Monitor) orchestrates all components needed to run
//! a virtual machine: hypervisor, vCPUs, memory, and devices.
//!
//! Platform-specific logic lives in submodules:
//! - `darwin`: macOS (Virtualization.framework) managed execution
//! - `linux`: Linux (KVM) manual execution

use std::any::Any;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::device::DeviceManager;
use crate::error::{Result, VmmError};
use crate::event::EventLoop;
use crate::irq::{Gsi, IrqChip, IrqTriggerCallback};
use crate::memory::MemoryManager;
use crate::vcpu::VcpuManager;

use arcbox_hypervisor::VirtioDeviceConfig;
use arcbox_hypervisor::VmConfig;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;

/// Type-erased VM handle for managed execution mode.
type ManagedVm = Box<dyn Any + Send + Sync>;

/// Shared directory configuration for `VirtioFS`.
#[derive(Debug, Clone)]
pub struct SharedDirConfig {
    /// Host path to share.
    pub host_path: PathBuf,
    /// Tag for mounting in guest.
    pub tag: String,
    /// Whether the share is read-only.
    pub read_only: bool,
}

/// Block device configuration for `VirtIO` block devices.
#[derive(Debug, Clone)]
pub struct BlockDeviceConfig {
    /// Path to the disk image file on the host.
    pub path: PathBuf,
    /// Whether the block device is read-only.
    pub read_only: bool,
}

/// VMM-specific configuration.
#[derive(Debug, Clone)]
pub struct VmmConfig {
    /// Number of virtual CPUs.
    pub vcpu_count: u32,
    /// Memory size in bytes.
    pub memory_size: u64,
    /// Path to the kernel image.
    pub kernel_path: PathBuf,
    /// Kernel command line arguments.
    pub kernel_cmdline: String,
    /// Path to initial ramdisk (optional).
    pub initrd_path: Option<PathBuf>,
    /// Enable Rosetta 2 translation (macOS ARM only).
    pub enable_rosetta: bool,
    /// Enable serial console.
    pub serial_console: bool,
    /// Enable virtio-console.
    pub virtio_console: bool,
    /// Shared directories for `VirtioFS`.
    pub shared_dirs: Vec<SharedDirConfig>,
    /// Enable networking.
    pub networking: bool,
    /// Enable vsock.
    pub vsock: bool,
    /// Guest CID for vsock connections (Linux).
    pub guest_cid: Option<u32>,
    /// Enable memory balloon device.
    ///
    /// The balloon device allows dynamic memory management by inflating
    /// (reclaiming memory from guest) or deflating (returning memory).
    /// This helps achieve low idle memory usage.
    pub balloon: bool,
    /// Block devices to attach to the VM.
    pub block_devices: Vec<BlockDeviceConfig>,
}

impl Default for VmmConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            memory_size: 512 * 1024 * 1024, // 512MB
            kernel_path: PathBuf::new(),
            kernel_cmdline: String::new(),
            initrd_path: None,
            enable_rosetta: false,
            serial_console: true,
            virtio_console: true,
            shared_dirs: Vec::new(),
            networking: true,
            vsock: true,
            guest_cid: None,
            balloon: true, // Enable balloon by default for memory optimization
            block_devices: Vec::new(),
        }
    }
}

impl VmmConfig {
    /// Creates a `VmConfig` for the hypervisor from this VMM config.
    fn to_vm_config(&self) -> VmConfig {
        let mut builder = VmConfig::builder()
            .vcpu_count(self.vcpu_count)
            .memory_size(self.memory_size)
            .kernel_path(self.kernel_path.to_string_lossy())
            .kernel_cmdline(&self.kernel_cmdline)
            .enable_rosetta(self.enable_rosetta);

        if let Some(initrd_path) = &self.initrd_path {
            builder = builder.initrd_path(initrd_path.to_string_lossy());
        }

        builder.build()
    }
}

/// VMM state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmmState {
    /// VMM created but not started.
    Created,
    /// VMM is initializing.
    Initializing,
    /// VMM is running.
    Running,
    /// VMM is paused.
    Paused,
    /// VMM is stopping.
    Stopping,
    /// VMM is stopped.
    Stopped,
    /// VMM encountered an error.
    Failed,
}

/// Virtual Machine Monitor.
///
/// Manages the complete lifecycle of a virtual machine including
/// vCPUs, memory, and devices.
///
/// # Example
///
/// ```ignore
/// use arcbox_vmm::{Vmm, VmmConfig};
/// use std::path::PathBuf;
///
/// let config = VmmConfig {
///     vcpu_count: 2,
///     memory_size: 1024 * 1024 * 1024, // 1GB
///     kernel_path: PathBuf::from("/path/to/vmlinux"),
///     kernel_cmdline: "console=ttyS0".to_string(),
///     guest_cid: Some(3),
///     ..Default::default()
/// };
///
/// let mut vmm = Vmm::new(config)?;
/// vmm.start()?;
/// ```
pub struct Vmm {
    /// Configuration.
    config: VmmConfig,
    /// Current state.
    state: VmmState,
    /// Running flag for graceful shutdown.
    running: Arc<AtomicBool>,
    /// vCPU manager (for manual execution mode).
    vcpu_manager: Option<VcpuManager>,
    /// Memory manager.
    memory_manager: Option<MemoryManager>,
    /// Device manager.
    device_manager: Option<DeviceManager>,
    /// IRQ chip (Arc for sharing with callback).
    irq_chip: Option<Arc<IrqChip>>,
    /// Event loop.
    event_loop: Option<EventLoop>,
    /// Whether using managed execution mode (e.g., Darwin Virtualization.framework).
    managed_execution: bool,
    /// Type-erased VM handle for managed execution mode.
    /// Stored to keep the VM alive and for lifecycle control.
    managed_vm: Option<ManagedVm>,
    /// Cancellation token for the network datapath task (Darwin only).
    #[cfg(target_os = "macos")]
    net_cancel: Option<tokio_util::sync::CancellationToken>,
    /// VZ side network fd for `VZFileHandleNetworkDeviceAttachment` lifecycle.
    /// Kept open while the VM is running and closed on stop.
    #[cfg(target_os = "macos")]
    net_vz_fd: Option<OwnedFd>,
    /// Inbound listener manager for port forwarding (Darwin only).
    #[cfg(target_os = "macos")]
    inbound_listener_manager: Option<arcbox_net::darwin::inbound_relay::InboundListenerManager>,
}

impl Vmm {
    /// Creates a new VMM with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn new(config: VmmConfig) -> Result<Self> {
        // Validate configuration
        if config.vcpu_count == 0 {
            return Err(VmmError::config("vcpu_count must be > 0".to_string()));
        }

        if config.memory_size < 64 * 1024 * 1024 {
            return Err(VmmError::config("memory_size must be >= 64MB".to_string()));
        }

        if !config.kernel_path.as_os_str().is_empty() && !config.kernel_path.exists() {
            return Err(VmmError::config(format!(
                "kernel not found: {}",
                config.kernel_path.display()
            )));
        }
        if config.vsock && config.guest_cid.is_none() {
            return Err(VmmError::config(
                "guest_cid must be set when vsock is enabled".to_string(),
            ));
        }

        tracing::info!(
            "Creating VMM: vcpus={}, memory={}MB",
            config.vcpu_count,
            config.memory_size / (1024 * 1024)
        );

        Ok(Self {
            config,
            state: VmmState::Created,
            running: Arc::new(AtomicBool::new(false)),
            vcpu_manager: None,
            memory_manager: None,
            device_manager: None,
            irq_chip: None,
            event_loop: None,
            managed_execution: false,
            managed_vm: None,
            #[cfg(target_os = "macos")]
            net_cancel: None,
            #[cfg(target_os = "macos")]
            net_vz_fd: None,
            #[cfg(target_os = "macos")]
            inbound_listener_manager: None,
        })
    }

    /// Returns the current VMM state.
    #[must_use]
    pub const fn state(&self) -> VmmState {
        self.state
    }

    /// Returns whether the VMM is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns a clone of the running flag for external monitoring.
    #[must_use]
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Initializes the VMM components.
    ///
    /// This sets up the hypervisor, VM, memory, devices, and vCPUs.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn initialize(&mut self) -> Result<()> {
        if self.state != VmmState::Created {
            return Err(VmmError::invalid_state(format!(
                "cannot initialize from state {:?}",
                self.state
            )));
        }

        self.state = VmmState::Initializing;
        tracing::info!("Initializing VMM");

        // Platform-specific initialization
        #[cfg(target_os = "macos")]
        {
            self.initialize_darwin()?;
        }

        #[cfg(target_os = "linux")]
        {
            self.initialize_linux()?;
        }

        tracing::info!("VMM initialized successfully");
        Ok(())
    }

    /// Starts the VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be started.
    pub fn start(&mut self) -> Result<()> {
        // Initialize if not already done
        if self.state == VmmState::Created {
            self.initialize()?;
        }

        if self.state != VmmState::Initializing && self.state != VmmState::Stopped {
            return Err(VmmError::invalid_state(format!(
                "cannot start from state {:?}",
                self.state
            )));
        }

        tracing::info!("Starting VMM");

        if self.managed_execution {
            // For managed execution, start the VM directly
            #[cfg(target_os = "macos")]
            {
                self.start_managed_vm()?;
            }
        } else {
            // For manual execution, start vCPU threads
            if let Some(ref mut vcpu_manager) = self.vcpu_manager {
                vcpu_manager.start()?;
            }
        }

        // Start event loop
        if let Some(ref mut event_loop) = self.event_loop {
            event_loop.start()?;
        }

        self.running.store(true, Ordering::SeqCst);
        self.state = VmmState::Running;

        tracing::info!("VMM started");
        Ok(())
    }

    /// Pauses the VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be paused.
    pub fn pause(&mut self) -> Result<()> {
        if self.state != VmmState::Running {
            return Err(VmmError::invalid_state(format!(
                "cannot pause from state {:?}",
                self.state
            )));
        }

        tracing::info!("Pausing VMM");

        if self.managed_execution {
            #[cfg(target_os = "macos")]
            {
                self.pause_managed_vm()?;
            }
        } else if let Some(ref mut vcpu_manager) = self.vcpu_manager {
            vcpu_manager.pause()?;
        }

        self.state = VmmState::Paused;
        tracing::info!("VMM paused");
        Ok(())
    }

    /// Resumes a paused VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be resumed.
    pub fn resume(&mut self) -> Result<()> {
        if self.state != VmmState::Paused {
            return Err(VmmError::invalid_state(format!(
                "cannot resume from state {:?}",
                self.state
            )));
        }

        tracing::info!("Resuming VMM");

        if self.managed_execution {
            #[cfg(target_os = "macos")]
            {
                self.resume_managed_vm()?;
            }
        } else if let Some(ref mut vcpu_manager) = self.vcpu_manager {
            vcpu_manager.resume()?;
        }

        self.state = VmmState::Running;
        tracing::info!("VMM resumed");
        Ok(())
    }

    /// Stops the VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be stopped.
    pub fn stop(&mut self) -> Result<()> {
        if self.state == VmmState::Stopped {
            return Ok(());
        }

        tracing::info!("Stopping VMM");
        self.state = VmmState::Stopping;
        self.running.store(false, Ordering::SeqCst);

        // Stop event loop first
        if let Some(ref mut event_loop) = self.event_loop {
            event_loop.stop();
        }

        // Stop managed VM before canceling the custom file-handle datapath.
        #[cfg(target_os = "macos")]
        if self.managed_execution {
            self.stop_managed_vm()?;
        }

        // Stop vCPU threads (Linux always, macOS only in non-managed mode)
        if !self.managed_execution {
            if let Some(ref mut vcpu_manager) = self.vcpu_manager {
                vcpu_manager.stop()?;
            }
        }

        // Cancel custom file-handle network datapath after VM stop.
        #[cfg(target_os = "macos")]
        self.stop_network();

        self.state = VmmState::Stopped;
        tracing::info!("VMM stopped");
        Ok(())
    }

    /// Returns the configured memory size for this VM.
    ///
    /// This is the maximum memory the guest can use when the balloon is fully deflated.
    #[must_use]
    pub const fn configured_memory(&self) -> u64 {
        self.config.memory_size
    }

    /// Returns whether a balloon device is configured for this VM.
    #[must_use]
    pub const fn has_balloon(&self) -> bool {
        self.config.balloon
    }

    // ========================================================================
    // Snapshot
    // ========================================================================

    /// Captures a VM snapshot context from the running hypervisor VM.
    ///
    /// The returned context contains device state and full guest memory.
    /// vCPU register snapshots are currently placeholder values based on
    /// configured vCPU count.
    ///
    /// # Errors
    ///
    /// Returns an error if VM state is not snapshotable or VM handles are missing.
    pub fn capture_snapshot_context(&self) -> Result<crate::snapshot::VmSnapshotContext> {
        if self.state != VmmState::Running && self.state != VmmState::Paused {
            return Err(VmmError::invalid_state(format!(
                "cannot capture snapshot from state {:?}",
                self.state
            )));
        }

        #[cfg(target_os = "linux")]
        if let Some(result) = self.capture_snapshot_linux() {
            return result;
        }

        #[cfg(target_os = "macos")]
        if let Some(result) = self.capture_snapshot_darwin() {
            return result;
        }

        Err(VmmError::invalid_state(
            "hypervisor VM handle is unavailable for snapshot".to_string(),
        ))
    }

    /// Applies restored device + memory state to the running VM.
    ///
    /// # Errors
    ///
    /// Returns an error if restore cannot be applied.
    pub fn restore_from_snapshot_data(
        &mut self,
        restore_data: &crate::snapshot::VmRestoreData,
    ) -> Result<()> {
        if self.state != VmmState::Running && self.state != VmmState::Paused {
            return Err(VmmError::invalid_state(format!(
                "cannot restore snapshot from state {:?}",
                self.state
            )));
        }

        let expected_memory_len = usize::try_from(restore_data.memory_size()).map_err(|_| {
            VmmError::Memory(format!(
                "snapshot memory size {} does not fit in usize",
                restore_data.memory_size()
            ))
        })?;

        if restore_data.memory().len() != expected_memory_len {
            return Err(VmmError::Memory(format!(
                "snapshot memory length mismatch: expected {}, got {}",
                expected_memory_len,
                restore_data.memory().len()
            )));
        }

        #[cfg(target_os = "linux")]
        if let Some(result) = self.restore_snapshot_linux(restore_data) {
            return result;
        }

        #[cfg(target_os = "macos")]
        if let Some(result) = self.restore_snapshot_darwin(restore_data) {
            return result;
        }

        Err(VmmError::invalid_state(
            "hypervisor VM handle is unavailable for restore".to_string(),
        ))
    }

    // ========================================================================
    // Event loop and device I/O
    // ========================================================================

    /// Runs the VMM until it exits.
    ///
    /// This is the main event loop that blocks until the VM exits.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM encounters a fatal error.
    pub async fn run(&mut self) -> Result<()> {
        // Start if not already running
        if self.state != VmmState::Running {
            self.start()?;
        }

        tracing::info!("VMM running, waiting for exit");

        // Main event loop
        while self.is_running() {
            // Poll event loop
            if let Some(ref mut event_loop) = self.event_loop {
                if let Some(event) = event_loop.poll().await {
                    self.handle_event(event)?;
                }
            }

            // Small yield to prevent busy spinning
            tokio::task::yield_now().await;
        }

        tracing::info!("VMM exited");
        Ok(())
    }

    /// Handles an event from the event loop.
    fn handle_event(&mut self, event: crate::event::VmmEvent) -> Result<()> {
        use crate::event::VmmEvent;

        match event {
            VmmEvent::VcpuExit { vcpu_id, exit } => {
                self.handle_vcpu_exit(vcpu_id, exit)?;
            }
            VmmEvent::DeviceIo {
                device_id,
                is_read,
                addr,
                data,
            } => {
                self.handle_device_io(device_id, is_read, addr, data)?;
            }
            VmmEvent::Timer { id } => {
                tracing::trace!("Timer {} fired", id);
                // Timer handling would go here (e.g., for RTC, PIT, etc.)
            }
            VmmEvent::Shutdown => {
                tracing::info!("Shutdown requested");
                self.running.store(false, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    /// Handles a vCPU exit event.
    ///
    /// This processes exits from the hypervisor such as I/O, MMIO, and special
    /// instructions that require VMM intervention.
    fn handle_vcpu_exit(&mut self, vcpu_id: u32, exit: arcbox_hypervisor::VcpuExit) -> Result<()> {
        use arcbox_hypervisor::VcpuExit;

        match exit {
            VcpuExit::Halt => {
                tracing::debug!("vCPU {} halted", vcpu_id);
                // HLT instruction - guest is idle, can reduce CPU usage
                // In a real implementation, we might pause the vCPU until an interrupt
            }

            VcpuExit::IoOut { port, size, data } => {
                tracing::trace!(
                    "vCPU {} I/O out: port={:#x}, size={}, data={:#x}",
                    vcpu_id,
                    port,
                    size,
                    data
                );
                self.handle_io_out(port, size, data)?;
            }

            VcpuExit::IoIn { port, size } => {
                tracing::trace!("vCPU {} I/O in: port={:#x}, size={}", vcpu_id, port, size);
                let _value = self.handle_io_in(port, size)?;
                // Note: The value would need to be written back to the vCPU,
                // which requires access to the vCPU registers.
            }

            VcpuExit::MmioRead { addr, size } => {
                tracing::trace!(
                    "vCPU {} MMIO read: addr={:#x}, size={}",
                    vcpu_id,
                    addr,
                    size
                );
                if let Some(ref device_manager) = self.device_manager {
                    match device_manager.handle_mmio_read(addr, size as usize) {
                        Ok(value) => {
                            tracing::trace!("MMIO read returned: {:#x}", value);
                            // Note: Value would need to be written back to vCPU
                        }
                        Err(e) => {
                            tracing::warn!("MMIO read failed at {:#x}: {}", addr, e);
                        }
                    }
                }
            }

            VcpuExit::MmioWrite { addr, size, data } => {
                tracing::trace!(
                    "vCPU {} MMIO write: addr={:#x}, size={}, data={:#x}",
                    vcpu_id,
                    addr,
                    size,
                    data
                );
                if let Some(ref device_manager) = self.device_manager {
                    if let Err(e) = device_manager.handle_mmio_write(addr, size as usize, data) {
                        tracing::warn!("MMIO write failed at {:#x}: {}", addr, e);
                    }
                }
            }

            VcpuExit::Hypercall { nr, args } => {
                tracing::debug!("vCPU {} hypercall: nr={}, args={:?}", vcpu_id, nr, args);
                // Hypercall handling - used for paravirtualization
                self.handle_hypercall(vcpu_id, nr, args)?;
            }

            VcpuExit::SystemReset => {
                tracing::info!("vCPU {} requested system reset", vcpu_id);
                // Guest requested a reset - could restart VM or signal caller
                self.running.store(false, Ordering::SeqCst);
            }

            VcpuExit::Shutdown => {
                tracing::info!("vCPU {} requested shutdown", vcpu_id);
                self.running.store(false, Ordering::SeqCst);
            }

            VcpuExit::Unknown(code) => {
                tracing::warn!("vCPU {} unknown exit: {}", vcpu_id, code);
            }

            _ => {
                tracing::debug!("vCPU {} unhandled exit: {:?}", vcpu_id, exit);
            }
        }

        Ok(())
    }

    /// Handles device I/O events.
    fn handle_device_io(
        &mut self,
        device_id: u32,
        is_read: bool,
        addr: u64,
        data: Option<u64>,
    ) -> Result<()> {
        if let Some(ref device_manager) = self.device_manager {
            if is_read {
                match device_manager.handle_mmio_read(addr, 4) {
                    Ok(value) => {
                        tracing::trace!("Device {} read at {:#x}: {:#x}", device_id, addr, value);
                    }
                    Err(e) => {
                        tracing::warn!("Device {} read failed: {}", device_id, e);
                    }
                }
            } else if let Some(value) = data {
                if let Err(e) = device_manager.handle_mmio_write(addr, 4, value) {
                    tracing::warn!("Device {} write failed: {}", device_id, e);
                }
            }
        }
        Ok(())
    }

    /// Handles I/O port output.
    fn handle_io_out(&self, port: u16, size: u8, data: u64) -> Result<()> {
        match port {
            // Serial ports (COM1-COM4)
            0x3F8..=0x3FF => {
                // COM1 - primary serial port
                if port == 0x3F8 {
                    // Data register - output character
                    let ch = (data & 0xFF) as u8;
                    if ch.is_ascii() && (ch.is_ascii_graphic() || ch.is_ascii_whitespace()) {
                        tracing::trace!("Serial output: '{}'", ch as char);
                    }
                }
            }
            0x2F8..=0x2FF => {
                // COM2
            }

            // Debug port (Bochs/QEMU convention)
            0x402 => {
                let ch = (data & 0xFF) as u8;
                if ch.is_ascii() {
                    tracing::debug!("Debug port: '{}'", ch as char);
                }
            }

            // ACPI power management
            0x604 => {
                // ACPI PM1a control - check for S5 (shutdown)
                if data & 0x2000 != 0 {
                    tracing::info!("ACPI shutdown requested");
                    // Would signal shutdown here
                }
            }

            // PIC (Programmable Interrupt Controller)
            0x20 | 0x21 | 0xA0 | 0xA1 => {
                tracing::trace!("PIC write: port={:#x}, data={:#x}", port, data);
            }

            // PIT (Programmable Interval Timer)
            0x40..=0x43 => {
                tracing::trace!("PIT write: port={:#x}, data={:#x}", port, data);
            }

            _ => {
                tracing::trace!(
                    "Unhandled I/O out: port={:#x}, size={}, data={:#x}",
                    port,
                    size,
                    data
                );
            }
        }
        Ok(())
    }

    /// Handles I/O port input.
    fn handle_io_in(&self, port: u16, size: u8) -> Result<u64> {
        let value = match port {
            // Serial ports - Line Status Register
            0x3FD => {
                // LSR: Always report transmitter empty (0x60)
                0x60
            }

            // RTC (Real-Time Clock)
            0x70 | 0x71 => 0,

            // Keyboard controller status
            0x64 => {
                // Report output buffer empty, input buffer not full
                0x00
            }

            // PIC
            0x20 | 0x21 | 0xA0 | 0xA1 => 0xFF,

            _ => {
                tracing::trace!("Unhandled I/O in: port={:#x}, size={}", port, size);
                0xFF // Return all 1s for unhandled ports
            }
        };
        Ok(value)
    }

    /// Handles a hypercall from the guest.
    fn handle_hypercall(&self, vcpu_id: u32, nr: u64, args: [u64; 6]) -> Result<()> {
        // Common hypercall numbers (KVM convention):
        // 0: KVM_HC_VAPIC_POLL_IRQ
        // 1: KVM_HC_MMU_OP (deprecated)
        // 2: KVM_HC_FEATURES
        // 3: KVM_HC_PPC_MAP_MAGIC_PAGE
        // 4: KVM_HC_KICK_CPU
        // 5: KVM_HC_SEND_IPI
        // 9: KVM_HC_MAP_GPA_RANGE

        match nr {
            0 => {
                // Poll for pending interrupts
                tracing::trace!("vCPU {} hypercall: VAPIC_POLL_IRQ", vcpu_id);
            }
            2 => {
                // Get features
                tracing::trace!("vCPU {} hypercall: GET_FEATURES", vcpu_id);
            }
            4 => {
                // Kick another vCPU
                let target_vcpu = args[0] as u32;
                tracing::trace!(
                    "vCPU {} hypercall: KICK_CPU target={}",
                    vcpu_id,
                    target_vcpu
                );
            }
            _ => {
                tracing::debug!(
                    "vCPU {} unhandled hypercall: nr={}, args={:?}",
                    vcpu_id,
                    nr,
                    args
                );
            }
        }
        Ok(())
    }
}

fn placeholder_vcpu_snapshots(vcpu_count: u32) -> Vec<arcbox_hypervisor::VcpuSnapshot> {
    #[cfg(target_arch = "aarch64")]
    {
        (0..vcpu_count)
            .map(|id| {
                arcbox_hypervisor::VcpuSnapshot::new_arm64(
                    id,
                    arcbox_hypervisor::Arm64Registers::default(),
                )
            })
            .collect()
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        (0..vcpu_count)
            .map(|id| {
                arcbox_hypervisor::VcpuSnapshot::new_x86(
                    id,
                    arcbox_hypervisor::Registers::default(),
                )
            })
            .collect()
    }
}

impl Drop for Vmm {
    fn drop(&mut self) {
        if self.state != VmmState::Stopped && self.state != VmmState::Created {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmm_creation() {
        let config = VmmConfig {
            guest_cid: Some(3),
            ..Default::default()
        };
        let vmm = Vmm::new(config).unwrap();
        assert_eq!(vmm.state(), VmmState::Created);
    }

    #[test]
    fn test_vmm_invalid_config() {
        // Zero vCPUs
        let config = VmmConfig {
            vcpu_count: 0,
            guest_cid: Some(3),
            ..Default::default()
        };
        assert!(Vmm::new(config).is_err());

        // Too little memory
        let config = VmmConfig {
            memory_size: 1024, // 1KB
            guest_cid: Some(3),
            ..Default::default()
        };
        assert!(Vmm::new(config).is_err());
    }

    #[test]
    fn test_vmm_requires_guest_cid_when_vsock_enabled() {
        let config = VmmConfig {
            guest_cid: None,
            ..Default::default()
        };
        assert!(Vmm::new(config).is_err());

        let config = VmmConfig {
            vsock: false,
            guest_cid: None,
            ..Default::default()
        };
        assert!(Vmm::new(config).is_ok());
    }

    #[test]
    fn test_vmm_state_transitions() {
        let config = VmmConfig {
            guest_cid: Some(3),
            ..Default::default()
        };
        let mut vmm = Vmm::new(config).unwrap();

        // Can't pause before running
        assert!(vmm.pause().is_err());

        // Can't resume before pausing
        assert!(vmm.resume().is_err());
    }
}
