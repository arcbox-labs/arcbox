//! Main VMM implementation.
//!
//! The VMM (Virtual Machine Monitor) orchestrates all components needed to run
//! a virtual machine: hypervisor, vCPUs, memory, and devices.

use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::device::DeviceManager;
#[cfg(target_os = "linux")]
use crate::device::DeviceTreeEntry;
use crate::error::{Result, VmmError};
use crate::event::EventLoop;
use crate::irq::{Gsi, IrqChip, IrqTriggerCallback};
use crate::memory::MemoryManager;
use crate::vcpu::VcpuManager;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use arcbox_hypervisor::GuestAddress;
#[cfg(target_os = "linux")]
use arcbox_hypervisor::VirtioDeviceConfig;
use arcbox_hypervisor::VmConfig;
#[cfg(target_os = "linux")]
use arcbox_hypervisor::linux::VirtioDeviceInfo;

#[cfg(target_arch = "aarch64")]
use crate::boot::arm64;
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use crate::fdt::{FdtConfig, generate_fdt};

/// Type-erased VM handle for managed execution mode.
type ManagedVm = Box<dyn Any + Send + Sync>;

/// Shared directory configuration for VirtioFS.
#[derive(Debug, Clone)]
pub struct SharedDirConfig {
    /// Host path to share.
    pub host_path: PathBuf,
    /// Tag for mounting in guest.
    pub tag: String,
    /// Whether the share is read-only.
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
    /// Shared directories for VirtioFS.
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
        }
    }
}

impl VmmConfig {
    /// Creates a VmConfig for the hypervisor from this VMM config.
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
            return Err(VmmError::Config("vcpu_count must be > 0".to_string()));
        }

        if config.memory_size < 64 * 1024 * 1024 {
            return Err(VmmError::Config("memory_size must be >= 64MB".to_string()));
        }

        if !config.kernel_path.as_os_str().is_empty() && !config.kernel_path.exists() {
            return Err(VmmError::Config(format!(
                "kernel not found: {}",
                config.kernel_path.display()
            )));
        }
        if config.vsock && config.guest_cid.is_none() {
            return Err(VmmError::Config(
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
        })
    }

    /// Returns the current VMM state.
    #[must_use]
    pub fn state(&self) -> VmmState {
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
            return Err(VmmError::InvalidState(format!(
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

    /// Darwin-specific initialization using Virtualization.framework.
    #[cfg(target_os = "macos")]
    fn initialize_darwin(&mut self) -> Result<()> {
        use arcbox_hypervisor::VirtioDeviceConfig;
        use arcbox_hypervisor::darwin::DarwinHypervisor;
        use arcbox_hypervisor::traits::{Hypervisor, VirtualMachine};

        let hypervisor = DarwinHypervisor::new()?;
        tracing::debug!("Platform capabilities: {:?}", hypervisor.capabilities());

        let vm_config = self.config.to_vm_config();
        let mut vm = hypervisor.create_vm(vm_config)?;

        // Check if this is managed execution
        self.managed_execution = vm.is_managed_execution();
        tracing::info!("Using managed execution mode: {}", self.managed_execution);

        // Add VirtioFS devices for shared directories
        for shared_dir in &self.config.shared_dirs {
            let device_config = VirtioDeviceConfig::filesystem(
                shared_dir.host_path.to_string_lossy(),
                &shared_dir.tag,
                shared_dir.read_only,
            );
            vm.add_virtio_device(device_config)?;
            tracing::info!(
                "Added VirtioFS share: {} -> {} (read_only: {})",
                shared_dir.tag,
                shared_dir.host_path.display(),
                shared_dir.read_only
            );
        }

        // Add networking if enabled
        if self.config.networking {
            let net_config = VirtioDeviceConfig::network();
            vm.add_virtio_device(net_config)?;
            tracing::info!("Added network device with NAT");
        }

        // Add vsock if enabled
        if self.config.vsock {
            let vsock_config = VirtioDeviceConfig::vsock();
            vm.add_virtio_device(vsock_config)?;
            tracing::info!("Added vsock device");
        }

        // Add balloon device if enabled
        if self.config.balloon {
            let balloon_config = VirtioDeviceConfig::balloon();
            vm.add_virtio_device(balloon_config)?;
            tracing::info!("Added memory balloon device");
        }

        // Initialize memory manager
        let mut memory_manager = MemoryManager::new();
        memory_manager.initialize(self.config.memory_size)?;

        // Initialize device manager
        let device_manager = DeviceManager::new();

        // Initialize IRQ chip
        let irq_chip = Arc::new(IrqChip::new()?);

        // Set up IRQ callback for Darwin.
        // Virtualization.framework handles VirtIO interrupts internally,
        // so we set up a no-op callback that logs when IRQ is triggered.
        {
            let callback: IrqTriggerCallback = Box::new(|gsi: Gsi, level: bool| {
                // Darwin Virtualization.framework handles VirtIO interrupts internally.
                // For custom devices, interrupt injection is not supported.
                tracing::trace!(
                    "Darwin IRQ callback: gsi={}, level={} (handled by framework)",
                    gsi,
                    level
                );
                Ok(())
            });
            irq_chip.set_trigger_callback(Arc::new(callback));
            tracing::debug!("Darwin: IRQ callback configured (framework-managed)");
        }

        // Initialize event loop
        let event_loop = EventLoop::new()?;

        // Store managers
        self.memory_manager = Some(memory_manager);
        self.device_manager = Some(device_manager);
        self.irq_chip = Some(irq_chip);
        self.event_loop = Some(event_loop);

        // For managed execution, we don't create vCPU threads
        // Instead, store the VM for lifecycle management
        if self.managed_execution {
            tracing::debug!("Managed execution: skipping vCPU thread creation");
            self.managed_vm = Some(Box::new(vm));
        } else {
            // This shouldn't happen on Darwin, but handle it anyway
            let vcpu_manager = VcpuManager::new(self.config.vcpu_count);
            // Note: Darwin vCPUs are placeholders, but we add them anyway
            self.vcpu_manager = Some(vcpu_manager);
        }

        Ok(())
    }

    /// Linux-specific initialization using KVM.
    #[cfg(target_os = "linux")]
    fn initialize_linux(&mut self) -> Result<()> {
        use arcbox_hypervisor::linux::KvmVm;
        use arcbox_hypervisor::traits::VirtualMachine;
        use std::sync::Mutex;

        // Create hypervisor and VM
        let hypervisor = create_hypervisor()?;
        let vm_config = self.config.to_vm_config();

        tracing::debug!("Platform capabilities: {:?}", hypervisor.capabilities());

        let mut vm = hypervisor.create_vm(vm_config)?;

        // KVM uses manual execution mode
        self.managed_execution = false;

        // Add VirtioFS devices for shared directories
        for shared_dir in &self.config.shared_dirs {
            let device_config = VirtioDeviceConfig::filesystem(
                shared_dir.host_path.to_string_lossy(),
                &shared_dir.tag,
                shared_dir.read_only,
            );
            vm.add_virtio_device(device_config)?;
            tracing::info!(
                "Added VirtioFS share: {} -> {} (read_only: {})",
                shared_dir.tag,
                shared_dir.host_path.display(),
                shared_dir.read_only
            );
        }

        // Add networking if enabled
        if self.config.networking {
            let net_config = VirtioDeviceConfig::network();
            vm.add_virtio_device(net_config)?;
            tracing::info!("Added network device");
        }

        // Add vsock if enabled
        if self.config.vsock {
            let vsock_config = VirtioDeviceConfig::vsock();
            vm.add_virtio_device(vsock_config)?;
            tracing::info!("Added vsock device");
        }

        #[cfg(target_arch = "aarch64")]
        {
            let virtio_devices = vm.virtio_devices().map_err(VmmError::from)?;
            write_fdt_to_guest(&vm, &self.config, &virtio_devices)?;
        }

        // Initialize memory manager
        let mut memory_manager = MemoryManager::new();
        memory_manager.initialize(self.config.memory_size)?;

        // Initialize device manager
        let device_manager = DeviceManager::new();

        // Initialize IRQ chip
        let irq_chip = Arc::new(IrqChip::new()?);

        // Initialize vCPU manager
        let mut vcpu_manager = VcpuManager::new(self.config.vcpu_count);

        // Create vCPUs
        for i in 0..self.config.vcpu_count {
            let vcpu = vm.create_vcpu(i)?;
            vcpu_manager.add_vcpu(vcpu)?;
        }

        // Wrap VM in Arc<Mutex> for callback access
        let vm_arc: Arc<Mutex<KvmVm>> = Arc::new(Mutex::new(vm));

        // Set up IRQ callback that calls KVM's set_irq_line
        {
            let vm_weak = Arc::downgrade(&vm_arc);
            let callback: IrqTriggerCallback = Box::new(move |gsi: Gsi, level: bool| {
                if let Some(vm_strong) = vm_weak.upgrade() {
                    let vm_guard = vm_strong.lock().map_err(|_| {
                        crate::error::VmmError::Irq("Failed to lock VM for IRQ".to_string())
                    })?;
                    vm_guard.set_irq_line(gsi, level).map_err(|e| {
                        crate::error::VmmError::Irq(format!("KVM IRQ injection failed: {}", e))
                    })?;
                    tracing::trace!("KVM: Triggered IRQ gsi={}, level={}", gsi, level);
                } else {
                    tracing::warn!("KVM: VM dropped, cannot inject IRQ gsi={}", gsi);
                }
                Ok(())
            });
            irq_chip.set_trigger_callback(Arc::new(callback));
            tracing::debug!("Linux KVM: IRQ callback connected to VM");
        }

        // Initialize event loop
        let event_loop = EventLoop::new()?;

        // Store managers
        self.memory_manager = Some(memory_manager);
        self.device_manager = Some(device_manager);
        self.irq_chip = Some(irq_chip);
        self.vcpu_manager = Some(vcpu_manager);
        self.event_loop = Some(event_loop);

        // Store VM for lifecycle management (also keeps Arc alive for callback)
        self.managed_vm = Some(Box::new(vm_arc));

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
            return Err(VmmError::InvalidState(format!(
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

    /// Starts the managed VM (Darwin-specific).
    #[cfg(target_os = "macos")]
    fn start_managed_vm(&mut self) -> Result<()> {
        use arcbox_hypervisor::darwin::DarwinVm;
        use arcbox_hypervisor::traits::VirtualMachine;

        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.start().map_err(VmmError::Hypervisor)?;
            }
        }
        Ok(())
    }

    /// Pauses the VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be paused.
    pub fn pause(&mut self) -> Result<()> {
        if self.state != VmmState::Running {
            return Err(VmmError::InvalidState(format!(
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
        } else {
            if let Some(ref mut vcpu_manager) = self.vcpu_manager {
                vcpu_manager.pause()?;
            }
        }

        self.state = VmmState::Paused;
        tracing::info!("VMM paused");
        Ok(())
    }

    /// Pauses the managed VM (Darwin-specific).
    #[cfg(target_os = "macos")]
    fn pause_managed_vm(&mut self) -> Result<()> {
        use arcbox_hypervisor::darwin::DarwinVm;
        use arcbox_hypervisor::traits::VirtualMachine;

        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.pause().map_err(VmmError::Hypervisor)?;
            }
        }
        Ok(())
    }

    /// Resumes a paused VMM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VMM cannot be resumed.
    pub fn resume(&mut self) -> Result<()> {
        if self.state != VmmState::Paused {
            return Err(VmmError::InvalidState(format!(
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
        } else {
            if let Some(ref mut vcpu_manager) = self.vcpu_manager {
                vcpu_manager.resume()?;
            }
        }

        self.state = VmmState::Running;
        tracing::info!("VMM resumed");
        Ok(())
    }

    /// Resumes the managed VM (Darwin-specific).
    #[cfg(target_os = "macos")]
    fn resume_managed_vm(&mut self) -> Result<()> {
        use arcbox_hypervisor::darwin::DarwinVm;
        use arcbox_hypervisor::traits::VirtualMachine;

        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.resume().map_err(VmmError::Hypervisor)?;
            }
        }
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

        if self.managed_execution {
            #[cfg(target_os = "macos")]
            {
                self.stop_managed_vm()?;
            }
        } else {
            // Stop vCPUs
            if let Some(ref mut vcpu_manager) = self.vcpu_manager {
                vcpu_manager.stop()?;
            }
        }

        self.state = VmmState::Stopped;
        tracing::info!("VMM stopped");
        Ok(())
    }

    /// Stops the managed VM (Darwin-specific).
    #[cfg(target_os = "macos")]
    fn stop_managed_vm(&mut self) -> Result<()> {
        use arcbox_hypervisor::darwin::DarwinVm;
        use arcbox_hypervisor::traits::VirtualMachine;

        if let Some(ref mut managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_mut::<DarwinVm>() {
                vm.stop().map_err(VmmError::Hypervisor)?;
            }
        }
        Ok(())
    }

    /// Connects to a vsock port on the guest VM.
    ///
    /// This establishes a vsock connection to the specified port number
    /// on the guest VM. The VM must be running.
    ///
    /// # Arguments
    /// * `port` - The port number to connect to (e.g., 1024 for agent)
    ///
    /// # Returns
    /// A file descriptor for the connection that can be used for I/O.
    ///
    /// # Errors
    /// Returns an error if the VM is not running or the connection fails.
    #[cfg(target_os = "macos")]
    pub fn connect_vsock(&self, port: u32) -> Result<std::os::unix::io::RawFd> {
        use arcbox_hypervisor::darwin::DarwinVm;

        if self.state != VmmState::Running {
            return Err(VmmError::InvalidState(format!(
                "cannot connect vsock: VMM is {:?}",
                self.state
            )));
        }

        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm.connect_vsock(port).map_err(VmmError::Hypervisor);
            }
        }

        Err(VmmError::InvalidState(
            "vsock not available in manual execution mode".to_string(),
        ))
    }

    /// Reads serial console output from a managed VM (macOS only).
    #[cfg(target_os = "macos")]
    pub fn read_console_output(&self) -> Result<String> {
        use arcbox_hypervisor::darwin::DarwinVm;

        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm.read_console_output().map_err(VmmError::Hypervisor);
            }
        }

        Ok(String::new())
    }

    // ========================================================================
    // Memory Balloon Control
    // ========================================================================

    /// Sets the target memory size for the balloon device.
    ///
    /// The balloon device will inflate or deflate to reach the target:
    /// - **Smaller target**: Balloon inflates, reclaiming memory from guest
    /// - **Larger target**: Balloon deflates, returning memory to guest
    ///
    /// # Arguments
    /// * `target_bytes` - Target memory size in bytes
    ///
    /// # Errors
    /// Returns an error if the VM is not running or no balloon device is configured.
    #[cfg(target_os = "macos")]
    pub fn set_balloon_target(&self, target_bytes: u64) -> Result<()> {
        use arcbox_hypervisor::darwin::DarwinVm;

        if self.state != VmmState::Running {
            return Err(VmmError::InvalidState(format!(
                "cannot set balloon target: VMM is {:?}",
                self.state
            )));
        }

        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm
                    .set_balloon_target_memory(target_bytes)
                    .map_err(VmmError::Hypervisor);
            }
        }

        Err(VmmError::InvalidState(
            "balloon not available in manual execution mode".to_string(),
        ))
    }

    /// Gets the current target memory size from the balloon device.
    ///
    /// Returns the target memory size in bytes, or 0 if no balloon is configured
    /// or the VM is not running.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn get_balloon_target(&self) -> u64 {
        use arcbox_hypervisor::darwin::DarwinVm;

        if self.state != VmmState::Running {
            return 0;
        }

        if let Some(ref managed_vm) = self.managed_vm {
            if let Some(vm) = managed_vm.downcast_ref::<DarwinVm>() {
                return vm.get_balloon_target_memory();
            }
        }

        0
    }

    /// Returns the configured memory size for this VM.
    ///
    /// This is the maximum memory the guest can use when the balloon is fully deflated.
    #[must_use]
    pub fn configured_memory(&self) -> u64 {
        self.config.memory_size
    }

    /// Returns whether a balloon device is configured for this VM.
    #[must_use]
    pub fn has_balloon(&self) -> bool {
        self.config.balloon
    }

    /// Gets balloon statistics.
    ///
    /// Returns current balloon stats including target, current, and configured memory sizes.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn get_balloon_stats(&self) -> arcbox_hypervisor::BalloonStats {
        arcbox_hypervisor::BalloonStats {
            target_bytes: self.get_balloon_target(),
            current_bytes: 0, // macOS doesn't expose current balloon size
            configured_bytes: self.config.memory_size,
        }
    }

    /// Connects to a vsock port on the guest VM.
    ///
    /// On Linux, this creates a direct AF_VSOCK connection to the guest CID.
    #[cfg(target_os = "linux")]
    pub fn connect_vsock(&self, port: u32) -> Result<std::os::unix::io::RawFd> {
        if self.state != VmmState::Running {
            return Err(VmmError::InvalidState(format!(
                "cannot connect vsock: VMM is {:?}",
                self.state
            )));
        }

        #[repr(C)]
        struct SockaddrVm {
            svm_family: libc::sa_family_t,
            svm_reserved1: u16,
            svm_port: u32,
            svm_cid: u32,
            svm_flags: u8,
            svm_zero: [u8; 3],
        }

        impl SockaddrVm {
            fn new(cid: u32, port: u32) -> Self {
                Self {
                    svm_family: libc::AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: cid,
                    svm_flags: 0,
                    svm_zero: [0; 3],
                }
            }
        }

        let guest_cid = self
            .config
            .guest_cid
            .ok_or_else(|| VmmError::InvalidState("guest_cid not configured".to_string()))?;

        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(VmmError::Device(format!(
                "vsock socket failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let sockaddr = SockaddrVm::new(guest_cid, port);
        let result = unsafe {
            libc::connect(
                fd,
                &sockaddr as *const SockaddrVm as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            )
        };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(VmmError::Device(format!("vsock connect failed: {}", err)));
        }

        Ok(fd)
    }

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
        use arcbox_hypervisor::VcpuExit;

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

#[cfg(target_os = "linux")]
fn map_virtio_devices_to_fdt_entries(
    devices: &[arcbox_hypervisor::linux::VirtioDeviceInfo],
) -> Vec<DeviceTreeEntry> {
    devices
        .iter()
        .map(|device| DeviceTreeEntry {
            compatible: "virtio,mmio".to_string(),
            reg_base: device.mmio_base,
            reg_size: device.mmio_size,
            irq: device.irq,
        })
        .collect()
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn build_fdt_config(
    config: &VmmConfig,
    virtio_devices: &[arcbox_hypervisor::linux::VirtioDeviceInfo],
) -> Result<FdtConfig> {
    let mut fdt_config = FdtConfig::default();
    fdt_config.num_cpus = config.vcpu_count;
    fdt_config.memory_size = config.memory_size;
    fdt_config.memory_base = 0;
    fdt_config.cmdline = config.kernel_cmdline.clone();
    fdt_config.virtio_devices = map_virtio_devices_to_fdt_entries(virtio_devices);

    if let Some(initrd) = &config.initrd_path {
        let size = std::fs::metadata(initrd)
            .map_err(|e| VmmError::Config(format!("Cannot stat initrd: {}", e)))?
            .len();
        fdt_config.initrd_addr = Some(arm64::INITRD_LOAD_ADDR);
        fdt_config.initrd_size = Some(size);
    }

    Ok(fdt_config)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn choose_fdt_addr(memory_size: u64, fdt_size: usize) -> Result<u64> {
    let fdt_size = fdt_size as u64;
    let gib: u64 = 1024 * 1024 * 1024;
    let preferred = if memory_size >= gib {
        arm64::FDT_LOAD_ADDR
    } else {
        0x0800_0000
    };

    if fdt_size > memory_size {
        return Err(VmmError::Memory(
            "FDT size exceeds guest memory".to_string(),
        ));
    }

    if preferred + fdt_size > memory_size {
        return Err(VmmError::Memory(
            "FDT does not fit at fixed load address".to_string(),
        ));
    }

    Ok(preferred)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn write_fdt_to_guest(
    vm: &arcbox_hypervisor::linux::KvmVm,
    config: &VmmConfig,
    virtio_devices: &[arcbox_hypervisor::linux::VirtioDeviceInfo],
) -> Result<()> {
    let fdt_config = build_fdt_config(config, virtio_devices)?;
    let blob = generate_fdt(&fdt_config)?;

    if blob.len() > arm64::FDT_MAX_SIZE {
        return Err(VmmError::Memory(
            "Generated FDT exceeds maximum size".to_string(),
        ));
    }

    let fdt_addr = choose_fdt_addr(config.memory_size, blob.len())?;
    vm.memory()
        .write(GuestAddress::new(fdt_addr), &blob)
        .map_err(VmmError::from)?;

    tracing::info!(
        "Loaded FDT: addr={:#x}, size={} bytes, devices={}",
        fdt_addr,
        blob.len(),
        fdt_config.virtio_devices.len()
    );

    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod fdt_tests {
    use super::*;

    #[test]
    fn test_map_virtio_devices_to_fdt_entries() {
        let devices = vec![
            VirtioDeviceInfo {
                device_type: arcbox_hypervisor::VirtioDeviceType::Block,
                mmio_base: 0x1000,
                mmio_size: 0x200,
                irq: 32,
                irq_fd: 0,
                notify_fd: 0,
            },
            VirtioDeviceInfo {
                device_type: arcbox_hypervisor::VirtioDeviceType::Net,
                mmio_base: 0x2000,
                mmio_size: 0x200,
                irq: 33,
                irq_fd: 0,
                notify_fd: 0,
            },
        ];

        let entries = map_virtio_devices_to_fdt_entries(&devices);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].reg_base, 0x1000);
        assert_eq!(entries[1].irq, 33);
        assert_eq!(entries[0].compatible, "virtio,mmio");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_choose_fdt_addr_prefers_default_when_in_range() {
        let addr = choose_fdt_addr(arm64::FDT_LOAD_ADDR + 0x2000, 0x1000).unwrap();
        assert_eq!(addr, arm64::FDT_LOAD_ADDR);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_choose_fdt_addr_rejects_out_of_range() {
        let result = choose_fdt_addr(arm64::FDT_LOAD_ADDR + 0x1000, 0x2000);
        assert!(result.is_err());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_choose_fdt_addr_uses_fallback_for_small_ram() {
        let addr = choose_fdt_addr(512 * 1024 * 1024, 0x1000).unwrap();
        assert_eq!(addr, 0x0800_0000);
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
