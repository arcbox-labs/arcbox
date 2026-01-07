//! Main VMM implementation.
//!
//! The VMM (Virtual Machine Monitor) orchestrates all components needed to run
//! a virtual machine: hypervisor, vCPUs, memory, and devices.

use std::any::Any;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::device::DeviceManager;
use crate::error::{Result, VmmError};
use crate::event::EventLoop;
use crate::irq::{Gsi, IrqChip, IrqTriggerCallback};
use crate::memory::MemoryManager;
use crate::vcpu::VcpuManager;

use arcbox_hypervisor::VmConfig;

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
        }
    }
}

impl VmmConfig {
    /// Creates a VmConfig for the hypervisor from this VMM config.
    fn to_vm_config(&self) -> VmConfig {
        VmConfig::builder()
            .vcpu_count(self.vcpu_count)
            .memory_size(self.memory_size)
            .kernel_path(self.kernel_path.to_string_lossy())
            .kernel_cmdline(&self.kernel_cmdline)
            .enable_rosetta(self.enable_rosetta)
            .build()
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
            return Err(VmmError::Config(
                "memory_size must be >= 64MB".to_string(),
            ));
        }

        if !config.kernel_path.as_os_str().is_empty() && !config.kernel_path.exists() {
            return Err(VmmError::Config(format!(
                "kernel not found: {}",
                config.kernel_path.display()
            )));
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
        use arcbox_hypervisor::darwin::DarwinHypervisor;
        use arcbox_hypervisor::traits::{Hypervisor, VirtualMachine};
        use arcbox_hypervisor::VirtioDeviceConfig;

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
        use std::sync::Mutex;
        use arcbox_hypervisor::linux::KvmVm;
        use arcbox_hypervisor::traits::VirtualMachine;

        // Create hypervisor and VM
        let hypervisor = create_hypervisor()?;
        let vm_config = self.config.to_vm_config();

        tracing::debug!("Platform capabilities: {:?}", hypervisor.capabilities());

        let mut vm = hypervisor.create_vm(vm_config)?;

        // KVM uses manual execution mode
        self.managed_execution = false;

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

    /// Connects to a vsock port on the guest VM (Linux stub).
    #[cfg(target_os = "linux")]
    pub fn connect_vsock(&self, _port: u32) -> Result<std::os::unix::io::RawFd> {
        // On Linux, vsock connections are made directly via AF_VSOCK socket
        Err(VmmError::InvalidState(
            "use AF_VSOCK socket directly on Linux".to_string(),
        ))
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

        match event {
            VmmEvent::VcpuExit { vcpu_id, exit } => {
                tracing::debug!("vCPU {} exit: {:?}", vcpu_id, exit);
                // Handle vCPU exit (I/O, MMIO, etc.)
            }
            VmmEvent::DeviceIo { device_id, .. } => {
                tracing::debug!("Device {} I/O", device_id);
                // Forward to device manager
            }
            VmmEvent::Timer { id } => {
                tracing::trace!("Timer {} fired", id);
            }
            VmmEvent::Shutdown => {
                tracing::info!("Shutdown requested");
                self.running.store(false, Ordering::SeqCst);
            }
        }

        Ok(())
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
        let config = VmmConfig::default();
        let vmm = Vmm::new(config).unwrap();
        assert_eq!(vmm.state(), VmmState::Created);
    }

    #[test]
    fn test_vmm_invalid_config() {
        // Zero vCPUs
        let config = VmmConfig {
            vcpu_count: 0,
            ..Default::default()
        };
        assert!(Vmm::new(config).is_err());

        // Too little memory
        let config = VmmConfig {
            memory_size: 1024, // 1KB
            ..Default::default()
        };
        assert!(Vmm::new(config).is_err());
    }

    #[test]
    fn test_vmm_state_transitions() {
        let config = VmmConfig::default();
        let mut vmm = Vmm::new(config).unwrap();

        // Can't pause before running
        assert!(vmm.pause().is_err());

        // Can't resume before pausing
        assert!(vmm.resume().is_err());
    }
}
