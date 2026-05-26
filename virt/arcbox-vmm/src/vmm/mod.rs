//! Main VMM implementation.
//!
//! The VMM (Virtual Machine Monitor) orchestrates all components needed to run
//! a virtual machine: hypervisor, vCPUs, memory, and devices.
//!
//! Platform-specific logic lives in submodules:
//! - `darwin`: macOS (Virtualization.framework) managed execution
//! - `linux`: Linux (KVM) manual execution

#[cfg(target_os = "macos")]
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
#[cfg(target_os = "linux")]
use crate::vcpu::VcpuManager;

use arcbox_hypervisor::VirtioDeviceConfig;
use arcbox_hypervisor::VmConfig;

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
mod darwin_hv;
#[cfg(target_os = "linux")]
mod linux;

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
    /// Optional MAC address for the bridge NAT NIC on macOS.
    pub bridge_nic_mac: Option<String>,
    /// VM backend selection (macOS only).
    ///
    /// Controls whether to use Hypervisor.framework (custom VMM with TSO
    /// support) or Virtualization.framework (managed execution). Requires
    /// macOS 15+ for HV backend. See [`VmBackend`] for details.
    pub backend: VmBackend,
}

impl Default for VmmConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            memory_size: arcbox_hypervisor::default_vm_memory_size(),
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
            bridge_nic_mac: None,
            backend: VmBackend::default(),
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

/// VM backend selection for macOS.
///
/// Controls whether the VMM uses Apple's Virtualization.framework (managed
/// execution) or Hypervisor.framework (custom VMM with manual execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmBackend {
    /// Auto-select: HV for native ARM64, VZ when Rosetta is needed.
    #[default]
    Auto,
    /// Force Hypervisor.framework (custom VMM). Requires macOS 15+.
    Hv,
    /// Force Virtualization.framework (managed execution).
    Vz,
}

/// Resolved backend after evaluating platform constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedBackend {
    /// Hypervisor.framework (custom VMM with manual vCPU execution).
    Hv,
    /// Virtualization.framework (managed execution by Apple's runtime).
    Vz,
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
    /// vCPU manager (Linux only — KVM uses manual execution).
    #[cfg(target_os = "linux")]
    vcpu_manager: Option<VcpuManager>,
    /// Memory manager.
    memory_manager: Option<MemoryManager>,
    /// Device manager.
    device_manager: Option<DeviceManager>,
    /// IRQ chip (Arc for sharing with callback).
    irq_chip: Option<Arc<IrqChip>>,
    /// Event loop.
    event_loop: Option<EventLoop>,
    /// When true, Drop will skip calling into the hypervisor stop path.
    /// Used when the guest has already halted (e.g. ACPI shutdown) and the
    /// hypervisor teardown would crash. FDs and other resources are still freed.
    skip_hypervisor_stop: bool,
    /// Typed VM handle — Virtualization.framework managed VM.
    #[cfg(target_os = "macos")]
    darwin_vm: Option<arcbox_hypervisor::darwin::DarwinVm>,
    /// Typed VM handle — KVM VM (Arc for sharing with IRQ callback).
    #[cfg(target_os = "linux")]
    linux_vm: Option<Arc<std::sync::Mutex<arcbox_hypervisor::linux::KvmVm>>>,
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
    /// Shared DNS hosts table from NetworkManager.
    #[cfg(target_os = "macos")]
    shared_dns_hosts: Option<std::sync::Arc<arcbox_dns::LocalHostsTable>>,
    /// Kernel entry address for the custom HV VMM path (stored during
    /// `initialize_darwin_hv`, consumed by `start_darwin_hv`).
    #[cfg(target_os = "macos")]
    hv_kernel_entry: Option<u64>,
    /// FDT load address for the custom HV VMM path.
    #[cfg(target_os = "macos")]
    hv_fdt_addr: Option<u64>,
    /// vCPU thread join handles for the custom HV VMM path.
    #[cfg(target_os = "macos")]
    hv_vcpu_threads: Vec<std::thread::JoinHandle<()>>,
    /// Shared vCPU thread handle registry for WFI unparking (custom HV).
    #[cfg(target_os = "macos")]
    hv_vcpu_thread_handles: Option<darwin_hv::VcpuThreadHandles>,
    /// Shared registry of Hypervisor.framework vCPU IDs (custom HV).
    /// Populated by each vCPU thread after it creates its `HvVcpu`. Used
    /// by `pause`/`stop` to target `hv_vcpus_exit` correctly on arm64.
    #[cfg(target_os = "macos")]
    hv_vcpu_ids: Option<darwin_hv::HvVcpuIds>,
    /// PSCI CPU_ON channel senders for secondary vCPUs (custom HV).
    #[cfg(target_os = "macos")]
    #[allow(clippy::type_complexity)]
    hv_cpu_on_senders: Option<
        std::sync::Arc<
            std::sync::Mutex<Vec<Option<std::sync::mpsc::Sender<darwin_hv::CpuOnRequest>>>>,
        >,
    >,
    /// vmnet bridge interface for the bridge NIC (`vmnet` feature only).
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    vmnet_bridge: Option<std::sync::Arc<arcbox_vmnet::Vmnet>>,
    /// Cancellation token for the vmnet relay task.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    vmnet_relay_cancel: Option<tokio_util::sync::CancellationToken>,
    /// VZ-side fd for the vmnet bridge NIC attachment.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    vmnet_bridge_fd: Option<OwnedFd>,
    /// Resolved backend choice for this VM instance.
    #[cfg(target_os = "macos")]
    resolved_backend: Option<ResolvedBackend>,
    /// Shared DeviceManager reference for HV backend (set during start_darwin_hv).
    /// Used by connect_vsock_hv to inject OP_REQUEST packets after VM starts.
    ///
    /// Declared before `hv_vm` so it drops first: `FsServer` inside the
    /// DeviceManager holds `Arc<HvDaxMapper>` handles that call
    /// `hv_vm_unmap` on drop. Those must complete before `hv_vm_destroy`.
    #[cfg(target_os = "macos")]
    hv_device_manager: Option<std::sync::Arc<DeviceManager>>,
    /// HV-side network fd (NIC1). Paired with the NetworkDatapath fd.
    /// Kept alive so the socketpair stays open while the VM runs.
    #[cfg(target_os = "macos")]
    hv_net_fd: Option<OwnedFd>,
    /// HV-side bridge network fd (NIC2). Paired with the VmnetRelay fd.
    /// Kept alive so the vmnet socketpair stays open while the VM runs.
    #[cfg(target_os = "macos")]
    hv_bridge_net_fd: Option<OwnedFd>,
    /// Block device info captured during initialize for worker thread spawn.
    /// (DeviceId, raw_fd, blk_size, read_only, device_id_string)
    #[cfg(target_os = "macos")]
    /// (DeviceId, raw_fd, blk_size, read_only, device_id_string, num_queues)
    hv_blk_devices: Vec<(crate::device::DeviceId, i32, u32, bool, String, u16)>,
    /// Block I/O worker thread handles for join on shutdown.
    #[cfg(target_os = "macos")]
    hv_blk_worker_threads: Vec<std::thread::JoinHandle<()>>,
    /// HVC fast path: device_idx → (raw_fd, blk_size). Shared with vCPU threads.
    #[cfg(target_os = "macos")]
    hvc_blk_fds: Arc<Vec<(i32, u32)>>,
    /// Per-VirtioFS-share DAX mappers (concrete type).
    ///
    /// One `Arc<HvDaxMapper>` per configured shared directory, in the
    /// same order as `config.shared_dirs`. The mapper itself is also
    /// handed to the `FsServer` as a `dyn DaxMapper` trait object —
    /// both Arcs point to the same underlying counters, so
    /// `dax_stats(share_idx)` reports live values as the guest issues
    /// `FUSE_SETUPMAPPING` / `FUSE_REMOVEMAPPING` requests.
    ///
    /// Declared before `hv_vm` so implicit Drop order is safe: any
    /// remaining `Arc<HvDaxMapper>` refs call `hv_vm_unmap` before
    /// `hv_vm_destroy` runs. `stop_darwin_hv` explicitly calls
    /// `drain_all` first, making implicit drop a no-op for the normal path.
    #[cfg(target_os = "macos")]
    hv_dax_mappers: Vec<std::sync::Arc<crate::dax::HvDaxMapper>>,
    /// HV backend balloon device handle (ABX-363).
    ///
    /// `None` until `initialize_darwin_hv` registers the device (only
    /// happens when `config.balloon` is true). Used by the HV dispatch
    /// path in `darwin.rs` for `set_balloon_target` / `get_balloon_stats`.
    #[cfg(target_os = "macos")]
    hv_balloon: Option<std::sync::Arc<std::sync::Mutex<arcbox_virtio::balloon::VirtioBalloon>>>,
    /// GICv3 handle (custom VMM path, macOS 15+).
    ///
    /// **Drop order — must be declared before `hv_vm`.**
    /// Rust drops struct fields in declaration order (top to bottom). The GIC
    /// interrupt controller holds internal references into the VM; its FFI
    /// destroy/release routines must run while the VM is still alive.
    /// Declaring `hv_gic` before `hv_vm` guarantees that on any exit path
    /// (both the normal `stop_darwin_hv` and the panic / implicit-drop path),
    /// the GIC is torn down before `hv_vm_destroy` is called.
    #[cfg(all(target_os = "macos", feature = "gic"))]
    hv_gic: Option<std::sync::Arc<arcbox_hv::Gic>>,
    /// Hypervisor.framework VM handle (custom VMM path).
    ///
    /// **Drop order — must be declared after `hv_gic`, `hv_dax_mappers`,
    /// and `hv_device_manager`.**
    /// Rust drops fields in declaration order (top to bottom), so fields
    /// declared above this one drop first. This ordering ensures:
    ///   1. `hv_device_manager` (FsServer → Arc<HvDaxMapper> → hv_vm_unmap)
    ///   2. `hv_dax_mappers` (remaining mapper refs → hv_vm_unmap)
    ///   3. `hv_gic` (GIC FFI teardown referencing the live VM)
    ///   4. `hv_vm` → `hv_vm_destroy`
    ///   5. `hv_guest_mem` (mmap'd pages — must outlive the VM)
    ///
    /// `stop_darwin_hv` also calls `drain_all` explicitly for the normal
    /// path; this declaration ordering is the safety net for panic paths.
    #[cfg(target_os = "macos")]
    hv_vm: Option<arcbox_hv::HvVm>,
    /// Guest memory backing (vm-memory mmap, custom VMM path).
    ///
    /// **Drop order — must be declared after `hv_vm`.**
    /// The mmap'd pages must remain accessible until after `hv_vm_destroy`
    /// releases all stage-2 mappings. Declaring this last ensures the host
    /// VA range is freed only after the VM no longer references it.
    #[cfg(target_os = "macos")]
    hv_guest_mem: Option<darwin_hv::HvGuestMem>,
    /// Cooperative pause flag for the HV backend.
    ///
    /// When set to `true`, every vCPU thread parks itself after its next
    /// `vcpu.run()` return instead of re-entering guest execution. `resume`
    /// clears the flag and unparks the threads. Orthogonal to `running`
    /// (which is a terminal stop signal).
    #[cfg(target_os = "macos")]
    hv_paused: Arc<AtomicBool>,
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
            #[cfg(target_os = "linux")]
            vcpu_manager: None,
            memory_manager: None,
            device_manager: None,
            irq_chip: None,
            event_loop: None,
            skip_hypervisor_stop: false,
            #[cfg(target_os = "macos")]
            darwin_vm: None,
            #[cfg(target_os = "linux")]
            linux_vm: None,
            #[cfg(target_os = "macos")]
            net_cancel: None,
            #[cfg(target_os = "macos")]
            net_vz_fd: None,
            #[cfg(target_os = "macos")]
            inbound_listener_manager: None,
            #[cfg(target_os = "macos")]
            shared_dns_hosts: None,
            #[cfg(target_os = "macos")]
            hv_kernel_entry: None,
            #[cfg(target_os = "macos")]
            hv_fdt_addr: None,
            #[cfg(target_os = "macos")]
            hv_vcpu_threads: Vec::new(),
            #[cfg(target_os = "macos")]
            hv_vcpu_thread_handles: None,
            #[cfg(target_os = "macos")]
            hv_vcpu_ids: None,
            #[cfg(target_os = "macos")]
            hv_cpu_on_senders: None,
            #[cfg(all(target_os = "macos", feature = "vmnet"))]
            vmnet_bridge: None,
            #[cfg(all(target_os = "macos", feature = "vmnet"))]
            vmnet_relay_cancel: None,
            #[cfg(all(target_os = "macos", feature = "vmnet"))]
            vmnet_bridge_fd: None,
            #[cfg(all(target_os = "macos", feature = "gic"))]
            hv_gic: None,
            #[cfg(target_os = "macos")]
            hv_vm: None,
            #[cfg(target_os = "macos")]
            hv_guest_mem: None,
            #[cfg(target_os = "macos")]
            resolved_backend: None,
            #[cfg(target_os = "macos")]
            hv_device_manager: None,
            #[cfg(target_os = "macos")]
            hv_net_fd: None,
            hv_bridge_net_fd: None,
            #[cfg(target_os = "macos")]
            hv_blk_devices: Vec::new(),
            #[cfg(target_os = "macos")]
            hv_blk_worker_threads: Vec::new(),
            #[cfg(target_os = "macos")]
            hvc_blk_fds: Arc::new(Vec::new()),
            #[cfg(target_os = "macos")]
            hv_dax_mappers: Vec::new(),
            #[cfg(target_os = "macos")]
            hv_balloon: None,
            #[cfg(target_os = "macos")]
            hv_paused: Arc::new(AtomicBool::new(false)),
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

    /// Sets the shared DNS hosts table from the host-side `NetworkManager`.
    ///
    /// Must be called before `initialize()`. When set, the VMM-side
    /// `DnsForwarder` (in the network datapath) shares this table so that
    /// host-side `register_dns()` calls are visible to guest DNS queries.
    #[cfg(target_os = "macos")]
    pub fn set_shared_dns_hosts(&mut self, table: std::sync::Arc<arcbox_dns::LocalHostsTable>) {
        self.shared_dns_hosts = Some(table);
    }

    /// Returns vmnet interface info for the bridge NIC, if available.
    ///
    /// Only populated when `vmnet` feature is enabled and interface started.
    #[cfg(all(target_os = "macos", feature = "vmnet"))]
    #[must_use]
    pub fn vmnet_interface_info(&self) -> Option<arcbox_vmnet::VmnetInterfaceInfo> {
        self.vmnet_bridge
            .as_ref()
            .and_then(|v| v.interface_info().cloned())
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
            let resolved = resolve_backend(&self.config);
            tracing::info!(
                "VM backend resolved: {:?} (requested: {:?})",
                resolved,
                self.config.backend
            );
            match resolved {
                ResolvedBackend::Hv => self.initialize_darwin_hv()?,
                ResolvedBackend::Vz => self.initialize_darwin()?,
            }
            self.resolved_backend = Some(resolved);
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

        // Darwin: dispatch to the resolved backend.
        // Linux: start vCPU threads for manual execution.
        #[cfg(target_os = "macos")]
        {
            match self.resolved_backend {
                Some(ResolvedBackend::Hv) => self.start_darwin_hv()?,
                Some(ResolvedBackend::Vz) | None => self.start_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        {
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

        #[cfg(target_os = "macos")]
        {
            match self.resolved_backend {
                Some(ResolvedBackend::Hv) => self.pause_darwin_hv()?,
                Some(ResolvedBackend::Vz) | None => self.pause_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(ref mut vcpu_manager) = self.vcpu_manager {
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

        #[cfg(target_os = "macos")]
        {
            match self.resolved_backend {
                Some(ResolvedBackend::Hv) => self.resume_darwin_hv()?,
                Some(ResolvedBackend::Vz) | None => self.resume_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(ref mut vcpu_manager) = self.vcpu_manager {
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

        // Darwin: stop the resolved backend before canceling the network datapath.
        // Linux: stop vCPU threads.
        #[cfg(target_os = "macos")]
        {
            match self.resolved_backend {
                Some(ResolvedBackend::Hv) => self.stop_darwin_hv()?,
                Some(ResolvedBackend::Vz) | None => self.stop_darwin_vm()?,
            }
        }
        #[cfg(target_os = "linux")]
        {
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

    /// Returns a snapshot of DAX counters for the given VirtioFS share
    /// index (0-based, in the order of `config.shared_dirs`). Only
    /// meaningful on the HV backend — the VZ path does not use
    /// `HvDaxMapper`. Returns `None` if the index is out of range or
    /// DAX mappers have not been initialized yet.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn dax_stats(&self, share_idx: usize) -> Option<crate::dax::DaxStats> {
        self.hv_dax_mappers.get(share_idx).map(|m| m.stats())
    }

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
        {
            if matches!(self.resolved_backend, Some(ResolvedBackend::Hv)) {
                return Err(VmmError::Unsupported(
                    "snapshot capture is not yet implemented for the HV backend".to_string(),
                ));
            }
            if let Some(result) = self.capture_snapshot_darwin() {
                return result;
            }
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
        {
            if matches!(self.resolved_backend, Some(ResolvedBackend::Hv)) {
                return Err(VmmError::Unsupported(
                    "snapshot restore is not yet implemented for the HV backend".to_string(),
                ));
            }
            if let Some(result) = self.restore_snapshot_darwin(restore_data) {
                return result;
            }
        }

        Err(VmmError::invalid_state(
            "hypervisor VM handle is unavailable for restore".to_string(),
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
                    self.handle_event(event);
                }
            }

            // Small yield to prevent busy spinning
            tokio::task::yield_now().await;
        }

        tracing::info!("VMM exited");
        Ok(())
    }

    /// Handles an event from the event loop.
    fn handle_event(&self, event: crate::event::VmmEvent) {
        use crate::event::VmmEvent;

        match event {
            VmmEvent::VcpuExit { vcpu_id, exit } => {
                self.handle_vcpu_exit(vcpu_id, exit);
            }
            VmmEvent::DeviceIo {
                device_id,
                is_read,
                addr,
                data,
            } => {
                self.handle_device_io(device_id, is_read, addr, data);
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
    }

    /// Handles a vCPU exit event.
    ///
    /// This processes exits from the hypervisor such as I/O, MMIO, and special
    /// instructions that require VMM intervention.
    fn handle_vcpu_exit(&self, vcpu_id: u32, exit: arcbox_hypervisor::VcpuExit) {
        use arcbox_hypervisor::VcpuExit;

        match &exit {
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
                self.handle_io_out(*port, *size, *data);
            }

            VcpuExit::IoIn { port, size } => {
                tracing::trace!("vCPU {} I/O in: port={:#x}, size={}", vcpu_id, port, size);
                let _value = self.handle_io_in(*port, *size);
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
                    match device_manager.handle_mmio_read(*addr, *size as usize) {
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
                    if let Err(e) = device_manager.handle_mmio_write(*addr, *size as usize, *data) {
                        tracing::warn!("MMIO write failed at {:#x}: {}", addr, e);
                    }
                }
            }

            VcpuExit::Hypercall { nr, args } => {
                tracing::debug!("vCPU {} hypercall: nr={}, args={:?}", vcpu_id, nr, args);
                // Hypercall handling - used for paravirtualization
                self.handle_hypercall(vcpu_id, *nr, *args);
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

            VcpuExit::Debug => {
                tracing::debug!("vCPU {} unhandled exit: {:?}", vcpu_id, exit);
            }
        }
    }

    /// Handles device I/O events.
    fn handle_device_io(&self, device_id: u32, is_read: bool, addr: u64, data: Option<u64>) {
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
    }

    /// Handles I/O port output.
    fn handle_io_out(&self, port: u16, size: u8, data: u64) {
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
    }

    /// Handles I/O port input.
    fn handle_io_in(&self, port: u16, size: u8) -> u64 {
        match port {
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
        }
    }

    /// Handles a hypercall from the guest.
    fn handle_hypercall(&self, vcpu_id: u32, nr: u64, args: [u64; 6]) {
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
    }
}

/// Resolves the backend selection based on platform constraints.
///
/// When `Auto` is selected, Rosetta requires VZ (Hypervisor.framework cannot
/// translate x86_64 instructions). Otherwise, default to VZ until the HV
/// backend is fully validated.
#[cfg(target_os = "macos")]
fn resolve_backend(config: &VmmConfig) -> ResolvedBackend {
    match config.backend {
        VmBackend::Vz => ResolvedBackend::Vz,
        VmBackend::Hv => ResolvedBackend::Hv,
        // Auto: Rosetta x86_64 translation requires VZ (Hypervisor.framework
        // cannot translate instructions). For native ARM64 workloads, prefer HV.
        VmBackend::Auto => {
            if config.enable_rosetta {
                ResolvedBackend::Vz
            } else {
                ResolvedBackend::Hv
            }
        }
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

impl Vmm {
    /// Marks this VMM to skip the Virtualization.framework stop path on drop.
    ///
    /// macOS-only: the VF stop call can crash when the guest has already
    /// halted via ACPI. FDs and network resources are still cleaned up.
    /// Must only be called after ACPI shutdown.
    #[cfg(target_os = "macos")]
    pub fn set_skip_hypervisor_stop(&mut self) {
        self.skip_hypervisor_stop = true;
        self.mark_darwin_vm_skip_stop();
    }
}

impl Drop for Vmm {
    fn drop(&mut self) {
        if self.state != VmmState::Stopped && self.state != VmmState::Created {
            if self.skip_hypervisor_stop {
                // The hypervisor stop path is unsafe (VF may crash when guest
                // already halted). Only clean up network resources.
                #[cfg(target_os = "macos")]
                self.stop_network();
                self.state = VmmState::Stopped;
            } else {
                let _ = self.stop();
            }
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

    /// With the HV backend resolved, `capture_snapshot_context` must return
    /// `VmmError::Unsupported` rather than the old generic `invalid_state
    /// ("hypervisor VM handle is unavailable")` error. This covers the
    /// ABX-360 correctness gap: HV-backed VMs were silently hitting
    /// VZ-only snapshot code paths.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_hv_snapshot_returns_unsupported() {
        let config = VmmConfig {
            guest_cid: Some(3),
            ..Default::default()
        };
        let mut vmm = Vmm::new(config).unwrap();

        // Simulate a started HV VM without actually booting one.
        vmm.resolved_backend = Some(ResolvedBackend::Hv);
        vmm.state = VmmState::Running;

        match vmm.capture_snapshot_context() {
            Err(VmmError::Unsupported(msg)) => assert!(msg.contains("HV backend")),
            Err(other) => panic!("expected Unsupported for HV capture, got Err({other:?})"),
            Ok(_) => panic!("expected Unsupported for HV capture, got Ok"),
        }
    }
}
