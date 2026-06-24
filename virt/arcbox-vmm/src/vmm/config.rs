use std::path::PathBuf;

use arcbox_hypervisor::VmConfig;

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
            vcpu_count: arcbox_hypervisor::default_vm_cpu_count(),
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
    pub(super) fn to_vm_config(&self) -> VmConfig {
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
