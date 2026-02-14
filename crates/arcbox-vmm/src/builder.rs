//! VM builder for fluent configuration.
//!
//! Provides a builder pattern for constructing VMs with various configurations.

use std::path::PathBuf;
use std::sync::Arc;

use crate::device::{DeviceManager, DeviceType};
use crate::error::{Result, VmmError};
use crate::irq::IrqChip;
use crate::memory::MemoryManager;
use crate::vmm::{Vmm, VmmConfig};

use arcbox_virtio::VirtioDevice;
use arcbox_virtio::blk::{BlockConfig, VirtioBlock};
use arcbox_virtio::console::{ConsoleConfig, VirtioConsole};
use arcbox_virtio::fs::{FsConfig, VirtioFs};
use arcbox_virtio::net::{NetConfig, VirtioNet};
use arcbox_virtio::vsock::{VirtioVsock, VsockConfig};

/// Block device configuration for the builder.
#[derive(Debug, Clone)]
pub struct BlockDeviceConfig {
    /// Path to the disk image.
    pub path: PathBuf,
    /// Whether the disk is read-only.
    pub read_only: bool,
    /// Device ID (e.g., "vda", "vdb").
    pub id: String,
}

/// Network device configuration for the builder.
#[derive(Debug, Clone)]
pub struct NetworkDeviceConfig {
    /// MAC address (if None, random MAC is generated).
    pub mac: Option<[u8; 6]>,
    /// TAP device name (Linux only).
    pub tap_name: Option<String>,
    /// Device ID.
    pub id: String,
}

/// Console configuration for the builder.
#[derive(Debug, Clone)]
pub struct ConsoleDeviceConfig {
    /// Console columns.
    pub cols: u16,
    /// Console rows.
    pub rows: u16,
}

/// Shared directory configuration for virtio-fs.
#[derive(Debug, Clone)]
pub struct SharedDirConfig {
    /// Host path to share.
    pub host_path: PathBuf,
    /// Tag for mounting in guest.
    pub tag: String,
    /// Whether read-only.
    pub read_only: bool,
}

/// Vsock configuration.
#[derive(Debug, Clone)]
pub struct VsockDeviceConfig {
    /// Guest CID.
    pub guest_cid: u64,
}

/// VM builder for constructing virtual machines.
///
/// # Example
///
/// ```ignore
/// use arcbox_vmm::builder::VmBuilder;
///
/// let vm = VmBuilder::new()
///     .name("my-vm")
///     .cpus(4)
///     .memory_mb(2048)
///     .kernel("/path/to/vmlinux")
///     .cmdline("console=hvc0 root=/dev/vda")
///     .initrd("/path/to/initrd")
///     .block_device("/path/to/disk.img", false)
///     .network_device(None, None)
///     .console(80, 25)
///     .build()?;
/// ```
pub struct VmBuilder {
    name: String,
    cpus: u32,
    memory_size: u64,
    kernel_path: Option<PathBuf>,
    kernel_cmdline: String,
    initrd_path: Option<PathBuf>,
    enable_rosetta: bool,
    block_devices: Vec<BlockDeviceConfig>,
    network_devices: Vec<NetworkDeviceConfig>,
    console_config: Option<ConsoleDeviceConfig>,
    shared_dirs: Vec<SharedDirConfig>,
    vsock_config: Option<VsockDeviceConfig>,
}

impl VmBuilder {
    /// Creates a new VM builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "arcbox-vm".to_string(),
            cpus: 1,
            memory_size: 512 * 1024 * 1024, // 512MB
            kernel_path: None,
            kernel_cmdline: String::new(),
            initrd_path: None,
            enable_rosetta: false,
            block_devices: Vec::new(),
            network_devices: Vec::new(),
            console_config: Some(ConsoleDeviceConfig { cols: 80, rows: 25 }),
            shared_dirs: Vec::new(),
            vsock_config: None,
        }
    }

    /// Sets the VM name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the number of CPUs.
    #[must_use]
    pub fn cpus(mut self, count: u32) -> Self {
        self.cpus = count;
        self
    }

    /// Sets the memory size in bytes.
    #[must_use]
    pub fn memory(mut self, size: u64) -> Self {
        self.memory_size = size;
        self
    }

    /// Sets the memory size in megabytes.
    #[must_use]
    pub fn memory_mb(mut self, mb: u64) -> Self {
        self.memory_size = mb * 1024 * 1024;
        self
    }

    /// Sets the memory size in gigabytes.
    #[must_use]
    pub fn memory_gb(mut self, gb: u64) -> Self {
        self.memory_size = gb * 1024 * 1024 * 1024;
        self
    }

    /// Sets the kernel path.
    #[must_use]
    pub fn kernel(mut self, path: impl Into<PathBuf>) -> Self {
        self.kernel_path = Some(path.into());
        self
    }

    /// Sets the kernel command line.
    #[must_use]
    pub fn cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = cmdline.into();
        self
    }

    /// Appends to the kernel command line.
    #[must_use]
    pub fn append_cmdline(mut self, arg: impl AsRef<str>) -> Self {
        if !self.kernel_cmdline.is_empty() {
            self.kernel_cmdline.push(' ');
        }
        self.kernel_cmdline.push_str(arg.as_ref());
        self
    }

    /// Sets the initrd path.
    #[must_use]
    pub fn initrd(mut self, path: impl Into<PathBuf>) -> Self {
        self.initrd_path = Some(path.into());
        self
    }

    /// Enables Rosetta 2 translation (macOS ARM only).
    #[must_use]
    pub fn rosetta(mut self, enable: bool) -> Self {
        self.enable_rosetta = enable;
        self
    }

    /// Adds a block device.
    #[must_use]
    pub fn block_device(mut self, path: impl Into<PathBuf>, read_only: bool) -> Self {
        let id = format!("vd{}", (b'a' + self.block_devices.len() as u8) as char);
        self.block_devices.push(BlockDeviceConfig {
            path: path.into(),
            read_only,
            id,
        });
        self
    }

    /// Adds a block device with custom ID.
    #[must_use]
    pub fn block_device_with_id(
        mut self,
        path: impl Into<PathBuf>,
        read_only: bool,
        id: impl Into<String>,
    ) -> Self {
        self.block_devices.push(BlockDeviceConfig {
            path: path.into(),
            read_only,
            id: id.into(),
        });
        self
    }

    /// Adds a network device.
    #[must_use]
    pub fn network_device(mut self, mac: Option<[u8; 6]>, tap_name: Option<String>) -> Self {
        let id = format!("eth{}", self.network_devices.len());
        self.network_devices
            .push(NetworkDeviceConfig { mac, tap_name, id });
        self
    }

    /// Sets the console configuration.
    #[must_use]
    pub fn console(mut self, cols: u16, rows: u16) -> Self {
        self.console_config = Some(ConsoleDeviceConfig { cols, rows });
        self
    }

    /// Disables the console.
    #[must_use]
    pub fn no_console(mut self) -> Self {
        self.console_config = None;
        self
    }

    /// Adds a shared directory (virtio-fs).
    #[must_use]
    pub fn shared_dir(
        mut self,
        host_path: impl Into<PathBuf>,
        tag: impl Into<String>,
        read_only: bool,
    ) -> Self {
        self.shared_dirs.push(SharedDirConfig {
            host_path: host_path.into(),
            tag: tag.into(),
            read_only,
        });
        self
    }

    /// Enables vsock with the given guest CID.
    #[must_use]
    pub fn vsock(mut self, guest_cid: u64) -> Self {
        self.vsock_config = Some(VsockDeviceConfig { guest_cid });
        self
    }

    /// Builds the VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be built.
    pub fn build(self) -> Result<Vmm> {
        // Validate configuration
        if self.cpus == 0 {
            return Err(VmmError::Config("cpus must be > 0".to_string()));
        }

        if self.memory_size < 64 * 1024 * 1024 {
            return Err(VmmError::Config("memory must be >= 64MB".to_string()));
        }

        // Create VMM config
        let config = VmmConfig {
            vcpu_count: self.cpus,
            memory_size: self.memory_size,
            kernel_path: self.kernel_path.unwrap_or_default(),
            kernel_cmdline: self.kernel_cmdline,
            initrd_path: self.initrd_path,
            enable_rosetta: self.enable_rosetta,
            serial_console: self.console_config.is_some(),
            virtio_console: self.console_config.is_some(),
            shared_dirs: self
                .shared_dirs
                .iter()
                .map(|cfg| crate::SharedDirConfig {
                    host_path: cfg.host_path.clone(),
                    tag: cfg.tag.clone(),
                    read_only: cfg.read_only,
                })
                .collect(),
            networking: !self.network_devices.is_empty(),
            vsock: self.vsock_config.is_some(),
            guest_cid: self.vsock_config.as_ref().map(|cfg| cfg.guest_cid as u32),
            balloon: true, // Enable balloon by default for memory optimization
        };

        tracing::info!(
            "Building VM '{}': cpus={}, memory={}MB, devices={}",
            self.name,
            self.cpus,
            self.memory_size / (1024 * 1024),
            self.block_devices.len() + self.network_devices.len()
        );

        // Create VMM
        let vmm = Vmm::new(config)?;

        // Note: Devices will be registered during vmm.initialize()
        // The builder stores the configuration, actual device creation
        // happens when the VMM is initialized with the full hypervisor context

        Ok(vmm)
    }
}

impl Default for VmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Extended VMM with device management.
///
/// This is returned by `VmBuilder::build_with_devices()` and includes
/// the configured VirtIO devices.
pub struct VmInstance {
    /// The underlying VMM.
    pub vmm: Vmm,
    /// Block devices.
    pub block_devices: Vec<Arc<VirtioBlock>>,
    /// Network devices.
    pub network_devices: Vec<Arc<VirtioNet>>,
    /// Console device.
    pub console: Option<Arc<VirtioConsole>>,
    /// Filesystem devices.
    pub fs_devices: Vec<Arc<VirtioFs>>,
    /// Vsock device.
    pub vsock: Option<Arc<VirtioVsock>>,
}

impl VmBuilder {
    /// Builds the VM with configured devices.
    ///
    /// This creates all the VirtIO devices specified in the builder
    /// and returns a `VmInstance` with access to them.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM or devices cannot be created.
    pub fn build_with_devices(self) -> Result<VmInstance> {
        let block_configs = self.block_devices.clone();
        let network_configs = self.network_devices.clone();
        let console_config = self.console_config.clone();
        let shared_dirs = self.shared_dirs.clone();
        let vsock_config = self.vsock_config.clone();

        let vmm = self.build()?;

        // Create block devices
        let block_devices: Vec<Arc<VirtioBlock>> = block_configs
            .iter()
            .map(|cfg| {
                let config = BlockConfig {
                    capacity: 0, // Will be determined from file
                    read_only: cfg.read_only,
                    ..Default::default()
                };
                Arc::new(VirtioBlock::new(config))
            })
            .collect();

        // Create network devices
        let network_devices: Vec<Arc<VirtioNet>> = network_configs
            .iter()
            .map(|cfg| {
                let config = NetConfig {
                    mac: cfg.mac.unwrap_or_else(NetConfig::random_mac),
                    tap_name: cfg.tap_name.clone(),
                    ..Default::default()
                };
                Arc::new(VirtioNet::new(config))
            })
            .collect();

        // Create console device
        let console = console_config.map(|cfg| {
            let config = ConsoleConfig {
                cols: cfg.cols,
                rows: cfg.rows,
                ..Default::default()
            };
            Arc::new(VirtioConsole::new(config))
        });

        // Create filesystem devices
        let fs_devices: Vec<Arc<VirtioFs>> = shared_dirs
            .iter()
            .map(|cfg| {
                let config = FsConfig {
                    tag: cfg.tag.clone(),
                    shared_dir: cfg.host_path.to_string_lossy().to_string(),
                    ..Default::default()
                };
                Arc::new(VirtioFs::new(config))
            })
            .collect();

        // Create vsock device
        let vsock = vsock_config.map(|cfg| {
            let config = VsockConfig {
                guest_cid: cfg.guest_cid,
            };
            Arc::new(VirtioVsock::new(config))
        });

        Ok(VmInstance {
            vmm,
            block_devices,
            network_devices,
            console,
            fs_devices,
            vsock,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = VmBuilder::new();
        assert_eq!(builder.cpus, 1);
        assert_eq!(builder.memory_size, 512 * 1024 * 1024);
    }

    #[test]
    fn test_builder_cpus() {
        let builder = VmBuilder::new().cpus(4);
        assert_eq!(builder.cpus, 4);
    }

    #[test]
    fn test_builder_memory() {
        let builder = VmBuilder::new().memory_mb(2048);
        assert_eq!(builder.memory_size, 2048 * 1024 * 1024);

        let builder = VmBuilder::new().memory_gb(4);
        assert_eq!(builder.memory_size, 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_builder_cmdline() {
        let builder = VmBuilder::new()
            .cmdline("console=hvc0")
            .append_cmdline("root=/dev/vda");

        assert_eq!(builder.kernel_cmdline, "console=hvc0 root=/dev/vda");
    }

    #[test]
    fn test_builder_block_devices() {
        let builder = VmBuilder::new()
            .block_device("/dev/sda", false)
            .block_device("/dev/sdb", true);

        assert_eq!(builder.block_devices.len(), 2);
        assert_eq!(builder.block_devices[0].id, "vda");
        assert_eq!(builder.block_devices[1].id, "vdb");
        assert!(!builder.block_devices[0].read_only);
        assert!(builder.block_devices[1].read_only);
    }

    #[test]
    fn test_builder_network_devices() {
        let builder = VmBuilder::new()
            .network_device(None, None)
            .network_device(Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]), None);

        assert_eq!(builder.network_devices.len(), 2);
        assert_eq!(builder.network_devices[0].id, "eth0");
        assert_eq!(builder.network_devices[1].id, "eth1");
    }

    #[test]
    fn test_builder_shared_dirs() {
        let builder = VmBuilder::new()
            .shared_dir("/home/user/shared", "myshare", false)
            .shared_dir("/home/user/readonly", "rodata", true);

        assert_eq!(builder.shared_dirs.len(), 2);
        assert_eq!(builder.shared_dirs[0].tag, "myshare");
        assert!(builder.shared_dirs[1].read_only);
    }

    #[test]
    fn test_builder_vsock() {
        let builder = VmBuilder::new().vsock(3);
        assert!(builder.vsock_config.is_some());
        assert_eq!(builder.vsock_config.unwrap().guest_cid, 3);
    }

    #[test]
    fn test_builder_validation_zero_cpus() {
        let result = VmBuilder::new().cpus(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_validation_small_memory() {
        let result = VmBuilder::new().memory_mb(32).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_full_chain() {
        let builder = VmBuilder::new()
            .name("test-vm")
            .cpus(2)
            .memory_gb(1)
            .cmdline("console=hvc0")
            .block_device("/path/to/disk.img", false)
            .network_device(None, None)
            .console(120, 40)
            .shared_dir("/tmp/share", "share", false)
            .vsock(3);

        assert_eq!(builder.name, "test-vm");
        assert_eq!(builder.cpus, 2);
        assert_eq!(builder.memory_size, 1024 * 1024 * 1024);
        assert_eq!(builder.block_devices.len(), 1);
        assert_eq!(builder.network_devices.len(), 1);
        assert!(builder.console_config.is_some());
        assert_eq!(builder.shared_dirs.len(), 1);
        assert!(builder.vsock_config.is_some());
    }
}
