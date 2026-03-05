//! Linux platform-specific VMM implementation.
//!
//! Uses KVM for hardware-accelerated virtualization.

use super::*;

use crate::device::DeviceTreeEntry;
#[cfg(target_arch = "aarch64")]
use arcbox_hypervisor::GuestAddress;
use arcbox_hypervisor::VirtioDeviceConfig;
use arcbox_hypervisor::linux::VirtioDeviceInfo;

#[cfg(target_arch = "aarch64")]
use crate::boot::arm64;
#[cfg(target_arch = "aarch64")]
use crate::fdt::{FdtConfig, generate_fdt};

impl Vmm {
    /// Linux-specific initialization using KVM.
    pub(super) fn initialize_linux(&mut self) -> Result<()> {
        use arcbox_hypervisor::linux::KvmVm;
        use arcbox_hypervisor::traits::{Hypervisor, VirtualMachine};
        use std::sync::Mutex;

        // Create hypervisor and VM
        let hypervisor = arcbox_hypervisor::create_hypervisor()?;
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

        // Add block devices
        for block_dev in &self.config.block_devices {
            let device_config =
                VirtioDeviceConfig::block(block_dev.path.to_string_lossy(), block_dev.read_only);
            vm.add_virtio_device(device_config)?;
            tracing::info!(
                "Added block device: {} (read_only: {})",
                block_dev.path.display(),
                block_dev.read_only
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

    /// Requests graceful stop on Linux (not yet supported).
    pub fn request_stop(&self, _timeout: Duration) -> Result<bool> {
        Ok(false)
    }

    /// Connects to a vsock port on the guest VM.
    ///
    /// On Linux, this creates a direct AF_VSOCK connection to the guest CID.
    pub fn connect_vsock(&self, port: u32) -> Result<std::os::unix::io::RawFd> {
        if self.state != VmmState::Running {
            return Err(VmmError::invalid_state(format!(
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
            .ok_or_else(|| VmmError::invalid_state("guest_cid not configured".to_string()))?;

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

    /// Captures a VM snapshot context from the running Linux VM.
    pub(super) fn capture_snapshot_linux(
        &self,
    ) -> Option<Result<crate::snapshot::VmSnapshotContext>> {
        use arcbox_hypervisor::linux::KvmVm;
        use arcbox_hypervisor::traits::{GuestMemory, VirtualMachine};

        let managed_vm = self.managed_vm.as_ref()?;
        let vm_arc = managed_vm.downcast_ref::<Arc<std::sync::Mutex<KvmVm>>>()?;
        let vm = match vm_arc.lock() {
            Ok(v) => v,
            Err(_) => {
                return Some(Err(VmmError::Device(
                    "failed to lock Linux VM for snapshot".to_string(),
                )));
            }
        };

        let device_snapshots = match vm.snapshot_devices() {
            Ok(s) => s,
            Err(e) => return Some(Err(e.into())),
        };
        let memory_size = vm.memory().size();
        let memory_len = match usize::try_from(memory_size) {
            Ok(l) => l,
            Err(_) => {
                return Some(Err(VmmError::Memory(format!(
                    "guest memory size {} does not fit in usize",
                    memory_size
                ))));
            }
        };

        let mut memory = vec![0u8; memory_len];
        if let Err(e) = vm.memory().dump_all(&mut memory) {
            return Some(Err(e.into()));
        }

        let memory_len = memory.len();
        let memory_reader = Box::new(move |buf: &mut [u8]| {
            if buf.len() != memory_len {
                return Err(crate::snapshot::SnapshotError::Internal(format!(
                    "snapshot buffer size mismatch: expected {}, got {}",
                    memory_len,
                    buf.len()
                )));
            }
            buf.copy_from_slice(&memory);
            Ok(())
        });

        Some(Ok(crate::snapshot::VmSnapshotContext {
            vcpu_snapshots: placeholder_vcpu_snapshots(self.config.vcpu_count),
            device_snapshots,
            memory_size,
            memory_reader,
        }))
    }

    /// Restores snapshot data to the running Linux VM.
    pub(super) fn restore_snapshot_linux(
        &mut self,
        restore_data: &crate::snapshot::VmRestoreData,
    ) -> Option<Result<()>> {
        use arcbox_hypervisor::linux::KvmVm;
        use arcbox_hypervisor::traits::{GuestMemory, VirtualMachine};

        let managed_vm = self.managed_vm.as_ref()?;
        let vm_arc = managed_vm.downcast_ref::<Arc<std::sync::Mutex<KvmVm>>>()?;
        let mut vm = match vm_arc.lock() {
            Ok(v) => v,
            Err(_) => {
                return Some(Err(VmmError::Device(
                    "failed to lock Linux VM for restore".to_string(),
                )));
            }
        };

        if let Err(e) = vm.restore_devices(restore_data.device_snapshots()) {
            return Some(Err(e.into()));
        }
        if let Err(e) = vm.memory().write(
            arcbox_hypervisor::GuestAddress::new(0),
            restore_data.memory(),
        ) {
            return Some(Err(e.into()));
        }

        if restore_data
            .vcpu_snapshots()
            .iter()
            .any(|s| !s.is_placeholder())
        {
            return Some(Err(VmmError::invalid_state(
                "vCPU register restore is not yet supported; snapshot contains non-placeholder vCPU state".to_string(),
            )));
        }

        Some(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// FDT helpers (free functions)
// ---------------------------------------------------------------------------

pub(super) fn map_virtio_devices_to_fdt_entries(
    devices: &[VirtioDeviceInfo],
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

#[cfg(target_arch = "aarch64")]
fn build_fdt_config(config: &VmmConfig, virtio_devices: &[VirtioDeviceInfo]) -> Result<FdtConfig> {
    let mut fdt_config = FdtConfig::default();
    fdt_config.num_cpus = config.vcpu_count;
    fdt_config.memory_size = config.memory_size;
    fdt_config.memory_base = 0;
    fdt_config.cmdline = config.kernel_cmdline.clone();
    fdt_config.virtio_devices = map_virtio_devices_to_fdt_entries(virtio_devices);

    if let Some(initrd) = &config.initrd_path {
        let size = std::fs::metadata(initrd)
            .map_err(|e| VmmError::config(format!("Cannot stat initrd: {}", e)))?
            .len();
        fdt_config.initrd_addr = Some(arm64::INITRD_LOAD_ADDR);
        fdt_config.initrd_size = Some(size);
    }

    Ok(fdt_config)
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
fn write_fdt_to_guest(
    vm: &arcbox_hypervisor::linux::KvmVm,
    config: &VmmConfig,
    virtio_devices: &[VirtioDeviceInfo],
) -> Result<()> {
    use arcbox_hypervisor::traits::{GuestMemory, VirtualMachine};

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

#[cfg(test)]
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
