//! Virtual machine implementation for Linux KVM.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::{
    config::VmConfig,
    error::HypervisorError,
    memory::GuestAddress,
    traits::VirtualMachine,
    types::{VirtioDeviceConfig, VirtioDeviceType},
};

use std::os::unix::io::RawFd;

use super::ffi::{self, KvmPitConfig, KvmSystem, KvmUserspaceMemoryRegion, KvmVmFd};
use super::memory::KvmMemory;
use super::vcpu::KvmVcpu;

/// Global VM ID counter.
static VM_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// VirtIO MMIO Constants
// ============================================================================

/// Base address for VirtIO MMIO devices (ARM64).
/// This is placed at 160MB to avoid conflicts with RAM and other devices.
const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;

/// Size of each VirtIO MMIO device region (512 bytes).
const VIRTIO_MMIO_SIZE: u64 = 0x200;

/// Gap between VirtIO MMIO devices (for alignment).
const VIRTIO_MMIO_GAP: u64 = 0x200;

/// VirtIO MMIO register offset for queue notify (used for IOEVENTFD).
const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x50;

/// Base IRQ for VirtIO devices.
/// On ARM64 GIC, SPI interrupts start at 32.
/// On x86 IOAPIC, we use IRQs starting at 5 (avoiding legacy devices).
#[cfg(target_arch = "aarch64")]
const VIRTIO_IRQ_BASE: u32 = 32;

#[cfg(target_arch = "x86_64")]
const VIRTIO_IRQ_BASE: u32 = 5;

/// Maximum number of VirtIO devices.
const MAX_VIRTIO_DEVICES: usize = 32;

// ============================================================================
// VirtIO Device Tracking
// ============================================================================

/// Information about an attached VirtIO device.
#[derive(Debug)]
pub struct VirtioDeviceInfo {
    /// Device type.
    pub device_type: VirtioDeviceType,
    /// MMIO base address.
    pub mmio_base: u64,
    /// MMIO region size.
    pub mmio_size: u64,
    /// Assigned IRQ (GSI).
    pub irq: u32,
    /// Eventfd for IRQ injection.
    pub irq_fd: RawFd,
    /// Eventfd for queue notification.
    pub notify_fd: RawFd,
}

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

/// Virtual machine implementation for Linux KVM.
///
/// This wraps a KVM VM and provides the platform-agnostic interface.
pub struct KvmVm {
    /// Unique VM ID.
    id: u64,
    /// VM configuration.
    config: VmConfig,
    /// KVM system handle.
    #[allow(dead_code)]
    kvm: Arc<KvmSystem>,
    /// KVM VM file descriptor.
    vm_fd: KvmVmFd,
    /// vCPU mmap size.
    vcpu_mmap_size: usize,
    /// Guest memory.
    memory: KvmMemory,
    /// Next memory slot ID.
    next_slot: AtomicU32,
    /// Created vCPU IDs.
    vcpus: RwLock<Vec<u32>>,
    /// Current state.
    state: RwLock<VmState>,
    /// Whether the VM is running.
    running: AtomicBool,
    /// Attached VirtIO devices.
    virtio_devices: RwLock<Vec<VirtioDeviceInfo>>,
    /// Next VirtIO IRQ offset.
    next_virtio_irq: AtomicU32,
}

// Safety: All mutable state is properly synchronized.
unsafe impl Send for KvmVm {}
unsafe impl Sync for KvmVm {}

impl KvmVm {
    /// Creates a new KVM VM.
    pub(crate) fn new(
        kvm: Arc<KvmSystem>,
        vcpu_mmap_size: usize,
        config: VmConfig,
    ) -> Result<Self, HypervisorError> {
        let id = VM_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Create the VM
        let vm_fd = kvm.create_vm().map_err(|e| {
            HypervisorError::VmCreationFailed(format!("Failed to create KVM VM: {}", e))
        })?;

        // Setup architecture-specific components
        #[cfg(target_arch = "x86_64")]
        Self::setup_x86_vm(&vm_fd)?;

        // Allocate guest memory
        let memory = KvmMemory::new(config.memory_size)?;

        // Map memory to the VM
        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: config.memory_size,
            userspace_addr: memory.host_address() as u64,
        };

        vm_fd.set_user_memory_region(&region).map_err(|e| {
            HypervisorError::VmCreationFailed(format!("Failed to map guest memory: {}", e))
        })?;

        tracing::info!(
            "Created KVM VM {}: vcpus={}, memory={}MB",
            id,
            config.vcpu_count,
            config.memory_size / (1024 * 1024)
        );

        Ok(Self {
            id,
            config,
            kvm,
            vm_fd,
            vcpu_mmap_size,
            memory,
            next_slot: AtomicU32::new(1), // Slot 0 is used for main memory
            vcpus: RwLock::new(Vec::new()),
            state: RwLock::new(VmState::Created),
            running: AtomicBool::new(false),
            virtio_devices: RwLock::new(Vec::new()),
            next_virtio_irq: AtomicU32::new(0),
        })
    }

    /// Sets up x86-specific VM components.
    #[cfg(target_arch = "x86_64")]
    fn setup_x86_vm(vm_fd: &KvmVmFd) -> Result<(), HypervisorError> {
        // Set TSS address (required for Intel VT-x)
        // The TSS is placed at the end of the 4GB space to avoid conflicts
        const TSS_ADDR: u64 = 0xfffb_d000;
        vm_fd
            .set_tss_addr(TSS_ADDR)
            .map_err(|e| HypervisorError::VmCreationFailed(format!("Failed to set TSS: {}", e)))?;

        // Set identity map address
        const IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;
        vm_fd.set_identity_map_addr(IDENTITY_MAP_ADDR).map_err(|e| {
            HypervisorError::VmCreationFailed(format!("Failed to set identity map: {}", e))
        })?;

        // Create in-kernel IRQ chip (APIC, IOAPIC, PIC)
        vm_fd.create_irqchip().map_err(|e| {
            HypervisorError::VmCreationFailed(format!("Failed to create IRQ chip: {}", e))
        })?;

        // Create PIT (Programmable Interval Timer)
        let pit_config = KvmPitConfig::default();
        vm_fd.create_pit2(&pit_config).map_err(|e| {
            HypervisorError::VmCreationFailed(format!("Failed to create PIT: {}", e))
        })?;

        Ok(())
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

    /// Returns the KVM VM file descriptor.
    pub(crate) fn vm_fd(&self) -> &KvmVmFd {
        &self.vm_fd
    }

    /// Returns the vCPU mmap size.
    pub(crate) fn vcpu_mmap_size(&self) -> usize {
        self.vcpu_mmap_size
    }

    /// Adds an additional memory region to the VM.
    pub fn add_memory_region(
        &self,
        guest_addr: GuestAddress,
        host_addr: *mut u8,
        size: u64,
        read_only: bool,
    ) -> Result<u32, HypervisorError> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);

        let mut flags = 0u32;
        if read_only {
            flags |= ffi::KVM_MEM_READONLY;
        }

        let region = KvmUserspaceMemoryRegion {
            slot,
            flags,
            guest_phys_addr: guest_addr.raw(),
            memory_size: size,
            userspace_addr: host_addr as u64,
        };

        self.vm_fd.set_user_memory_region(&region).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to add memory region: {}", e))
        })?;

        tracing::debug!(
            "Added memory region {} at {}: {}MB, read_only={}",
            slot,
            guest_addr,
            size / (1024 * 1024),
            read_only
        );

        Ok(slot)
    }

    /// Removes a memory region from the VM.
    pub fn remove_memory_region(&self, slot: u32) -> Result<(), HypervisorError> {
        let region = KvmUserspaceMemoryRegion {
            slot,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
        };

        self.vm_fd.set_user_memory_region(&region).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to remove memory region: {}", e))
        })?;

        tracing::debug!("Removed memory region {}", slot);

        Ok(())
    }

    // ========================================================================
    // IRQ Injection Interface
    // ========================================================================

    /// Sets the IRQ line level on the in-kernel irqchip.
    ///
    /// For edge-triggered interrupts, call with level=true then level=false.
    /// For level-triggered interrupts, keep level=true until acknowledged.
    ///
    /// # Arguments
    /// * `gsi` - Global System Interrupt number
    /// * `level` - true to assert, false to deassert
    pub fn set_irq_line(&self, gsi: u32, level: bool) -> Result<(), HypervisorError> {
        self.vm_fd.set_irq_line(gsi, level).map_err(|e| {
            HypervisorError::DeviceError(format!("Failed to set IRQ line: {}", e))
        })
    }

    /// Triggers an edge-triggered interrupt.
    ///
    /// Convenience method that asserts then immediately deasserts the IRQ line.
    pub fn trigger_edge_irq(&self, gsi: u32) -> Result<(), HypervisorError> {
        self.set_irq_line(gsi, true)?;
        self.set_irq_line(gsi, false)
    }

    /// Registers an eventfd for IRQ injection (IRQFD).
    ///
    /// When the eventfd is signaled (write 1 to it), KVM will automatically
    /// inject the specified GSI into the guest. This is the most efficient
    /// method for interrupt delivery.
    ///
    /// # Arguments
    /// * `eventfd` - The eventfd file descriptor
    /// * `gsi` - The GSI to inject when eventfd is signaled
    /// * `resample_fd` - For level-triggered IRQs, optional resample eventfd
    pub fn register_irqfd(
        &self,
        eventfd: RawFd,
        gsi: u32,
        resample_fd: Option<RawFd>,
    ) -> Result<(), HypervisorError> {
        self.vm_fd.register_irqfd(eventfd, gsi, resample_fd).map_err(|e| {
            HypervisorError::DeviceError(format!("Failed to register IRQFD: {}", e))
        })
    }

    /// Unregisters an eventfd for IRQ injection.
    pub fn unregister_irqfd(&self, eventfd: RawFd, gsi: u32) -> Result<(), HypervisorError> {
        self.vm_fd.unregister_irqfd(eventfd, gsi).map_err(|e| {
            HypervisorError::DeviceError(format!("Failed to unregister IRQFD: {}", e))
        })
    }

    // ========================================================================
    // VirtIO Device Support
    // ========================================================================

    /// Allocates an MMIO region for a VirtIO device.
    ///
    /// Returns the base address for the device.
    fn allocate_mmio_region(&self) -> Result<u64, HypervisorError> {
        let devices = self.virtio_devices.read().map_err(|_| {
            HypervisorError::DeviceError("Lock poisoned".to_string())
        })?;

        if devices.len() >= MAX_VIRTIO_DEVICES {
            return Err(HypervisorError::DeviceError(
                "Maximum number of VirtIO devices reached".to_string(),
            ));
        }

        // Calculate next available address.
        let offset = devices.len() as u64 * (VIRTIO_MMIO_SIZE + VIRTIO_MMIO_GAP);
        Ok(VIRTIO_MMIO_BASE + offset)
    }

    /// Allocates an IRQ (GSI) for a VirtIO device.
    fn allocate_irq(&self) -> u32 {
        let offset = self.next_virtio_irq.fetch_add(1, Ordering::SeqCst);
        VIRTIO_IRQ_BASE + offset
    }

    /// Creates an eventfd.
    fn create_eventfd() -> Result<RawFd, HypervisorError> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(HypervisorError::DeviceError(format!(
                "Failed to create eventfd: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(fd)
    }

    /// Sets up IOEVENTFD for VirtIO queue notification.
    ///
    /// This allows the guest to notify the host about queue updates by writing
    /// to a specific MMIO address, without causing a VM exit.
    fn setup_ioeventfd(&self, mmio_base: u64) -> Result<RawFd, HypervisorError> {
        let notify_fd = Self::create_eventfd()?;

        // Register IOEVENTFD at the queue notify register address.
        // 4 bytes for 32-bit writes to VIRTIO_MMIO_QUEUE_NOTIFY.
        let notify_addr = mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY;

        self.vm_fd
            .register_ioeventfd(notify_addr, 4, notify_fd, None)
            .map_err(|e| {
                // Clean up the eventfd on failure.
                unsafe { libc::close(notify_fd) };
                HypervisorError::DeviceError(format!("Failed to register IOEVENTFD: {}", e))
            })?;

        tracing::debug!(
            "Registered IOEVENTFD at {:#x} with fd={}",
            notify_addr,
            notify_fd
        );

        Ok(notify_fd)
    }

    /// Returns a copy of the attached VirtIO devices info.
    pub fn virtio_devices(&self) -> Result<Vec<VirtioDeviceInfo>, HypervisorError> {
        let devices = self.virtio_devices.read().map_err(|_| {
            HypervisorError::DeviceError("Lock poisoned".to_string())
        })?;

        Ok(devices.iter().map(|d| VirtioDeviceInfo {
            device_type: d.device_type.clone(),
            mmio_base: d.mmio_base,
            mmio_size: d.mmio_size,
            irq: d.irq,
            irq_fd: d.irq_fd,
            notify_fd: d.notify_fd,
        }).collect())
    }
}

impl VirtualMachine for KvmVm {
    type Vcpu = KvmVcpu;
    type Memory = KvmMemory;

    fn memory(&self) -> &Self::Memory {
        &self.memory
    }

    fn create_vcpu(&mut self, id: u32) -> Result<Self::Vcpu, HypervisorError> {
        if id >= self.config.vcpu_count {
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
            let vcpus = self.vcpus.read().map_err(|_| HypervisorError::VcpuCreationFailed {
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

        // Create vCPU via KVM
        let vcpu_fd = self.vm_fd.create_vcpu(id, self.vcpu_mmap_size).map_err(|e| {
            HypervisorError::VcpuCreationFailed {
                id,
                reason: format!("KVM error: {}", e),
            }
        })?;

        // Create wrapper
        let vcpu = KvmVcpu::new(id, vcpu_fd)?;

        // Record creation
        {
            let mut vcpus = self.vcpus.write().map_err(|_| HypervisorError::VcpuCreationFailed {
                id,
                reason: "Lock poisoned".to_string(),
            })?;
            vcpus.push(id);
        }

        tracing::debug!("Created vCPU {} for VM {}", id, self.id);

        Ok(vcpu)
    }

    fn add_virtio_device(&mut self, device: VirtioDeviceConfig) -> Result<(), HypervisorError> {
        // 1. Check state - devices can only be added before VM starts.
        let state = self.state();
        if state != VmState::Created {
            return Err(HypervisorError::DeviceError(
                "Cannot add device: VM not in Created state".to_string(),
            ));
        }

        // 2. Allocate MMIO address space for the device.
        let mmio_base = self.allocate_mmio_region()?;

        // 3. Allocate an IRQ (GSI) for the device.
        let gsi = self.allocate_irq();

        // 4. Create eventfd for IRQ injection and register IRQFD.
        let irq_fd = Self::create_eventfd()?;

        if let Err(e) = self.register_irqfd(irq_fd, gsi, None) {
            // Clean up on failure.
            unsafe { libc::close(irq_fd) };
            return Err(e);
        }

        // 5. Set up IOEVENTFD for queue notification.
        let notify_fd = match self.setup_ioeventfd(mmio_base) {
            Ok(fd) => fd,
            Err(e) => {
                // Clean up on failure.
                let _ = self.unregister_irqfd(irq_fd, gsi);
                unsafe { libc::close(irq_fd) };
                return Err(e);
            }
        };

        // 6. Record the device information.
        let device_info = VirtioDeviceInfo {
            device_type: device.device_type.clone(),
            mmio_base,
            mmio_size: VIRTIO_MMIO_SIZE,
            irq: gsi,
            irq_fd,
            notify_fd,
        };

        {
            let mut devices = self.virtio_devices.write().map_err(|_| {
                // Clean up on failure.
                let _ = self.unregister_irqfd(irq_fd, gsi);
                unsafe {
                    libc::close(irq_fd);
                    libc::close(notify_fd);
                }
                HypervisorError::DeviceError("Lock poisoned".to_string())
            })?;

            devices.push(device_info);
        }

        tracing::info!(
            "Added {:?} device to VM {}: MMIO={:#x}-{:#x}, IRQ={}, irq_fd={}, notify_fd={}",
            device.device_type,
            self.id,
            mmio_base,
            mmio_base + VIRTIO_MMIO_SIZE,
            gsi,
            irq_fd,
            notify_fd
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

        // Mark as running
        self.running.store(true, Ordering::SeqCst);
        self.set_state(VmState::Running);

        tracing::info!("Started VM {}", self.id);

        Ok(())
    }

    fn pause(&mut self) -> Result<(), HypervisorError> {
        let state = self.state();
        if state != VmState::Running {
            return Err(HypervisorError::InvalidState {
                expected: "Running".to_string(),
                actual: format!("{:?}", state),
            });
        }

        // Signal all vCPUs to pause
        // In KVM, this is typically done by setting immediate_exit and signaling
        // the vCPU threads

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

        // Signal all vCPUs to stop
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

impl Drop for KvmVm {
    fn drop(&mut self) {
        // Stop VM if running.
        if self.is_running() {
            let _ = self.stop();
        }

        // Clean up VirtIO device resources.
        if let Ok(devices) = self.virtio_devices.read() {
            for device in devices.iter() {
                // Unregister IRQFD.
                let _ = self.unregister_irqfd(device.irq_fd, device.irq);

                // Unregister IOEVENTFD.
                let notify_addr = device.mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY;
                let _ = self.vm_fd.unregister_ioeventfd(notify_addr, 4, device.notify_fd);

                // Close eventfds.
                unsafe {
                    libc::close(device.irq_fd);
                    libc::close(device.notify_fd);
                }
            }
        }

        tracing::debug!("Dropped VM {}", self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CpuArch;

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_vm_creation() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 2,
            memory_size: 128 * 1024 * 1024,
            arch: CpuArch::native(),
            ..Default::default()
        };

        let vm = KvmVm::new(kvm, mmap_size, config).unwrap();
        assert_eq!(vm.state(), VmState::Created);
        assert!(!vm.is_running());
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_vcpu_creation() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 4,
            memory_size: 128 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = KvmVm::new(kvm, mmap_size, config).unwrap();

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
    #[ignore] // Requires /dev/kvm
    fn test_vm_lifecycle() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 64 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = KvmVm::new(kvm, mmap_size, config).unwrap();
        assert_eq!(vm.state(), VmState::Created);

        // Start
        vm.start().unwrap();
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

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_add_virtio_device() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 64 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = KvmVm::new(kvm, mmap_size, config).unwrap();
        assert_eq!(vm.state(), VmState::Created);

        // Add a block device.
        let blk_config = VirtioDeviceConfig::block("/dev/null", true);
        vm.add_virtio_device(blk_config).unwrap();

        // Verify device info.
        let devices = vm.virtio_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_type, VirtioDeviceType::Block);
        assert_eq!(devices[0].mmio_base, VIRTIO_MMIO_BASE);
        assert_eq!(devices[0].mmio_size, VIRTIO_MMIO_SIZE);
        assert!(devices[0].irq_fd >= 0);
        assert!(devices[0].notify_fd >= 0);

        // Add a network device.
        let net_config = VirtioDeviceConfig::net();
        vm.add_virtio_device(net_config).unwrap();

        // Verify second device.
        let devices = vm.virtio_devices().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].device_type, VirtioDeviceType::Net);
        assert_eq!(
            devices[1].mmio_base,
            VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE + VIRTIO_MMIO_GAP
        );

        // Cannot add device after VM starts.
        vm.start().unwrap();
        let fs_config = VirtioDeviceConfig::filesystem("/share", "share");
        let result = vm.add_virtio_device(fs_config);
        assert!(result.is_err());
    }
}
