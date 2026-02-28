//! Virtual machine implementation for Linux KVM.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::{
    config::VmConfig,
    error::HypervisorError,
    memory::{GuestAddress, PAGE_SIZE},
    traits::VirtualMachine,
    types::{DeviceSnapshot, DirtyPageInfo, VirtioDeviceConfig, VirtioDeviceType},
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
// Memory Slot Tracking for Dirty Logging
// ============================================================================

/// Information about a memory slot for dirty page tracking.
#[derive(Debug, Clone)]
struct MemorySlotInfo {
    /// Slot ID.
    slot: u32,
    /// Guest physical address.
    guest_phys_addr: u64,
    /// Size in bytes.
    size: u64,
    /// Host virtual address.
    userspace_addr: u64,
}

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
    /// Memory slots for dirty page tracking.
    memory_slots: RwLock<Vec<MemorySlotInfo>>,
    /// Whether dirty page tracking is enabled.
    dirty_tracking_enabled: AtomicBool,
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

        // Track the main memory slot for dirty page tracking.
        let main_slot = MemorySlotInfo {
            slot: 0,
            guest_phys_addr: 0,
            size: config.memory_size,
            userspace_addr: memory.host_address() as u64,
        };

        memory.attach_vm_fd(vm_fd.as_raw_fd());
        memory.register_slot(
            main_slot.slot,
            main_slot.guest_phys_addr,
            main_slot.size,
            main_slot.userspace_addr,
            0,
        )?;

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
            memory_slots: RwLock::new(vec![main_slot]),
            dirty_tracking_enabled: AtomicBool::new(false),
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
        vm_fd
            .set_identity_map_addr(IDENTITY_MAP_ADDR)
            .map_err(|e| {
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

        let mut base_flags = 0u32;
        if read_only {
            base_flags |= ffi::KVM_MEM_READONLY;
        }

        let mut region_flags = base_flags;
        if self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            region_flags |= ffi::KVM_MEM_LOG_DIRTY_PAGES;
        }

        let region = KvmUserspaceMemoryRegion {
            slot,
            flags: region_flags,
            guest_phys_addr: guest_addr.raw(),
            memory_size: size,
            userspace_addr: host_addr as u64,
        };

        self.vm_fd.set_user_memory_region(&region).map_err(|e| {
            HypervisorError::MemoryError(format!("Failed to add memory region: {}", e))
        })?;

        {
            let mut slots = self
                .memory_slots
                .write()
                .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;
            slots.push(MemorySlotInfo {
                slot,
                guest_phys_addr: guest_addr.raw(),
                size,
                userspace_addr: host_addr as u64,
            });
        }

        self.memory
            .register_slot(slot, guest_addr.raw(), size, host_addr as u64, base_flags)?;

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

        {
            let mut slots = self
                .memory_slots
                .write()
                .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;
            slots.retain(|entry| entry.slot != slot);
        }

        self.memory.unregister_slot(slot)?;

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
        self.vm_fd
            .set_irq_line(gsi, level)
            .map_err(|e| HypervisorError::DeviceError(format!("Failed to set IRQ line: {}", e)))
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
        self.vm_fd
            .register_irqfd(eventfd, gsi, resample_fd)
            .map_err(|e| HypervisorError::DeviceError(format!("Failed to register IRQFD: {}", e)))
    }

    /// Unregisters an eventfd for IRQ injection.
    pub fn unregister_irqfd(&self, eventfd: RawFd, gsi: u32) -> Result<(), HypervisorError> {
        self.vm_fd
            .unregister_irqfd(eventfd, gsi)
            .map_err(|e| HypervisorError::DeviceError(format!("Failed to unregister IRQFD: {}", e)))
    }

    // ========================================================================
    // VirtIO Device Support
    // ========================================================================

    /// Allocates an MMIO region for a VirtIO device.
    ///
    /// Returns the base address for the device.
    fn allocate_mmio_region(&self) -> Result<u64, HypervisorError> {
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::DeviceError("Lock poisoned".to_string()))?;

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
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::DeviceError("Lock poisoned".to_string()))?;

        Ok(devices
            .iter()
            .map(|d| VirtioDeviceInfo {
                device_type: d.device_type.clone(),
                mmio_base: d.mmio_base,
                mmio_size: d.mmio_size,
                irq: d.irq,
                irq_fd: d.irq_fd,
                notify_fd: d.notify_fd,
            })
            .collect())
    }

    // ========================================================================
    // Dirty Page Tracking
    // ========================================================================

    /// Enables dirty page tracking for all memory regions.
    ///
    /// When enabled, KVM tracks which pages have been written to by the guest.
    /// Use `get_dirty_pages` to retrieve and clear the dirty page bitmap.
    ///
    /// This is useful for:
    /// - Live migration: Only transfer modified pages
    /// - Snapshotting: Track incremental changes
    ///
    /// # Errors
    ///
    /// Returns an error if dirty logging cannot be enabled.
    pub fn enable_dirty_tracking(&self) -> Result<(), HypervisorError> {
        if self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            // Already enabled.
            return Ok(());
        }

        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        // Enable dirty logging for all memory slots.
        for slot in slots.iter() {
            self.vm_fd
                .enable_dirty_logging(
                    slot.slot,
                    slot.guest_phys_addr,
                    slot.size,
                    slot.userspace_addr,
                )
                .map_err(|e| {
                    HypervisorError::SnapshotError(format!(
                        "Failed to enable dirty logging for slot {}: {}",
                        slot.slot, e
                    ))
                })?;

            tracing::debug!(
                "Enabled dirty logging for slot {}: guest={:#x}, size={}MB",
                slot.slot,
                slot.guest_phys_addr,
                slot.size / (1024 * 1024)
            );
        }

        self.dirty_tracking_enabled.store(true, Ordering::SeqCst);
        self.memory.set_dirty_tracking_enabled(true);
        tracing::info!("Dirty page tracking enabled for VM {}", self.id);

        Ok(())
    }

    /// Disables dirty page tracking for all memory regions.
    ///
    /// # Errors
    ///
    /// Returns an error if dirty logging cannot be disabled.
    pub fn disable_dirty_tracking(&self) -> Result<(), HypervisorError> {
        if !self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            // Already disabled.
            return Ok(());
        }

        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        // Disable dirty logging for all memory slots.
        for slot in slots.iter() {
            self.vm_fd
                .disable_dirty_logging(
                    slot.slot,
                    slot.guest_phys_addr,
                    slot.size,
                    slot.userspace_addr,
                )
                .map_err(|e| {
                    HypervisorError::SnapshotError(format!(
                        "Failed to disable dirty logging for slot {}: {}",
                        slot.slot, e
                    ))
                })?;
        }

        self.dirty_tracking_enabled.store(false, Ordering::SeqCst);
        self.memory.set_dirty_tracking_enabled(false);
        tracing::info!("Dirty page tracking disabled for VM {}", self.id);

        Ok(())
    }

    /// Returns whether dirty page tracking is enabled.
    #[must_use]
    pub fn is_dirty_tracking_enabled(&self) -> bool {
        self.dirty_tracking_enabled.load(Ordering::SeqCst)
    }

    /// Gets the list of dirty pages across all memory regions.
    ///
    /// This retrieves and clears the dirty page bitmap from KVM.
    /// Each call returns pages that were written since the last call.
    ///
    /// # Errors
    ///
    /// Returns an error if dirty tracking is not enabled or if the
    /// dirty log cannot be retrieved.
    pub fn get_dirty_pages(&self) -> Result<Vec<DirtyPageInfo>, HypervisorError> {
        if !self.dirty_tracking_enabled.load(Ordering::SeqCst) {
            return Err(HypervisorError::SnapshotError(
                "Dirty tracking not enabled".to_string(),
            ));
        }

        let slots = self
            .memory_slots
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        let mut dirty_pages = Vec::new();

        for slot in slots.iter() {
            // Get the dirty bitmap for this slot.
            let bitmap = self
                .vm_fd
                .get_dirty_log(slot.slot, slot.size, PAGE_SIZE)
                .map_err(|e| {
                    HypervisorError::SnapshotError(format!(
                        "Failed to get dirty log for slot {}: {}",
                        slot.slot, e
                    ))
                })?;

            // Parse the bitmap to extract dirty page addresses.
            let pages = Self::parse_dirty_bitmap(&bitmap, slot.guest_phys_addr, slot.size);

            tracing::debug!(
                "Slot {}: {} dirty pages out of {} total",
                slot.slot,
                pages.len(),
                slot.size / PAGE_SIZE
            );

            dirty_pages.extend(pages);
        }

        tracing::debug!(
            "get_dirty_pages: found {} dirty pages total",
            dirty_pages.len()
        );

        Ok(dirty_pages)
    }

    /// Parses a dirty bitmap to extract individual dirty page addresses.
    ///
    /// # Arguments
    /// * `bitmap` - The bitmap from KVM_GET_DIRTY_LOG
    /// * `base_addr` - The guest physical address of the region start
    /// * `size` - Total size of the region
    ///
    /// # Returns
    /// A vector of DirtyPageInfo for each dirty page.
    fn parse_dirty_bitmap(bitmap: &[u64], base_addr: u64, size: u64) -> Vec<DirtyPageInfo> {
        let mut pages = Vec::new();
        let num_pages = size / PAGE_SIZE;

        for (word_idx, &word) in bitmap.iter().enumerate() {
            if word == 0 {
                // Skip words with no dirty pages.
                continue;
            }

            // Check each bit in the word.
            for bit_idx in 0..64 {
                if (word >> bit_idx) & 1 != 0 {
                    let page_num = (word_idx as u64 * 64) + bit_idx as u64;
                    if page_num < num_pages {
                        pages.push(DirtyPageInfo {
                            guest_addr: base_addr + page_num * PAGE_SIZE,
                            size: PAGE_SIZE,
                        });
                    }
                }
            }
        }

        pages
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

        // Create vCPU via KVM
        let vcpu_fd = self
            .vm_fd
            .create_vcpu(id, self.vcpu_mmap_size)
            .map_err(|e| HypervisorError::VcpuCreationFailed {
                id,
                reason: format!("KVM error: {}", e),
            })?;

        // Create wrapper
        let vcpu = KvmVcpu::new(id, vcpu_fd)?;

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
            return Err(HypervisorError::VmStateError {
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
            return Err(HypervisorError::VmStateError {
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
            return Err(HypervisorError::VmStateError {
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
            return Err(HypervisorError::VmStateError {
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

    fn vcpu_count(&self) -> u32 {
        self.config.vcpu_count
    }

    fn snapshot_devices(&self) -> Result<Vec<DeviceSnapshot>, HypervisorError> {
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        let mut snapshots = Vec::with_capacity(devices.len());

        for device in devices.iter() {
            // KVM VirtIO devices don't have internal state accessible from host.
            // The actual device state is managed by the VMM layer (e.g., arcbox-virtio).
            // We record the device configuration here; the VMM would need to
            // serialize its own device state.
            let state_bytes = bincode_serialize_device_config(device);

            snapshots.push(DeviceSnapshot {
                device_type: device.device_type.clone(),
                name: format!("{:?}-{}", device.device_type, snapshots.len()),
                state: state_bytes,
            });
        }

        tracing::debug!(
            "snapshot_devices: captured {} device configurations",
            snapshots.len()
        );

        Ok(snapshots)
    }

    fn restore_devices(&mut self, snapshots: &[DeviceSnapshot]) -> Result<(), HypervisorError> {
        // KVM device restoration is complex:
        // 1. VirtIO MMIO regions must be at the same addresses
        // 2. IRQs must be assigned to the same GSIs
        // 3. The VMM layer must restore internal device state
        //
        // For now, we verify that the device configuration matches.
        let devices = self
            .virtio_devices
            .read()
            .map_err(|_| HypervisorError::SnapshotError("Lock poisoned".to_string()))?;

        if snapshots.len() != devices.len() {
            return Err(HypervisorError::SnapshotError(format!(
                "Device count mismatch: snapshot has {}, VM has {}",
                snapshots.len(),
                devices.len()
            )));
        }

        for (snapshot, device) in snapshots.iter().zip(devices.iter()) {
            if snapshot.device_type != device.device_type {
                return Err(HypervisorError::SnapshotError(format!(
                    "Device type mismatch: snapshot has {:?}, VM has {:?}",
                    snapshot.device_type, device.device_type
                )));
            }
        }

        tracing::debug!(
            "restore_devices: verified {} device configurations",
            snapshots.len()
        );

        Ok(())
    }
}

/// Serializes device configuration to bytes for snapshot storage.
fn bincode_serialize_device_config(device: &VirtioDeviceInfo) -> Vec<u8> {
    // Simple serialization of device config for snapshot purposes.
    // A full implementation would use serde/bincode.
    let mut bytes = Vec::new();

    // Serialize device type as u8
    let type_byte = match device.device_type {
        VirtioDeviceType::Block => 0u8,
        VirtioDeviceType::Net => 1,
        VirtioDeviceType::Console => 2,
        VirtioDeviceType::Rng => 3,
        VirtioDeviceType::Balloon => 4,
        VirtioDeviceType::Fs => 5,
        VirtioDeviceType::Vsock => 6,
        VirtioDeviceType::Gpu => 7,
    };
    bytes.push(type_byte);

    // Serialize MMIO base and size
    bytes.extend_from_slice(&device.mmio_base.to_le_bytes());
    bytes.extend_from_slice(&device.mmio_size.to_le_bytes());

    // Serialize IRQ
    bytes.extend_from_slice(&device.irq.to_le_bytes());

    bytes
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
                let _ = self
                    .vm_fd
                    .unregister_ioeventfd(notify_addr, 4, device.notify_fd);

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

    #[test]
    fn test_parse_dirty_bitmap_empty() {
        let bitmap: Vec<u64> = vec![0; 4];
        let pages = KvmVm::parse_dirty_bitmap(&bitmap, 0, 1024 * 1024);
        assert!(pages.is_empty());
    }

    #[test]
    fn test_parse_dirty_bitmap_all_dirty() {
        // 64 pages = 1 word, all bits set.
        let bitmap: Vec<u64> = vec![u64::MAX];
        let pages = KvmVm::parse_dirty_bitmap(&bitmap, 0, 64 * PAGE_SIZE);
        assert_eq!(pages.len(), 64);

        // Verify first and last page addresses.
        assert_eq!(pages[0].guest_addr, 0);
        assert_eq!(pages[0].size, PAGE_SIZE);
        assert_eq!(pages[63].guest_addr, 63 * PAGE_SIZE);
    }

    #[test]
    fn test_parse_dirty_bitmap_sparse() {
        // Only pages 0, 63, 64, and 127 are dirty (first and last of two words).
        let mut bitmap: Vec<u64> = vec![0; 2];
        bitmap[0] = 1 | (1 << 63); // Page 0 and 63.
        bitmap[1] = 1 | (1 << 63); // Page 64 and 127.

        let pages = KvmVm::parse_dirty_bitmap(&bitmap, 0x1000_0000, 128 * PAGE_SIZE);
        assert_eq!(pages.len(), 4);

        assert_eq!(pages[0].guest_addr, 0x1000_0000);
        assert_eq!(pages[1].guest_addr, 0x1000_0000 + 63 * PAGE_SIZE);
        assert_eq!(pages[2].guest_addr, 0x1000_0000 + 64 * PAGE_SIZE);
        assert_eq!(pages[3].guest_addr, 0x1000_0000 + 127 * PAGE_SIZE);
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_dirty_tracking_enable_disable() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 16 * 1024 * 1024, // 16MB
            ..Default::default()
        };

        let vm = KvmVm::new(kvm, mmap_size, config).unwrap();

        // Initially disabled.
        assert!(!vm.is_dirty_tracking_enabled());

        // Cannot get dirty pages when not enabled.
        assert!(vm.get_dirty_pages().is_err());

        // Enable dirty tracking.
        vm.enable_dirty_tracking().unwrap();
        assert!(vm.is_dirty_tracking_enabled());

        // Re-enabling is a no-op.
        vm.enable_dirty_tracking().unwrap();
        assert!(vm.is_dirty_tracking_enabled());

        // Can get dirty pages (should be all pages initially).
        let pages = vm.get_dirty_pages().unwrap();
        // All pages might be marked dirty initially.
        println!("Initial dirty pages: {}", pages.len());

        // Disable dirty tracking.
        vm.disable_dirty_tracking().unwrap();
        assert!(!vm.is_dirty_tracking_enabled());

        // Cannot get dirty pages when disabled.
        assert!(vm.get_dirty_pages().is_err());
    }
}
