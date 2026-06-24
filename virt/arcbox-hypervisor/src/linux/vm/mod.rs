//! Virtual machine implementation for Linux KVM.

mod dirty;
mod drop;
mod irq;
#[cfg(test)]
mod tests;
mod virtio;
mod virtual_machine;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::{config::VmConfig, error::HypervisorError};

#[cfg(target_arch = "x86_64")]
use super::ffi::KvmPitConfig;
use super::ffi::{self, KvmSystem, KvmUserspaceMemoryRegion, KvmVmFd};
use super::memory::KvmMemory;
pub use virtio::VirtioDeviceInfo;

/// Global VM ID counter.
static VM_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Information about a memory slot for dirty page tracking.
#[derive(Debug, Clone)]
pub(super) struct MemorySlotInfo {
    /// Slot ID.
    slot: u32,
    /// Guest physical address.
    guest_phys_addr: u64,
    /// Size in bytes.
    size: u64,
    /// Host virtual address.
    userspace_addr: u64,
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
    pub(super) fn set_state(&self, new_state: VmState) {
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
}
