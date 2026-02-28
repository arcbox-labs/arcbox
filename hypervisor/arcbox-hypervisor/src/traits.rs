//! Core traits for hypervisor abstraction.
//!
//! These traits define the platform-agnostic interface that all hypervisor
//! backends must implement.

use std::any::Any;

use crate::{
    config::VmConfig,
    error::HypervisorError,
    memory::GuestAddress,
    types::{
        DeviceSnapshot, DirtyPageInfo, PlatformCapabilities, Registers, VcpuExit, VcpuSnapshot,
        VirtioDeviceConfig,
    },
};

/// Main hypervisor trait for creating and managing virtual machines.
///
/// Each platform (macOS, Linux) provides its own implementation.
pub trait Hypervisor: Send + Sync + 'static {
    /// The virtual machine type created by this hypervisor.
    type Vm: VirtualMachine;

    /// Returns the platform capabilities.
    fn capabilities(&self) -> &PlatformCapabilities;

    /// Creates a new virtual machine with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be created.
    fn create_vm(&self, config: VmConfig) -> Result<Self::Vm, HypervisorError>;
}

/// Virtual machine trait for managing VM lifecycle and devices.
pub trait VirtualMachine: Send + Sync {
    /// The vCPU type for this VM.
    type Vcpu: Vcpu;
    /// The guest memory type for this VM.
    type Memory: GuestMemory;

    /// Returns whether this VM uses managed execution.
    ///
    /// **Managed execution** (returns `true`):
    /// - The hypervisor manages vCPU execution internally
    /// - `start()` begins VM execution, `stop()` ends it
    /// - `create_vcpu()` is optional/placeholder
    /// - Examples: macOS Virtualization.framework
    ///
    /// **Manual execution** (returns `false`):
    /// - The caller must create vCPU threads and call `vcpu.run()` in a loop
    /// - `start()` and `stop()` are optional state markers
    /// - Examples: Linux KVM
    fn is_managed_execution(&self) -> bool {
        false // Default to manual execution (KVM-style)
    }

    /// Returns a reference to the guest memory.
    fn memory(&self) -> &Self::Memory;

    /// Creates a new vCPU.
    ///
    /// For managed execution VMs, this may return a placeholder vCPU.
    ///
    /// # Errors
    ///
    /// Returns an error if the vCPU cannot be created.
    fn create_vcpu(&mut self, id: u32) -> Result<Self::Vcpu, HypervisorError>;

    /// Adds a VirtIO device to the VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the device cannot be added.
    fn add_virtio_device(&mut self, device: VirtioDeviceConfig) -> Result<(), HypervisorError>;

    /// Starts the VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be started.
    fn start(&mut self) -> Result<(), HypervisorError>;

    /// Pauses the VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be paused.
    fn pause(&mut self) -> Result<(), HypervisorError>;

    /// Resumes a paused VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be resumed.
    fn resume(&mut self) -> Result<(), HypervisorError>;

    /// Stops the VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be stopped.
    fn stop(&mut self) -> Result<(), HypervisorError>;

    /// Returns the VM as a reference to `Any` for downcasting.
    ///
    /// This allows the caller to downcast the VM to its concrete type
    /// for platform-specific operations like IRQ injection.
    fn as_any(&self) -> &dyn Any;

    /// Returns the VM as a mutable reference to `Any` for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Returns the number of vCPUs in the VM.
    fn vcpu_count(&self) -> u32;

    /// Gets snapshots of all device states.
    ///
    /// # Errors
    ///
    /// Returns an error if device states cannot be captured.
    fn snapshot_devices(&self) -> Result<Vec<DeviceSnapshot>, HypervisorError>;

    /// Restores device states from snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if device states cannot be restored.
    fn restore_devices(&mut self, snapshots: &[DeviceSnapshot]) -> Result<(), HypervisorError>;
}

/// Virtual CPU trait for executing guest code.
pub trait Vcpu: Send {
    /// Runs the vCPU until a VM exit occurs.
    ///
    /// # Errors
    ///
    /// Returns an error if vCPU execution fails.
    fn run(&mut self) -> Result<VcpuExit, HypervisorError>;

    /// Gets the current register state.
    ///
    /// # Errors
    ///
    /// Returns an error if registers cannot be read.
    fn get_regs(&self) -> Result<Registers, HypervisorError>;

    /// Sets the register state.
    ///
    /// # Errors
    ///
    /// Returns an error if registers cannot be set.
    fn set_regs(&mut self, regs: &Registers) -> Result<(), HypervisorError>;

    /// Gets the vCPU ID.
    fn id(&self) -> u32;

    /// Sets the result of an I/O read operation.
    ///
    /// This is called after handling an IoIn exit to provide the value
    /// that should be returned to the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be set.
    fn set_io_result(&mut self, value: u64) -> Result<(), HypervisorError>;

    /// Sets the result of an MMIO read operation.
    ///
    /// This is called after handling an MmioRead exit to provide the value
    /// that should be returned to the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the result cannot be set.
    fn set_mmio_result(&mut self, value: u64) -> Result<(), HypervisorError>;

    /// Creates a snapshot of the vCPU state.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be created.
    fn snapshot(&self) -> Result<VcpuSnapshot, HypervisorError>;

    /// Restores the vCPU state from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be restored.
    fn restore(&mut self, snapshot: &VcpuSnapshot) -> Result<(), HypervisorError>;
}

/// Guest memory trait for reading/writing guest physical memory.
pub trait GuestMemory: Send + Sync {
    /// Reads bytes from guest memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, addr: GuestAddress, buf: &mut [u8]) -> Result<(), HypervisorError>;

    /// Writes bytes to guest memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write(&self, addr: GuestAddress, buf: &[u8]) -> Result<(), HypervisorError>;

    /// Gets the host virtual address for a guest physical address.
    ///
    /// This is used for zero-copy operations.
    ///
    /// # Safety
    ///
    /// The returned pointer is only valid while the memory mapping exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not mapped.
    fn get_host_address(&self, addr: GuestAddress) -> Result<*mut u8, HypervisorError>;

    /// Returns the total size of guest memory in bytes.
    fn size(&self) -> u64;

    /// Enables dirty page tracking.
    ///
    /// After enabling, use `get_dirty_pages()` to retrieve modified pages.
    ///
    /// # Errors
    ///
    /// Returns an error if dirty tracking cannot be enabled.
    fn enable_dirty_tracking(&mut self) -> Result<(), HypervisorError>;

    /// Disables dirty page tracking.
    ///
    /// # Errors
    ///
    /// Returns an error if dirty tracking cannot be disabled.
    fn disable_dirty_tracking(&mut self) -> Result<(), HypervisorError>;

    /// Gets and clears the list of dirty pages since the last call.
    ///
    /// This resets the dirty bitmap after returning.
    ///
    /// # Errors
    ///
    /// Returns an error if dirty pages cannot be retrieved.
    fn get_dirty_pages(&mut self) -> Result<Vec<DirtyPageInfo>, HypervisorError>;

    /// Reads all guest memory into a buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if memory cannot be read.
    fn dump_all(&self, buf: &mut [u8]) -> Result<(), HypervisorError>;
}
