//! Virtual CPU implementation for macOS.
//!
//! On macOS, Virtualization.framework uses a managed execution model where
//! the framework internally handles vCPU scheduling and execution. Unlike
//! KVM or Hypervisor.framework, there is no direct `run vCPU` API.
//!
//! The `DarwinVcpu` implementation adapts to this model:
//! - `run()` waits for VM state changes (from Running to another state)
//! - Register access is not supported (Virtualization.framework doesn't expose this)
//! - The actual vCPU execution is handled by `VZVirtualMachine.start()`

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use objc2::runtime::AnyObject;

use super::ffi::VZVirtualMachineState;
use crate::{
    error::HypervisorError,
    traits::Vcpu,
    types::{CpuArch, Registers, VcpuExit, VcpuSnapshot},
};

/// Virtual CPU implementation for Darwin (macOS).
///
/// On macOS with Virtualization.framework, vCPU execution is managed internally
/// by the framework. This struct provides a compatible interface with the `Vcpu`
/// trait, but the actual execution model is different:
///
/// - **Managed execution**: The VM's vCPUs run automatically after `VZVirtualMachine.start()`
/// - **run() semantics**: Instead of executing guest code, `run()` waits for VM state changes
/// - **No register access**: Virtualization.framework doesn't expose vCPU registers
///
/// For code that needs to distinguish between managed and manual execution,
/// check `VirtualMachine::is_managed_execution()`.
pub struct DarwinVcpu {
    /// vCPU ID.
    id: u32,
    /// Whether the vCPU's run() method is currently blocking.
    running: Arc<AtomicBool>,
    /// Current register state (cached, not synced with actual vCPU).
    /// Note: Virtualization.framework doesn't expose register access.
    regs: Registers,
    /// Raw pointer to the VZVirtualMachine for state queries.
    /// This is safe to read from any thread (state property is thread-safe).
    vz_vm: *mut AnyObject,
}

// Safety: The vz_vm pointer is only used for reading the state property,
// which is documented as thread-safe by Apple.
unsafe impl Send for DarwinVcpu {}

impl DarwinVcpu {
    /// Creates a new vCPU.
    ///
    /// For managed execution VMs (Virtualization.framework), use `new_managed()`
    /// to pass the VM pointer for state queries.
    pub(crate) fn new(id: u32) -> Self {
        Self {
            id,
            running: Arc::new(AtomicBool::new(false)),
            regs: Registers::default(),
            vz_vm: std::ptr::null_mut(),
        }
    }

    /// Creates a new vCPU with a reference to the VZ VM for state queries.
    ///
    /// This is the preferred constructor for Virtualization.framework VMs,
    /// as it enables `run()` to properly wait for VM state changes.
    pub(crate) fn new_managed(id: u32, vz_vm: *mut AnyObject) -> Self {
        Self {
            id,
            running: Arc::new(AtomicBool::new(false)),
            regs: Registers::default(),
            vz_vm,
        }
    }

    /// Queries the current VM state from Virtualization.framework.
    ///
    /// Returns `None` if no VZ VM pointer is available.
    fn query_vm_state(&self) -> Option<VZVirtualMachineState> {
        if self.vz_vm.is_null() {
            return None;
        }

        unsafe {
            // VZVirtualMachine.state is thread-safe to read
            let sel = objc2::sel!(state);
            let func: unsafe extern "C" fn(*const AnyObject, objc2::runtime::Sel) -> i64 =
                std::mem::transmute(objc2::ffi::objc_msgSend as *const std::ffi::c_void);
            let state = func(self.vz_vm as *const AnyObject, sel);
            Some(VZVirtualMachineState::from(state))
        }
    }

    /// Returns whether the vCPU is currently running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Returns a clone of the running flag for external monitoring.
    #[must_use]
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Sets the instruction pointer.
    pub fn set_instruction_pointer(&mut self, ip: u64) {
        self.regs.rip = ip;
    }

    /// Sets the stack pointer.
    pub fn set_stack_pointer(&mut self, sp: u64) {
        self.regs.rsp = sp;
    }

    /// Sets up initial register state for Linux boot.
    ///
    /// This configures registers as expected by the Linux boot protocol.
    #[cfg(target_arch = "x86_64")]
    pub fn setup_linux_boot(&mut self, entry_point: u64, boot_params_addr: u64) {
        // Clear all registers
        self.regs = Registers::default();

        // Set instruction pointer to kernel entry
        self.regs.rip = entry_point;

        // RSI points to boot_params structure
        self.regs.rsi = boot_params_addr;

        // Flags: interrupts disabled, reserved bit set
        self.regs.rflags = 0x2;

        tracing::debug!(
            "vCPU {} setup for Linux boot: entry={:#x}, boot_params={:#x}",
            self.id,
            entry_point,
            boot_params_addr
        );
    }

    #[cfg(target_arch = "aarch64")]
    pub fn setup_linux_boot(&mut self, entry_point: u64, dtb_addr: u64) {
        // Clear all registers
        self.regs = Registers::default();

        // ARM64 Linux boot: x0 = dtb address, PC = entry point
        // Note: We use rip/rax here as placeholders for PC/x0
        // Real implementation would use ARM64-specific register struct
        self.regs.rip = entry_point; // PC
        self.regs.rax = dtb_addr; // x0

        tracing::debug!(
            "vCPU {} setup for Linux boot: entry={:#x}, dtb={:#x}",
            self.id,
            entry_point,
            dtb_addr
        );
    }
}

impl Vcpu for DarwinVcpu {
    fn run(&mut self) -> Result<VcpuExit, HypervisorError> {
        self.running.store(true, Ordering::SeqCst);

        // On Virtualization.framework, vCPU execution is managed internally.
        // The run() method waits for VM state changes instead of executing guest code.
        //
        // This implementation polls the VM state until:
        // - The VM exits Running state (pause, stop, error)
        // - The VZ VM pointer is not available (legacy mode, return immediately)

        let poll_interval = Duration::from_millis(100);

        // If no VZ VM pointer, return immediately (legacy behavior or placeholder vCPU)
        if self.vz_vm.is_null() {
            tracing::warn!(
                "vCPU {} run() called without VZ VM pointer, returning Halt",
                self.id
            );
            self.running.store(false, Ordering::SeqCst);
            return Ok(VcpuExit::Halt);
        }

        tracing::debug!("vCPU {} entering managed execution wait loop", self.id);

        loop {
            let state = match self.query_vm_state() {
                Some(s) => s,
                None => {
                    // VM pointer became invalid
                    self.running.store(false, Ordering::SeqCst);
                    return Ok(VcpuExit::Halt);
                }
            };

            match state {
                VZVirtualMachineState::Running => {
                    // VM is still running, continue waiting
                    std::thread::sleep(poll_interval);
                }
                VZVirtualMachineState::Stopped => {
                    tracing::debug!("vCPU {} detected VM stopped", self.id);
                    self.running.store(false, Ordering::SeqCst);
                    return Ok(VcpuExit::Shutdown);
                }
                VZVirtualMachineState::Paused => {
                    tracing::debug!("vCPU {} detected VM paused", self.id);
                    self.running.store(false, Ordering::SeqCst);
                    return Ok(VcpuExit::Halt);
                }
                VZVirtualMachineState::Error => {
                    tracing::error!("vCPU {} detected VM error state", self.id);
                    self.running.store(false, Ordering::SeqCst);
                    return Err(HypervisorError::VcpuRunError(
                        "VM entered error state".to_string(),
                    ));
                }
                VZVirtualMachineState::Starting
                | VZVirtualMachineState::Pausing
                | VZVirtualMachineState::Resuming
                | VZVirtualMachineState::Stopping => {
                    // Transitional states, wait for final state
                    tracing::trace!("vCPU {} VM in transitional state: {:?}", self.id, state);
                    std::thread::sleep(poll_interval);
                }
                VZVirtualMachineState::Saving | VZVirtualMachineState::Restoring => {
                    // Snapshot operations (macOS 14+), wait for completion
                    tracing::trace!("vCPU {} VM performing snapshot operation", self.id);
                    std::thread::sleep(poll_interval);
                }
            }
        }
    }

    fn get_regs(&self) -> Result<Registers, HypervisorError> {
        // LIMITATION: Virtualization.framework does not expose vCPU register access.
        //
        // Unlike Hypervisor.framework or KVM, Virtualization.framework is a
        // high-level API that abstracts away direct vCPU control. There is no
        // public API to read or write guest CPU registers.
        //
        // Options for working around this limitation:
        // 1. Use the guest agent to query register state (requires guest cooperation)
        // 2. Use Hypervisor.framework instead (lower-level, more complex)
        // 3. Accept that register debugging is not available on this platform
        //
        // Currently we return cached values that may be set during setup but
        // are NOT synchronized with actual vCPU state during execution.
        tracing::trace!(
            "get_regs() called on vCPU {} - returning cached values (not live)",
            self.id
        );
        Ok(self.regs.clone())
    }

    fn set_regs(&mut self, regs: &Registers) -> Result<(), HypervisorError> {
        // LIMITATION: Virtualization.framework does not expose vCPU register access.
        //
        // This method caches the register values but DOES NOT actually set
        // the guest vCPU registers. On Virtualization.framework, the initial
        // register state (entry point, boot params) is configured through
        // VZLinuxBootLoader, not through direct register manipulation.
        //
        // For managed execution VMs, this method is effectively a no-op for
        // actual vCPU state but can be used for internal bookkeeping.
        tracing::trace!(
            "set_regs() called on vCPU {} - caching values (not applied to vCPU)",
            self.id
        );
        self.regs = regs.clone();
        Ok(())
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn set_io_result(&mut self, _value: u64) -> Result<(), HypervisorError> {
        // NOT APPLICABLE: Virtualization.framework handles I/O internally.
        //
        // On Virtualization.framework, all device I/O (port I/O, MMIO) is
        // handled internally by the framework through its device abstraction
        // layer (VZVirtioBlockDeviceConfiguration, VZVirtioNetworkDeviceConfiguration,
        // etc.). There is no vCPU exit for I/O that we need to handle.
        //
        // This method exists for API compatibility with manual execution
        // backends (KVM, Hypervisor.framework) but is a no-op on Darwin.
        Ok(())
    }

    fn set_mmio_result(&mut self, _value: u64) -> Result<(), HypervisorError> {
        // NOT APPLICABLE: Virtualization.framework handles MMIO internally.
        //
        // Similar to set_io_result(), MMIO accesses are handled by the
        // framework's device emulation layer. VirtIO devices configured
        // through VZ*DeviceConfiguration automatically handle their MMIO
        // regions without exposing exits to userspace.
        //
        // For custom devices not supported by Virtualization.framework,
        // one would need to use Hypervisor.framework or implement a
        // paravirtualized interface through vsock.
        Ok(())
    }

    fn snapshot(&self) -> Result<VcpuSnapshot, HypervisorError> {
        // LIMITATION: Virtualization.framework does not expose vCPU register access.
        //
        // We return the cached register state, which may not reflect the actual
        // vCPU state during execution. For accurate snapshots, the VM should be
        // paused first and register state should be obtained through other means
        // (e.g., guest agent).
        tracing::warn!(
            "vCPU {} snapshot: returning cached registers (not live state)",
            self.id
        );

        #[cfg(target_arch = "aarch64")]
        {
            // On ARM64, create an ARM64 snapshot with default registers
            // since we don't have access to actual register state
            let mut arm_regs = crate::types::Arm64Registers::default();
            // Map cached x86 style regs to ARM64 format as best we can
            arm_regs.pc = self.regs.rip;
            arm_regs.sp = self.regs.rsp;
            arm_regs.x[0] = self.regs.rax;
            arm_regs.x[1] = self.regs.rbx;
            arm_regs.x[2] = self.regs.rcx;
            arm_regs.x[3] = self.regs.rdx;

            Ok(VcpuSnapshot::new_arm64(self.id, arm_regs))
        }

        #[cfg(target_arch = "x86_64")]
        {
            Ok(VcpuSnapshot::new_x86(self.id, self.regs.clone()))
        }
    }

    fn restore(&mut self, snapshot: &VcpuSnapshot) -> Result<(), HypervisorError> {
        // LIMITATION: Virtualization.framework does not expose vCPU register access.
        //
        // We cache the register values but cannot actually restore them to the vCPU.
        // For actual restore functionality, one would need to use Hypervisor.framework
        // or rely on the guest agent to restore state.
        if snapshot.id != self.id {
            return Err(HypervisorError::SnapshotError(format!(
                "vCPU ID mismatch: expected {}, got {}",
                self.id, snapshot.id
            )));
        }

        tracing::warn!(
            "vCPU {} restore: caching registers (not applied to vCPU)",
            self.id
        );

        match snapshot.arch {
            CpuArch::Aarch64 => {
                if let Some(arm_regs) = &snapshot.arm64_regs {
                    // Map ARM64 registers back to x86-style cached regs
                    self.regs.rip = arm_regs.pc;
                    self.regs.rsp = arm_regs.sp;
                    self.regs.rax = arm_regs.x[0];
                    self.regs.rbx = arm_regs.x[1];
                    self.regs.rcx = arm_regs.x[2];
                    self.regs.rdx = arm_regs.x[3];
                }
            }
            CpuArch::X86_64 => {
                if let Some(x86_regs) = &snapshot.x86_regs {
                    self.regs = x86_regs.clone();
                }
            }
        }

        Ok(())
    }
}

/// Extended vCPU state for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Default)]
pub struct SpecialRegisters {
    /// Code segment.
    pub cs: SegmentRegister,
    /// Data segment.
    pub ds: SegmentRegister,
    /// Stack segment.
    pub ss: SegmentRegister,
    /// Extra segment.
    pub es: SegmentRegister,
    /// FS segment.
    pub fs: SegmentRegister,
    /// GS segment.
    pub gs: SegmentRegister,
    /// Global descriptor table.
    pub gdt: DescriptorTable,
    /// Interrupt descriptor table.
    pub idt: DescriptorTable,
    /// Control register 0.
    pub cr0: u64,
    /// Control register 3 (page table base).
    pub cr3: u64,
    /// Control register 4.
    pub cr4: u64,
    /// Extended feature enable register.
    pub efer: u64,
}

/// Segment register.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Default)]
pub struct SegmentRegister {
    /// Base address.
    pub base: u64,
    /// Limit.
    pub limit: u32,
    /// Selector.
    pub selector: u16,
    /// Type.
    pub type_: u8,
    /// Present.
    pub present: u8,
    /// Descriptor privilege level.
    pub dpl: u8,
    /// Default operation size.
    pub db: u8,
    /// Granularity.
    pub granularity: u8,
    /// Long mode.
    pub long_mode: u8,
}

/// Descriptor table (GDT/IDT).
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Default)]
pub struct DescriptorTable {
    /// Base address.
    pub base: u64,
    /// Limit.
    pub limit: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ========================================================================
    // Basic Creation Tests
    // ========================================================================

    #[test]
    fn test_vcpu_creation() {
        let vcpu = DarwinVcpu::new(0);
        assert_eq!(vcpu.id(), 0);
        assert!(!vcpu.is_running());
        assert!(vcpu.vz_vm.is_null());
    }

    #[test]
    fn test_vcpu_creation_managed() {
        // Create with null pointer (for testing)
        let vcpu = DarwinVcpu::new_managed(1, std::ptr::null_mut());
        assert_eq!(vcpu.id(), 1);
        assert!(!vcpu.is_running());
        assert!(vcpu.vz_vm.is_null());
    }

    #[test]
    fn test_vcpu_creation_with_different_ids() {
        // Test creating vCPUs with various IDs
        for id in [0, 1, 7, 63, 255] {
            let vcpu = DarwinVcpu::new(id);
            assert_eq!(vcpu.id(), id);
        }
    }

    // ========================================================================
    // Register Tests
    // ========================================================================

    #[test]
    fn test_vcpu_registers_cached() {
        // Test that register access works on cached values
        // (not synchronized with actual vCPU state on Virtualization.framework)
        let mut vcpu = DarwinVcpu::new(0);

        // Set some registers
        let mut regs = Registers::default();
        regs.rax = 0x1234;
        regs.rip = 0x5678;

        vcpu.set_regs(&regs).unwrap();

        // Read them back - should return cached values
        let read_regs = vcpu.get_regs().unwrap();
        assert_eq!(read_regs.rax, 0x1234);
        assert_eq!(read_regs.rip, 0x5678);
    }

    #[test]
    fn test_vcpu_registers_all_gprs() {
        // Test all general-purpose registers
        let mut vcpu = DarwinVcpu::new(0);

        let mut regs = Registers::default();
        regs.rax = 0x1111_1111_1111_1111;
        regs.rbx = 0x2222_2222_2222_2222;
        regs.rcx = 0x3333_3333_3333_3333;
        regs.rdx = 0x4444_4444_4444_4444;
        regs.rsi = 0x5555_5555_5555_5555;
        regs.rdi = 0x6666_6666_6666_6666;
        regs.rsp = 0x7777_7777_7777_7777;
        regs.rbp = 0x8888_8888_8888_8888;
        regs.r8 = 0x9999_9999_9999_9999;
        regs.r9 = 0xAAAA_AAAA_AAAA_AAAA;
        regs.r10 = 0xBBBB_BBBB_BBBB_BBBB;
        regs.r11 = 0xCCCC_CCCC_CCCC_CCCC;
        regs.r12 = 0xDDDD_DDDD_DDDD_DDDD;
        regs.r13 = 0xEEEE_EEEE_EEEE_EEEE;
        regs.r14 = 0xFFFF_FFFF_FFFF_FFFF;
        regs.r15 = 0x0123_4567_89AB_CDEF;
        regs.rip = 0xDEAD_BEEF_CAFE_BABE;
        regs.rflags = 0x0000_0000_0000_0202;

        vcpu.set_regs(&regs).unwrap();
        let read_regs = vcpu.get_regs().unwrap();

        assert_eq!(read_regs.rax, regs.rax);
        assert_eq!(read_regs.rbx, regs.rbx);
        assert_eq!(read_regs.rcx, regs.rcx);
        assert_eq!(read_regs.rdx, regs.rdx);
        assert_eq!(read_regs.rsi, regs.rsi);
        assert_eq!(read_regs.rdi, regs.rdi);
        assert_eq!(read_regs.rsp, regs.rsp);
        assert_eq!(read_regs.rbp, regs.rbp);
        assert_eq!(read_regs.r8, regs.r8);
        assert_eq!(read_regs.r9, regs.r9);
        assert_eq!(read_regs.r10, regs.r10);
        assert_eq!(read_regs.r11, regs.r11);
        assert_eq!(read_regs.r12, regs.r12);
        assert_eq!(read_regs.r13, regs.r13);
        assert_eq!(read_regs.r14, regs.r14);
        assert_eq!(read_regs.r15, regs.r15);
        assert_eq!(read_regs.rip, regs.rip);
        assert_eq!(read_regs.rflags, regs.rflags);
    }

    #[test]
    fn test_vcpu_registers_multiple_updates() {
        // Test that registers can be updated multiple times
        let mut vcpu = DarwinVcpu::new(0);

        for i in 0..10u64 {
            let mut regs = Registers::default();
            regs.rax = i * 1000;
            regs.rip = 0x1000 + i * 0x100;

            vcpu.set_regs(&regs).unwrap();
            let read_regs = vcpu.get_regs().unwrap();

            assert_eq!(read_regs.rax, i * 1000);
            assert_eq!(read_regs.rip, 0x1000 + i * 0x100);
        }
    }

    // ========================================================================
    // Run Behavior Tests
    // ========================================================================

    #[test]
    fn test_vcpu_run_without_vm() {
        // When run() is called without a VZ VM pointer, it should return Halt immediately
        let mut vcpu = DarwinVcpu::new(0);
        let exit = vcpu.run().unwrap();
        assert!(matches!(exit, VcpuExit::Halt));
        assert!(!vcpu.is_running());
    }

    #[test]
    fn test_vcpu_run_with_null_managed() {
        // new_managed with null pointer should also return Halt immediately
        let mut vcpu = DarwinVcpu::new_managed(0, std::ptr::null_mut());
        let exit = vcpu.run().unwrap();
        assert!(matches!(exit, VcpuExit::Halt));
        assert!(!vcpu.is_running());
    }

    #[test]
    fn test_vcpu_run_multiple_times() {
        // run() can be called multiple times
        let mut vcpu = DarwinVcpu::new(0);

        for _ in 0..5 {
            let exit = vcpu.run().unwrap();
            assert!(matches!(exit, VcpuExit::Halt));
            assert!(!vcpu.is_running());
        }
    }

    #[test]
    fn test_vcpu_running_flag_transitions() {
        // Test that the running flag properly transitions
        let mut vcpu = DarwinVcpu::new(0);

        // Initially not running
        assert!(!vcpu.is_running());

        // Clone the flag before run
        let running_flag = vcpu.running_flag();

        // Before run, flag should be false
        assert!(!running_flag.load(std::sync::atomic::Ordering::SeqCst));

        // After run (which returns immediately with null VM), should be false again
        let _ = vcpu.run();
        assert!(!running_flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    // ========================================================================
    // VM State Query Tests
    // ========================================================================

    #[test]
    fn test_vcpu_query_vm_state_without_vm() {
        let vcpu = DarwinVcpu::new(0);
        // Without VZ VM pointer, should return None
        assert!(vcpu.query_vm_state().is_none());
    }

    #[test]
    fn test_vcpu_query_vm_state_null_managed() {
        let vcpu = DarwinVcpu::new_managed(0, std::ptr::null_mut());
        assert!(vcpu.query_vm_state().is_none());
    }

    // ========================================================================
    // Linux Boot Setup Tests
    // ========================================================================

    #[test]
    fn test_vcpu_linux_setup() {
        let mut vcpu = DarwinVcpu::new(0);

        #[cfg(target_arch = "x86_64")]
        {
            vcpu.setup_linux_boot(0x100000, 0x10000);
            let regs = vcpu.get_regs().unwrap();
            assert_eq!(regs.rip, 0x100000);
            assert_eq!(regs.rsi, 0x10000);
        }

        #[cfg(target_arch = "aarch64")]
        {
            vcpu.setup_linux_boot(0x40000000, 0x44000000);
            let regs = vcpu.get_regs().unwrap();
            assert_eq!(regs.rip, 0x40000000); // PC
            assert_eq!(regs.rax, 0x44000000); // x0 = dtb
        }
    }

    #[test]
    fn test_vcpu_linux_setup_clears_previous_regs() {
        let mut vcpu = DarwinVcpu::new(0);

        // Set some garbage values first
        let mut garbage = Registers::default();
        garbage.rax = 0xDEADBEEF;
        garbage.rbx = 0xCAFEBABE;
        vcpu.set_regs(&garbage).unwrap();

        // Setup Linux boot should clear and set proper values
        #[cfg(target_arch = "x86_64")]
        {
            vcpu.setup_linux_boot(0x100000, 0x10000);
            let regs = vcpu.get_regs().unwrap();
            // rax should be cleared (not DEADBEEF)
            assert_eq!(regs.rax, 0);
            assert_eq!(regs.rbx, 0);
            assert_eq!(regs.rip, 0x100000);
            assert_eq!(regs.rsi, 0x10000);
            assert_eq!(regs.rflags, 0x2); // Reserved bit set
        }

        #[cfg(target_arch = "aarch64")]
        {
            vcpu.setup_linux_boot(0x40000000, 0x44000000);
            let regs = vcpu.get_regs().unwrap();
            assert_eq!(regs.rip, 0x40000000);
            assert_eq!(regs.rax, 0x44000000);
        }
    }

    // ========================================================================
    // Helper Method Tests
    // ========================================================================

    #[test]
    fn test_vcpu_set_instruction_pointer() {
        let mut vcpu = DarwinVcpu::new(0);

        vcpu.set_instruction_pointer(0xFFFF_0000_0000_1000);

        let regs = vcpu.get_regs().unwrap();
        assert_eq!(regs.rip, 0xFFFF_0000_0000_1000);
    }

    #[test]
    fn test_vcpu_set_stack_pointer() {
        let mut vcpu = DarwinVcpu::new(0);

        vcpu.set_stack_pointer(0x7FFF_FFFF_FFFF_FF00);

        let regs = vcpu.get_regs().unwrap();
        assert_eq!(regs.rsp, 0x7FFF_FFFF_FFFF_FF00);
    }

    // ========================================================================
    // I/O Result Tests (No-op on Darwin)
    // ========================================================================

    #[test]
    fn test_vcpu_set_io_result_noop() {
        // set_io_result should succeed but is a no-op on Virtualization.framework
        let mut vcpu = DarwinVcpu::new(0);

        let result = vcpu.set_io_result(0x1234);
        assert!(result.is_ok());

        // Call multiple times with different values
        for value in [0u64, 0xFF, 0xFFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF] {
            assert!(vcpu.set_io_result(value).is_ok());
        }
    }

    #[test]
    fn test_vcpu_set_mmio_result_noop() {
        // set_mmio_result should succeed but is a no-op on Virtualization.framework
        let mut vcpu = DarwinVcpu::new(0);

        let result = vcpu.set_mmio_result(0xDEAD_BEEF);
        assert!(result.is_ok());

        // Call multiple times with different values
        for value in [0u64, 0xFF, 0xFFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF] {
            assert!(vcpu.set_mmio_result(value).is_ok());
        }
    }

    // ========================================================================
    // Thread Safety Tests
    // ========================================================================

    #[test]
    fn test_vcpu_running_flag_is_shared() {
        // Test that running_flag() returns a shared reference
        let vcpu = DarwinVcpu::new(0);

        let flag1 = vcpu.running_flag();
        let flag2 = vcpu.running_flag();

        // Both flags should reference the same atomic
        flag1.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(flag2.load(std::sync::atomic::Ordering::SeqCst));

        flag2.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(!flag1.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_vcpu_send_trait() {
        // Test that DarwinVcpu implements Send
        let vcpu = DarwinVcpu::new(0);

        // Move vcpu to another thread
        let handle = thread::spawn(move || {
            assert_eq!(vcpu.id(), 0);
        });

        handle.join().unwrap();
    }

    // ========================================================================
    // VZ State Mapping Tests (Unit tests for state conversion)
    // ========================================================================

    #[test]
    fn test_vz_state_from_i64() {
        // Test VZVirtualMachineState::from(i64) mapping
        assert_eq!(VZVirtualMachineState::from(0), VZVirtualMachineState::Stopped);
        assert_eq!(VZVirtualMachineState::from(1), VZVirtualMachineState::Running);
        assert_eq!(VZVirtualMachineState::from(2), VZVirtualMachineState::Paused);
        assert_eq!(VZVirtualMachineState::from(3), VZVirtualMachineState::Error);
        assert_eq!(VZVirtualMachineState::from(4), VZVirtualMachineState::Starting);
        assert_eq!(VZVirtualMachineState::from(5), VZVirtualMachineState::Pausing);
        assert_eq!(VZVirtualMachineState::from(6), VZVirtualMachineState::Resuming);
        assert_eq!(VZVirtualMachineState::from(7), VZVirtualMachineState::Stopping);
        assert_eq!(VZVirtualMachineState::from(8), VZVirtualMachineState::Saving);
        assert_eq!(VZVirtualMachineState::from(9), VZVirtualMachineState::Restoring);

        // Unknown values should map to Error
        assert_eq!(VZVirtualMachineState::from(10), VZVirtualMachineState::Error);
        assert_eq!(VZVirtualMachineState::from(-1), VZVirtualMachineState::Error);
        assert_eq!(VZVirtualMachineState::from(100), VZVirtualMachineState::Error);
    }
}
