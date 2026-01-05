//! Virtual CPU implementation for macOS.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::{
    error::HypervisorError,
    traits::Vcpu,
    types::{Registers, VcpuExit},
};

/// Virtual CPU implementation for Darwin (macOS).
///
/// Each vCPU represents a virtual processor that can execute guest code.
/// On macOS, vCPUs are managed by Virtualization.framework.
pub struct DarwinVcpu {
    /// vCPU ID.
    id: u32,
    /// Whether the vCPU is running.
    running: Arc<AtomicBool>,
    /// Current register state (cached).
    regs: Registers,
}

impl DarwinVcpu {
    /// Creates a new vCPU.
    pub(crate) fn new(id: u32) -> Self {
        Self {
            id,
            running: Arc::new(AtomicBool::new(false)),
            regs: Registers::default(),
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

        // TODO: Actually run the vCPU via Virtualization.framework
        //
        // In Virtualization.framework, vCPU execution is handled internally
        // by VZVirtualMachine. We don't get direct vCPU control like with
        // Hypervisor.framework or KVM.
        //
        // The VM runs asynchronously after calling [vm start], and we receive
        // events through delegates. This is a significant architectural
        // difference from traditional VMMs.
        //
        // For now, we simulate a halt exit to allow the event loop to work.

        self.running.store(false, Ordering::SeqCst);

        // Placeholder: return halt
        // Real implementation would block until VM exit
        Ok(VcpuExit::Halt)
    }

    fn get_regs(&self) -> Result<Registers, HypervisorError> {
        // TODO: In Virtualization.framework, we don't have direct access
        // to vCPU registers like in Hypervisor.framework.
        //
        // This would need to be handled differently, possibly through
        // the guest agent or by using Hypervisor.framework for low-level
        // control.

        Ok(self.regs.clone())
    }

    fn set_regs(&mut self, regs: &Registers) -> Result<(), HypervisorError> {
        // TODO: Same limitation as get_regs - Virtualization.framework
        // doesn't expose direct register access.

        self.regs = regs.clone();
        Ok(())
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn set_io_result(&mut self, _value: u64) -> Result<(), HypervisorError> {
        // Virtualization.framework handles I/O internally through its device
        // abstraction layer. Direct I/O port access isn't exposed.
        //
        // For VirtIO MMIO devices, we handle this through the device manager.
        // For legacy I/O ports on x86, they're typically handled by
        // Virtualization.framework's built-in device emulation.
        Ok(())
    }

    fn set_mmio_result(&mut self, _value: u64) -> Result<(), HypervisorError> {
        // Virtualization.framework handles MMIO internally through its device
        // abstraction layer. MMIO accesses to VirtIO devices are handled by
        // the framework.
        //
        // For custom MMIO regions that we trap (like VirtIO MMIO transport),
        // we would need to use Hypervisor.framework for true fine-grained
        // control, or implement a userspace device model.
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

    #[test]
    fn test_vcpu_creation() {
        let vcpu = DarwinVcpu::new(0);
        assert_eq!(vcpu.id(), 0);
        assert!(!vcpu.is_running());
    }

    #[test]
    fn test_vcpu_registers() {
        let mut vcpu = DarwinVcpu::new(0);

        // Set some registers
        let mut regs = Registers::default();
        regs.rax = 0x1234;
        regs.rip = 0x5678;

        vcpu.set_regs(&regs).unwrap();

        // Read them back
        let read_regs = vcpu.get_regs().unwrap();
        assert_eq!(read_regs.rax, 0x1234);
        assert_eq!(read_regs.rip, 0x5678);
    }

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
}
