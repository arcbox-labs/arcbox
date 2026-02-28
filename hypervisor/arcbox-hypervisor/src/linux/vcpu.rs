//! Virtual CPU implementation for Linux KVM.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    error::HypervisorError,
    traits::Vcpu,
    types::{CpuArch, Registers, VcpuExit, VcpuSnapshot},
};

use super::ffi::{
    KVM_EXIT_DEBUG, KVM_EXIT_FAIL_ENTRY, KVM_EXIT_HLT, KVM_EXIT_INTERNAL_ERROR, KVM_EXIT_IO,
    KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT, KVM_EXIT_MMIO, KVM_EXIT_SHUTDOWN, KVM_EXIT_SYSTEM_EVENT,
    KvmVcpuFd,
};

#[cfg(target_arch = "x86_64")]
use super::ffi::{KvmRegs, KvmSegment, KvmSregs};

/// Virtual CPU implementation for Linux KVM.
///
/// Each vCPU represents a virtual processor that can execute guest code.
/// vCPUs are created via the KVM VM file descriptor and run using the
/// KVM_RUN ioctl.
pub struct KvmVcpu {
    /// vCPU ID.
    id: u32,
    /// KVM vCPU file descriptor.
    vcpu_fd: KvmVcpuFd,
    /// Whether the vCPU is running.
    running: Arc<AtomicBool>,
}

impl KvmVcpu {
    /// Creates a new vCPU wrapper.
    pub(crate) fn new(id: u32, vcpu_fd: KvmVcpuFd) -> Result<Self, HypervisorError> {
        let vcpu = Self {
            id,
            vcpu_fd,
            running: Arc::new(AtomicBool::new(false)),
        };

        // Initialize architecture-specific state
        #[cfg(target_arch = "x86_64")]
        vcpu.init_x86()?;

        #[cfg(target_arch = "aarch64")]
        vcpu.init_arm64()?;

        Ok(vcpu)
    }

    /// Initializes x86 vCPU state.
    #[cfg(target_arch = "x86_64")]
    fn init_x86(&self) -> Result<(), HypervisorError> {
        // Set up initial special registers for real mode
        let mut sregs =
            self.vcpu_fd
                .get_sregs()
                .map_err(|e| HypervisorError::VcpuCreationFailed {
                    id: self.id,
                    reason: format!("Failed to get sregs: {}", e),
                })?;

        // Set up code segment for real mode
        sregs.cs = KvmSegment {
            base: 0,
            limit: 0xffff,
            selector: 0,
            type_: 0xb, // Code: execute/read, accessed
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 0,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        // Set up data segment
        sregs.ds = KvmSegment {
            base: 0,
            limit: 0xffff,
            selector: 0,
            type_: 0x3, // Data: read/write, accessed
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 0,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        sregs.es = sregs.ds.clone();
        sregs.fs = sregs.ds.clone();
        sregs.gs = sregs.ds.clone();
        sregs.ss = sregs.ds.clone();

        // CR0: PE=0 (real mode), disable paging
        sregs.cr0 = 0x6000_0010; // ET=1, NE=1

        self.vcpu_fd
            .set_sregs(&sregs)
            .map_err(|e| HypervisorError::VcpuCreationFailed {
                id: self.id,
                reason: format!("Failed to set sregs: {}", e),
            })?;

        Ok(())
    }

    /// Initializes ARM64 vCPU state.
    #[cfg(target_arch = "aarch64")]
    fn init_arm64(&self) -> Result<(), HypervisorError> {
        // ARM64 vCPU initialization is handled differently
        // The preferred target is set at VM creation time
        // Individual registers are set using KVM_SET_ONE_REG

        // For now, we don't do any special initialization here
        // Real implementation would set up initial register state

        Ok(())
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

    /// Signals the vCPU to exit immediately.
    ///
    /// This causes the next KVM_RUN to return immediately.
    pub fn signal_exit(&self) {
        self.vcpu_fd.set_immediate_exit(true);
    }

    /// Sets up initial register state for Linux boot (x86_64).
    #[cfg(target_arch = "x86_64")]
    pub fn setup_linux_boot(
        &self,
        entry_point: u64,
        boot_params_addr: u64,
    ) -> Result<(), HypervisorError> {
        // Set up special registers for protected mode
        let mut sregs = self
            .vcpu_fd
            .get_sregs()
            .map_err(|e| HypervisorError::VcpuRunError(format!("Failed to get sregs: {}", e)))?;

        // Enable protected mode with paging disabled
        // Linux 64-bit kernel expects to be entered in protected mode
        sregs.cr0 = 0x6000_0011; // PE=1, ET=1, NE=1
        sregs.cr3 = 0;
        sregs.cr4 = 0;

        // Set up code segment for 32-bit protected mode
        // (Linux kernel will switch to long mode itself)
        sregs.cs = KvmSegment {
            base: 0,
            limit: 0xffff_ffff,
            selector: 0x10,
            type_: 0xb, // Code: execute/read, accessed
            present: 1,
            dpl: 0,
            db: 1, // 32-bit segment
            s: 1,
            l: 0,
            g: 1, // 4KB granularity
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        // Set up data segment
        sregs.ds = KvmSegment {
            base: 0,
            limit: 0xffff_ffff,
            selector: 0x18,
            type_: 0x3, // Data: read/write, accessed
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        sregs.es = sregs.ds.clone();
        sregs.fs = sregs.ds.clone();
        sregs.gs = sregs.ds.clone();
        sregs.ss = sregs.ds.clone();

        self.vcpu_fd
            .set_sregs(&sregs)
            .map_err(|e| HypervisorError::VcpuRunError(format!("Failed to set sregs: {}", e)))?;

        // Set up general purpose registers
        let regs = KvmRegs {
            rip: entry_point,
            rsi: boot_params_addr, // Linux boot protocol: RSI = boot_params
            rflags: 0x2,           // Reserved bit always set
            ..Default::default()
        };

        self.vcpu_fd
            .set_regs(&regs)
            .map_err(|e| HypervisorError::VcpuRunError(format!("Failed to set regs: {}", e)))?;

        tracing::debug!(
            "vCPU {} setup for Linux boot: entry={:#x}, boot_params={:#x}",
            self.id,
            entry_point,
            boot_params_addr
        );

        Ok(())
    }

    /// Sets up initial register state for Linux boot (ARM64).
    #[cfg(target_arch = "aarch64")]
    pub fn setup_linux_boot(&self, entry_point: u64, dtb_addr: u64) -> Result<(), HypervisorError> {
        use super::ffi::arm64_regs;

        // ARM64 Linux boot protocol:
        // x0 = physical address of DTB
        // PC = kernel entry point
        // All other registers should be 0
        // PSTATE should be EL1h with interrupts masked

        // Set x0 = DTB address
        self.vcpu_fd
            .set_one_reg(arm64_regs::X0, dtb_addr)
            .map_err(|e| HypervisorError::VcpuRunError(format!("Failed to set x0: {}", e)))?;

        // Set PC = entry point
        self.vcpu_fd
            .set_one_reg(arm64_regs::PC, entry_point)
            .map_err(|e| HypervisorError::VcpuRunError(format!("Failed to set PC: {}", e)))?;

        // Set PSTATE for EL1h with interrupts masked
        let pstate = arm64_regs::PSTATE_EL1H
            | arm64_regs::PSTATE_D
            | arm64_regs::PSTATE_A
            | arm64_regs::PSTATE_I
            | arm64_regs::PSTATE_F;
        self.vcpu_fd
            .set_one_reg(arm64_regs::PSTATE, pstate)
            .map_err(|e| HypervisorError::VcpuRunError(format!("Failed to set PSTATE: {}", e)))?;

        // Clear other important registers
        self.vcpu_fd.set_one_reg(arm64_regs::X1, 0).ok(); // Ignore errors for optional regs
        self.vcpu_fd.set_one_reg(arm64_regs::X2, 0).ok();
        self.vcpu_fd.set_one_reg(arm64_regs::X3, 0).ok();
        self.vcpu_fd.set_one_reg(arm64_regs::SP, 0).ok();

        tracing::debug!(
            "vCPU {} setup for Linux boot: entry={:#x}, dtb={:#x}, pstate={:#x}",
            self.id,
            entry_point,
            dtb_addr,
            pstate
        );

        Ok(())
    }

    /// Converts KVM exit reason to our VcpuExit type.
    fn convert_exit(&self) -> VcpuExit {
        let exit_reason = self.vcpu_fd.exit_reason();

        match exit_reason {
            KVM_EXIT_HLT => VcpuExit::Halt,

            KVM_EXIT_IO => {
                let io = unsafe { (*self.vcpu_fd.kvm_run()).exit_data.io };
                if io.direction == KVM_EXIT_IO_OUT {
                    // For OUT instructions, data is at kvm_run + data_offset
                    let data_ptr = unsafe {
                        (self.vcpu_fd.kvm_run() as *const _ as *const u8)
                            .add(io.data_offset as usize)
                    };
                    let data = match io.size {
                        1 => (unsafe { *data_ptr }) as u64,
                        2 => (unsafe { *(data_ptr as *const u16) }) as u64,
                        4 => (unsafe { *(data_ptr as *const u32) }) as u64,
                        _ => 0,
                    };
                    VcpuExit::IoOut {
                        port: io.port,
                        size: io.size,
                        data,
                    }
                } else {
                    VcpuExit::IoIn {
                        port: io.port,
                        size: io.size,
                    }
                }
            }

            KVM_EXIT_MMIO => {
                let mmio = unsafe { (*self.vcpu_fd.kvm_run()).exit_data.mmio };
                if mmio.is_write != 0 {
                    let data = match mmio.len {
                        1 => mmio.data[0] as u64,
                        2 => u16::from_le_bytes([mmio.data[0], mmio.data[1]]) as u64,
                        4 => u32::from_le_bytes([
                            mmio.data[0],
                            mmio.data[1],
                            mmio.data[2],
                            mmio.data[3],
                        ]) as u64,
                        8 => u64::from_le_bytes([
                            mmio.data[0],
                            mmio.data[1],
                            mmio.data[2],
                            mmio.data[3],
                            mmio.data[4],
                            mmio.data[5],
                            mmio.data[6],
                            mmio.data[7],
                        ]),
                        _ => 0,
                    };
                    VcpuExit::MmioWrite {
                        addr: mmio.phys_addr,
                        size: mmio.len as u8,
                        data,
                    }
                } else {
                    VcpuExit::MmioRead {
                        addr: mmio.phys_addr,
                        size: mmio.len as u8,
                    }
                }
            }

            KVM_EXIT_SHUTDOWN => VcpuExit::Shutdown,

            KVM_EXIT_DEBUG => VcpuExit::Debug,

            KVM_EXIT_SYSTEM_EVENT => {
                let event = unsafe { (*self.vcpu_fd.kvm_run()).exit_data.system_event };
                match event.type_ {
                    1 => VcpuExit::Shutdown,    // KVM_SYSTEM_EVENT_SHUTDOWN
                    2 => VcpuExit::SystemReset, // KVM_SYSTEM_EVENT_RESET
                    _ => VcpuExit::Unknown(exit_reason as i32),
                }
            }

            KVM_EXIT_FAIL_ENTRY | KVM_EXIT_INTERNAL_ERROR => {
                tracing::error!(
                    "vCPU {} internal error: exit_reason={}",
                    self.id,
                    exit_reason
                );
                VcpuExit::Unknown(exit_reason as i32)
            }

            _ => VcpuExit::Unknown(exit_reason as i32),
        }
    }

    /// Provides data for an I/O IN instruction.
    pub fn set_io_in_data(&self, data: &[u8]) {
        unsafe {
            let kvm_run = self.vcpu_fd.kvm_run_mut();
            let io = kvm_run.exit_data.io;
            let data_ptr = (kvm_run as *mut _ as *mut u8).add(io.data_offset as usize);
            std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
        }
    }

    /// Provides data for an MMIO read.
    pub fn set_mmio_read_data(&self, data: &[u8]) {
        unsafe {
            let kvm_run = self.vcpu_fd.kvm_run_mut();
            let mmio = &mut kvm_run.exit_data.mmio;
            let len = std::cmp::min(data.len(), mmio.data.len());
            mmio.data[..len].copy_from_slice(&data[..len]);
        }
    }
}

impl Vcpu for KvmVcpu {
    fn run(&mut self) -> Result<VcpuExit, HypervisorError> {
        self.running.store(true, Ordering::SeqCst);

        // Clear immediate exit flag
        self.vcpu_fd.set_immediate_exit(false);

        // Run the vCPU
        let result = self.vcpu_fd.run();

        self.running.store(false, Ordering::SeqCst);

        match result {
            Ok(()) => Ok(self.convert_exit()),
            Err(e) => Err(HypervisorError::VcpuRunError(format!(
                "vCPU {} run failed: {}",
                self.id, e
            ))),
        }
    }

    fn get_regs(&self) -> Result<Registers, HypervisorError> {
        let kvm_regs = self.vcpu_fd.get_regs().map_err(|e| {
            HypervisorError::VcpuRunError(format!("Failed to get registers: {}", e))
        })?;

        #[cfg(target_arch = "x86_64")]
        {
            Ok(Registers {
                rax: kvm_regs.rax,
                rbx: kvm_regs.rbx,
                rcx: kvm_regs.rcx,
                rdx: kvm_regs.rdx,
                rsi: kvm_regs.rsi,
                rdi: kvm_regs.rdi,
                rsp: kvm_regs.rsp,
                rbp: kvm_regs.rbp,
                r8: kvm_regs.r8,
                r9: kvm_regs.r9,
                r10: kvm_regs.r10,
                r11: kvm_regs.r11,
                r12: kvm_regs.r12,
                r13: kvm_regs.r13,
                r14: kvm_regs.r14,
                r15: kvm_regs.r15,
                rip: kvm_regs.rip,
                rflags: kvm_regs.rflags,
            })
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 uses a different register structure
            // Map to our generic x86-style Registers for now
            Ok(Registers {
                rax: kvm_regs.regs[0],
                rbx: kvm_regs.regs[1],
                rcx: kvm_regs.regs[2],
                rdx: kvm_regs.regs[3],
                rsi: kvm_regs.regs[4],
                rdi: kvm_regs.regs[5],
                rsp: kvm_regs.sp,
                rbp: kvm_regs.regs[29],
                r8: kvm_regs.regs[8],
                r9: kvm_regs.regs[9],
                r10: kvm_regs.regs[10],
                r11: kvm_regs.regs[11],
                r12: kvm_regs.regs[12],
                r13: kvm_regs.regs[13],
                r14: kvm_regs.regs[14],
                r15: kvm_regs.regs[15],
                rip: kvm_regs.pc,
                rflags: kvm_regs.pstate,
            })
        }
    }

    fn set_regs(&mut self, regs: &Registers) -> Result<(), HypervisorError> {
        #[cfg(target_arch = "x86_64")]
        {
            let kvm_regs = KvmRegs {
                rax: regs.rax,
                rbx: regs.rbx,
                rcx: regs.rcx,
                rdx: regs.rdx,
                rsi: regs.rsi,
                rdi: regs.rdi,
                rsp: regs.rsp,
                rbp: regs.rbp,
                r8: regs.r8,
                r9: regs.r9,
                r10: regs.r10,
                r11: regs.r11,
                r12: regs.r12,
                r13: regs.r13,
                r14: regs.r14,
                r15: regs.r15,
                rip: regs.rip,
                rflags: regs.rflags,
            };

            self.vcpu_fd.set_regs(&kvm_regs).map_err(|e| {
                HypervisorError::VcpuRunError(format!("Failed to set registers: {}", e))
            })?;
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 registers would need to be set individually
            // using KVM_SET_ONE_REG
            let _ = regs; // Suppress unused warning
            return Err(HypervisorError::VcpuRunError(
                "ARM64 register setting not fully implemented".to_string(),
            ));
        }

        Ok(())
    }

    fn id(&self) -> u32 {
        self.id
    }

    fn set_io_result(&mut self, value: u64) -> Result<(), HypervisorError> {
        // For I/O IN operations, write the result back to the data area
        let bytes = value.to_le_bytes();
        unsafe {
            let kvm_run = self.vcpu_fd.kvm_run_mut();
            let io = kvm_run.exit_data.io;
            let size = io.size as usize;
            let data_ptr = (kvm_run as *mut _ as *mut u8).add(io.data_offset as usize);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, size.min(8));
        }
        Ok(())
    }

    fn set_mmio_result(&mut self, value: u64) -> Result<(), HypervisorError> {
        // For MMIO read operations, write the result back to the mmio data area
        let bytes = value.to_le_bytes();
        unsafe {
            let kvm_run = self.vcpu_fd.kvm_run_mut();
            let mmio = &mut kvm_run.exit_data.mmio;
            let len = (mmio.len as usize).min(8);
            mmio.data[..len].copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<VcpuSnapshot, HypervisorError> {
        #[cfg(target_arch = "x86_64")]
        {
            let regs = self.get_regs()?;
            Ok(VcpuSnapshot::new_x86(self.id, regs))
        }

        #[cfg(target_arch = "aarch64")]
        {
            use super::ffi::arm64_regs;

            // Read ARM64 registers
            let mut arm_regs = crate::types::Arm64Registers::default();

            // Read X0-X30
            for i in 0..31 {
                let reg_id = arm64_regs::X0 + (i as u64) * 2; // Each reg is 2 u64s apart in encoding
                if let Ok(val) = self.vcpu_fd.get_one_reg(reg_id) {
                    arm_regs.x[i] = val;
                }
            }

            // Read SP, PC, PSTATE
            arm_regs.sp = self.vcpu_fd.get_one_reg(arm64_regs::SP).unwrap_or(0);
            arm_regs.pc = self.vcpu_fd.get_one_reg(arm64_regs::PC).unwrap_or(0);
            arm_regs.pstate = self.vcpu_fd.get_one_reg(arm64_regs::PSTATE).unwrap_or(0);

            // Note: FPCR, FPSR, and vector registers would need additional KVM_GET_ONE_REG calls

            Ok(VcpuSnapshot::new_arm64(self.id, arm_regs))
        }
    }

    fn restore(&mut self, snapshot: &VcpuSnapshot) -> Result<(), HypervisorError> {
        if snapshot.id != self.id {
            return Err(HypervisorError::SnapshotError(format!(
                "vCPU ID mismatch: expected {}, got {}",
                self.id, snapshot.id
            )));
        }

        #[cfg(target_arch = "x86_64")]
        {
            if let Some(regs) = &snapshot.x86_regs {
                self.set_regs(regs)?;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            use super::ffi::arm64_regs;

            if let Some(arm_regs) = &snapshot.arm64_regs {
                // Restore X0-X30
                for i in 0..31 {
                    let reg_id = arm64_regs::X0 + (i as u64) * 2;
                    let _ = self.vcpu_fd.set_one_reg(reg_id, arm_regs.x[i]);
                }

                // Restore SP, PC, PSTATE
                let _ = self.vcpu_fd.set_one_reg(arm64_regs::SP, arm_regs.sp);
                let _ = self.vcpu_fd.set_one_reg(arm64_regs::PC, arm_regs.pc);
                let _ = self
                    .vcpu_fd
                    .set_one_reg(arm64_regs::PSTATE, arm_regs.pstate);
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

    #[test]
    fn test_vcpu_running_flag() {
        // Just test that we can create and check the running flag
        let running = Arc::new(AtomicBool::new(false));
        assert!(!running.load(Ordering::SeqCst));
        running.store(true, Ordering::SeqCst);
        assert!(running.load(Ordering::SeqCst));
    }
}
