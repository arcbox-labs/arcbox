//! Safe wrapper around Hypervisor.framework vCPU operations.
//!
//! **Threading constraint**: Apple's Hypervisor.framework requires that all
//! operations on a vCPU happen on the thread that created it. This type is
//! intentionally `!Send` to enforce this at compile time.

use std::marker::PhantomData;
use std::ptr;
use std::rc::Rc;

use tracing::trace;

use crate::error::{self, HvResult};
use crate::exit::{self, VcpuExit};
use crate::ffi;

/// Handle to a single ARM64 vCPU.
///
/// This type is `!Send` — it can only be used on the thread that created it,
/// as required by Hypervisor.framework.
pub struct HvVcpu {
    /// Opaque framework handle.
    id: u64,
    /// Pointer to the framework-managed exit info structure.
    /// Valid for the lifetime of the vCPU.
    exit_info: *const ffi::HvVcpuExitInfo,
    /// Prevent `Send` — `Rc<()>` is genuinely `!Send`.
    _not_send: PhantomData<Rc<()>>,
}

impl HvVcpu {
    /// Returns the raw framework handle for use with `hv_vcpus_exit`.
    ///
    /// The handle is valid for the lifetime of this vCPU and can be
    /// shared (as a `u64`) with other threads for targeted exit.
    #[must_use]
    pub fn raw_handle(&self) -> u64 {
        self.id
    }
}

impl HvVcpu {
    /// Creates a new vCPU with default configuration.
    ///
    /// Must be called from the thread that will run the vCPU.
    pub fn new() -> HvResult<Self> {
        let mut id: u64 = 0;
        let mut exit: ffi::hv_vcpu_exit_t = ptr::null();

        // SAFETY: We pass valid pointers for the out-parameters. The framework
        // allocates the exit info structure and returns a pointer to it.
        error::check(unsafe { ffi::hv_vcpu_create(&raw mut id, &raw mut exit, ptr::null_mut()) })?;

        trace!(vcpu_id = id, "vCPU created");
        Ok(Self {
            id,
            exit_info: exit,
            _not_send: PhantomData,
        })
    }

    /// Returns the framework vCPU identifier.
    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Runs the vCPU until it exits.
    ///
    /// Returns a [`VcpuExit`] describing why execution stopped. The VMM should
    /// handle the exit (e.g. emulate MMIO) and call `run()` again.
    pub fn run(&self) -> HvResult<VcpuExit> {
        // SAFETY: The vCPU was created on this thread and `self.id` is valid.
        error::check(unsafe { ffi::hv_vcpu_run(self.id) })?;

        if self.exit_info.is_null() {
            return Err(crate::error::HvError::Error);
        }
        // SAFETY: `exit_info` was set by `hv_vcpu_create` and remains valid
        // for the lifetime of the vCPU. The framework populates it after each
        // run. We only read from it — no mutation.
        let info = unsafe { &*self.exit_info };
        Ok(exit::parse_exit(info))
    }

    /// Reads a general-purpose register (X0–X30, PC, FPCR, FPSR, CPSR).
    pub fn get_reg(&self, reg: u32) -> HvResult<u64> {
        let mut value: u64 = 0;
        // SAFETY: `self.id` is a valid vCPU, `value` is a valid out-pointer.
        error::check(unsafe { ffi::hv_vcpu_get_reg(self.id, reg, &raw mut value) })?;
        Ok(value)
    }

    /// Writes a general-purpose register.
    pub fn set_reg(&self, reg: u32, value: u64) -> HvResult<()> {
        // SAFETY: `self.id` is a valid vCPU.
        error::check(unsafe { ffi::hv_vcpu_set_reg(self.id, reg, value) })
    }

    /// Reads a system register (e.g. `SCTLR_EL1`, `VBAR_EL1`).
    pub fn get_sys_reg(&self, reg: u16) -> HvResult<u64> {
        let mut value: u64 = 0;
        // SAFETY: `self.id` is a valid vCPU, `value` is a valid out-pointer.
        error::check(unsafe { ffi::hv_vcpu_get_sys_reg(self.id, reg, &raw mut value) })?;
        Ok(value)
    }

    /// Writes a system register.
    pub fn set_sys_reg(&self, reg: u16, value: u64) -> HvResult<()> {
        // SAFETY: `self.id` is a valid vCPU.
        error::check(unsafe { ffi::hv_vcpu_set_sys_reg(self.id, reg, value) })
    }

    /// Sets or clears pending IRQ and FIQ interrupts on this vCPU.
    ///
    /// When a GIC is not in use, this is the mechanism to inject interrupts.
    pub fn set_pending_interrupt(&self, irq: bool, fiq: bool) -> HvResult<()> {
        // SAFETY: `self.id` is a valid vCPU.
        error::check(unsafe {
            ffi::hv_vcpu_set_pending_interrupt(self.id, ffi::HV_INTERRUPT_TYPE_IRQ, irq)
        })?;
        // SAFETY: Same as above.
        error::check(unsafe {
            ffi::hv_vcpu_set_pending_interrupt(self.id, ffi::HV_INTERRUPT_TYPE_FIQ, fiq)
        })
    }

    /// Masks or unmasks the virtual timer for this vCPU.
    ///
    /// When masked, `VcpuExit::VtimerActivated` will not be reported. This is
    /// useful to suppress exits while the VMM decides how to handle the timer.
    pub fn set_vtimer_mask(&self, masked: bool) -> HvResult<()> {
        // SAFETY: `self.id` is a valid vCPU.
        error::check(unsafe { ffi::hv_vcpu_set_vtimer_mask(self.id, masked) })
    }
}

impl Drop for HvVcpu {
    fn drop(&mut self) {
        // SAFETY: `self.id` is valid and we are on the creation thread (enforced
        // by `!Send`). After this call the handle is no longer usable.
        let ret = unsafe { ffi::hv_vcpu_destroy(self.id) };
        if let Err(e) = error::check(ret) {
            tracing::warn!(vcpu_id = self.id, "hv_vcpu_destroy failed: {e}");
        } else {
            trace!(vcpu_id = self.id, "vCPU destroyed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requires `com.apple.security.hypervisor` entitlement.
    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn create_vcpu_requires_vm() {
        // vCPU creation without a VM should fail.
        let result = HvVcpu::new();
        assert!(result.is_err(), "vCPU create without VM should fail");
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn create_and_destroy_vcpu() {
        let vm = crate::HvVm::new().expect("VM create failed");
        let vcpu = HvVcpu::new().expect("vCPU create failed");
        let id = vcpu.id();
        assert!(id < u64::MAX, "vCPU should have a valid ID");
        drop(vcpu);
        drop(vm);
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn set_and_get_register() {
        let vm = crate::HvVm::new().expect("VM create failed");
        let vcpu = HvVcpu::new().expect("vCPU create failed");

        vcpu.set_reg(ffi::HV_REG_X0, 0xDEAD_BEEF)
            .expect("set_reg failed");
        let val = vcpu.get_reg(ffi::HV_REG_X0).expect("get_reg failed");
        assert_eq!(val, 0xDEAD_BEEF);
        drop(vm);
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn set_and_get_sys_register() {
        let vm = crate::HvVm::new().expect("VM create failed");
        let vcpu = HvVcpu::new().expect("vCPU create failed");

        // Read SCTLR_EL1 default value (should succeed even if value is 0).
        let _ = vcpu
            .get_sys_reg(ffi::HV_SYS_REG_SCTLR_EL1)
            .expect("get_sys_reg failed");
        drop(vm);
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn run_wfi_exit() {
        let vm = crate::HvVm::new().expect("VM create failed");

        // Allocate a page and write a WFI instruction (0xD503207F).
        let size = 4096usize;
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        // SAFETY: Layout is valid.
        let code = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!code.is_null());

        // Write WFI (little-endian ARM64 encoding) as raw bytes to avoid
        // alignment lint — alloc guarantees 4096-byte alignment in practice.
        // SAFETY: code points to at least 4096 bytes.
        unsafe {
            std::slice::from_raw_parts_mut(code, 4).copy_from_slice(&0xD503_207Fu32.to_le_bytes());
        }

        let ram_base: u64 = 0x4000_0000;
        // SAFETY: code is valid 4KB-aligned allocation.
        unsafe {
            vm.map_memory(code, ram_base, size, crate::MemoryPermission::ALL)
                .expect("map failed");
        }

        let vcpu = HvVcpu::new().expect("vCPU create failed");
        vcpu.set_reg(ffi::HV_REG_PC, ram_base)
            .expect("set PC failed");
        // CPSR = EL1h, all interrupts masked.
        vcpu.set_reg(ffi::HV_REG_CPSR, 0x3C5)
            .expect("set CPSR failed");

        let exit = vcpu.run().expect("run failed");
        match exit {
            VcpuExit::Exception {
                class: crate::ExceptionClass::WaitForInterrupt,
                ..
            } => {} // Expected
            other => panic!("expected WFI exit, got {other:?}"),
        }

        drop(vcpu);
        vm.unmap_memory(ram_base, size).expect("unmap failed");
        // SAFETY: code was allocated with layout.
        unsafe { std::alloc::dealloc(code, layout) };
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn mmio_exit_on_unmapped_address() {
        let vm = crate::HvVm::new().expect("VM create failed");

        // Write instructions: STR X0, [X1] then WFI
        let size = 4096usize;
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        // SAFETY: Layout is valid.
        let code = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!code.is_null());

        // Write instruction bytes directly to avoid alignment lint.
        // SAFETY: code is at least 4096 bytes.
        unsafe {
            let buf = std::slice::from_raw_parts_mut(code, 8);
            // STR W0, [X1]  (32-bit store) = 0xB9000020
            buf[0..4].copy_from_slice(&0xB900_0020u32.to_le_bytes());
            // WFI = 0xD503207F
            buf[4..8].copy_from_slice(&0xD503_207Fu32.to_le_bytes());
        }

        let ram_base: u64 = 0x4000_0000;
        let mmio_addr: u64 = 0x0A00_0000; // Not mapped → data abort

        // SAFETY: code is valid.
        unsafe {
            vm.map_memory(code, ram_base, size, crate::MemoryPermission::ALL)
                .expect("map failed");
        }

        let vcpu = HvVcpu::new().expect("vCPU create failed");
        vcpu.set_reg(ffi::HV_REG_PC, ram_base)
            .expect("set PC failed");
        vcpu.set_reg(ffi::HV_REG_CPSR, 0x3C5)
            .expect("set CPSR failed");
        vcpu.set_reg(ffi::HV_REG_X0, 0x42).expect("set X0 failed");
        vcpu.set_reg(ffi::HV_REG_X1, mmio_addr)
            .expect("set X1 failed");

        let exit = vcpu.run().expect("run failed");
        match exit {
            VcpuExit::Exception {
                class: crate::ExceptionClass::DataAbort(ref mmio),
                ..
            } => {
                assert!(mmio.is_write);
                assert_eq!(mmio.access_size, 4);
                assert_eq!(mmio.address, mmio_addr);
            }
            other => panic!("expected DataAbort MMIO exit, got {other:?}"),
        }

        drop(vcpu);
        vm.unmap_memory(ram_base, size).expect("unmap failed");
        // SAFETY: code was allocated with layout.
        unsafe { std::alloc::dealloc(code, layout) };
    }
}
