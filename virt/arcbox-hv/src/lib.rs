//! Safe Rust bindings for Apple Hypervisor.framework (ARM64).
//!
//! Provides VM creation, vCPU management, memory mapping, GICv3 interrupt
//! control, and exit handling for building custom VMMs on macOS.
//!
//! On unsupported platforms this crate compiles to an empty library.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

mod error;
mod exit;
pub mod ffi;
#[cfg(feature = "gic")]
mod gic;
mod memory;
mod vcpu;
mod vm;

pub use error::{HvError, HvResult, check};
pub use exit::{ExceptionClass, MmioInfo, VcpuExit};
#[cfg(feature = "gic")]
pub use gic::{Gic, GicConfig};
pub use memory::MemoryPermission;
pub use vcpu::HvVcpu;
pub use vm::HvVm;

/// ARM64 general-purpose and special register IDs.
///
/// These correspond to the `hv_reg_t` values used by
/// [`HvVcpu::get_reg`] / [`HvVcpu::set_reg`].
pub mod reg {
    pub use crate::ffi::{
        HV_REG_CPSR, HV_REG_FPCR, HV_REG_FPSR, HV_REG_PC, HV_REG_X0, HV_REG_X1, HV_REG_X2,
        HV_REG_X3, HV_REG_X4, HV_REG_X5, HV_REG_X6, HV_REG_X7, HV_REG_X8, HV_REG_X9, HV_REG_X10,
        HV_REG_X11, HV_REG_X12, HV_REG_X13, HV_REG_X14, HV_REG_X15, HV_REG_X16, HV_REG_X17,
        HV_REG_X18, HV_REG_X19, HV_REG_X20, HV_REG_X21, HV_REG_X22, HV_REG_X23, HV_REG_X24,
        HV_REG_X25, HV_REG_X26, HV_REG_X27, HV_REG_X28, HV_REG_X29, HV_REG_X30,
    };
}

/// ARM64 system register IDs.
///
/// These correspond to the `hv_sys_reg_t` values used by
/// [`HvVcpu::get_sys_reg`] / [`HvVcpu::set_sys_reg`].
pub mod sys_reg {
    pub use crate::ffi::{
        HV_SYS_REG_ELR_EL1, HV_SYS_REG_MAIR_EL1, HV_SYS_REG_MPIDR_EL1, HV_SYS_REG_SCTLR_EL1,
        HV_SYS_REG_SP_EL1, HV_SYS_REG_SPSR_EL1, HV_SYS_REG_TCR_EL1, HV_SYS_REG_TTBR0_EL1,
        HV_SYS_REG_TTBR1_EL1, HV_SYS_REG_VBAR_EL1,
    };
}
