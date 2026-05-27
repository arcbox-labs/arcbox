//! Raw FFI declarations for Apple Hypervisor.framework (ARM64).
//!
//! These bindings correspond to the C headers shipped with Xcode:
//! `<Hypervisor/hv.h>`, `<Hypervisor/hv_vcpu.h>`, `<Hypervisor/hv_gic.h>`.
//!
//! All functions are `unsafe` — callers are responsible for upholding the
//! framework's threading and alignment invariants.

#![allow(non_camel_case_types, dead_code)]

use std::ffi::c_void;

// ---------------------------------------------------------------------------
// Scalar type aliases
// ---------------------------------------------------------------------------

pub type hv_return_t = i32;
pub type hv_vcpu_t = u64;
pub type hv_vcpu_exit_t = *const HvVcpuExitInfo;
pub type hv_ipa_t = u64;
pub type hv_memory_flags_t = u64;

// ---------------------------------------------------------------------------
// Memory permission flags
// ---------------------------------------------------------------------------

pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

// ---------------------------------------------------------------------------
// Exit reasons
// ---------------------------------------------------------------------------

pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;
pub const HV_EXIT_REASON_UNKNOWN: u32 = 3;

// ---------------------------------------------------------------------------
// ARM64 general-purpose registers (hv_reg_t)
// ---------------------------------------------------------------------------

pub const HV_REG_X0: u32 = 0;
pub const HV_REG_X1: u32 = 1;
pub const HV_REG_X2: u32 = 2;
pub const HV_REG_X3: u32 = 3;
pub const HV_REG_X4: u32 = 4;
pub const HV_REG_X5: u32 = 5;
pub const HV_REG_X6: u32 = 6;
pub const HV_REG_X7: u32 = 7;
pub const HV_REG_X8: u32 = 8;
pub const HV_REG_X9: u32 = 9;
pub const HV_REG_X10: u32 = 10;
pub const HV_REG_X11: u32 = 11;
pub const HV_REG_X12: u32 = 12;
pub const HV_REG_X13: u32 = 13;
pub const HV_REG_X14: u32 = 14;
pub const HV_REG_X15: u32 = 15;
pub const HV_REG_X16: u32 = 16;
pub const HV_REG_X17: u32 = 17;
pub const HV_REG_X18: u32 = 18;
pub const HV_REG_X19: u32 = 19;
pub const HV_REG_X20: u32 = 20;
pub const HV_REG_X21: u32 = 21;
pub const HV_REG_X22: u32 = 22;
pub const HV_REG_X23: u32 = 23;
pub const HV_REG_X24: u32 = 24;
pub const HV_REG_X25: u32 = 25;
pub const HV_REG_X26: u32 = 26;
pub const HV_REG_X27: u32 = 27;
pub const HV_REG_X28: u32 = 28;
pub const HV_REG_X29: u32 = 29;
pub const HV_REG_X30: u32 = 30;
pub const HV_REG_PC: u32 = 31;
pub const HV_REG_FPCR: u32 = 32;
pub const HV_REG_FPSR: u32 = 33;
pub const HV_REG_CPSR: u32 = 34;

// ---------------------------------------------------------------------------
// ARM64 system registers (hv_sys_reg_t)
//
// Encoding: (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
// ---------------------------------------------------------------------------

pub const HV_SYS_REG_MPIDR_EL1: u16 = 0xc005;
pub const HV_SYS_REG_SCTLR_EL1: u16 = 0xc080;
pub const HV_SYS_REG_TTBR0_EL1: u16 = 0xc100;
pub const HV_SYS_REG_TTBR1_EL1: u16 = 0xc108;
pub const HV_SYS_REG_TCR_EL1: u16 = 0xc102;
pub const HV_SYS_REG_MAIR_EL1: u16 = 0xc510;
pub const HV_SYS_REG_VBAR_EL1: u16 = 0xc600;
pub const HV_SYS_REG_SP_EL1: u16 = 0xe208;
pub const HV_SYS_REG_SPSR_EL1: u16 = 0xe200;
pub const HV_SYS_REG_ELR_EL1: u16 = 0xe201;

// ---------------------------------------------------------------------------
// Interrupt types for hv_vcpu_set_pending_interrupt
// ---------------------------------------------------------------------------

pub const HV_INTERRUPT_TYPE_IRQ: u32 = 0;
pub const HV_INTERRUPT_TYPE_FIQ: u32 = 1;

// ---------------------------------------------------------------------------
// Exit info structures
// ---------------------------------------------------------------------------

/// Describes the exception that triggered a VM exit.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HvVcpuExitException {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

/// Top-level exit information returned for each vCPU run.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HvVcpuExitInfo {
    pub reason: u32,
    pub exception: HvVcpuExitException,
}

// ---------------------------------------------------------------------------
// Framework functions
// ---------------------------------------------------------------------------

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    // VM lifecycle
    pub fn hv_vm_create(config: *mut c_void) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;

    // Guest physical memory management
    pub fn hv_vm_map(
        addr: *mut u8,
        ipa: hv_ipa_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;
    pub fn hv_vm_unmap(ipa: hv_ipa_t, size: usize) -> hv_return_t;
    pub fn hv_vm_protect(ipa: hv_ipa_t, size: usize, flags: hv_memory_flags_t) -> hv_return_t;

    // vCPU lifecycle
    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut hv_vcpu_exit_t,
        config: *mut c_void,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;

    // vCPU execution
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpus_exit(vcpus: *const hv_vcpu_t, count: u32) -> hv_return_t;

    // vCPU register access
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: u32, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: u32, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: u16, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: u16, value: u64) -> hv_return_t;

    // vCPU interrupt / timer control
    pub fn hv_vcpu_set_pending_interrupt(
        vcpu: hv_vcpu_t,
        int_type: u32,
        pending: bool,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_vtimer_mask(vcpu: hv_vcpu_t, masked: bool) -> hv_return_t;

    // VM configuration (macOS 13+)
    pub fn hv_vm_config_create() -> *mut c_void;
    pub fn hv_vm_config_get_ipa_size(config: *mut c_void, ipa_size: *mut u32) -> hv_return_t;
    pub fn hv_vm_config_set_ipa_size(config: *mut c_void, ipa_size: u32) -> hv_return_t;

    // vCPU configuration
    pub fn hv_vcpu_config_create() -> *mut c_void;
    pub fn hv_vcpu_config_get_feature_reg(
        config: *mut c_void,
        feature_reg: u16,
        value: *mut u64,
    ) -> hv_return_t;
    pub fn hv_vcpu_get_exec_time(vcpu: hv_vcpu_t, time: *mut u64) -> hv_return_t;

    // vCPU debug traps
    pub fn hv_vcpu_set_trap_debug_exceptions(vcpu: hv_vcpu_t, enable: bool) -> hv_return_t;
    pub fn hv_vcpu_set_trap_debug_reg_accesses(vcpu: hv_vcpu_t, enable: bool) -> hv_return_t;

}

// GICv3 APIs (macOS 15+). Gated behind the `gic` cargo feature because
// they require a macOS 15+ SDK to link. Without the feature, the rest
// of the crate (VM, vCPU, memory, exit parsing) compiles on macOS 11+.
//
// Xcode 26 SDK changed the GIC API: the VMM now explicitly sets
// distributor/redistributor base addresses via a config object instead
// of the framework choosing them.
#[cfg(feature = "gic")]
#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    // --- Config-based creation (Xcode 26 / macOS 15+) ---
    pub fn hv_gic_config_create() -> *mut c_void; // Returns os_object (hv_gic_config_t)
    pub fn hv_gic_config_set_distributor_base(
        config: *mut c_void,
        distributor_base: u64,
    ) -> hv_return_t;
    pub fn hv_gic_config_set_redistributor_base(
        config: *mut c_void,
        redistributor_base: u64,
    ) -> hv_return_t;

    pub fn hv_gic_create(config: *mut c_void) -> hv_return_t;
    pub fn hv_gic_reset() -> hv_return_t;
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> hv_return_t;

    // --- Size / alignment queries ---
    pub fn hv_gic_get_distributor_size(size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_distributor_base_alignment(alignment: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_redistributor_base(vcpu: hv_vcpu_t, addr: *mut u64) -> hv_return_t;
    pub fn hv_gic_get_redistributor_region_size(size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_redistributor_size(size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_msi_region_size(size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_msi_region_base_alignment(alignment: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_spi_interrupt_range(base: *mut u32, count: *mut u32) -> hv_return_t;

    // --- State save/restore ---
    pub fn hv_gic_set_state(data: *const c_void, size: usize) -> hv_return_t;
}
