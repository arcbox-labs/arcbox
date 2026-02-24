//! FFI bindings for Linux KVM API.
//!
//! This module provides safe Rust wrappers around the KVM ioctl interface.
//! All ioctl commands are defined according to the Linux kernel headers.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::ptr;

// ============================================================================
// KVM ioctl Numbers
// ============================================================================

/// KVM magic number for ioctl encoding.
const KVMIO: u8 = 0xAE;

/// Macro to create KVM ioctl numbers.
macro_rules! kvm_io {
    ($nr:expr) => {
        nix::request_code_none!(KVMIO, $nr)
    };
}

macro_rules! kvm_ior {
    ($nr:expr, $ty:ty) => {
        nix::request_code_read!(KVMIO, $nr, std::mem::size_of::<$ty>())
    };
}

macro_rules! kvm_iow {
    ($nr:expr, $ty:ty) => {
        nix::request_code_write!(KVMIO, $nr, std::mem::size_of::<$ty>())
    };
}

macro_rules! kvm_iowr {
    ($nr:expr, $ty:ty) => {
        nix::request_code_readwrite!(KVMIO, $nr, std::mem::size_of::<$ty>())
    };
}

// System ioctls
pub const KVM_GET_API_VERSION: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x00);
pub const KVM_CREATE_VM: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x01);
pub const KVM_CHECK_EXTENSION: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x03);
pub const KVM_GET_VCPU_MMAP_SIZE: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x04);

// VM ioctls
pub const KVM_SET_USER_MEMORY_REGION: nix::sys::ioctl::ioctl_num_type =
    kvm_iow!(0x46, KvmUserspaceMemoryRegion);
pub const KVM_CREATE_VCPU: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x41);
pub const KVM_SET_TSS_ADDR: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x47);
pub const KVM_CREATE_IRQCHIP: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x60);
pub const KVM_CREATE_PIT2: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x77, KvmPitConfig);
pub const KVM_SET_IDENTITY_MAP_ADDR: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x48, u64);
pub const KVM_IRQFD: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x76, KvmIrqfd);
pub const KVM_IOEVENTFD: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x79, KvmIoeventfd);
pub const KVM_IRQ_LINE: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x61, KvmIrqLevel);
pub const KVM_SET_GSI_ROUTING: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x6a, KvmIrqRouting);
pub const KVM_GET_DIRTY_LOG: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x42, KvmDirtyLog);

// vCPU ioctls for interrupt injection
pub const KVM_INTERRUPT: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x86, KvmInterrupt);

// vCPU ioctls
pub const KVM_RUN: nix::sys::ioctl::ioctl_num_type = kvm_io!(0x80);
pub const KVM_GET_REGS: nix::sys::ioctl::ioctl_num_type = kvm_ior!(0x81, KvmRegs);
pub const KVM_SET_REGS: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x82, KvmRegs);
pub const KVM_GET_SREGS: nix::sys::ioctl::ioctl_num_type = kvm_ior!(0x83, KvmSregs);
pub const KVM_SET_SREGS: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x84, KvmSregs);
pub const KVM_SET_CPUID2: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0x90, KvmCpuid2);
pub const KVM_GET_CPUID2: nix::sys::ioctl::ioctl_num_type = kvm_iowr!(0x91, KvmCpuid2);

// ARM64-specific ioctls
#[cfg(target_arch = "aarch64")]
pub const KVM_ARM_PREFERRED_TARGET: nix::sys::ioctl::ioctl_num_type = kvm_ior!(0xaf, KvmVcpuInit);
#[cfg(target_arch = "aarch64")]
pub const KVM_ARM_VCPU_INIT: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0xae, KvmVcpuInit);
#[cfg(target_arch = "aarch64")]
pub const KVM_GET_ONE_REG: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0xab, KvmOneReg);
#[cfg(target_arch = "aarch64")]
pub const KVM_SET_ONE_REG: nix::sys::ioctl::ioctl_num_type = kvm_iow!(0xac, KvmOneReg);

// ============================================================================
// KVM Capability Constants
// ============================================================================

pub const KVM_CAP_IRQCHIP: u32 = 0;
pub const KVM_CAP_USER_MEMORY: u32 = 3;
pub const KVM_CAP_SET_TSS_ADDR: u32 = 4;
pub const KVM_CAP_EXT_CPUID: u32 = 7;
pub const KVM_CAP_NR_VCPUS: u32 = 9;
pub const KVM_CAP_NR_MEMSLOTS: u32 = 10;
pub const KVM_CAP_PIT2: u32 = 33;
pub const KVM_CAP_IOEVENTFD: u32 = 36;
pub const KVM_CAP_IRQFD: u32 = 32;
pub const KVM_CAP_MAX_VCPUS: u32 = 66;
pub const KVM_CAP_MAX_VCPU_ID: u32 = 128;
#[cfg(target_arch = "aarch64")]
pub const KVM_CAP_ARM_VM_IPA_SIZE: u32 = 165;

// ============================================================================
// ARM64 Register IDs
// ============================================================================

#[cfg(target_arch = "aarch64")]
pub mod arm64_regs {
    /// KVM register type bits
    const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
    const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
    const KVM_REG_ARM_CORE: u64 = 0x0010_0000_0000_0000;

    /// Macro to create ARM64 core register IDs
    macro_rules! arm64_core_reg {
        ($offset:expr) => {
            KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (($offset as u64) * 2)
        };
    }

    // General purpose registers x0-x30
    pub const X0: u64 = arm64_core_reg!(0);
    pub const X1: u64 = arm64_core_reg!(1);
    pub const X2: u64 = arm64_core_reg!(2);
    pub const X3: u64 = arm64_core_reg!(3);
    pub const X29: u64 = arm64_core_reg!(29); // FP
    pub const X30: u64 = arm64_core_reg!(30); // LR

    // Stack pointer
    pub const SP: u64 = arm64_core_reg!(31);

    // Program counter
    pub const PC: u64 = arm64_core_reg!(32);

    // Processor state (PSTATE/CPSR)
    pub const PSTATE: u64 = arm64_core_reg!(33);

    /// PSTATE bits for EL1h (Exception Level 1, SP_ELx)
    pub const PSTATE_EL1H: u64 = 0x0000_0005;

    /// PSTATE bits for EL1 with interrupts masked
    pub const PSTATE_D: u64 = 1 << 9; // Debug mask
    pub const PSTATE_A: u64 = 1 << 8; // SError mask
    pub const PSTATE_I: u64 = 1 << 7; // IRQ mask
    pub const PSTATE_F: u64 = 1 << 6; // FIQ mask
}

// ============================================================================
// KVM Exit Reasons
// ============================================================================

pub const KVM_EXIT_UNKNOWN: u32 = 0;
pub const KVM_EXIT_EXCEPTION: u32 = 1;
pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_HYPERCALL: u32 = 3;
pub const KVM_EXIT_DEBUG: u32 = 4;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_IRQ_WINDOW_OPEN: u32 = 7;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTR: u32 = 10;
pub const KVM_EXIT_SET_TPR: u32 = 11;
pub const KVM_EXIT_TPR_ACCESS: u32 = 12;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
pub const KVM_EXIT_SYSTEM_EVENT: u32 = 24;

// I/O direction
pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;

// ============================================================================
// Memory Region Flags
// ============================================================================

pub const KVM_MEM_LOG_DIRTY_PAGES: u32 = 1 << 0;
pub const KVM_MEM_READONLY: u32 = 1 << 1;

// ============================================================================
// Dirty Log Structures
// ============================================================================

/// Structure for KVM_GET_DIRTY_LOG ioctl.
///
/// This is used to retrieve a bitmap of dirty pages for a memory slot.
/// Each bit in the bitmap represents one page (typically 4KB).
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmDirtyLog {
    /// Memory slot ID.
    pub slot: u32,
    /// Padding for alignment.
    pub padding: u32,
    /// Pointer to userspace bitmap buffer.
    /// The buffer must be large enough to hold (memory_size / page_size / 8) bytes.
    pub dirty_bitmap: *mut u64,
}

// ============================================================================
// Data Structures
// ============================================================================

/// Userspace memory region descriptor.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmUserspaceMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

/// PIT configuration (x86 only).
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmPitConfig {
    pub flags: u32,
    pub pad: [u32; 15],
}

/// IRQFD configuration.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmIrqfd {
    pub fd: u32,
    pub gsi: u32,
    pub flags: u32,
    pub resamplefd: u32,
    pub pad: [u8; 16],
}

/// IOEVENTFD configuration.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmIoeventfd {
    pub datamatch: u64,
    pub addr: u64,
    pub len: u32,
    pub fd: i32,
    pub flags: u32,
    pub pad: [u8; 36],
}

impl Default for KvmIoeventfd {
    fn default() -> Self {
        Self {
            datamatch: 0,
            addr: 0,
            len: 0,
            fd: 0,
            flags: 0,
            pad: [0; 36],
        }
    }
}

/// IRQ level for KVM_IRQ_LINE.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmIrqLevel {
    /// IRQ number (GSI for in-kernel irqchip, or legacy PIC IRQ).
    /// For ARM, this encodes: (irq & 0xff) | ((irq_type & 0xff) << 24)
    pub irq: u32,
    /// Level: 0 = deassert, 1 = assert.
    pub level: u32,
}

/// External interrupt injection (for vCPU).
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmInterrupt {
    /// Interrupt vector (0-255 for x86).
    pub irq: u32,
}

/// IRQFD flags.
pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
pub const KVM_IRQFD_FLAG_RESAMPLE: u32 = 1 << 1;

/// IOEVENTFD flags.
pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 1 << 0;
pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1 << 1;
pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 1 << 2;
pub const KVM_IOEVENTFD_FLAG_VIRTIO_CCW_NOTIFY: u32 = 1 << 3;

/// GSI routing entry type.
pub const KVM_IRQ_ROUTING_IRQCHIP: u32 = 1;
pub const KVM_IRQ_ROUTING_MSI: u32 = 2;
pub const KVM_IRQ_ROUTING_S390_ADAPTER: u32 = 3;
pub const KVM_IRQ_ROUTING_HV_SINT: u32 = 4;

/// IRQ routing entry for in-kernel irqchip.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmIrqRoutingIrqchip {
    pub irqchip: u32,
    pub pin: u32,
}

/// IRQ routing entry for MSI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmIrqRoutingMsi {
    pub address_lo: u32,
    pub address_hi: u32,
    pub data: u32,
    pub devid: u32,
}

/// Union for IRQ routing entry data.
#[repr(C)]
#[derive(Clone, Copy)]
pub union KvmIrqRoutingUnion {
    pub irqchip: KvmIrqRoutingIrqchip,
    pub msi: KvmIrqRoutingMsi,
    pub pad: [u32; 8],
}

impl Default for KvmIrqRoutingUnion {
    fn default() -> Self {
        Self { pad: [0; 8] }
    }
}

/// Single IRQ routing entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KvmIrqRoutingEntry {
    pub gsi: u32,
    pub type_: u32,
    pub flags: u32,
    pub pad: u32,
    pub u: KvmIrqRoutingUnion,
}

impl Default for KvmIrqRoutingEntry {
    fn default() -> Self {
        Self {
            gsi: 0,
            type_: 0,
            flags: 0,
            pad: 0,
            u: KvmIrqRoutingUnion::default(),
        }
    }
}

/// IRQ routing table header.
/// Note: The actual entries follow this header in memory (variable length).
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmIrqRouting {
    pub nr: u32,
    pub flags: u32,
    // Followed by: entries: [KvmIrqRoutingEntry; nr]
}

/// x86_64 general purpose registers.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// x86_64 segment descriptor.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

/// x86_64 descriptor table.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

/// x86_64 special registers.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

/// CPUID entry.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

/// CPUID array header (x86 only).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct KvmCpuid2 {
    pub nent: u32,
    pub padding: u32,
    pub entries: [KvmCpuidEntry2; 256],
}

#[cfg(target_arch = "x86_64")]
impl Default for KvmCpuid2 {
    fn default() -> Self {
        Self {
            nent: 0,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); 256],
        }
    }
}

/// ARM64 vCPU initialization.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmVcpuInit {
    pub target: u32,
    pub features: [u32; 7],
}

/// ARM64 register access.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmOneReg {
    pub id: u64,
    pub addr: u64,
}

/// ARM64 registers (placeholder - real implementation uses KVM_GET/SET_ONE_REG).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmRegs {
    pub regs: [u64; 31], // x0-x30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// ARM64 special registers (placeholder).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct KvmSregs {
    // ARM64 uses different register access mechanism
    _placeholder: u64,
}

// ============================================================================
// KVM Run Structure
// ============================================================================

/// KVM run structure for vCPU execution.
/// This is mmap'd and shared between kernel and userspace.
#[repr(C)]
pub struct KvmRun {
    // Request flags
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub padding1: [u8; 6],

    // Exit information
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,

    // CR8 value
    pub cr8: u64,

    // APIC base
    pub apic_base: u64,

    // Exit data (union in C, using largest variant)
    pub exit_data: KvmRunExitData,
}

/// Exit data union (using repr(C) struct to represent the union).
#[repr(C)]
pub union KvmRunExitData {
    pub io: KvmRunIo,
    pub mmio: KvmRunMmio,
    pub hypercall: KvmRunHypercall,
    pub system_event: KvmRunSystemEvent,
    pub padding: [u8; 256],
}

/// I/O exit data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmRunIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64,
}

/// MMIO exit data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmRunMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
    pub padding: [u8; 3],
}

/// Hypercall exit data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmRunHypercall {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret: u64,
    pub longmode: u32,
    pub pad: u32,
}

/// System event exit data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmRunSystemEvent {
    pub type_: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

// ============================================================================
// Safe Wrapper Types
// ============================================================================

/// Result type for KVM operations.
pub type KvmResult<T> = Result<T, KvmError>;

/// KVM error type.
#[derive(Debug, Clone)]
pub struct KvmError {
    pub errno: i32,
    pub message: String,
}

impl std::fmt::Display for KvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KVM error ({}): {}", self.errno, self.message)
    }
}

impl std::error::Error for KvmError {}

impl From<std::io::Error> for KvmError {
    fn from(e: std::io::Error) -> Self {
        Self {
            errno: e.raw_os_error().unwrap_or(-1),
            message: e.to_string(),
        }
    }
}

impl From<nix::Error> for KvmError {
    fn from(e: nix::Error) -> Self {
        Self {
            errno: e as i32,
            message: e.to_string(),
        }
    }
}

/// Safe wrapper for KVM system handle (/dev/kvm).
pub struct KvmSystem {
    fd: OwnedFd,
}

impl KvmSystem {
    /// Opens /dev/kvm and creates a new KVM system handle.
    pub fn open() -> KvmResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map_err(|e| KvmError {
                errno: e.raw_os_error().unwrap_or(-1),
                message: format!("Failed to open /dev/kvm: {}", e),
            })?;

        let fd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };

        Ok(Self { fd })
    }

    /// Gets the KVM API version.
    pub fn api_version(&self) -> KvmResult<i32> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_GET_API_VERSION) };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(ret)
    }

    /// Checks if an extension is supported.
    pub fn check_extension(&self, extension: u32) -> KvmResult<i32> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_CHECK_EXTENSION,
                extension as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(ret)
    }

    /// Gets the size of the vCPU mmap region.
    pub fn vcpu_mmap_size(&self) -> KvmResult<usize> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE) };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(ret as usize)
    }

    /// Creates a new VM.
    pub fn create_vm(&self) -> KvmResult<KvmVmFd> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_CREATE_VM, 0) };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(KvmVmFd {
            fd: unsafe { OwnedFd::from_raw_fd(ret) },
        })
    }

    /// Returns the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Safe wrapper for KVM VM file descriptor.
pub struct KvmVmFd {
    fd: OwnedFd,
}

impl KvmVmFd {
    /// Sets a memory region for the VM.
    pub fn set_user_memory_region(&self, region: &KvmUserspaceMemoryRegion) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_SET_USER_MEMORY_REGION,
                region as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Creates a new vCPU.
    pub fn create_vcpu(&self, id: u32, mmap_size: usize) -> KvmResult<KvmVcpuFd> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_CREATE_VCPU, id as libc::c_ulong) };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }

        let fd = unsafe { OwnedFd::from_raw_fd(ret) };

        // mmap the kvm_run structure
        let run = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };

        if run == libc::MAP_FAILED {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }

        Ok(KvmVcpuFd {
            fd,
            kvm_run: run.cast(),
            mmap_size,
        })
    }

    /// Sets the TSS address (x86 only).
    #[cfg(target_arch = "x86_64")]
    pub fn set_tss_addr(&self, addr: u64) -> KvmResult<()> {
        let ret =
            unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_SET_TSS_ADDR, addr as libc::c_ulong) };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Sets the identity map address (x86 only).
    #[cfg(target_arch = "x86_64")]
    pub fn set_identity_map_addr(&self, addr: u64) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_SET_IDENTITY_MAP_ADDR,
                &addr as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Creates an in-kernel IRQ chip (x86 only).
    #[cfg(target_arch = "x86_64")]
    pub fn create_irqchip(&self) -> KvmResult<()> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_CREATE_IRQCHIP, 0) };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Creates a PIT2 (x86 only).
    #[cfg(target_arch = "x86_64")]
    pub fn create_pit2(&self, config: &KvmPitConfig) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_CREATE_PIT2,
                config as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Gets the preferred target for ARM64.
    #[cfg(target_arch = "aarch64")]
    pub fn get_preferred_target(&self) -> KvmResult<KvmVcpuInit> {
        let mut init = KvmVcpuInit::default();
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_ARM_PREFERRED_TARGET,
                &mut init as *mut _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(init)
    }

    /// Sets the IRQ line level.
    ///
    /// This is used to assert or deassert an IRQ line on the in-kernel irqchip.
    /// For edge-triggered interrupts, assert then deassert.
    /// For level-triggered interrupts, assert and keep asserted until acknowledged.
    ///
    /// # Arguments
    /// * `irq` - The GSI (Global System Interrupt) number
    /// * `level` - true to assert, false to deassert
    pub fn set_irq_line(&self, irq: u32, level: bool) -> KvmResult<()> {
        let irq_level = KvmIrqLevel {
            irq,
            level: if level { 1 } else { 0 },
        };
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_IRQ_LINE,
                &irq_level as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Registers an eventfd for IRQ injection (IRQFD).
    ///
    /// When the eventfd is written to, KVM will inject the specified GSI
    /// into the guest. This is the preferred method for high-performance
    /// interrupt delivery as it avoids kernel transitions.
    ///
    /// # Arguments
    /// * `fd` - The eventfd file descriptor
    /// * `gsi` - The GSI to inject
    /// * `resample_fd` - Optional eventfd for level-triggered IRQ resampling
    pub fn register_irqfd(&self, fd: RawFd, gsi: u32, resample_fd: Option<RawFd>) -> KvmResult<()> {
        let mut irqfd = KvmIrqfd {
            fd: fd as u32,
            gsi,
            flags: 0,
            resamplefd: 0,
            pad: [0; 16],
        };

        if let Some(resample) = resample_fd {
            irqfd.flags |= KVM_IRQFD_FLAG_RESAMPLE;
            irqfd.resamplefd = resample as u32;
        }

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_IRQFD,
                &irqfd as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Unregisters an eventfd for IRQ injection.
    pub fn unregister_irqfd(&self, fd: RawFd, gsi: u32) -> KvmResult<()> {
        let irqfd = KvmIrqfd {
            fd: fd as u32,
            gsi,
            flags: KVM_IRQFD_FLAG_DEASSIGN,
            resamplefd: 0,
            pad: [0; 16],
        };

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_IRQFD,
                &irqfd as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Registers an IOEVENTFD for MMIO writes.
    ///
    /// When a guest write occurs at the specified address, KVM will signal
    /// the eventfd instead of exiting to userspace. This is used for VirtIO
    /// queue notification.
    ///
    /// # Arguments
    /// * `addr` - The MMIO address to watch
    /// * `len` - The access size (1, 2, 4, or 8 bytes)
    /// * `fd` - The eventfd file descriptor to signal
    /// * `datamatch` - Optional: only trigger on matching data value
    pub fn register_ioeventfd(
        &self,
        addr: u64,
        len: u32,
        fd: RawFd,
        datamatch: Option<u64>,
    ) -> KvmResult<()> {
        let mut ioeventfd = KvmIoeventfd {
            addr,
            len,
            fd: fd as i32,
            flags: 0,
            datamatch: 0,
            pad: [0; 36],
        };

        if let Some(match_val) = datamatch {
            ioeventfd.datamatch = match_val;
            ioeventfd.flags |= KVM_IOEVENTFD_FLAG_DATAMATCH;
        }

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_IOEVENTFD,
                &ioeventfd as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Unregisters an IOEVENTFD.
    pub fn unregister_ioeventfd(&self, addr: u64, len: u32, fd: RawFd) -> KvmResult<()> {
        let ioeventfd = KvmIoeventfd {
            addr,
            len,
            fd: fd as i32,
            flags: KVM_IOEVENTFD_FLAG_DEASSIGN,
            datamatch: 0,
            pad: [0; 36],
        };

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_IOEVENTFD,
                &ioeventfd as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Enables dirty page logging for a memory slot.
    ///
    /// This updates the memory region to enable the `KVM_MEM_LOG_DIRTY_PAGES` flag.
    /// After enabling, dirty pages can be retrieved with `get_dirty_log`.
    ///
    /// # Arguments
    /// * `slot` - The memory slot ID
    /// * `guest_phys_addr` - Guest physical address of the region
    /// * `memory_size` - Size of the memory region
    /// * `userspace_addr` - Host virtual address of the memory
    pub fn enable_dirty_logging(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    ) -> KvmResult<()> {
        let region = KvmUserspaceMemoryRegion {
            slot,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
            guest_phys_addr,
            memory_size,
            userspace_addr,
        };

        self.set_user_memory_region(&region)
    }

    /// Disables dirty page logging for a memory slot.
    ///
    /// This updates the memory region to remove the `KVM_MEM_LOG_DIRTY_PAGES` flag.
    ///
    /// # Arguments
    /// * `slot` - The memory slot ID
    /// * `guest_phys_addr` - Guest physical address of the region
    /// * `memory_size` - Size of the memory region
    /// * `userspace_addr` - Host virtual address of the memory
    pub fn disable_dirty_logging(
        &self,
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    ) -> KvmResult<()> {
        let region = KvmUserspaceMemoryRegion {
            slot,
            flags: 0,
            guest_phys_addr,
            memory_size,
            userspace_addr,
        };

        self.set_user_memory_region(&region)
    }

    /// Gets the dirty page bitmap for a memory slot.
    ///
    /// The bitmap is a bit array where each bit represents one page.
    /// A bit set to 1 indicates the corresponding page was written to since
    /// the last call to `get_dirty_log`.
    ///
    /// **Important**: Calling this function clears the dirty log for the slot.
    ///
    /// # Arguments
    /// * `slot` - The memory slot ID
    /// * `memory_size` - Size of the memory region (used to determine bitmap size)
    /// * `page_size` - Page size (typically 4096 bytes)
    ///
    /// # Returns
    /// A vector of u64 values representing the dirty bitmap.
    /// Each bit corresponds to a page: bit 0 of word 0 is page 0, etc.
    pub fn get_dirty_log(
        &self,
        slot: u32,
        memory_size: u64,
        page_size: u64,
    ) -> KvmResult<Vec<u64>> {
        // Calculate the number of pages and bitmap size.
        let num_pages = (memory_size + page_size - 1) / page_size;
        let bitmap_size = ((num_pages + 63) / 64) as usize; // Round up to u64

        // Allocate and zero the bitmap buffer.
        let mut bitmap: Vec<u64> = vec![0; bitmap_size];

        let dirty_log = KvmDirtyLog {
            slot,
            padding: 0,
            dirty_bitmap: bitmap.as_mut_ptr(),
        };

        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_GET_DIRTY_LOG,
                &dirty_log as *const _ as libc::c_ulong,
            )
        };

        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }

        Ok(bitmap)
    }

    /// Returns the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Safe wrapper for KVM vCPU file descriptor.
pub struct KvmVcpuFd {
    fd: OwnedFd,
    kvm_run: *mut KvmRun,
    mmap_size: usize,
}

// Safety: The kvm_run pointer is only accessed through controlled methods.
unsafe impl Send for KvmVcpuFd {}

impl KvmVcpuFd {
    /// Runs the vCPU until a VM exit occurs.
    pub fn run(&self) -> KvmResult<()> {
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_RUN, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR is not an error, it just means we were interrupted
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(());
            }
            return Err(KvmError::from(err));
        }
        Ok(())
    }

    /// Gets the exit reason from the last run.
    pub fn exit_reason(&self) -> u32 {
        unsafe { (*self.kvm_run).exit_reason }
    }

    /// Gets the KVM run structure.
    ///
    /// # Safety
    ///
    /// The returned reference is only valid while the vCPU is not running.
    pub unsafe fn kvm_run(&self) -> &KvmRun {
        unsafe { &*self.kvm_run }
    }

    /// Gets the KVM run structure mutably.
    ///
    /// # Safety
    ///
    /// The returned reference is only valid while the vCPU is not running.
    pub unsafe fn kvm_run_mut(&self) -> &mut KvmRun {
        unsafe { &mut *self.kvm_run }
    }

    /// Gets the general purpose registers.
    pub fn get_regs(&self) -> KvmResult<KvmRegs> {
        let mut regs = KvmRegs::default();
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_GET_REGS,
                &mut regs as *mut _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(regs)
    }

    /// Sets the general purpose registers.
    pub fn set_regs(&self, regs: &KvmRegs) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_SET_REGS,
                regs as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Gets the special registers (x86 only).
    #[cfg(target_arch = "x86_64")]
    pub fn get_sregs(&self) -> KvmResult<KvmSregs> {
        let mut sregs = KvmSregs::default();
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_GET_SREGS,
                &mut sregs as *mut _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(sregs)
    }

    /// Sets the special registers (x86 only).
    #[cfg(target_arch = "x86_64")]
    pub fn set_sregs(&self, sregs: &KvmSregs) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_SET_SREGS,
                sregs as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Sets CPUID entries (x86 only).
    #[cfg(target_arch = "x86_64")]
    pub fn set_cpuid2(&self, cpuid: &KvmCpuid2) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_SET_CPUID2,
                cpuid as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Initializes the vCPU (ARM64 only).
    #[cfg(target_arch = "aarch64")]
    pub fn vcpu_init(&self, init: &KvmVcpuInit) -> KvmResult<()> {
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_ARM_VCPU_INIT,
                init as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Gets a single register (ARM64 only).
    #[cfg(target_arch = "aarch64")]
    pub fn get_one_reg(&self, reg_id: u64) -> KvmResult<u64> {
        let mut value: u64 = 0;
        let reg = KvmOneReg {
            id: reg_id,
            addr: &mut value as *mut u64 as u64,
        };
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_GET_ONE_REG,
                &reg as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(value)
    }

    /// Sets a single register (ARM64 only).
    #[cfg(target_arch = "aarch64")]
    pub fn set_one_reg(&self, reg_id: u64, value: u64) -> KvmResult<()> {
        let mut val = value;
        let reg = KvmOneReg {
            id: reg_id,
            addr: &mut val as *mut u64 as u64,
        };
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_SET_ONE_REG,
                &reg as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Sets the immediate_exit flag to cause the next KVM_RUN to return immediately.
    pub fn set_immediate_exit(&self, enable: bool) {
        unsafe {
            (*self.kvm_run).immediate_exit = if enable { 1 } else { 0 };
        }
    }

    /// Injects an external interrupt into the vCPU (x86 only).
    ///
    /// This is used to inject an interrupt directly into the vCPU.
    /// The vCPU must be in a state where it can receive interrupts
    /// (i.e., `ready_for_interrupt_injection` is true).
    ///
    /// # Arguments
    /// * `irq` - The interrupt vector (0-255)
    #[cfg(target_arch = "x86_64")]
    pub fn inject_interrupt(&self, irq: u32) -> KvmResult<()> {
        let interrupt = KvmInterrupt { irq };
        let ret = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                KVM_INTERRUPT,
                &interrupt as *const _ as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(KvmError::from(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Checks if the vCPU is ready for interrupt injection.
    ///
    /// Returns true if an interrupt can be injected via `inject_interrupt`.
    pub fn ready_for_interrupt(&self) -> bool {
        unsafe { (*self.kvm_run).ready_for_interrupt_injection != 0 }
    }

    /// Requests an interrupt window exit.
    ///
    /// When set, the next KVM_RUN will exit with KVM_EXIT_IRQ_WINDOW_OPEN
    /// when the vCPU becomes ready to receive interrupts.
    pub fn request_interrupt_window(&self, enable: bool) {
        unsafe {
            (*self.kvm_run).request_interrupt_window = if enable { 1 } else { 0 };
        }
    }

    /// Returns the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for KvmVcpuFd {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.kvm_run.cast(), self.mmap_size);
        }
    }
}

// ============================================================================
// Memory Allocation Helpers
// ============================================================================

/// Allocates guest memory using mmap.
pub fn allocate_memory(size: u64) -> KvmResult<*mut u8> {
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(KvmError::from(std::io::Error::last_os_error()));
    }

    // Zero the memory
    unsafe {
        libc::memset(ptr, 0, size as usize);
    }

    tracing::debug!("Allocated {}MB of guest memory", size / (1024 * 1024));

    Ok(ptr.cast::<u8>())
}

/// Frees guest memory.
pub fn free_memory(ptr: *mut u8, size: u64) {
    if !ptr.is_null() {
        unsafe {
            libc::munmap(ptr.cast(), size as usize);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_kvm_open() {
        let kvm = KvmSystem::open().expect("Failed to open /dev/kvm");
        let version = kvm.api_version().expect("Failed to get API version");
        println!("KVM API version: {}", version);
        assert_eq!(version, 12); // KVM API is stable at version 12
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_kvm_extensions() {
        let kvm = KvmSystem::open().expect("Failed to open /dev/kvm");

        let user_mem = kvm
            .check_extension(KVM_CAP_USER_MEMORY)
            .expect("Failed to check extension");
        println!("KVM_CAP_USER_MEMORY: {}", user_mem);
        assert!(user_mem > 0);

        let max_vcpus = kvm
            .check_extension(KVM_CAP_MAX_VCPUS)
            .expect("Failed to check extension");
        println!("KVM_CAP_MAX_VCPUS: {}", max_vcpus);
        assert!(max_vcpus > 0);
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_create_vm() {
        let kvm = KvmSystem::open().expect("Failed to open /dev/kvm");
        let vm = kvm.create_vm().expect("Failed to create VM");
        assert!(vm.as_raw_fd() >= 0);
    }

    #[test]
    fn test_allocate_memory() {
        let size = 16 * 1024 * 1024; // 16MB
        let ptr = allocate_memory(size).expect("Failed to allocate memory");
        assert!(!ptr.is_null());

        // Write and read back
        unsafe {
            *ptr = 42;
            assert_eq!(*ptr, 42);
        }

        free_memory(ptr, size);
    }
}
