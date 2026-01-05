//! Common types used across the hypervisor crate.

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuArch {
    /// x86_64 / AMD64
    X86_64,
    /// ARM64 / AArch64
    Aarch64,
}

impl CpuArch {
    /// Returns the native CPU architecture of the current system.
    #[must_use]
    pub fn native() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            compile_error!("Unsupported CPU architecture")
        }
    }
}

/// Platform capabilities reported by the hypervisor.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    /// Supported CPU architectures.
    pub supported_archs: Vec<CpuArch>,
    /// Maximum number of vCPUs per VM.
    pub max_vcpus: u32,
    /// Maximum memory size in bytes.
    pub max_memory: u64,
    /// Whether nested virtualization is supported.
    pub nested_virt: bool,
    /// Whether Rosetta 2 translation is available (macOS only).
    pub rosetta: bool,
}

impl Default for PlatformCapabilities {
    fn default() -> Self {
        Self {
            supported_archs: vec![CpuArch::native()],
            max_vcpus: 1,
            max_memory: 1024 * 1024 * 1024, // 1GB default
            nested_virt: false,
            rosetta: false,
        }
    }
}

/// CPU register state.
#[derive(Debug, Clone, Default)]
pub struct Registers {
    // General purpose registers (x86_64)
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

    // Instruction pointer and flags
    pub rip: u64,
    pub rflags: u64,
}

/// Reason for vCPU exit.
#[derive(Debug, Clone)]
pub enum VcpuExit {
    /// VM halted.
    Halt,
    /// I/O port access.
    IoOut {
        port: u16,
        size: u8,
        data: u64,
    },
    IoIn {
        port: u16,
        size: u8,
    },
    /// Memory-mapped I/O.
    MmioRead {
        addr: u64,
        size: u8,
    },
    MmioWrite {
        addr: u64,
        size: u8,
        data: u64,
    },
    /// Hypercall.
    Hypercall {
        nr: u64,
        args: [u64; 6],
    },
    /// System reset requested.
    SystemReset,
    /// Shutdown requested.
    Shutdown,
    /// Debug exception.
    Debug,
    /// Unknown exit reason.
    Unknown(i32),
}

/// VirtIO device configuration for attaching to a VM.
#[derive(Debug, Clone)]
pub struct VirtioDeviceConfig {
    /// Device type.
    pub device_type: VirtioDeviceType,
    /// Device-specific configuration.
    pub config: Vec<u8>,
}

/// VirtIO device types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioDeviceType {
    /// Block device.
    Block,
    /// Network device.
    Net,
    /// Console device.
    Console,
    /// Filesystem (9p/virtiofs).
    Fs,
    /// Socket device.
    Vsock,
    /// Entropy source.
    Rng,
    /// Balloon device.
    Balloon,
    /// GPU device.
    Gpu,
}
