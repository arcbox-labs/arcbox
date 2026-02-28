//! Common types used across the hypervisor crate.

use serde::{Deserialize, Serialize};

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioDeviceConfig {
    /// Device type.
    pub device_type: VirtioDeviceType,
    /// Device-specific configuration.
    pub config: Vec<u8>,
    /// Path to device (for block/fs devices).
    pub path: Option<String>,
    /// Whether the device is read-only.
    pub read_only: bool,
    /// Tag for filesystem devices.
    pub tag: Option<String>,
    /// File descriptor for file-handle-based network attachment.
    #[serde(skip)]
    pub net_fd: Option<i32>,
}

impl VirtioDeviceConfig {
    /// Creates a new block device configuration.
    pub fn block(path: impl Into<String>, read_only: bool) -> Self {
        Self {
            device_type: VirtioDeviceType::Block,
            config: Vec::new(),
            path: Some(path.into()),
            read_only,
            tag: None,
            net_fd: None,
        }
    }

    /// Creates a new network device configuration with NAT attachment.
    pub fn network() -> Self {
        Self {
            device_type: VirtioDeviceType::Net,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
        }
    }

    /// Creates a network device configuration with file-handle attachment.
    ///
    /// The VZ framework side uses one connected datagram socket file descriptor
    /// for bidirectional frame I/O.
    pub fn network_file_handle(fd: i32) -> Self {
        Self {
            device_type: VirtioDeviceType::Net,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: Some(fd),
        }
    }

    /// Creates a new console device configuration.
    pub fn console() -> Self {
        Self {
            device_type: VirtioDeviceType::Console,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
        }
    }

    /// Creates a new filesystem device configuration.
    pub fn filesystem(path: impl Into<String>, tag: impl Into<String>, read_only: bool) -> Self {
        Self {
            device_type: VirtioDeviceType::Fs,
            config: Vec::new(),
            path: Some(path.into()),
            read_only,
            tag: Some(tag.into()),
            net_fd: None,
        }
    }

    /// Creates a new vsock device configuration.
    pub fn vsock() -> Self {
        Self {
            device_type: VirtioDeviceType::Vsock,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
        }
    }

    /// Creates a new entropy device configuration.
    pub fn entropy() -> Self {
        Self {
            device_type: VirtioDeviceType::Rng,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
        }
    }
}

/// VirtIO device types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

// ============================================================================
// Memory Balloon Types
// ============================================================================

/// Memory balloon statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BalloonStats {
    /// Target memory size in bytes.
    ///
    /// This is the memory size the balloon is trying to achieve.
    pub target_bytes: u64,

    /// Current balloon size in bytes.
    ///
    /// This is how much memory the balloon has currently claimed.
    /// `actual_guest_memory = configured_memory - current_balloon_size`
    pub current_bytes: u64,

    /// Configured VM memory size in bytes.
    ///
    /// This is the maximum memory available to the guest when
    /// the balloon is fully deflated.
    pub configured_bytes: u64,
}

impl BalloonStats {
    /// Returns the effective memory available to the guest in bytes.
    ///
    /// This is `configured_bytes - current_bytes`.
    #[must_use]
    pub fn effective_memory(&self) -> u64 {
        self.configured_bytes.saturating_sub(self.current_bytes)
    }

    /// Returns the target memory as a percentage of configured memory.
    #[must_use]
    pub fn target_percent(&self) -> f64 {
        if self.configured_bytes == 0 {
            return 100.0;
        }
        (self.target_bytes as f64 / self.configured_bytes as f64) * 100.0
    }
}

impl VirtioDeviceConfig {
    /// Creates a new balloon device configuration.
    ///
    /// The balloon device allows dynamic memory management by inflating
    /// (reclaiming memory from guest) or deflating (returning memory to guest).
    #[must_use]
    pub fn balloon() -> Self {
        Self {
            device_type: VirtioDeviceType::Balloon,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
        }
    }
}

// ============================================================================
// Snapshot Types
// ============================================================================

/// ARM64 register state for snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Arm64Registers {
    /// General purpose registers X0-X30.
    pub x: [u64; 31],
    /// Stack pointer (SP).
    pub sp: u64,
    /// Program counter (PC).
    pub pc: u64,
    /// Processor state (PSTATE/CPSR).
    pub pstate: u64,
    /// Floating point control register.
    pub fpcr: u64,
    /// Floating point status register.
    pub fpsr: u64,
    /// Vector registers Q0-Q31 (128-bit each, stored as [u64; 2]).
    pub v: [[u64; 2]; 32],
}

/// vCPU snapshot state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuSnapshot {
    /// vCPU ID.
    pub id: u32,
    /// CPU architecture.
    pub arch: CpuArch,
    /// x86_64 registers (if applicable).
    pub x86_regs: Option<Registers>,
    /// ARM64 registers (if applicable).
    pub arm64_regs: Option<Arm64Registers>,
    /// Additional architecture-specific state (opaque bytes).
    pub extra_state: Vec<u8>,
}

impl VcpuSnapshot {
    /// Creates a new x86_64 vCPU snapshot.
    #[must_use]
    pub fn new_x86(id: u32, regs: Registers) -> Self {
        Self {
            id,
            arch: CpuArch::X86_64,
            x86_regs: Some(regs),
            arm64_regs: None,
            extra_state: Vec::new(),
        }
    }

    /// Creates a new ARM64 vCPU snapshot.
    #[must_use]
    pub fn new_arm64(id: u32, regs: Arm64Registers) -> Self {
        Self {
            id,
            arch: CpuArch::Aarch64,
            x86_regs: None,
            arm64_regs: Some(regs),
            extra_state: Vec::new(),
        }
    }
}

/// Device snapshot state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    /// Device type.
    pub device_type: VirtioDeviceType,
    /// Device name/identifier.
    pub name: String,
    /// Device-specific state (serialized).
    pub state: Vec<u8>,
}

/// Memory region info for snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionSnapshot {
    /// Guest physical address start.
    pub guest_addr: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Whether this region is read-only.
    pub read_only: bool,
    /// Offset in the memory dump file.
    pub file_offset: u64,
}

/// Dirty page tracking info.
#[derive(Debug, Clone)]
pub struct DirtyPageInfo {
    /// Guest physical address of the page.
    pub guest_addr: u64,
    /// Page size (usually 4KB).
    pub size: u64,
}

/// Full VM snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSnapshot {
    /// Snapshot format version.
    pub version: u32,
    /// CPU architecture.
    pub arch: CpuArch,
    /// vCPU states.
    pub vcpus: Vec<VcpuSnapshot>,
    /// Device states.
    pub devices: Vec<DeviceSnapshot>,
    /// Memory region info.
    pub memory_regions: Vec<MemoryRegionSnapshot>,
    /// Total memory size.
    pub total_memory: u64,
    /// Whether memory is compressed.
    pub compressed: bool,
    /// Compression algorithm (if compressed).
    pub compression: Option<String>,
    /// Parent snapshot ID (for incremental).
    pub parent_id: Option<String>,
}
