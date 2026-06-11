//! Common types used across the hypervisor crate.

use serde::{Deserialize, Serialize};

/// Returns the effective memory limit for the host process in bytes.
///
/// On macOS this queries `hw.memsize` via `sysctlbyname`.
/// On Linux this returns `min(sysinfo.totalram, cgroup_memory_limit)` so
/// that defaults are sensible inside containers, CI runners, or systemd
/// units with `MemoryMax`.
///
/// Returns 0 if the query fails (should never happen on supported platforms).
#[must_use]
pub fn host_memory_size() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut size: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: `sysctlbyname` writes at most `len` bytes into `size`,
        // which is a correctly-sized `u64` buffer we own.
        let ret = unsafe {
            libc::sysctlbyname(
                c"hw.memsize".as_ptr(),
                std::ptr::addr_of_mut!(size).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret == 0 { size } else { 0 }
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: `info` is zero-initialized and we pass a valid pointer.
        // `sysinfo(2)` only writes to the provided struct; fields are
        // plain integers that are valid for any bit pattern.
        let physical = unsafe {
            let mut info: libc::sysinfo = std::mem::zeroed();
            if libc::sysinfo(&mut info) == 0 {
                info.totalram * u64::from(info.mem_unit)
            } else {
                return 0;
            }
        };

        // Respect cgroup memory limits so defaults are sensible inside
        // containers, CI runners, or systemd units with MemoryMax.
        let cgroup = cgroup_memory_limit();
        if cgroup > 0 && cgroup < physical {
            cgroup
        } else {
            physical
        }
    }
}

/// Reads the cgroup memory limit (bytes) for this process.
///
/// Resolves the actual cgroup path via `/proc/self/cgroup`, then reads
/// `memory.max` (v2) or `memory.limit_in_bytes` (v1) from the correct
/// directory. Falls back to root cgroup paths if resolution fails.
/// Returns 0 if no limit is set or the files cannot be read.
#[cfg(target_os = "linux")]
fn cgroup_memory_limit() -> u64 {
    // Try cgroup v2 first, then v1.
    if let Some(v) = cgroup_v2_memory_limit() {
        return v;
    }
    if let Some(v) = cgroup_v1_memory_limit() {
        return v;
    }
    0
}

/// Reads memory.max from the process's cgroup v2 directory.
#[cfg(target_os = "linux")]
fn cgroup_v2_memory_limit() -> Option<u64> {
    // Resolve current cgroup path from /proc/self/cgroup.
    // cgroup v2 has a single "0::" line.
    let cgroup_path = std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find(|l| l.starts_with("0::"))
        .map(|l| l.strip_prefix("0::").unwrap_or("/").to_string())?;

    // Try the process's own cgroup directory first, fall back to root.
    let paths = [
        format!("/sys/fs/cgroup{cgroup_path}/memory.max"),
        "/sys/fs/cgroup/memory.max".to_string(),
    ];
    for path in &paths {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim();
            if s != "max" {
                if let Ok(v) = s.parse::<u64>() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Reads memory.limit_in_bytes from the process's cgroup v1 memory controller.
#[cfg(target_os = "linux")]
fn cgroup_v1_memory_limit() -> Option<u64> {
    // Find the memory controller entry in /proc/self/cgroup.
    // v1 lines look like "N:memory:/path".
    let cgroup_path = std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|l| {
            let parts: Vec<&str> = l.splitn(3, ':').collect();
            if parts.len() == 3 && parts[1].split(',').any(|c| c == "memory") {
                Some(parts[2].to_string())
            } else {
                None
            }
        })?;

    let paths = [
        format!("/sys/fs/cgroup/memory{cgroup_path}/memory.limit_in_bytes"),
        "/sys/fs/cgroup/memory/memory.limit_in_bytes".to_string(),
    ];
    for path in &paths {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim();
            if let Ok(v) = s.parse::<u64>() {
                // Kernel sets this to a huge sentinel (PAGE_COUNTER_MAX)
                // when there is no limit; ignore values above 2^62.
                if v < (1 << 62) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Returns a sensible default VM memory size based on host physical memory.
///
/// The default is half of host RAM, clamped to `[512 MB, 16 GB]` and
/// rounded down to a 1 MiB boundary (KVM and Virtualization.framework
/// both require page-aligned memory sizes).
/// Falls back to 4 GB if host memory detection fails.
#[must_use]
pub fn default_vm_memory_size() -> u64 {
    const MIN_DEFAULT: u64 = 512 * 1024 * 1024; // 512 MB
    const MAX_DEFAULT: u64 = 16 * 1024 * 1024 * 1024; // 16 GB
    const FALLBACK: u64 = 4 * 1024 * 1024 * 1024; // 4 GB
    const MIB: u64 = 1024 * 1024;

    let host = host_memory_size();
    if host == 0 {
        return FALLBACK;
    }

    let size = (host / 2).clamp(MIN_DEFAULT, MAX_DEFAULT);
    // Round down to 1 MiB boundary.
    size & !(MIB - 1)
}

/// Returns a sensible default VM vCPU count: the host's logical core count.
///
/// Falls back to 4 if host CPU detection fails.
#[must_use]
pub fn default_vm_cpu_count() -> u32 {
    std::thread::available_parallelism().map_or(4, |n| u32::try_from(n.get()).unwrap_or(u32::MAX))
}

/// Emits a warning if `memory_size` exceeds 50% of host RAM.
///
/// Shared by Darwin and KVM `validate_config()` to keep the threshold
/// and message consistent.
pub fn warn_memory_exceeds_host_half(memory_size: u64) {
    let host_mem = host_memory_size();
    if host_mem > 0 && memory_size > host_mem / 2 {
        tracing::warn!(
            "VM memory {}MB exceeds 50% of host RAM ({}MB total) — host may experience memory pressure",
            memory_size / (1024 * 1024),
            host_mem / (1024 * 1024),
        );
    }
}

/// CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CpuArch {
    /// `x86_64` / AMD64
    X86_64,
    /// ARM64 / `AArch64`
    Aarch64,
}

impl CpuArch {
    /// Returns the native CPU architecture of the current system.
    #[must_use]
    pub const fn native() -> Self {
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

/// `VirtIO` device configuration for attaching to a VM.
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
    /// Optional MAC address for network devices.
    pub mac_address: Option<String>,
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
            mac_address: None,
        }
    }

    /// Creates a new network device configuration with NAT attachment.
    #[must_use]
    pub const fn network() -> Self {
        Self {
            device_type: VirtioDeviceType::Net,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
            mac_address: None,
        }
    }

    /// Creates a new network device configuration with NAT attachment and an explicit MAC address.
    pub fn network_with_mac(mac_address: impl Into<String>) -> Self {
        Self {
            device_type: VirtioDeviceType::Net,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
            mac_address: Some(mac_address.into()),
        }
    }

    /// Creates a network device configuration with file-handle attachment.
    ///
    /// The VZ framework side uses one connected datagram socket file descriptor
    /// for bidirectional frame I/O.
    #[must_use]
    pub const fn network_file_handle(fd: i32) -> Self {
        Self {
            device_type: VirtioDeviceType::Net,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: Some(fd),
            mac_address: None,
        }
    }

    /// Creates a network device configuration with file-handle attachment and
    /// an explicit MAC address.
    ///
    /// Use this when the MAC must match an external interface (e.g. vmnet) so
    /// that bridge FDB lookups resolve correctly.
    pub fn network_file_handle_with_mac(fd: i32, mac_address: impl Into<String>) -> Self {
        Self {
            device_type: VirtioDeviceType::Net,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: Some(fd),
            mac_address: Some(mac_address.into()),
        }
    }

    /// Creates a new console device configuration.
    #[must_use]
    pub const fn console() -> Self {
        Self {
            device_type: VirtioDeviceType::Console,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
            mac_address: None,
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
            mac_address: None,
        }
    }

    /// Creates a new vsock device configuration.
    #[must_use]
    pub const fn vsock() -> Self {
        Self {
            device_type: VirtioDeviceType::Vsock,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
            mac_address: None,
        }
    }

    /// Creates a new entropy device configuration.
    #[must_use]
    pub const fn entropy() -> Self {
        Self {
            device_type: VirtioDeviceType::Rng,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
            mac_address: None,
        }
    }
}

/// `VirtIO` device types.
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
    pub const fn effective_memory(&self) -> u64 {
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
    pub const fn balloon() -> Self {
        Self {
            device_type: VirtioDeviceType::Balloon,
            config: Vec::new(),
            path: None,
            read_only: false,
            tag: None,
            net_fd: None,
            mac_address: None,
        }
    }
}

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
    /// `x86_64` registers (if applicable).
    pub x86_regs: Option<Registers>,
    /// ARM64 registers (if applicable).
    pub arm64_regs: Option<Arm64Registers>,
    /// Additional architecture-specific state (opaque bytes).
    pub extra_state: Vec<u8>,
}

impl VcpuSnapshot {
    /// Creates a new `x86_64` vCPU snapshot.
    #[must_use]
    pub const fn new_x86(id: u32, regs: Registers) -> Self {
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
    pub const fn new_arm64(id: u32, regs: Arm64Registers) -> Self {
        Self {
            id,
            arch: CpuArch::Aarch64,
            x86_regs: None,
            arm64_regs: Some(regs),
            extra_state: Vec::new(),
        }
    }

    /// Returns `true` if this snapshot contains only default (zeroed) register
    /// state, i.e. it was created as a placeholder and does not represent real
    /// captured vCPU registers.
    #[must_use]
    pub fn is_placeholder(&self) -> bool {
        match (&self.x86_regs, &self.arm64_regs) {
            (Some(regs), _) => regs.rip == 0 && regs.rsp == 0 && regs.rflags == 0,
            (_, Some(regs)) => regs.pc == 0 && regs.sp == 0 && regs.pstate == 0,
            (None, None) => true,
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
