use serde::{Deserialize, Serialize};

use crate::error::{Result, VmmError};

// =============================================================================
// Rate-limiter primitives
// =============================================================================

/// A token-bucket rate-limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucketSpec {
    /// Bucket capacity in bytes (bandwidth) or operations (ops).
    pub size: i64,
    /// Refill interval in milliseconds.
    pub refill_time_ms: i64,
    /// Optional one-time burst allowance.
    pub one_time_burst: Option<i64>,
}

/// Combined bandwidth + ops rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSpec {
    pub bandwidth: Option<TokenBucketSpec>,
    pub ops: Option<TokenBucketSpec>,
}

impl From<TokenBucketSpec> for fc_sdk::types::TokenBucket {
    fn from(s: TokenBucketSpec) -> Self {
        fc_sdk::types::TokenBucket {
            size: s.size,
            refill_time: s.refill_time_ms,
            one_time_burst: s.one_time_burst,
        }
    }
}

impl From<RateLimitSpec> for fc_sdk::types::RateLimiter {
    fn from(s: RateLimitSpec) -> Self {
        fc_sdk::types::RateLimiter {
            bandwidth: s.bandwidth.map(Into::into),
            ops: s.ops.map(Into::into),
        }
    }
}

// =============================================================================
// Drive / IO enums
// =============================================================================

/// Block device IO engine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IoEngine {
    #[default]
    Sync,
    Async,
}

/// Block device cache mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CacheType {
    #[default]
    Unsafe,
    Writeback,
}

impl From<IoEngine> for fc_sdk::types::DriveIoEngine {
    fn from(e: IoEngine) -> Self {
        match e {
            IoEngine::Sync => fc_sdk::types::DriveIoEngine::Sync,
            IoEngine::Async => fc_sdk::types::DriveIoEngine::Async,
        }
    }
}

impl From<CacheType> for fc_sdk::types::DriveCacheType {
    fn from(c: CacheType) -> Self {
        match c {
            CacheType::Unsafe => fc_sdk::types::DriveCacheType::Unsafe,
            CacheType::Writeback => fc_sdk::types::DriveCacheType::Writeback,
        }
    }
}

// =============================================================================
// CPU template
// =============================================================================

/// CPU template to apply for cross-host snapshot compatibility.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CpuTemplateSpec {
    C3,
    T2,
    T2S,
    T2CL,
    T2A,
    V1N1,
}

impl From<CpuTemplateSpec> for fc_sdk::types::CpuTemplate {
    fn from(t: CpuTemplateSpec) -> Self {
        match t {
            CpuTemplateSpec::C3 => fc_sdk::types::CpuTemplate::C3,
            CpuTemplateSpec::T2 => fc_sdk::types::CpuTemplate::T2,
            CpuTemplateSpec::T2S => fc_sdk::types::CpuTemplate::T2s,
            CpuTemplateSpec::T2CL => fc_sdk::types::CpuTemplate::T2cl,
            CpuTemplateSpec::T2A => fc_sdk::types::CpuTemplate::T2a,
            CpuTemplateSpec::V1N1 => fc_sdk::types::CpuTemplate::V1n1,
        }
    }
}

// =============================================================================
// Huge pages
// =============================================================================

/// Huge-page backing for guest memory.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HugePagesSpec {
    /// Use 2 MiB huge pages.
    #[serde(rename = "2M")]
    TwoMB,
}

impl From<HugePagesSpec> for fc_sdk::types::MachineConfigurationHugePages {
    fn from(h: HugePagesSpec) -> Self {
        match h {
            HugePagesSpec::TwoMB => fc_sdk::types::MachineConfigurationHugePages::X2m,
        }
    }
}

// =============================================================================
// Extra drive spec
// =============================================================================

/// Configuration for an additional (non-root) block device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveSpec {
    /// Unique drive identifier within the VM.
    pub drive_id: String,
    /// Absolute path to the block device image on the host.
    pub path: String,
    /// Mount read-only.
    pub readonly: bool,
    /// IO engine to use.
    #[serde(default)]
    pub io_engine: IoEngine,
    /// Cache mode.
    #[serde(default)]
    pub cache_type: CacheType,
    /// Optional GPT partition UUID to pass to the guest.
    pub partuuid: Option<String>,
    /// Optional throughput / IOPS rate limiter.
    pub rate_limit: Option<RateLimitSpec>,
}

// =============================================================================
// Balloon device
// =============================================================================

/// Memory balloon device configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonSpec {
    /// Initial target balloon size in MiB.
    pub amount_mib: i64,
    /// Deflate the balloon when the guest runs out of memory.
    pub deflate_on_oom: bool,
    /// Interval at which balloon statistics are polled (seconds).
    pub stats_polling_interval_s: Option<i64>,
    /// Enable free-page hinting (virtio-balloon extension).
    pub free_page_hinting: Option<bool>,
    /// Enable free-page reporting (virtio-balloon extension).
    pub free_page_reporting: Option<bool>,
}

// =============================================================================
// Vsock device
// =============================================================================

/// Virtio-vsock device configuration.
///
/// The UDS path is managed by the VMM at `{vm_dir}/vsock.sock`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockSpec {
    /// Guest CID (must be ≥ 3).
    pub guest_cid: i64,
}

// =============================================================================
// Memory hotplug
// =============================================================================

/// Virtio-mem hotpluggable memory configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryHotplugSpec {
    /// Maximum hotpluggable memory in MiB.
    pub total_size_mib: i64,
    /// Each slot size in MiB (default: 128).
    pub slot_size_mib: Option<i64>,
    /// Minimum allocation unit in MiB (default: 2).
    pub block_size_mib: Option<i64>,
}

// =============================================================================
// MMDS
// =============================================================================

/// MMDS API version.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub enum MmdsVersionSpec {
    #[default]
    V1,
    V2,
}

impl From<MmdsVersionSpec> for fc_sdk::types::MmdsConfigVersion {
    fn from(v: MmdsVersionSpec) -> Self {
        match v {
            MmdsVersionSpec::V1 => fc_sdk::types::MmdsConfigVersion::V1,
            MmdsVersionSpec::V2 => fc_sdk::types::MmdsConfigVersion::V2,
        }
    }
}

/// Microvm Metadata Service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdsSpec {
    /// Network interfaces that can access the MMDS endpoint.
    pub network_interfaces: Vec<String>,
    /// MMDS API version.
    #[serde(default)]
    pub version: MmdsVersionSpec,
    /// Override the default MMDS IP address (`169.254.169.254`).
    pub ipv4_address: Option<String>,
    /// Enable EC2 IMDS compatibility mode.
    #[serde(default)]
    pub imds_compat: bool,
    /// Initial key-value data to pre-populate the MMDS data store.
    pub initial_data: Option<serde_json::Map<String, serde_json::Value>>,
}

// =============================================================================
// Jailer configuration
// =============================================================================

/// Configuration for running Firecracker under the Jailer sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailerConfig {
    /// Path to the `jailer` binary.
    pub binary: String,
    /// UID the Firecracker process runs as inside the jail.
    pub uid: u32,
    /// GID the Firecracker process runs as inside the jail.
    pub gid: u32,
    /// Base chroot directory (default: `/srv/jailer`).
    pub chroot_base_dir: Option<String>,
    /// Network namespace path (e.g., `/var/run/netns/myns`).
    pub netns: Option<String>,
    /// Create a new PID namespace.
    #[serde(default)]
    pub new_pid_ns: bool,
    /// cgroup version (`"1"` or `"2"`).
    pub cgroup_version: Option<String>,
    /// Parent cgroup path.
    pub parent_cgroup: Option<String>,
    /// Resource limits in `rlimit` format (e.g., `"fsize=2048"`).
    #[serde(default)]
    pub resource_limits: Vec<String>,
}

// =============================================================================
// Top-level VMM configuration
// =============================================================================

/// Top-level VMM daemon configuration (maps to `config.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmConfig {
    pub firecracker: FirecrackerConfig,
    pub network: NetworkConfig,
    pub grpc: GrpcConfig,
    pub defaults: DefaultVmConfig,
}

/// Firecracker binary paths, data directory, and process-level options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerConfig {
    /// Path to the `firecracker` binary.
    pub binary: String,
    /// Jailer configuration (absent = run Firecracker directly without sandbox).
    #[serde(default)]
    pub jailer: Option<JailerConfig>,
    /// Root data directory (VMs, snapshots, images).
    pub data_dir: String,

    // --- Process-level options ---
    /// Firecracker log level (`Error`, `Warning`, `Info`, `Debug`, `Trace`).
    #[serde(default)]
    pub log_level: Option<String>,
    /// Disable seccomp filtering (reduces isolation — use only for testing).
    #[serde(default)]
    pub no_seccomp: bool,
    /// Path to a custom seccomp filter BPF file.
    #[serde(default)]
    pub seccomp_filter: Option<String>,
    /// Maximum HTTP API payload size in bytes.
    #[serde(default)]
    pub http_api_max_payload_size: Option<usize>,
    /// MMDS in-memory store size limit in bytes.
    #[serde(default)]
    pub mmds_size_limit: Option<usize>,
    /// Seconds to wait for the Firecracker socket to become available (default: 5).
    #[serde(default)]
    pub socket_timeout_secs: Option<u64>,
}

/// Network bridge and IP-pool settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Linux bridge interface name for VM uplinks.
    pub bridge: String,
    /// IP CIDR pool from which guest addresses are allocated.
    pub cidr: String,
    /// Default gateway advertised to guests.
    pub gateway: String,
    /// DNS servers advertised to guests.
    pub dns: Vec<String>,
}

/// gRPC server transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Unix-domain socket path (primary transport).
    pub unix_socket: String,
    /// Optional TCP address (`host:port`). Empty = disabled.
    pub tcp_addr: String,
}

/// Default VM resource values used when a create request omits a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultVmConfig {
    pub vcpus: u64,
    pub memory_mib: u64,
    pub kernel: String,
    pub rootfs: String,
    pub boot_args: String,
}

impl Default for VmmConfig {
    fn default() -> Self {
        Self {
            firecracker: FirecrackerConfig {
                binary: "/usr/bin/firecracker".into(),
                jailer: None,
                data_dir: "/var/lib/firecracker-vmm".into(),
                log_level: None,
                no_seccomp: false,
                seccomp_filter: None,
                http_api_max_payload_size: None,
                mmds_size_limit: None,
                socket_timeout_secs: None,
            },
            network: NetworkConfig {
                bridge: "fcvmm0".into(),
                cidr: "172.20.0.0/16".into(),
                gateway: "172.20.0.1".into(),
                dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            },
            grpc: GrpcConfig {
                unix_socket: "/run/firecracker-vmm/vmm.sock".into(),
                tcp_addr: String::new(),
            },
            defaults: DefaultVmConfig {
                vcpus: 1,
                memory_mib: 512,
                kernel: "/var/lib/firecracker-vmm/kernels/vmlinux".into(),
                rootfs: "/var/lib/firecracker-vmm/images/ubuntu-22.04.ext4".into(),
                boot_args: "console=ttyS0 reboot=k panic=1 pci=off".into(),
            },
        }
    }
}

impl VmmConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| VmmError::Config(e.to_string()))?;
        toml::from_str(&content).map_err(|e| VmmError::Config(e.to_string()))
    }
}

// =============================================================================
// VmSpec — per-VM creation parameters
// =============================================================================

/// Full VM specification supplied at creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSpec {
    /// Human-readable name (must be unique within the manager).
    pub name: String,

    // --- Basic resources ---
    /// Number of virtual CPUs (0 = use daemon default).
    pub vcpus: u64,
    /// RAM size in mebibytes (0 = use daemon default).
    pub memory_mib: u64,

    // --- Boot ---
    /// Absolute path to the kernel image (`vmlinux`). Empty = use daemon default.
    pub kernel: String,
    /// Kernel command-line arguments. Empty = use daemon default.
    pub boot_args: String,
    /// Optional path to an initrd image.
    pub initrd: Option<String>,

    // --- Machine configuration ---
    /// Enable simultaneous multithreading (hyperthreading).
    pub smt: bool,
    /// Track dirty pages (required for diff snapshots).
    pub track_dirty_pages: bool,
    /// Huge-page backing for guest RAM.
    pub huge_pages: Option<HugePagesSpec>,
    /// CPU model template for cross-host snapshot compatibility.
    pub cpu_template: Option<CpuTemplateSpec>,

    // --- Root drive ---
    /// Absolute path to the root filesystem image. Empty = use daemon default.
    pub rootfs: String,
    /// Mount the root drive read-only.
    pub root_readonly: bool,
    /// IO engine for the root drive.
    #[serde(default)]
    pub root_io_engine: IoEngine,
    /// Cache mode for the root drive.
    #[serde(default)]
    pub root_cache_type: CacheType,
    /// GPT partition UUID to pass to the guest kernel.
    pub root_partuuid: Option<String>,
    /// Rate limiter for the root drive.
    pub root_rate_limit: Option<RateLimitSpec>,

    // --- Additional block devices ---
    /// Extra drives attached to the VM (non-root).
    #[serde(default)]
    pub extra_drives: Vec<DriveSpec>,

    // --- Network ---
    /// Receive rate limiter for the primary network interface.
    pub net_rx_rate_limit: Option<RateLimitSpec>,
    /// Transmit rate limiter for the primary network interface.
    pub net_tx_rate_limit: Option<RateLimitSpec>,

    // --- Optional devices ---
    /// Memory balloon device. Enables ballooning when set.
    pub balloon: Option<BalloonSpec>,
    /// Virtio-vsock device. Enables host↔guest socket communication when set.
    pub vsock: Option<VsockSpec>,
    /// Attach a virtio-rng entropy device.
    #[serde(default)]
    pub entropy_device: bool,
    /// Redirect serial console output to this host file path.
    pub serial_out: Option<String>,
    /// Virtio-mem hotpluggable memory region.
    pub memory_hotplug: Option<MemoryHotplugSpec>,
    /// Microvm Metadata Service (MMDS) configuration.
    pub mmds: Option<MmdsSpec>,

    // --- Provisioning helpers ---
    /// Disk pre-allocation size in bytes (informational; not sent to Firecracker).
    pub disk_size: Option<u64>,
    /// SSH public key injected via MMDS or cloud-init.
    pub ssh_public_key: Option<String>,
}

impl Default for VmSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            vcpus: 0,
            memory_mib: 0,
            kernel: String::new(),
            boot_args: String::new(),
            initrd: None,
            smt: false,
            track_dirty_pages: false,
            huge_pages: None,
            cpu_template: None,
            rootfs: String::new(),
            root_readonly: false,
            root_io_engine: IoEngine::Sync,
            root_cache_type: CacheType::Unsafe,
            root_partuuid: None,
            root_rate_limit: None,
            extra_drives: Vec::new(),
            net_rx_rate_limit: None,
            net_tx_rate_limit: None,
            balloon: None,
            vsock: None,
            entropy_device: false,
            serial_out: None,
            memory_hotplug: None,
            mmds: None,
            disk_size: None,
            ssh_public_key: None,
        }
    }
}

// =============================================================================
// Snapshot types
// =============================================================================

/// Snapshot type — mirrors Firecracker terminology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotType {
    /// Capture full memory + VM state.
    Full,
    /// Capture only dirty pages since the last snapshot.
    Diff,
}

/// Parameters for the `snapshot_vm` manager method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Optional human-readable label for the snapshot.
    pub name: Option<String>,
    pub snapshot_type: SnapshotType,
}

/// Parameters for the `restore_vm` manager method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreSpec {
    /// VM name to assign after restore.
    pub name: String,
    /// Path to the snapshot directory (must contain `vmstate` and optionally `mem`).
    pub snapshot_dir: String,
    /// Override the network configuration (e.g., assign a fresh TAP interface).
    pub network_override: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_sane_values() {
        let cfg = VmmConfig::default();
        assert_eq!(cfg.defaults.vcpus, 1);
        assert_eq!(cfg.defaults.memory_mib, 512);
        assert!(cfg.defaults.boot_args.contains("console=ttyS0"));
        assert!(!cfg.network.cidr.is_empty());
        assert!(!cfg.firecracker.binary.is_empty());
    }

    #[test]
    fn test_vmm_config_json_roundtrip() {
        let cfg = VmmConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: VmmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.defaults.vcpus, cfg.defaults.vcpus);
        assert_eq!(decoded.defaults.memory_mib, cfg.defaults.memory_mib);
        assert_eq!(decoded.network.cidr, cfg.network.cidr);
        assert_eq!(decoded.network.gateway, cfg.network.gateway);
    }

    #[test]
    fn test_vm_spec_default_is_empty() {
        let spec = VmSpec::default();
        assert!(spec.name.is_empty());
        assert!(spec.kernel.is_empty());
        assert!(spec.rootfs.is_empty());
        assert_eq!(spec.vcpus, 0);
        assert_eq!(spec.memory_mib, 0);
        assert!(!spec.smt);
        assert!(!spec.track_dirty_pages);
    }

    #[test]
    fn test_from_file_missing_returns_config_error() {
        let result = VmmConfig::from_file("/nonexistent/arcbox-test-config.toml");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::VmmError::Config(_)
        ));
    }
}
