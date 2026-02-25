use serde::{Deserialize, Serialize};

use crate::error::{Result, VmmError};

/// Top-level VMM daemon configuration (maps to `config.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmConfig {
    pub firecracker: FirecrackerConfig,
    pub network: NetworkConfig,
    pub grpc: GrpcConfig,
    pub defaults: DefaultVmConfig,
}

/// Firecracker binary paths and data directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerConfig {
    /// Path to the `firecracker` binary.
    pub binary: String,
    /// Path to the `jailer` binary (empty = no jailer).
    pub jailer: String,
    /// Root data directory (VMs, snapshots, images).
    pub data_dir: String,
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
                jailer: String::new(),
                data_dir: "/var/lib/firecracker-vmm".into(),
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
        let content =
            std::fs::read_to_string(path).map_err(|e| VmmError::Config(e.to_string()))?;
        toml::from_str(&content).map_err(|e| VmmError::Config(e.to_string()))
    }
}

/// Full VM specification supplied at creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSpec {
    /// Human-readable name (must be unique within the manager).
    pub name: String,
    /// Number of virtual CPUs.
    pub vcpus: u64,
    /// RAM size in mebibytes.
    pub memory_mib: u64,
    /// Absolute path to the kernel image (`vmlinux`).
    pub kernel: String,
    /// Absolute path to the root filesystem image.
    pub rootfs: String,
    /// Kernel command-line arguments.
    pub boot_args: String,
    /// Optional disk size in bytes (for image pre-allocation).
    pub disk_size: Option<u64>,
    /// SSH public key injected via MMDS or cloud-init.
    pub ssh_public_key: Option<String>,
}

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
