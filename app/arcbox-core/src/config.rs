//! Configuration management.
//!
//! `ArcBox` configuration is loaded from multiple sources with the following priority:
//!
//! 1. Environment variables (ARCBOX_*)
//! 2. Configuration file (~/.config/arcbox/config.toml)
//! 3. Default values
//!
//! ## Example Configuration File
//!
//! ```toml
//! # ArcBox configuration file
//! data_dir = "~/.arcbox"
//!
//! [vm]
//! cpus = 4
//! memory_mb = 4096
//!
//! [machine]
//! disk_gb = 50
//! default_distro = "ubuntu"
//!
//! [network]
//! subnet = "192.168.64.0/24"
//! dns = ["8.8.8.8", "8.8.4.4"]
//!
//! [docker]
//! socket_path = "~/.arcbox/docker.sock"
//!
//! [container]
//! guest_docker_vsock_port = 2375
//!
//! [logging]
//! level = "info"
//! ```

use arcbox_constants::ports::DOCKER_API_VSOCK_PORT;
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// `ArcBox` configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Data directory.
    pub data_dir: PathBuf,
    /// Default VM configuration.
    pub vm: VmDefaults,
    /// Default machine configuration.
    pub machine: MachineDefaults,
    /// Network configuration.
    pub network: NetworkConfig,
    /// Docker API configuration.
    pub docker: DockerConfig,
    /// Container runtime backend configuration.
    pub container: ContainerRuntimeConfig,
    /// Logging configuration.
    pub logging: LoggingConfig,
    /// Storage configuration.
    pub storage: StorageConfig,
    /// Sandbox (Firecracker microVM) configuration (Linux only).
    pub sandbox: SandboxConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            vm: VmDefaults::default(),
            machine: MachineDefaults::default(),
            network: NetworkConfig::default(),
            docker: DockerConfig::default(),
            container: ContainerRuntimeConfig::default(),
            logging: LoggingConfig::default(),
            storage: StorageConfig::default(),
            sandbox: SandboxConfig::default(),
        }
    }
}

impl Config {
    /// Loads configuration from files and environment.
    ///
    /// Configuration sources (in order of precedence):
    /// 1. Environment variables (ARCBOX_*)
    /// 2. User config file (~/.config/arcbox/config.toml)
    /// 3. System config file (/etc/arcbox/config.toml)
    /// 4. Default values
    ///
    /// # Errors
    ///
    /// Returns an error if configuration cannot be loaded.
    pub fn load() -> Result<Self, figment::Error> {
        Figment::new()
            .merge(Serialized::defaults(Self::default()))
            .merge(Toml::file(system_config_path()))
            .merge(Toml::file(user_config_path()))
            .merge(Env::prefixed("ARCBOX_").split("_"))
            .extract()
    }

    /// Loads configuration from a specific file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: impl AsRef<std::path::Path>) -> Result<Self, figment::Error> {
        Figment::new()
            .merge(Serialized::defaults(Self::default()))
            .merge(Toml::file(path))
            .merge(Env::prefixed("ARCBOX_").split("_"))
            .extract()
    }

    /// Returns the path to the images directory.
    #[must_use]
    pub fn images_dir(&self) -> PathBuf {
        self.data_dir.join("images")
    }

    /// Returns the path to the containers directory.
    #[must_use]
    pub fn containers_dir(&self) -> PathBuf {
        self.data_dir.join("containers")
    }

    /// Returns the path to the machines directory.
    #[must_use]
    pub fn machines_dir(&self) -> PathBuf {
        self.data_dir.join("machines")
    }

    /// Returns the path to the volumes directory.
    #[must_use]
    pub fn volumes_dir(&self) -> PathBuf {
        self.data_dir.join("volumes")
    }
}

/// Default VM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VmDefaults {
    /// Default number of CPUs.
    pub cpus: u32,
    /// Default memory in MB.
    pub memory_mb: u64,
    /// Kernel path (optional, uses embedded kernel if not set).
    pub kernel_path: Option<PathBuf>,
}

impl Default for VmDefaults {
    fn default() -> Self {
        Self {
            cpus: 4,
            memory_mb: 4096,
            kernel_path: None,
        }
    }
}

/// Default machine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MachineDefaults {
    /// Default disk size in GB.
    pub disk_gb: u64,
    /// Default Linux distribution.
    pub default_distro: String,
    /// Default distribution version.
    pub default_version: Option<String>,
    /// Auto-mount home directory.
    pub auto_mount_home: bool,
}

impl Default for MachineDefaults {
    fn default() -> Self {
        Self {
            disk_gb: 50,
            default_distro: "ubuntu".to_string(),
            default_version: None,
            auto_mount_home: true,
        }
    }
}

/// Network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Subnet for NAT networking.
    pub subnet: String,
    /// Gateway address (first address in subnet if not specified).
    pub gateway: Option<String>,
    /// DNS servers.
    pub dns: Vec<String>,
    /// Enable IPv6.
    pub ipv6: bool,
    /// MTU for virtual network interfaces.
    pub mtu: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            subnet: "192.168.64.0/24".to_string(),
            gateway: None,
            dns: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            ipv6: false,
            mtu: 1500,
        }
    }
}

/// Docker API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerConfig {
    /// Unix socket path for Docker API.
    pub socket_path: PathBuf,
    /// Enable Docker API.
    pub enabled: bool,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            socket_path: default_docker_socket_path(),
            enabled: true,
        }
    }
}

/// Container runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerRuntimeConfig {
    /// Guest dockerd API vsock port.
    pub guest_docker_vsock_port: u32,
    /// Backend startup timeout in milliseconds.
    pub startup_timeout_ms: u64,
}

impl Default for ContainerRuntimeConfig {
    fn default() -> Self {
        Self {
            guest_docker_vsock_port: DOCKER_API_VSOCK_PORT,
            startup_timeout_ms: 60_000,
        }
    }
}

fn default_docker_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".arcbox")
        .join("docker.sock")
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: String,
    /// Log to file.
    pub file: Option<PathBuf>,
    /// Log format (text, json).
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
            format: "text".to_string(),
        }
    }
}

/// Storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Storage driver (overlay2, btrfs, zfs).
    pub driver: String,
    /// Image storage backend.
    pub image_backend: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            driver: "overlay2".to_string(),
            image_backend: "oci".to_string(),
        }
    }
}

/// Sandbox (Firecracker microVM) configuration.
///
/// Only meaningful on Linux where Firecracker is available.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Enable the sandbox subsystem.
    pub enabled: bool,
    /// Path to the `firecracker` binary.
    pub firecracker_binary: String,
    /// Data directory for sandbox VMs, snapshots, and images.
    pub data_dir: String,
    /// Linux bridge interface name for sandbox uplinks.
    pub bridge: String,
    /// IP CIDR pool for guest address allocation.
    pub cidr: String,
    /// Default gateway advertised to sandbox guests.
    pub gateway: String,
    /// Default vCPU count for new sandboxes.
    pub default_vcpus: u64,
    /// Default memory in MiB for new sandboxes.
    pub default_memory_mib: u64,
    /// Default kernel image path.
    pub default_kernel: String,
    /// Default root filesystem image path.
    pub default_rootfs: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            firecracker_binary: "/usr/bin/firecracker".to_string(),
            data_dir: "/var/lib/arcbox/sandboxes".to_string(),
            bridge: "fcvmm0".to_string(),
            cidr: "172.20.0.0/16".to_string(),
            gateway: "172.20.0.1".to_string(),
            default_vcpus: 1,
            default_memory_mib: 512,
            default_kernel: "/var/lib/arcbox/sandboxes/kernels/vmlinux".to_string(),
            default_rootfs: "/var/lib/arcbox/sandboxes/images/rootfs.ext4".to_string(),
        }
    }
}

impl SandboxConfig {
    /// Converts to `arcbox_vm::VmmConfig` for initializing the `SandboxManager`.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn to_vmm_config(&self) -> arcbox_vm::VmmConfig {
        arcbox_vm::VmmConfig {
            firecracker: arcbox_vm::FirecrackerConfig {
                binary: self.firecracker_binary.clone(),
                jailer: None,
                data_dir: self.data_dir.clone(),
                log_level: None,
                no_seccomp: false,
                seccomp_filter: None,
                http_api_max_payload_size: None,
                mmds_size_limit: None,
                socket_timeout_secs: None,
            },
            network: arcbox_vm::NetworkConfig {
                bridge: self.bridge.clone(),
                cidr: self.cidr.clone(),
                gateway: self.gateway.clone(),
                dns: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            },
            grpc: arcbox_vm::GrpcConfig {
                unix_socket: String::new(),
                tcp_addr: String::new(),
            },
            defaults: arcbox_vm::DefaultVmConfig {
                vcpus: self.default_vcpus,
                memory_mib: self.default_memory_mib,
                kernel: self.default_kernel.clone(),
                rootfs: self.default_rootfs.clone(),
                boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            },
        }
    }
}

fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/var/lib"))
        .join(".arcbox")
}

fn user_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("arcbox")
        .join("config.toml")
}

fn system_config_path() -> PathBuf {
    PathBuf::from("/etc/arcbox/config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.vm.cpus, 4);
        assert_eq!(config.vm.memory_mb, 4096);
        assert_eq!(config.machine.disk_gb, 50);
        assert!(config.docker.enabled);
        assert_eq!(
            config.container.guest_docker_vsock_port,
            DOCKER_API_VSOCK_PORT
        );
    }

    #[test]
    fn test_config_paths() {
        let config = Config::default();
        assert!(config.images_dir().ends_with("images"));
        assert!(config.containers_dir().ends_with("containers"));
        assert!(config.machines_dir().ends_with("machines"));
        assert!(config.volumes_dir().ends_with("volumes"));
    }
}
