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
//! # cpus = 8         # default: host core count
//! # memory_mb = 8192  # default: half of host RAM (512–16384)
//!
//! [machine]
//! disk_gb = 50
//! default_distro = "ubuntu"
//!
//! [network]
//! subnet = "10.0.2.0/24"
//! dns = ["8.8.8.8", "8.8.4.4"]
//!
//! [docker]
//! socket_path = "~/.arcbox/run/docker.sock"
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
    pub fn load() -> Result<Self, Box<figment::Error>> {
        Figment::new()
            .merge(Serialized::defaults(Self::default()))
            .merge(Toml::file(system_config_path()))
            .merge(Toml::file(user_config_path()))
            .merge(Env::prefixed("ARCBOX_").split("_"))
            .extract()
            .map_err(Box::new)
    }

    /// Loads configuration from a specific file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from(path: impl AsRef<std::path::Path>) -> Result<Self, Box<figment::Error>> {
        Figment::new()
            .merge(Serialized::defaults(Self::default()))
            .merge(Toml::file(path))
            .merge(Env::prefixed("ARCBOX_").split("_"))
            .extract()
            .map_err(Box::new)
    }

    /// Returns the path to the persistent data directory (`data/`).
    #[must_use]
    pub fn data_subdir(&self) -> PathBuf {
        self.data_dir.join(arcbox_constants::paths::host::DATA)
    }

    /// Returns the path to the images directory (`data/images/`).
    #[must_use]
    pub fn images_dir(&self) -> PathBuf {
        self.data_subdir().join("images")
    }

    /// Returns the path to the containers directory (`data/containers/`).
    #[must_use]
    pub fn containers_dir(&self) -> PathBuf {
        self.data_subdir().join("containers")
    }

    /// Returns the path to the machines directory (`data/machines/`).
    #[must_use]
    pub fn machines_dir(&self) -> PathBuf {
        self.data_subdir().join("machines")
    }

    /// Returns the path to the volumes directory (`data/volumes/`).
    #[must_use]
    pub fn volumes_dir(&self) -> PathBuf {
        self.data_subdir().join("volumes")
    }

    /// Returns the path to the runtime state directory (`run/`).
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.data_dir.join(arcbox_constants::paths::host::RUN)
    }

    /// Returns the path to the log directory (`log/`).
    #[must_use]
    pub fn log_dir(&self) -> PathBuf {
        self.data_dir.join(arcbox_constants::paths::host::LOG)
    }

    /// Returns the path to the persistent Docker data image (`data/docker.img`).
    #[must_use]
    pub fn docker_img_path(&self) -> PathBuf {
        self.data_subdir().join("docker.img")
    }
}

/// Default VM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VmDefaults {
    /// Default number of CPUs (default: host core count).
    pub cpus: u32,
    /// Default memory in MB.
    pub memory_mb: u64,
    /// Kernel path (optional, uses embedded kernel if not set).
    pub kernel_path: Option<PathBuf>,
}

impl Default for VmDefaults {
    fn default() -> Self {
        Self {
            cpus: arcbox_hypervisor::default_vm_cpu_count(),
            memory_mb: arcbox_hypervisor::default_vm_memory_size() / (1024 * 1024),
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
            subnet: "10.0.2.0/24".to_string(),
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
        .join(arcbox_constants::paths::host::RUN)
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
        assert_eq!(config.vm.cpus, arcbox_hypervisor::default_vm_cpu_count());
        // Default memory is half of host RAM, clamped to [512, 16384] MB.
        let expected_mb = arcbox_hypervisor::default_vm_memory_size() / (1024 * 1024);
        assert_eq!(config.vm.memory_mb, expected_mb);
        assert!(config.vm.memory_mb >= 512);
        assert!(config.vm.memory_mb <= 16384);
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
        assert!(config.images_dir().ends_with("data/images"));
        assert!(config.containers_dir().ends_with("data/containers"));
        assert!(config.machines_dir().ends_with("data/machines"));
        assert!(config.volumes_dir().ends_with("data/volumes"));
        assert!(config.run_dir().ends_with("run"));
        assert!(config.log_dir().ends_with("log"));
        assert!(config.docker_img_path().ends_with("data/docker.img"));
    }
}
