//! Configuration management.
//!
//! ArcBox configuration is loaded from multiple sources with the following priority:
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
//! backend = "guest_docker"
//! provision = "bundled_assets"
//! guest_docker_vsock_port = 2375
//!
//! [logging]
//! level = "info"
//! ```

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// ArcBox configuration.
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
    /// Initrd path (optional).
    pub initrd_path: Option<PathBuf>,
}

impl Default for VmDefaults {
    fn default() -> Self {
        Self {
            cpus: 4,
            memory_mb: 4096,
            kernel_path: None,
            initrd_path: None,
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

/// Container runtime backend mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerBackendMode {
    /// Existing host control-plane + guest agent runtime path.
    NativeControlPlane,
    /// Guest VM Docker Engine path (dockerd/containerd/youki).
    GuestDocker,
}

/// Guest Docker runtime provisioning mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerProvisionMode {
    /// Runtime assets bundled with boot-assets release.
    BundledAssets,
    /// Runtime installed from distro packages inside guest.
    DistroEngine,
}

/// Container runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerRuntimeConfig {
    /// Container backend selector.
    pub backend: ContainerBackendMode,
    /// Guest runtime provisioning mode.
    pub provision: ContainerProvisionMode,
    /// Guest dockerd API vsock port.
    pub guest_docker_vsock_port: u32,
    /// Backend startup timeout in milliseconds.
    pub startup_timeout_ms: u64,
}

impl Default for ContainerRuntimeConfig {
    fn default() -> Self {
        Self {
            backend: ContainerBackendMode::GuestDocker,
            provision: ContainerProvisionMode::BundledAssets,
            guest_docker_vsock_port: 2375,
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
        assert_eq!(config.container.backend, ContainerBackendMode::GuestDocker);
        assert_eq!(
            config.container.provision,
            ContainerProvisionMode::BundledAssets
        );
        assert_eq!(config.container.guest_docker_vsock_port, 2375);
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
