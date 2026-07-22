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
//! # autostart = true  # boot the default Linux VM (Docker/K8s); false = VM-host only
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

use arcbox_constants::paths::{ArcboxProfile, HostLayout};
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
        Self::for_profile(ArcboxProfile::Production)
    }
}

impl Config {
    /// Creates default configuration for a runtime profile.
    #[must_use]
    pub fn for_profile(profile: ArcboxProfile) -> Self {
        let layout = HostLayout::for_profile(profile);
        Self {
            data_dir: layout.data_dir,
            vm: VmDefaults::default(),
            machine: MachineDefaults::default(),
            network: NetworkConfig::default(),
            docker: DockerConfig::for_profile(profile),
            container: ContainerRuntimeConfig::default(),
            logging: LoggingConfig::default(),
            storage: StorageConfig::default(),
        }
    }

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
        Self::load_for_profile(ArcboxProfile::from_env_or_default())
    }

    /// Loads configuration for a runtime profile from files and environment.
    ///
    /// Explicit `ARCBOX_*` environment values and config file values override
    /// profile defaults.
    pub fn load_for_profile(profile: ArcboxProfile) -> Result<Self, Box<figment::Error>> {
        Figment::new()
            .merge(Serialized::defaults(Self::for_profile(profile)))
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

    /// Returns the path to the Docker metadata image (`data/docker-meta.img`).
    ///
    /// Paired with [`Self::docker_img_path`]: the ext4 volume carrying the
    /// fsync-hot boltdb metadata (see internal-docs/plans/ext4-metadata-volume.md).
    #[must_use]
    pub fn docker_meta_img_path(&self) -> PathBuf {
        self.data_subdir().join("docker-meta.img")
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
    /// macOS hypervisor backend for the System VM (`"vz"` or `"hv"`).
    ///
    /// First-boot default only: once the machine exists, its persisted
    /// backend (as switched via `arcbox system backend`) wins. Settable
    /// non-interactively via `ARCBOX_VM_BACKEND` or `config.toml` — the
    /// entry point for the dual-backend e2e matrix.
    pub backend: arcbox_vmm::VmBackend,
    /// Whether to boot the default Linux VM (the Docker/Kubernetes system VM)
    /// on daemon startup. When `false`, the daemon runs as a VM host only:
    /// the Linux VM never starts and the Docker API, Docker CLI integration,
    /// and Kubernetes proxy are all disabled. macOS guest management is
    /// unaffected. Overridden to `false` by the daemon's `--no-linux-vm` flag.
    pub autostart: bool,
}

impl VmDefaults {
    /// Returns the effective CPU count, resolving `0` to the host core
    /// count default.
    ///
    /// `0` means "use the default" both on the wire (gRPC
    /// `CreateMachineRequest.cpus`) and in `config.toml`, so callers must
    /// never propagate it into a VM configuration verbatim.
    #[must_use]
    pub fn effective_cpus(&self) -> u32 {
        if self.cpus == 0 {
            arcbox_hypervisor::default_vm_cpu_count()
        } else {
            self.cpus
        }
    }
}

impl Default for VmDefaults {
    fn default() -> Self {
        Self {
            cpus: arcbox_hypervisor::default_vm_cpu_count(),
            memory_mb: arcbox_hypervisor::default_vm_memory_size() / (1024 * 1024),
            kernel_path: None,
            backend: arcbox_vmm::VmBackend::default(),
            autostart: true,
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
        Self::for_profile(ArcboxProfile::Production)
    }
}

impl DockerConfig {
    /// Creates default Docker configuration for a runtime profile.
    #[must_use]
    pub fn for_profile(profile: ArcboxProfile) -> Self {
        Self {
            socket_path: HostLayout::for_profile(profile).docker_socket,
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
    ///
    /// Must exceed the guest agent's worst-case runtime bring-up with
    /// headroom: readiness gates on dockerd answering `/_ping`, and the
    /// guest can spend up to ~30 s waiting for containerd plus its ~90 s
    /// dockerd readiness poll (~120 s total) on large data volumes. A
    /// shorter host timeout would abort boots the guest was still going
    /// to finish.
    pub startup_timeout_ms: u64,
}

impl Default for ContainerRuntimeConfig {
    fn default() -> Self {
        Self {
            guest_docker_vsock_port: DOCKER_API_VSOCK_PORT,
            startup_timeout_ms: 150_000,
        }
    }
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
    fn test_effective_cpus_zero_resolves_to_default() {
        let vm = VmDefaults {
            cpus: 0,
            ..VmDefaults::default()
        };
        assert_eq!(
            vm.effective_cpus(),
            arcbox_hypervisor::default_vm_cpu_count()
        );
    }

    #[test]
    fn test_effective_cpus_explicit_passes_through() {
        let vm = VmDefaults {
            cpus: 3,
            ..VmDefaults::default()
        };
        assert_eq!(vm.effective_cpus(), 3);
    }

    #[test]
    fn vm_backend_defaults_to_vz() {
        assert_eq!(Config::default().vm.backend, arcbox_vmm::VmBackend::Vz);
    }

    #[test]
    fn vm_backend_parses_from_toml() {
        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::string("[vm]\nbackend = \"hv\""))
            .extract()
            .expect("config with vm.backend");
        assert_eq!(config.vm.backend, arcbox_vmm::VmBackend::Hv);
    }

    #[test]
    #[allow(clippy::result_large_err, reason = "figment::Jail closure signature")]
    fn vm_backend_parses_from_env() {
        // Mirrors the env layer of `load_for_profile` without reading the
        // host's real config files.
        figment::Jail::expect_with(|jail| {
            jail.set_env("ARCBOX_VM_BACKEND", "hv");
            let config: Config = Figment::new()
                .merge(Serialized::defaults(Config::default()))
                .merge(Env::prefixed("ARCBOX_").split("_"))
                .extract()?;
            assert_eq!(config.vm.backend, arcbox_vmm::VmBackend::Hv);
            Ok(())
        });
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
