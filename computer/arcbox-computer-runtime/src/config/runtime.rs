use serde::{Deserialize, Serialize};

use crate::error::{ComputerError, Result};

use super::JailerConfig;

/// Top-level configuration of the sandbox runtime, as the composer's
/// config file spells it out (`/etc/arcbox/vmm.toml` in the System VM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub firecracker: FirecrackerConfig,
    pub network: NetworkConfig,
    pub grpc: GrpcConfig,
    pub defaults: DefaultVmConfig,
}

/// The `[firecracker]` keys this runtime reads.
///
/// The section is named for the VMM because that is what a deployed
/// `vmm.toml` has always called it, and the on-disk vocabulary is frozen
/// (`computer/AGENTS.md`) — but nothing here is Firecracker's. The keys
/// that configure a VMM adapter (its binaries, its process-level flags,
/// the sandbox datapath) belong to whoever builds that adapter, and are
/// read out of this same section by the composer; serde ignores what it
/// does not know, so one section serves both halves and the file's shape
/// is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerConfig {
    /// Jailer isolation for every sandbox VMM (absent = no isolation).
    #[serde(default)]
    pub jailer: Option<JailerConfig>,
    /// Root data directory (VMs, snapshots, images).
    pub data_dir: String,
    /// Spare pre-warmed restore slots kept per snapshot id (CORE-78).
    ///
    /// A slot pre-executes the fixed host-side restore setup — jailer
    /// chroot, Firecracker spawn, kernel/vmstate/mem staging, dm-snapshot
    /// — so a restore only claims it and issues LoadSnapshot. Only
    /// snapshots that have been restored at least once are pooled, for at
    /// most two distinct snapshot ids (LRU-evicted). `0` disables pooling.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// Serve eligible Creates from warm template snapshots (CORE-77).
    ///
    /// The first create of a template shape cold-boots and checkpoints the
    /// idle guest; every later create of the same shape restores from that
    /// snapshot instead of booting a kernel. Requires jailer isolation;
    /// only networked creates without a custom boot recipe participate.
    /// `false` restores plain cold boots for every create.
    #[serde(default = "default_warm_create")]
    pub warm_create: bool,
    /// Where to look for the `dmsetup` binary that drives dm-snapshot CoW
    /// rootfs images. The first entry that exists and answers
    /// `dmsetup version` wins; none usable disables CoW (every sandbox
    /// copies its rootfs). `PATH` is never searched. `None` — the field
    /// absent from the file — leaves the choice to the composer, whose
    /// fallback is the library's stock-distro list; an explicit list is
    /// used exactly as written, so `[]` is how a config disables CoW.
    #[serde(default)]
    pub dmsetup_candidates: Option<Vec<String>>,
}

fn default_pool_size() -> usize {
    1
}

fn default_warm_create() -> bool {
    true
}

/// Network IP-pool settings for sandbox TAP interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
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

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            firecracker: FirecrackerConfig {
                jailer: None,
                data_dir: "/var/lib/firecracker-vmm".into(),
                pool_size: default_pool_size(),
                warm_create: default_warm_create(),
                dmsetup_candidates: None,
            },
            network: NetworkConfig {
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

impl RuntimeConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ComputerError::Config(e.to_string()))?;
        toml::from_str(&content).map_err(|e| ComputerError::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_sane_values() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.defaults.vcpus, 1);
        assert_eq!(cfg.defaults.memory_mib, 512);
        assert!(cfg.defaults.boot_args.contains("console=ttyS0"));
        assert!(!cfg.network.cidr.is_empty());
        assert!(!cfg.firecracker.data_dir.is_empty());
    }

    #[test]
    fn pool_size_defaults_to_one_spare_slot() {
        assert_eq!(RuntimeConfig::default().firecracker.pool_size, 1);
        // A config written before the knob existed still loads with the default.
        let cfg: FirecrackerConfig = toml::from_str("data_dir = \"/var/lib/vmm\"\n").unwrap();
        assert_eq!(cfg.pool_size, 1);
    }

    #[test]
    fn warm_create_defaults_on_and_parses_the_escape_hatch() {
        assert!(RuntimeConfig::default().firecracker.warm_create);
        // A config written before the knob existed still loads with the default.
        let cfg: FirecrackerConfig = toml::from_str("data_dir = \"/var/lib/vmm\"\n").unwrap();
        assert!(cfg.warm_create);
        // The escape hatch is reachable by config alone.
        let cfg: FirecrackerConfig =
            toml::from_str("data_dir = \"/var/lib/vmm\"\nwarm_create = false\n").unwrap();
        assert!(!cfg.warm_create);
    }

    #[test]
    fn dmsetup_candidates_absent_is_none_and_explicit_lists_parse_as_written() {
        // A config written before the field existed still loads; the
        // absence is preserved so the composer can supply its own list.
        let cfg: FirecrackerConfig = toml::from_str("data_dir = \"/var/lib/vmm\"\n").unwrap();
        assert_eq!(cfg.dmsetup_candidates, None);
        // An explicit list is used exactly as written.
        let cfg: FirecrackerConfig = toml::from_str(
            "data_dir = \"/var/lib/vmm\"\n\
             dmsetup_candidates = [\"/opt/arcbox/dmsetup\", \"/sbin/dmsetup\"]\n",
        )
        .unwrap();
        assert_eq!(
            cfg.dmsetup_candidates.as_deref(),
            Some(
                &[
                    "/opt/arcbox/dmsetup".to_string(),
                    "/sbin/dmsetup".to_string()
                ][..]
            )
        );
        // An empty list is a deliberate "no dmsetup" — CoW off.
        let cfg: FirecrackerConfig = toml::from_str(
            "data_dir = \"/var/lib/vmm\"\n\
             dmsetup_candidates = []\n",
        )
        .unwrap();
        assert_eq!(cfg.dmsetup_candidates.as_deref(), Some(&[][..]));
    }

    #[test]
    fn test_vmm_config_json_roundtrip() {
        let cfg = RuntimeConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: RuntimeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.defaults.vcpus, cfg.defaults.vcpus);
        assert_eq!(decoded.defaults.memory_mib, cfg.defaults.memory_mib);
        assert_eq!(decoded.network.cidr, cfg.network.cidr);
        assert_eq!(decoded.network.gateway, cfg.network.gateway);
    }

    #[test]
    fn test_from_file_missing_returns_config_error() {
        let result = RuntimeConfig::from_file("/nonexistent/arcbox-test-config.toml");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::error::ComputerError::Config(_)
        ));
    }
}
