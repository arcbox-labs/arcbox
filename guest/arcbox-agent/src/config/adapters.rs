//! The half of `[firecracker]` that configures the adapters this composer
//! builds, rather than the runtime it builds them for.
//!
//! `arcbox-computer-runtime` reads the same section for what it owns — the
//! data directory, the jailer isolation, the pool and warm-create knobs,
//! the `dmsetup` search list. Everything here exists only to be handed to
//! `arcbox-fc-driver` or `arcbox-tap-net`, and so belongs to whoever
//! decides that those are the adapters: this crate.
//!
//! One TOML section, two readers. serde ignores unknown fields, so each
//! side takes its own keys out of one `[firecracker]` table and a deployed
//! `vmm.toml` needs no migration.

use std::path::PathBuf;
use std::time::Duration;

use arcbox_fc_driver::FcDriverConfig;
use arcbox_tap_net::Datapath;
use serde::{Deserialize, Serialize};

/// The `[firecracker]` keys that describe the VMM adapter and the sandbox
/// datapath.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// Path to the `firecracker` binary.
    pub binary: String,
    /// The jailer's node-wide half; absent = run Firecracker directly.
    ///
    /// Absent *here* is not the same question as absent in the runtime's
    /// half: this one decides whether the driver knows a jailer binary,
    /// that one whether a sandbox gets jailer isolation. A file sets both
    /// or neither, because they are one `[firecracker.jailer]` table.
    #[serde(default)]
    pub jailer: Option<JailerProcess>,
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
    /// Seconds to wait for the Firecracker socket to become available.
    /// `None` uses the driver's own default.
    #[serde(default)]
    pub socket_timeout_secs: Option<u64>,
    /// Host-side translation mechanism for invariant sandbox TAPs
    /// (CORE-83) — the TAP network's own [`Datapath`], under the name this
    /// config has always used.
    #[serde(default)]
    pub sandbox_datapath: Datapath,
}

/// The node-wide half of `[firecracker.jailer]`: what the driver needs to
/// spawn the jailer, as opposed to the isolation each VM gets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailerProcess {
    /// Path to the `jailer` binary.
    pub binary: String,
    /// Resource limits in `rlimit` format (e.g. `"fsize=2048"`).
    #[serde(default)]
    pub resource_limits: Vec<String>,
}

impl AdapterConfig {
    /// The adapter half of one `vmm.toml`.
    ///
    /// Takes the text rather than a path so a caller reads the file once
    /// and parses both halves out of the same bytes.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        #[derive(Deserialize)]
        struct File {
            firecracker: AdapterConfig,
        }
        Ok(toml::from_str::<File>(content)?.firecracker)
    }
}

impl From<&AdapterConfig> for FcDriverConfig {
    fn from(fc: &AdapterConfig) -> Self {
        Self {
            firecracker_binary: PathBuf::from(&fc.binary),
            jailer_binary: fc.jailer.as_ref().map(|jc| PathBuf::from(&jc.binary)),
            log_level: fc.log_level.clone(),
            no_seccomp: fc.no_seccomp,
            seccomp_filter: fc.seccomp_filter.as_deref().map(PathBuf::from),
            http_api_max_payload_size: fc.http_api_max_payload_size,
            mmds_size_limit: fc.mmds_size_limit,
            socket_timeout: fc
                .socket_timeout_secs
                .map_or(Self::DEFAULT_SOCKET_TIMEOUT, Duration::from_secs),
            resource_limits: fc
                .jailer
                .as_ref()
                .map(|jc| jc.resource_limits.clone())
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_driver_config_takes_the_process_flags_and_the_jailer_binary() {
        let bare = AdapterConfig {
            binary: "/usr/bin/firecracker".into(),
            jailer: None,
            log_level: None,
            no_seccomp: false,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout_secs: None,
            sandbox_datapath: Datapath::default(),
        };
        assert_eq!(
            FcDriverConfig::from(&bare),
            FcDriverConfig::new("/usr/bin/firecracker")
        );

        let full = AdapterConfig {
            jailer: Some(JailerProcess {
                binary: "/usr/bin/jailer".into(),
                resource_limits: vec!["fsize=2048".into()],
            }),
            log_level: Some("Error".into()),
            no_seccomp: true,
            seccomp_filter: Some("/etc/fc/seccomp.bpf".into()),
            http_api_max_payload_size: Some(1 << 20),
            mmds_size_limit: Some(4096),
            socket_timeout_secs: Some(15),
            ..bare
        };
        let driver = FcDriverConfig::from(&full);
        assert_eq!(driver.jailer_binary, Some(PathBuf::from("/usr/bin/jailer")));
        assert_eq!(driver.log_level.as_deref(), Some("Error"));
        assert!(driver.no_seccomp);
        assert_eq!(
            driver.seccomp_filter,
            Some(PathBuf::from("/etc/fc/seccomp.bpf"))
        );
        assert_eq!(driver.http_api_max_payload_size, Some(1 << 20));
        assert_eq!(driver.mmds_size_limit, Some(4096));
        assert_eq!(driver.socket_timeout, Duration::from_secs(15));
        assert_eq!(driver.resource_limits, vec!["fsize=2048".to_string()]);
    }

    #[test]
    fn the_datapath_defaults_to_ebpf_and_parses_the_fallback() {
        assert_eq!(
            AdapterConfig::from_toml("[firecracker]\nbinary = \"/fc\"\n")
                .unwrap()
                .sandbox_datapath,
            Datapath::Ebpf
        );
        // The fallback is reachable by config alone...
        assert_eq!(
            AdapterConfig::from_toml(
                "[firecracker]\nbinary = \"/fc\"\nsandbox_datapath = \"filter\"\n"
            )
            .unwrap()
            .sandbox_datapath,
            Datapath::Filter
        );
        // ...and under the name it had while iptables was the only
        // rendering, which a node's config file predates the nftables
        // backend with.
        assert_eq!(
            AdapterConfig::from_toml(
                "[firecracker]\nbinary = \"/fc\"\nsandbox_datapath = \"iptables\"\n"
            )
            .unwrap()
            .sandbox_datapath,
            Datapath::Filter
        );
    }

    /// The `binary` key has no default on either side of the split, so a
    /// file that omits it is rejected exactly as it was before — by this
    /// half, since the runtime's half no longer knows the key.
    #[test]
    fn a_config_without_a_firecracker_binary_is_refused() {
        assert!(AdapterConfig::from_toml("[firecracker]\ndata_dir = \"/d\"\n").is_err());
    }
}
