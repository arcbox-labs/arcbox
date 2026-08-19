//! VMM configuration loading for the guest agent.
//!
//! One TOML file, read into the two halves that consume it: the
//! [`RuntimeConfig`] the embedded [`ComputerManager`] runs on, and the
//! [`AdapterConfig`] this crate builds the VMM driver and the sandbox
//! network from. The load priority is:
//!
//! 1. `ARCBOX_VMM_CONFIG` environment variable (path to TOML file)
//! 2. `/etc/arcbox/vmm.toml`
//! 3. Built-in guest defaults

mod adapters;

pub use adapters::{AdapterConfig, JailerProcess};

use arcbox_computer_runtime::RuntimeConfig;
use arcbox_computer_runtime::config::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, JailerConfig, NetworkConfig,
};
use arcbox_constants::paths::{ARCBOX_RUNTIME_BIN_DIR, ARCBOX_RUNTIME_DIR, JAILER_CHROOT_BASE};

/// The System VM's `vmm.toml`, in the two halves that read it.
#[derive(Debug, Clone)]
pub struct GuestConfig {
    /// What the sandbox runtime owns.
    pub runtime: RuntimeConfig,
    /// What this composer builds its adapters from.
    pub adapters: AdapterConfig,
}

impl GuestConfig {
    /// Both halves out of the same bytes, so the two parses cannot see
    /// different versions of a file being rewritten under them.
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        Ok(Self {
            runtime: toml::from_str(content)?,
            adapters: AdapterConfig::from_toml(content)?,
        })
    }

    /// Both halves of one file, or why it could not be read.
    pub fn from_file(path: &str) -> Result<Self, GuestConfigError> {
        Ok(Self::from_toml(&std::fs::read_to_string(path)?)?)
    }
}

/// Why a `vmm.toml` did not load.
///
/// The parse half keeps `toml`'s own error rather than its text: the span
/// it carries is the useful part when a deployed file fails, and the two
/// failures are answered differently — a missing file falls through to the
/// next candidate, a malformed one is a config the operator wrote wrong.
#[derive(Debug, thiserror::Error)]
pub enum GuestConfigError {
    /// The file could not be read.
    #[error("read config: {0}")]
    Read(#[from] std::io::Error),
    /// The file is not a config this agent understands.
    #[error("parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Persistent Btrfs mount that owns sandbox images, snapshots, and VM state.
pub const SANDBOX_DATA_DIR: &str = "/var/lib/arcbox/sandbox";

/// Guest-specific VMM configuration defaults.
///
/// These differ from [`RuntimeConfig::default()`] which targets the host-side
/// daemon. Paths follow the guest view of host assets:
///
/// - Boot-manifest binaries are materialized onto the guest Btrfs data disk
///   before the sandbox service can use them.
/// - The default sandbox rootfs is auto-built by the agent (busybox +
///   vm-agent, see `RootfsBuilder::ensure_default_rootfs`) on the writable
///   btrfs data volume.
fn guest_defaults() -> GuestConfig {
    let runtime_bin = std::path::Path::new(ARCBOX_RUNTIME_BIN_DIR);
    let runtime_root = std::path::Path::new(ARCBOX_RUNTIME_DIR);
    let runtime = RuntimeConfig {
        firecracker: FirecrackerConfig {
            jailer: Some(JailerConfig {
                uid: 0,
                gid: 0,
                chroot_base_dir: Some(JAILER_CHROOT_BASE.into()),
                netns: None,
                new_pid_ns: false,
                cgroup_version: None,
                parent_cgroup: None,
            }),
            data_dir: SANDBOX_DATA_DIR.into(),
            pool_size: 1,
            warm_create: true,
            dmsetup_candidates: Some(guest_dmsetup_candidates()),
        },
        network: NetworkConfig {
            cidr: "172.20.0.0/16".into(),
            gateway: "172.20.0.1".into(),
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
        },
        grpc: GrpcConfig {
            unix_socket: "/run/arcbox/vmm.sock".into(),
            tcp_addr: String::new(),
        },
        defaults: DefaultVmConfig {
            vcpus: 1,
            memory_mib: 512,
            kernel: runtime_root.join("kernel/vmlinux").to_string_lossy().into(),
            rootfs: format!("{SANDBOX_DATA_DIR}/rootfs.ext4"),
            // `quiet`: every boot printk is a serial MMIO exit, doubled by
            // nesting — silencing the console measurably shortens the cold
            // kernel boot (CORE-75/CORE-79).
            boot_args: "console=ttyS0 quiet reboot=k panic=1 pci=off init=/sbin/vm-agent".into(),
        },
    };
    GuestConfig {
        runtime,
        adapters: AdapterConfig {
            binary: runtime_bin.join("firecracker").to_string_lossy().into(),
            jailer: Some(JailerProcess {
                binary: runtime_bin.join("jailer").to_string_lossy().into(),
                resource_limits: Vec::new(),
            }),
            log_level: None,
            no_seccomp: false,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout_secs: None,
            sandbox_datapath: arcbox_tap_net::Datapath::default(),
        },
    }
}

/// The host-shared `dmsetup` copy (`/arcbox/bin`, the VirtioFS share the
/// staged `vm-agent` also lives on).
const GUEST_DMSETUP: &str = "/arcbox/bin/dmsetup";

/// Where the guest looks for `dmsetup`: the host-shared copy first, then
/// the stock locations. The library's own default is the stock list alone;
/// the guest-specific entry is this composer's to add.
fn guest_dmsetup_candidates() -> Vec<String> {
    vec![
        GUEST_DMSETUP.into(),
        "/usr/sbin/dmsetup".into(),
        "/sbin/dmsetup".into(),
    ]
}

/// Apply the guest's environment facts on top of a config loaded from a
/// file: a config that does not mention `dmsetup_candidates` — every one
/// written before the field existed — gets the search order the guest has
/// always used, host-shared copy first. A config that spells the list out
/// is taken as written, including `[]` to run without CoW.
fn with_guest_environment(mut cfg: GuestConfig) -> GuestConfig {
    cfg.runtime
        .firecracker
        .dmsetup_candidates
        .get_or_insert_with(guest_dmsetup_candidates);
    cfg
}

/// Load the VMM configuration for the guest agent.
///
/// Priority: `ARCBOX_VMM_CONFIG` env var → `/etc/arcbox/vmm.toml` → guest defaults.
pub fn load() -> GuestConfig {
    // 1. Environment variable override.
    if let Ok(path) = std::env::var("ARCBOX_VMM_CONFIG") {
        if !path.is_empty() {
            match GuestConfig::from_file(&path) {
                Ok(cfg) => {
                    tracing::info!(path, "loaded VMM config from ARCBOX_VMM_CONFIG");
                    return with_guest_environment(cfg);
                }
                Err(e) => {
                    tracing::warn!(path, error = %e, "failed to load ARCBOX_VMM_CONFIG, falling through");
                }
            }
        }
    }

    // 2. Well-known guest config file.
    const GUEST_CONFIG_PATH: &str = "/etc/arcbox/vmm.toml";
    if std::path::Path::new(GUEST_CONFIG_PATH).exists() {
        match GuestConfig::from_file(GUEST_CONFIG_PATH) {
            Ok(cfg) => {
                tracing::info!(path = GUEST_CONFIG_PATH, "loaded VMM config");
                return with_guest_environment(cfg);
            }
            Err(e) => {
                tracing::warn!(
                    path = GUEST_CONFIG_PATH,
                    error = %e,
                    "failed to load guest VMM config, using defaults"
                );
            }
        }
    }

    // 3. Built-in guest defaults.
    tracing::debug!("using built-in guest VMM config defaults");
    guest_defaults()
}

#[cfg(test)]
mod tests {
    use super::{
        GUEST_DMSETUP, GuestConfig, SANDBOX_DATA_DIR, guest_defaults, guest_dmsetup_candidates,
        with_guest_environment,
    };

    #[test]
    fn defaults_keep_sandbox_state_on_its_data_mount() {
        let config = guest_defaults();

        assert_eq!(config.runtime.firecracker.data_dir, SANDBOX_DATA_DIR);
        assert!(
            std::path::Path::new(&config.runtime.defaults.rootfs).starts_with(SANDBOX_DATA_DIR)
        );
    }

    /// The order is the behaviour: the host-shared copy is tried before the
    /// stock locations, exactly as the snapshot crate's built-in list did
    /// before it became configuration. Reordering would not fail — CoW would
    /// silently degrade to a full rootfs copy per sandbox.
    #[test]
    fn dmsetup_search_starts_with_the_host_shared_copy() {
        assert_eq!(
            guest_defaults()
                .runtime
                .firecracker
                .dmsetup_candidates
                .as_deref(),
            Some(
                &[
                    GUEST_DMSETUP.to_string(),
                    "/usr/sbin/dmsetup".to_string(),
                    "/sbin/dmsetup".to_string()
                ][..]
            )
        );
    }

    /// A config file that does not mention `dmsetup_candidates` gets the
    /// guest's own search order; one that spells it out is left alone,
    /// including the empty list that switches CoW off.
    #[test]
    fn file_configs_without_the_field_gain_the_guest_search_order() {
        let mut cfg = guest_defaults();
        cfg.runtime.firecracker.dmsetup_candidates = None;
        let cfg = with_guest_environment(cfg);
        assert_eq!(
            cfg.runtime.firecracker.dmsetup_candidates,
            Some(guest_dmsetup_candidates())
        );

        let mut cfg = guest_defaults();
        cfg.runtime.firecracker.dmsetup_candidates = Some(vec!["/opt/dm/dmsetup".into()]);
        let cfg = with_guest_environment(cfg);
        assert_eq!(
            cfg.runtime.firecracker.dmsetup_candidates.as_deref(),
            Some(&["/opt/dm/dmsetup".to_string()][..])
        );

        let mut cfg = guest_defaults();
        cfg.runtime.firecracker.dmsetup_candidates = Some(Vec::new());
        let cfg = with_guest_environment(cfg);
        assert_eq!(
            cfg.runtime.firecracker.dmsetup_candidates.as_deref(),
            Some(&[][..])
        );
    }

    /// A complete `vmm.toml`: every key either half knows, in the one
    /// `[firecracker]` section a deployed System VM already has on disk.
    ///
    /// **Every optional key has to be named here**, because
    /// [`every_firecracker_key_lands_in_exactly_one_half`] reads each
    /// half's key set off a *parsed value*, and TOML omits a field that
    /// came out `None`. A new `Option` field this fixture does not set is
    /// therefore invisible to both sides of that comparison — which costs
    /// nothing in the direction that matters (a file key read by neither
    /// half is still in the file, so it still fails), but does mean the
    /// fixture stops being the complete config it claims to be.
    ///
    /// [`every_firecracker_key_lands_in_exactly_one_half`]:
    ///     #method.every_firecracker_key_lands_in_exactly_one_half
    const COMPLETE_CONFIG: &str = r#"
[firecracker]
binary = "/arcbox/runtime/bin/firecracker"
data_dir = "/var/lib/arcbox/sandbox"
log_level = "Error"
no_seccomp = true
seccomp_filter = "/etc/fc/seccomp.bpf"
http_api_max_payload_size = 1048576
mmds_size_limit = 4096
socket_timeout_secs = 15
sandbox_datapath = "filter"
pool_size = 2
warm_create = false
dmsetup_candidates = ["/arcbox/bin/dmsetup"]

[firecracker.jailer]
binary = "/arcbox/runtime/bin/jailer"
uid = 0
gid = 0
chroot_base_dir = "/var/lib/arcbox/jail"
netns = "/var/run/netns/sbx"
new_pid_ns = true
cgroup_version = "2"
parent_cgroup = "arcbox"
resource_limits = ["fsize=2048"]

[network]
cidr = "172.20.0.0/16"
gateway = "172.20.0.1"
dns = ["1.1.1.1"]

[grpc]
unix_socket = "/run/arcbox/vmm.sock"
tcp_addr = ""

[defaults]
vcpus = 1
memory_mib = 512
kernel = "/arcbox/runtime/kernel/vmlinux"
rootfs = "/var/lib/arcbox/sandbox/rootfs.ext4"
boot_args = "console=ttyS0"
"#;

    /// The keys a value round-trips back to, which for a struct parsed out
    /// of `COMPLETE_CONFIG` is exactly the set of fields it claimed.
    fn keys<T: serde::Serialize>(value: &T) -> std::collections::BTreeSet<String> {
        toml::Value::try_from(value)
            .expect("the config halves serialize back to TOML")
            .as_table()
            .expect("a table")
            .keys()
            .cloned()
            .collect()
    }

    /// One `[firecracker]` section, two readers: every key of a complete
    /// config must land in one of them, and neither may claim a key the
    /// section does not have.
    ///
    /// The failure this split invites is silent — a key that belongs to
    /// neither half is simply ignored by both, and the setting stops
    /// working with nothing to read in a log. The `[firecracker.jailer]`
    /// sub-table splits the same way and is checked the same way.
    #[test]
    fn every_firecracker_key_lands_in_exactly_one_half() {
        let file: toml::Table = toml::from_str(COMPLETE_CONFIG).unwrap();
        let section = file["firecracker"].as_table().unwrap();
        let config = GuestConfig::from_toml(COMPLETE_CONFIG).unwrap();

        let mut halves = keys(&config.runtime.firecracker);
        let adapters = keys(&config.adapters);
        // `jailer` is the one key both halves read: they take different
        // fields out of the same sub-table, checked below.
        assert_eq!(
            halves.intersection(&adapters).cloned().collect::<Vec<_>>(),
            ["jailer"],
            "the halves must not read the same key twice"
        );
        halves.extend(adapters);
        let written: std::collections::BTreeSet<String> = section.keys().cloned().collect();
        assert_eq!(
            halves, written,
            "every `[firecracker]` key must be read by exactly one half"
        );

        let jailer = section["jailer"].as_table().unwrap();
        let mut jailer_halves = keys(config.runtime.firecracker.jailer.as_ref().unwrap());
        jailer_halves.extend(keys(config.adapters.jailer.as_ref().unwrap()));
        assert_eq!(
            jailer_halves,
            jailer
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            "every `[firecracker.jailer]` key must be read by exactly one half"
        );
    }

    /// The split is compile-time only: the same file yields the values a
    /// deployed System VM has always run with.
    #[test]
    fn a_complete_config_parses_to_the_values_it_names() {
        let config = GuestConfig::from_toml(COMPLETE_CONFIG).unwrap();
        assert_eq!(
            config.runtime.firecracker.data_dir,
            "/var/lib/arcbox/sandbox"
        );
        assert_eq!(config.runtime.firecracker.pool_size, 2);
        assert!(!config.runtime.firecracker.warm_create);
        let isolation = arcbox_computer_runtime::config::JailerConfig::clone(
            config.runtime.firecracker.jailer.as_ref().unwrap(),
        );
        assert_eq!(
            isolation.chroot_base_dir.as_deref(),
            Some("/var/lib/arcbox/jail")
        );
        assert_eq!(config.adapters.binary, "/arcbox/runtime/bin/firecracker");
        assert_eq!(config.adapters.socket_timeout_secs, Some(15));
        assert_eq!(
            config.adapters.sandbox_datapath,
            arcbox_tap_net::Datapath::Filter
        );
        assert_eq!(
            config.adapters.jailer.as_ref().unwrap().resource_limits,
            ["fsize=2048"]
        );
    }
}
