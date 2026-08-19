//! VMM configuration loading for the guest agent.
//!
//! Loads [`RuntimeConfig`] for the embedded [`SandboxManager`] that runs inside
//! the guest VM.  The load priority is:
//!
//! 1. `ARCBOX_VMM_CONFIG` environment variable (path to TOML file)
//! 2. `/etc/arcbox/vmm.toml`
//! 3. Built-in guest defaults

use arcbox_computer_runtime::RuntimeConfig;
use arcbox_computer_runtime::config::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig,
};
use arcbox_constants::paths::{ARCBOX_RUNTIME_BIN_DIR, ARCBOX_RUNTIME_DIR, JAILER_CHROOT_BASE};

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
fn guest_defaults() -> RuntimeConfig {
    let runtime_bin = std::path::Path::new(ARCBOX_RUNTIME_BIN_DIR);
    let runtime_root = std::path::Path::new(ARCBOX_RUNTIME_DIR);
    RuntimeConfig {
        firecracker: FirecrackerConfig {
            binary: runtime_bin.join("firecracker").to_string_lossy().into(),
            jailer: Some(arcbox_computer_runtime::config::JailerConfig {
                binary: runtime_bin.join("jailer").to_string_lossy().into(),
                uid: 0,
                gid: 0,
                chroot_base_dir: Some(JAILER_CHROOT_BASE.into()),
                netns: None,
                new_pid_ns: false,
                cgroup_version: None,
                parent_cgroup: None,
                resource_limits: vec![],
            }),
            data_dir: SANDBOX_DATA_DIR.into(),
            log_level: None,
            no_seccomp: false,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout_secs: None,
            sandbox_datapath: arcbox_computer_runtime::config::SandboxDatapath::default(),
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
fn with_guest_environment(mut cfg: RuntimeConfig) -> RuntimeConfig {
    cfg.firecracker
        .dmsetup_candidates
        .get_or_insert_with(guest_dmsetup_candidates);
    cfg
}

/// Load the VMM configuration for the guest agent.
///
/// Priority: `ARCBOX_VMM_CONFIG` env var → `/etc/arcbox/vmm.toml` → guest defaults.
pub fn load() -> RuntimeConfig {
    // 1. Environment variable override.
    if let Ok(path) = std::env::var("ARCBOX_VMM_CONFIG") {
        if !path.is_empty() {
            match RuntimeConfig::from_file(&path) {
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
        match RuntimeConfig::from_file(GUEST_CONFIG_PATH) {
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
        GUEST_DMSETUP, SANDBOX_DATA_DIR, guest_defaults, guest_dmsetup_candidates,
        with_guest_environment,
    };

    #[test]
    fn defaults_keep_sandbox_state_on_its_data_mount() {
        let config = guest_defaults();

        assert_eq!(config.firecracker.data_dir, SANDBOX_DATA_DIR);
        assert!(std::path::Path::new(&config.defaults.rootfs).starts_with(SANDBOX_DATA_DIR));
    }

    /// The order is the behaviour: the host-shared copy is tried before the
    /// stock locations, exactly as the snapshot crate's built-in list did
    /// before it became configuration. Reordering would not fail — CoW would
    /// silently degrade to a full rootfs copy per sandbox.
    #[test]
    fn dmsetup_search_starts_with_the_host_shared_copy() {
        assert_eq!(
            guest_defaults().firecracker.dmsetup_candidates.as_deref(),
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
        cfg.firecracker.dmsetup_candidates = None;
        let cfg = with_guest_environment(cfg);
        assert_eq!(
            cfg.firecracker.dmsetup_candidates,
            Some(guest_dmsetup_candidates())
        );

        let mut cfg = guest_defaults();
        cfg.firecracker.dmsetup_candidates = Some(vec!["/opt/dm/dmsetup".into()]);
        let cfg = with_guest_environment(cfg);
        assert_eq!(
            cfg.firecracker.dmsetup_candidates.as_deref(),
            Some(&["/opt/dm/dmsetup".to_string()][..])
        );

        let mut cfg = guest_defaults();
        cfg.firecracker.dmsetup_candidates = Some(Vec::new());
        let cfg = with_guest_environment(cfg);
        assert_eq!(cfg.firecracker.dmsetup_candidates.as_deref(), Some(&[][..]));
    }
}
