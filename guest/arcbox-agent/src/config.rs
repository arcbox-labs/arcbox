//! VMM configuration loading for the guest agent.
//!
//! Loads [`VmmConfig`] for the embedded [`SandboxManager`] that runs inside
//! the guest VM.  The load priority is:
//!
//! 1. `ARCBOX_VMM_CONFIG` environment variable (path to TOML file)
//! 2. `/etc/arcbox/vmm.toml`
//! 3. Built-in guest defaults

use arcbox_constants::paths::{ARCBOX_RUNTIME_BIN_DIR, ARCBOX_RUNTIME_DIR};
use arcbox_vm::VmmConfig;
use arcbox_vm::config::{DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig};

/// Persistent Btrfs mount that owns sandbox images, snapshots, and VM state.
pub const SANDBOX_DATA_DIR: &str = "/var/lib/arcbox/sandbox";

/// Guest-specific VMM configuration defaults.
///
/// These differ from [`VmmConfig::default()`] which targets the host-side
/// daemon. Paths follow the guest view of host assets:
///
/// - Boot-manifest binaries are materialized onto the guest Btrfs data disk
///   before the sandbox service can use them.
/// - The default sandbox rootfs is auto-built by the agent (busybox +
///   vm-agent, see `rootfs_builder::ensure_default_rootfs`) on the writable
///   btrfs data volume.
fn guest_defaults() -> VmmConfig {
    let runtime_bin = std::path::Path::new(ARCBOX_RUNTIME_BIN_DIR);
    let runtime_root = std::path::Path::new(ARCBOX_RUNTIME_DIR);
    VmmConfig {
        firecracker: FirecrackerConfig {
            binary: runtime_bin.join("firecracker").to_string_lossy().into(),
            jailer: Some(arcbox_vm::config::JailerConfig {
                binary: runtime_bin.join("jailer").to_string_lossy().into(),
                uid: 0,
                gid: 0,
                chroot_base_dir: Some("/var/lib/arcbox/jailer".into()),
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
            sandbox_datapath: arcbox_vm::config::SandboxDatapath::default(),
            pool_size: 1,
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

/// Load the VMM configuration for the guest agent.
///
/// Priority: `ARCBOX_VMM_CONFIG` env var → `/etc/arcbox/vmm.toml` → guest defaults.
pub fn load() -> VmmConfig {
    // 1. Environment variable override.
    if let Ok(path) = std::env::var("ARCBOX_VMM_CONFIG") {
        if !path.is_empty() {
            match VmmConfig::from_file(&path) {
                Ok(cfg) => {
                    tracing::info!(path, "loaded VMM config from ARCBOX_VMM_CONFIG");
                    return cfg;
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
        match VmmConfig::from_file(GUEST_CONFIG_PATH) {
            Ok(cfg) => {
                tracing::info!(path = GUEST_CONFIG_PATH, "loaded VMM config");
                return cfg;
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
    use super::{SANDBOX_DATA_DIR, guest_defaults};

    #[test]
    fn defaults_keep_sandbox_state_on_its_data_mount() {
        let config = guest_defaults();

        assert_eq!(config.firecracker.data_dir, SANDBOX_DATA_DIR);
        assert!(std::path::Path::new(&config.defaults.rootfs).starts_with(SANDBOX_DATA_DIR));
    }
}
