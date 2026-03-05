//! VMM configuration loading for the guest agent.
//!
//! Loads [`VmmConfig`] for the embedded [`SandboxManager`] that runs inside
//! the guest VM.  The load priority is:
//!
//! 1. `ARCBOX_VMM_CONFIG` environment variable (path to TOML file)
//! 2. `/etc/arcbox/vmm.toml`
//! 3. Built-in guest defaults

use arcbox_vm::VmmConfig;
use arcbox_vm::config::{DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig};

/// Guest-specific VMM configuration defaults.
///
/// These differ from [`VmmConfig::default()`] which targets the host-side daemon.
fn guest_defaults() -> VmmConfig {
    VmmConfig {
        firecracker: FirecrackerConfig {
            binary: "/usr/local/bin/firecracker".into(),
            jailer: None,
            data_dir: "/var/lib/arcbox/sandboxes".into(),
            log_level: None,
            no_seccomp: false,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout_secs: None,
        },
        network: NetworkConfig {
            bridge: "arcbox-sb0".into(),
            cidr: "10.88.0.0/16".into(),
            gateway: "10.88.0.1".into(),
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
        },
        grpc: GrpcConfig {
            unix_socket: "/run/arcbox/vmm.sock".into(),
            tcp_addr: String::new(),
        },
        defaults: DefaultVmConfig {
            vcpus: 1,
            memory_mib: 512,
            kernel: "/var/lib/arcbox/kernel/vmlinux".into(),
            rootfs: "/var/lib/arcbox/images/sandbox.ext4".into(),
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".into(),
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
