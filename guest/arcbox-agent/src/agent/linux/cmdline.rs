//! Kernel cmdline / environment readers for guest configuration.

use std::path::Path;

use arcbox_constants::cmdline::{
    DOCKER_DATA_DEVICE_KEY as DOCKER_DATA_DEVICE_CMDLINE_KEY,
    DOCKER_METADATA_DEVICE_KEY as DOCKER_METADATA_DEVICE_CMDLINE_KEY, GUEST_DOCKER_VSOCK_PORT_KEY,
    RUNTIME_GENERATION_KEY,
};
use arcbox_constants::devices::DOCKER_DATA_BLOCK_DEVICE as DOCKER_DATA_DEVICE_DEFAULT;
use arcbox_constants::env::GUEST_DOCKER_VSOCK_PORT as GUEST_DOCKER_VSOCK_PORT_ENV;
use arcbox_constants::ports::{DOCKER_API_VSOCK_PORT, KUBERNETES_API_VSOCK_PORT};

/// HVC fast-path block device for the data disk (device index 1 = vdb).
/// Falls back to the standard VirtIO block device if HVC device is absent.
const HVC_DATA_DEVICE: &str = "/dev/arcboxhvc1";

pub(super) fn cmdline_value(key: &str) -> Option<String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    cmdline_value_from(&cmdline, key).map(str::to_owned)
}

fn cmdline_value_from<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline
        .split_whitespace()
        .find_map(|token| token.strip_prefix(key).filter(|value| !value.is_empty()))
}

pub(super) fn docker_api_vsock_port() -> u32 {
    if let Some(port) = std::env::var(GUEST_DOCKER_VSOCK_PORT_ENV)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|port| *port > 0)
    {
        return port;
    }

    if let Some(port) = cmdline_value(GUEST_DOCKER_VSOCK_PORT_KEY)
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|port| *port > 0)
    {
        return port;
    }

    DOCKER_API_VSOCK_PORT
}

pub(super) fn docker_data_device() -> String {
    // Prefer explicit kernel cmdline override.
    if let Some(v) = cmdline_value(DOCKER_DATA_DEVICE_CMDLINE_KEY) {
        if !v.trim().is_empty() {
            return v;
        }
    }
    // Use HVC fast-path device if available.
    if Path::new(HVC_DATA_DEVICE).exists() {
        tracing::info!("using HVC fast-path block device: {}", HVC_DATA_DEVICE);
        return HVC_DATA_DEVICE.to_string();
    }
    DOCKER_DATA_DEVICE_DEFAULT.to_string()
}

/// The metadata device path the host declared on the cmdline when it
/// attached the disk (there is no HVC fast path to auto-detect, so the host
/// declares instead). `None` means an older daemon that never attached one.
pub(super) fn declared_docker_metadata_device() -> Option<String> {
    cmdline_value(DOCKER_METADATA_DEVICE_CMDLINE_KEY).filter(|v| !v.trim().is_empty())
}

/// The immutable boot-asset generation the guest must materialize locally.
pub(super) fn runtime_generation() -> Result<String, String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|error| format!("read kernel cmdline: {error}"))?;
    runtime_generation_from(&cmdline)
}

fn runtime_generation_from(cmdline: &str) -> Result<String, String> {
    let generation = cmdline_value_from(cmdline, RUNTIME_GENERATION_KEY)
        .ok_or_else(|| format!("kernel cmdline is missing {RUNTIME_GENERATION_KEY}<version>"))?;
    let valid = generation != "."
        && generation != ".."
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if !valid {
        return Err(format!("invalid runtime generation {generation:?}"));
    }
    Ok(generation.to_string())
}

/// Verifies the Btrfs runtime contract for the System VM.
///
/// Machine VMs share this agent binary but do not carry the System VM's
/// runtime-generation or Docker-metadata device keys.
pub(super) fn validate_runtime_boot_contract() -> Result<(), String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .map_err(|error| format!("read kernel cmdline: {error}"))?;
    validate_runtime_boot_contract_from(&cmdline)
}

fn validate_runtime_boot_contract_from(cmdline: &str) -> Result<(), String> {
    if cmdline_value_from(cmdline, RUNTIME_GENERATION_KEY).is_some()
        || cmdline_value_from(cmdline, DOCKER_METADATA_DEVICE_CMDLINE_KEY).is_some()
    {
        return runtime_generation_from(cmdline).map(drop);
    }
    Ok(())
}

pub(super) fn kubernetes_api_vsock_port() -> u32 {
    KUBERNETES_API_VSOCK_PORT
}

#[cfg(test)]
mod tests {
    use super::validate_runtime_boot_contract_from;

    #[test]
    fn runtime_contract_is_required_only_for_the_system_vm() {
        assert!(
            validate_runtime_boot_contract_from("root=/dev/vda arcbox.runtime_generation=0.6.13")
                .is_ok()
        );
        assert!(
            validate_runtime_boot_contract_from(
                "root=/dev/vda arcbox.docker_metadata_device=/dev/vdc"
            )
            .is_err()
        );
        assert!(
            validate_runtime_boot_contract_from("root=/dev/vda arcbox.machine_rootfs=/dev/vdb")
                .is_ok()
        );
        assert!(validate_runtime_boot_contract_from("root=/dev/vda custom=1").is_ok());
    }
}
