//! Kernel cmdline / environment readers for guest configuration.

use std::path::Path;

use arcbox_constants::cmdline::{
    DOCKER_DATA_DEVICE_KEY as DOCKER_DATA_DEVICE_CMDLINE_KEY, GUEST_DOCKER_VSOCK_PORT_KEY,
};
use arcbox_constants::devices::DOCKER_DATA_BLOCK_DEVICE as DOCKER_DATA_DEVICE_DEFAULT;
use arcbox_constants::env::GUEST_DOCKER_VSOCK_PORT as GUEST_DOCKER_VSOCK_PORT_ENV;
use arcbox_constants::ports::{DOCKER_API_VSOCK_PORT, KUBERNETES_API_VSOCK_PORT};

/// HVC fast-path block device for the data disk (device index 1 = vdb).
/// Falls back to the standard VirtIO block device if HVC device is absent.
const HVC_DATA_DEVICE: &str = "/dev/arcboxhvc1";

pub(super) fn cmdline_value(key: &str) -> Option<String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    for token in cmdline.split_whitespace() {
        if let Some(value) = token.strip_prefix(key) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
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

pub(super) fn kubernetes_api_vsock_port() -> u32 {
    KUBERNETES_API_VSOCK_PORT
}
