/// Kernel cmdline token that enables machine-mode guest initialization.
pub const MODE_MACHINE: &str = "arcbox.mode=machine";

/// Kernel cmdline key for boot asset version propagation.
pub const BOOT_ASSET_VERSION_KEY: &str = "arcbox.boot_asset_version=";

/// Kernel cmdline key for guest Docker API vsock port propagation.
pub const GUEST_DOCKER_VSOCK_PORT_KEY: &str = "arcbox.guest_docker_vsock_port=";

/// Kernel cmdline key for guest Docker data block-device path.
pub const DOCKER_DATA_DEVICE_KEY: &str = "arcbox.docker_data_device=";
