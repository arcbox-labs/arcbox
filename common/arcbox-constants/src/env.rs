/// Environment variable for selecting boot asset version.
pub const BOOT_ASSET_VERSION: &str = "ARCBOX_BOOT_ASSET_VERSION";

/// Environment variable for selecting the runtime profile.
pub const PROFILE: &str = "ARCBOX_PROFILE";

/// Environment variable for overriding the host data directory.
pub const DATA_DIR: &str = "ARCBOX_DATA_DIR";

/// Environment variable for overriding guest Docker API vsock port.
pub const GUEST_DOCKER_VSOCK_PORT: &str = "ARCBOX_GUEST_DOCKER_VSOCK_PORT";

/// Environment variable overriding the VM idle timeout, in seconds.
///
/// Dev/test knob: the idle-balloon e2e shortens the 5-minute default so an
/// idle shrink happens within a test budget.
pub const IDLE_TIMEOUT_SECS: &str = "ARCBOX_IDLE_TIMEOUT_SECS";
