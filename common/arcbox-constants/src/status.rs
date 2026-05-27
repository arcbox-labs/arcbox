/// Runtime ensure status: runtime started in this request.
pub const RUNTIME_STARTED: &str = "started";

/// Runtime ensure status: runtime start is in progress; poll again.
///
/// The agent returns this immediately instead of blocking the RPC for the
/// full cold-boot window (up to ~90s for containerd + dockerd). The host's
/// blocking vsock transport has a short per-RPC deadline (~5s); a blocking
/// agent would cause the daemon to close the socketpair mid-call and the
/// agent's eventual response write would fail with EPIPE.
pub const RUNTIME_STARTING: &str = "starting";

/// Runtime ensure status: runtime was already available.
pub const RUNTIME_REUSED: &str = "reused";

/// Runtime ensure status: runtime failed or is unavailable.
pub const RUNTIME_FAILED: &str = "failed";

/// Service status: reachable and healthy.
pub const SERVICE_READY: &str = "ready";

/// Service status: not reachable yet.
pub const SERVICE_NOT_READY: &str = "not_ready";

/// Service status: discovered but unhealthy.
pub const SERVICE_ERROR: &str = "error";
