/// Runtime ensure status: runtime started in this request.
pub const RUNTIME_STARTED: &str = "started";

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
