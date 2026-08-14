//! Sandbox API (Connect surface) constants shared by the daemon and tests.

/// Sandbox API protocol level reported by `SandboxService.GetCapabilities`.
///
/// SDKs compare it against their floor and raise `PROTOCOL_MISMATCH` with
/// an upgrade suggestion instead of sprinkling per-call version checks
/// (CORE-13). Bump when the sandbox surface changes incompatibly; purely
/// additive capabilities ship as [`SANDBOX_FEATURES`] flags instead.
pub const SANDBOX_API_PROTOCOL: u32 = 1;

/// Named feature flags for capabilities that postdate the protocol level.
///
/// Append-only: SDKs feature-detect by name, so renaming or removing a
/// shipped flag silently disables the feature for older clients.
pub const SANDBOX_FEATURES: &[&str] = &[
    // Pause/Resume on a stable sandbox id (CORE-21).
    "pause_resume",
    // Data-plane calls transparently resume a paused sandbox (CORE-21).
    "auto_resume",
    // idle_timeout_seconds + on_idle are enforced (CORE-21).
    "idle_policy",
    // SetLifecycle re-arms TTL / replaces idle knobs (CORE-60).
    "set_lifecycle",
    // Authoritative host-listener reconciliation (CORE-102).
    "list_exposed_ports",
    // The template catalog: Build/Publish/Get/List/Delete plus
    // name[:version] resolution in Create (CORE-107).
    "templates",
    // TemplateDefaults.ready_probe gates READY on port/command probes
    // (CORE-107).
    "ready_probe",
];
