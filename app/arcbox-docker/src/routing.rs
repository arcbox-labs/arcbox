//! Docker workload runtime placement decisions for ArcBox.
//!
//! ABX-375: all runtime containers run in the single HV utility VM. The
//! routing decision no longer selects between utility VMs — it selects the
//! in-guest *translator* for the workload's platform:
//!
//! - `linux/arm64` and unspecified → [`RuntimeTranslator::Native`] (no translation).
//! - `linux/amd64` → [`RuntimeTranslator::Fex64`] (x86-64 via FEX `binfmt_misc`
//!   inside the HV guest).
//!
//! VZ/Rosetta is no longer a default runtime target. It is retained only as an
//! explicit, opt-in `docker build` backend (see PLAN.md step 7); the runtime
//! path never selects it and never boots the VZ VM.

use axum::http::Uri;
use bytes::Bytes;
use serde_json::Value;

pub use arcbox_core::UtilityVmRole;

/// In-guest execution path for a workload's platform inside the HV utility VM.
///
/// Surfaced in diagnostics as PLAN.md's `translator` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTranslator {
    /// Native arm64 execution — no translation.
    Native,
    /// x86-64 execution through FEX (`binfmt_misc`) inside the HV guest.
    Fex64,
}

impl RuntimeTranslator {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Fex64 => "fex64",
        }
    }
}

/// Parsed workload platform from Docker API request metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadPlatform {
    /// Linux ARM64 / AArch64 userspace.
    LinuxArm64,
    /// Linux AMD64 / x86_64 userspace.
    LinuxAmd64,
    /// No explicit or recognized platform was requested.
    Unspecified,
}

impl WorkloadPlatform {
    /// Parses Docker platform strings such as `linux/amd64` and `linux/arm64`.
    #[must_use]
    pub fn parse(platform: &str) -> Self {
        let normalized = platform.trim().to_ascii_lowercase().replace("%2f", "/");
        match normalized.as_str() {
            "linux/amd64" | "linux/x86_64" | "amd64" | "x86_64" => Self::LinuxAmd64,
            "linux/arm64" | "linux/aarch64" | "arm64" | "aarch64" => Self::LinuxArm64,
            _ => Self::Unspecified,
        }
    }

    /// Returns the in-guest translator required to run this platform in the
    /// single HV utility VM. `amd64` needs FEX64; everything else runs
    /// natively.
    #[must_use]
    pub const fn runtime_translator(self) -> RuntimeTranslator {
        match self {
            Self::LinuxAmd64 => RuntimeTranslator::Fex64,
            Self::LinuxArm64 | Self::Unspecified => RuntimeTranslator::Native,
        }
    }
}

/// Runtime placement decision for a Docker workload.
///
/// Runtime always targets the single HV utility VM ([`UtilityVmRole::Native`]);
/// [`Self::translator`] says how the platform executes inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingDecision {
    /// Requested or inferred platform.
    pub platform: WorkloadPlatform,
    /// In-guest translator selected for the platform.
    pub translator: RuntimeTranslator,
}

impl RoutingDecision {
    /// Creates a routing decision from a parsed workload platform.
    #[must_use]
    pub const fn from_platform(platform: WorkloadPlatform) -> Self {
        Self {
            platform,
            translator: platform.runtime_translator(),
        }
    }

    /// Returns the native/HV default routing decision.
    #[must_use]
    pub const fn native_default() -> Self {
        Self::from_platform(WorkloadPlatform::Unspecified)
    }

    /// The utility VM that serves this workload. Always the single HV VM —
    /// runtime no longer routes across utility VMs.
    #[must_use]
    pub const fn utility_vm(self) -> UtilityVmRole {
        UtilityVmRole::Native
    }

    /// Whether this workload requires FEX64 in the HV guest to run.
    #[must_use]
    pub const fn needs_fex64(self) -> bool {
        matches!(self.translator, RuntimeTranslator::Fex64)
    }
}

/// Returns whether a routing decision can be admitted given FEX64 availability
/// in the HV guest.
///
/// Native (arm64) workloads are always admissible. amd64 workloads are
/// admitted only when FEX64 is available; otherwise the caller must fail
/// closed (PLAN.md error behavior) rather than silently falling back to
/// VZ/Rosetta or QEMU.
#[must_use]
pub const fn is_admissible(decision: RoutingDecision, fex64_available: bool) -> bool {
    match decision.translator {
        RuntimeTranslator::Native => true,
        RuntimeTranslator::Fex64 => fex64_available,
    }
}

/// Computes the route for `POST /containers/create`.
#[must_use]
pub fn route_container_create(uri: &Uri, body: &Bytes) -> RoutingDecision {
    let platform = platform_from_query(uri)
        .or_else(|| platform_from_create_body(body))
        .unwrap_or(WorkloadPlatform::Unspecified);
    RoutingDecision::from_platform(platform)
}

/// Computes the route for `POST /build`.
#[must_use]
pub fn route_build(uri: &Uri) -> RoutingDecision {
    RoutingDecision::from_platform(
        platform_from_query(uri).unwrap_or(WorkloadPlatform::Unspecified),
    )
}

fn platform_from_query(uri: &Uri) -> Option<WorkloadPlatform> {
    query_param(uri, "platform").map(WorkloadPlatform::parse)
}

/// Returns the value of the first non-empty `key` parameter in `uri`'s
/// query string, matched case-insensitively.
///
/// The value is returned **raw** — percent-encoding is not decoded. Current
/// callers only use this for ASCII-safe identifiers (`platform`, `name`),
/// so this is acceptable; introducing values that could plausibly carry
/// percent-encoded bytes would require decoding first.
#[must_use]
pub fn query_param<'a>(uri: &'a Uri, key: &str) -> Option<&'a str> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.eq_ignore_ascii_case(key) && !v.is_empty()).then_some(v)
    })
}

fn platform_from_create_body(body: &Bytes) -> Option<WorkloadPlatform> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let platform = value.get("Platform")?.as_str()?;
    Some(WorkloadPlatform::parse(platform))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_amd64_platform_aliases() {
        assert_eq!(
            WorkloadPlatform::parse("linux/amd64"),
            WorkloadPlatform::LinuxAmd64
        );
        assert_eq!(
            WorkloadPlatform::parse("linux/x86_64"),
            WorkloadPlatform::LinuxAmd64
        );
        assert_eq!(
            WorkloadPlatform::parse("amd64"),
            WorkloadPlatform::LinuxAmd64
        );
    }

    #[test]
    fn parses_arm64_platform_aliases() {
        assert_eq!(
            WorkloadPlatform::parse("linux/arm64"),
            WorkloadPlatform::LinuxArm64
        );
        assert_eq!(
            WorkloadPlatform::parse("linux/aarch64"),
            WorkloadPlatform::LinuxArm64
        );
        assert_eq!(
            WorkloadPlatform::parse("aarch64"),
            WorkloadPlatform::LinuxArm64
        );
    }

    #[test]
    fn amd64_selects_fex64_translator_on_hv() {
        let route = RoutingDecision::from_platform(WorkloadPlatform::LinuxAmd64);
        assert_eq!(route.translator, RuntimeTranslator::Fex64);
        // Runtime never leaves the single HV VM.
        assert_eq!(route.utility_vm(), UtilityVmRole::Native);
        assert!(route.needs_fex64());
    }

    #[test]
    fn arm64_and_unspecified_select_native_translator() {
        for platform in [WorkloadPlatform::LinuxArm64, WorkloadPlatform::Unspecified] {
            let route = RoutingDecision::from_platform(platform);
            assert_eq!(route.translator, RuntimeTranslator::Native);
            assert_eq!(route.utility_vm(), UtilityVmRole::Native);
            assert!(!route.needs_fex64());
        }
    }

    #[test]
    fn amd64_admitted_only_when_fex64_available() {
        let amd64 = RoutingDecision::from_platform(WorkloadPlatform::LinuxAmd64);
        assert!(
            !is_admissible(amd64, false),
            "amd64 must fail closed without FEX64"
        );
        assert!(is_admissible(amd64, true));
    }

    #[test]
    fn native_workloads_always_admissible() {
        let arm64 = RoutingDecision::from_platform(WorkloadPlatform::LinuxArm64);
        let unspec = RoutingDecision::native_default();
        // Native execution does not depend on FEX64.
        assert!(is_admissible(arm64, false));
        assert!(is_admissible(unspec, false));
    }

    #[test]
    fn container_create_prefers_query_platform_over_body() {
        let uri = "/containers/create?platform=linux/amd64".parse().unwrap();
        let body = Bytes::from_static(br#"{"Image":"alpine","Platform":"linux/arm64"}"#);
        let route = route_container_create(&uri, &body);
        assert_eq!(route.platform, WorkloadPlatform::LinuxAmd64);
        assert_eq!(route.translator, RuntimeTranslator::Fex64);
    }

    #[test]
    fn container_create_uses_body_platform_when_query_absent() {
        let uri = "/containers/create".parse().unwrap();
        let body = Bytes::from_static(br#"{"Image":"alpine","Platform":"linux/amd64"}"#);
        let route = route_container_create(&uri, &body);
        assert_eq!(route.translator, RuntimeTranslator::Fex64);
    }

    #[test]
    fn build_uses_query_platform() {
        let uri = "/build?t=image&platform=linux%2Famd64".parse().unwrap();
        let route = route_build(&uri);
        assert_eq!(route.platform, WorkloadPlatform::LinuxAmd64);
        assert_eq!(route.translator, RuntimeTranslator::Fex64);
    }
}
