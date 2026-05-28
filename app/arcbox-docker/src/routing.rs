//! Docker workload routing decisions for ArcBox utility VMs.

use axum::http::Uri;
use bytes::Bytes;
use serde_json::Value;

pub use arcbox_core::UtilityVmRole;

/// Extension methods on [`UtilityVmRole`] specific to Docker routing.
pub trait UtilityVmRoleExt {
    /// Returns `true` if the utility VM for this role is capable of
    /// hosting workloads of `platform`.
    fn can_host(self, platform: WorkloadPlatform) -> bool;
}

impl UtilityVmRoleExt for UtilityVmRole {
    fn can_host(self, platform: WorkloadPlatform) -> bool {
        match self {
            // VZ + Rosetta hosts both arm64 and amd64.
            Self::Rosetta => true,
            // HV runs native ARM64 only; amd64 needs translation only
            // available via VZ + Rosetta.
            Self::Native => !matches!(platform, WorkloadPlatform::LinuxAmd64),
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

    /// Returns the default utility VM role for this platform.
    #[must_use]
    pub const fn utility_vm_role(self) -> UtilityVmRole {
        match self {
            Self::LinuxAmd64 => UtilityVmRole::Rosetta,
            Self::LinuxArm64 | Self::Unspecified => UtilityVmRole::Native,
        }
    }
}

/// Routing decision for a Docker workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingDecision {
    /// Requested or inferred platform.
    pub platform: WorkloadPlatform,
    /// Selected utility VM role.
    pub utility_vm: UtilityVmRole,
}

impl RoutingDecision {
    /// Creates a routing decision from a parsed workload platform.
    #[must_use]
    pub const fn from_platform(platform: WorkloadPlatform) -> Self {
        Self {
            platform,
            utility_vm: platform.utility_vm_role(),
        }
    }

    /// Returns the native/HV default routing decision.
    #[must_use]
    pub const fn native_default() -> Self {
        Self::from_platform(WorkloadPlatform::Unspecified)
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

/// Extracts the `com.docker.compose.project` label from a
/// container-create body.
///
/// Compose-managed containers carry this label so all services in a
/// project can be scheduled onto a single utility VM role.
#[must_use]
pub fn extract_compose_project(body: &Bytes) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let project = value
        .pointer("/Labels/com.docker.compose.project")?
        .as_str()?;
    if project.is_empty() {
        return None;
    }
    Some(project.to_string())
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
    fn routes_amd64_to_rosetta_role() {
        let route = RoutingDecision::from_platform(WorkloadPlatform::LinuxAmd64);
        assert_eq!(route.utility_vm, UtilityVmRole::Rosetta);
    }

    #[test]
    fn routes_arm64_and_unspecified_to_native_role() {
        assert_eq!(
            RoutingDecision::from_platform(WorkloadPlatform::LinuxArm64).utility_vm,
            UtilityVmRole::Native
        );
        assert_eq!(
            RoutingDecision::native_default().utility_vm,
            UtilityVmRole::Native
        );
    }

    #[test]
    fn container_create_prefers_query_platform_over_body() {
        let uri = "/containers/create?platform=linux/amd64".parse().unwrap();
        let body = Bytes::from_static(br#"{"Image":"alpine","Platform":"linux/arm64"}"#);
        let route = route_container_create(&uri, &body);
        assert_eq!(route.platform, WorkloadPlatform::LinuxAmd64);
        assert_eq!(route.utility_vm, UtilityVmRole::Rosetta);
    }

    #[test]
    fn container_create_uses_body_platform_when_query_absent() {
        let uri = "/containers/create".parse().unwrap();
        let body = Bytes::from_static(br#"{"Image":"alpine","Platform":"linux/amd64"}"#);
        let route = route_container_create(&uri, &body);
        assert_eq!(route.utility_vm, UtilityVmRole::Rosetta);
    }

    #[test]
    fn build_uses_query_platform() {
        let uri = "/build?t=image&platform=linux%2Famd64".parse().unwrap();
        let route = route_build(&uri);
        assert_eq!(route.platform, WorkloadPlatform::LinuxAmd64);
        assert_eq!(route.utility_vm, UtilityVmRole::Rosetta);
    }

    #[test]
    fn extracts_compose_project_from_labels() {
        let body = Bytes::from_static(
            br#"{"Image":"alpine","Labels":{"com.docker.compose.project":"myproj"}}"#,
        );
        assert_eq!(extract_compose_project(&body).as_deref(), Some("myproj"));
    }

    #[test]
    fn returns_none_when_no_compose_project_label() {
        let body = Bytes::from_static(br#"{"Image":"alpine"}"#);
        assert!(extract_compose_project(&body).is_none());
        let body = Bytes::from_static(br#"{"Image":"alpine","Labels":{"foo":"bar"}}"#);
        assert!(extract_compose_project(&body).is_none());
    }

    #[test]
    fn returns_none_when_compose_project_is_empty() {
        let body =
            Bytes::from_static(br#"{"Image":"alpine","Labels":{"com.docker.compose.project":""}}"#);
        assert!(extract_compose_project(&body).is_none());
    }

    #[test]
    fn native_can_host_arm64_and_unspecified_only() {
        assert!(UtilityVmRole::Native.can_host(WorkloadPlatform::LinuxArm64));
        assert!(UtilityVmRole::Native.can_host(WorkloadPlatform::Unspecified));
        assert!(!UtilityVmRole::Native.can_host(WorkloadPlatform::LinuxAmd64));
    }

    #[test]
    fn rosetta_can_host_every_platform() {
        assert!(UtilityVmRole::Rosetta.can_host(WorkloadPlatform::LinuxAmd64));
        assert!(UtilityVmRole::Rosetta.can_host(WorkloadPlatform::LinuxArm64));
        assert!(UtilityVmRole::Rosetta.can_host(WorkloadPlatform::Unspecified));
    }
}
