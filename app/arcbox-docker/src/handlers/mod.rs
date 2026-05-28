//! Request handlers for Docker API endpoints.
//!
//! Most handlers forward requests to guest dockerd via the smart proxy.
//! System handlers (ping, version, info) also proxy directly to guest dockerd.
//! Docker events and lifecycle endpoints are proxied directly to guest dockerd.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::proxy;
use crate::routing::UtilityVmRole;
use axum::body::Body;
use axum::http::{Request, Uri};
use axum::response::Response;

/// Forwards a request that has no per-workload identity (e.g. `/_ping`,
/// `/containers/json`, `/images/json`). These hit the native default role
/// while the connector still resolves both roles to the same VM.
macro_rules! proxy_handler {
    ($name:ident) => {
        /// Forwards the request to guest dockerd.
        ///
        /// # Errors
        ///
        /// Returns an error if VM readiness fails or proxying to guest dockerd fails.
        pub async fn $name(
            axum::extract::State(state): axum::extract::State<crate::api::AppState>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
            req: axum::http::Request<axum::body::Body>,
        ) -> crate::error::Result<axum::response::Response> {
            $crate::handlers::proxy(&state, &uri, req).await
        }
    };
}

/// Forwards a `/containers/{id}/...` request to the utility VM role
/// recorded for that container, falling back to `native` when no record
/// exists (pre-existing or post-restart workloads).
macro_rules! container_proxy_handler {
    ($name:ident) => {
        /// Forwards the request to the container's utility VM.
        ///
        /// # Errors
        ///
        /// Returns an error if VM readiness fails or proxying to guest dockerd fails.
        pub async fn $name(
            axum::extract::State(state): axum::extract::State<crate::api::AppState>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
            req: axum::http::Request<axum::body::Body>,
        ) -> crate::error::Result<axum::response::Response> {
            let role = $crate::handlers::resolve_container_role(&state, &uri).await;
            $crate::handlers::proxy_to_role(&state, role, &uri, req).await
        }
    };
}

/// Forwards an `/exec/{id}/...` request to the utility VM role recorded for
/// the originating container, falling back to `native` when no record exists.
macro_rules! exec_proxy_handler {
    ($name:ident) => {
        /// Forwards the request to the exec instance's utility VM.
        ///
        /// # Errors
        ///
        /// Returns an error if VM readiness fails or proxying to guest dockerd fails.
        pub async fn $name(
            axum::extract::State(state): axum::extract::State<crate::api::AppState>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
            req: axum::http::Request<axum::body::Body>,
        ) -> crate::error::Result<axum::response::Response> {
            let role = $crate::handlers::resolve_exec_role(&state, &uri).await;
            $crate::handlers::proxy_to_role(&state, role, &uri, req).await
        }
    };
}

pub(crate) use {container_proxy_handler, exec_proxy_handler, proxy_handler};

/// Extracts the `{id}` token from a `/containers/{id}/...` URI, ignoring
/// collection endpoints (`/containers/json|create|prune`).
#[must_use]
pub(crate) fn extract_container_id(uri: &Uri) -> Option<String> {
    extract_id_after_segment(uri, "containers", &["json", "create", "prune"])
}

/// Extracts the `{id}` token from an `/exec/{id}/...` URI.
#[must_use]
pub(crate) fn extract_exec_id(uri: &Uri) -> Option<String> {
    extract_id_after_segment(uri, "exec", &[])
}

fn extract_id_after_segment(uri: &Uri, segment: &str, skip_tokens: &[&str]) -> Option<String> {
    let segments: Vec<&str> = uri.path().split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segments.iter().enumerate() {
        if *seg == segment && i + 1 < segments.len() {
            let id = segments[i + 1];
            if !skip_tokens.contains(&id) {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Resolves the utility VM role for a `/containers/{id}/...` URI from the
/// in-process workload registry, falling back to `native`.
pub(crate) async fn resolve_container_role(state: &AppState, uri: &Uri) -> UtilityVmRole {
    let Some(id) = extract_container_id(uri) else {
        return UtilityVmRole::Native;
    };
    state
        .workload_roles
        .lookup(&id)
        .await
        .unwrap_or(UtilityVmRole::Native)
}

/// Resolves the utility VM role for an `/exec/{id}/...` URI from the
/// in-process workload registry, falling back to `native`.
pub(crate) async fn resolve_exec_role(state: &AppState, uri: &Uri) -> UtilityVmRole {
    let Some(id) = extract_exec_id(uri) else {
        return UtilityVmRole::Native;
    };
    state
        .workload_roles
        .lookup(&id)
        .await
        .unwrap_or(UtilityVmRole::Native)
}

/// Forward a request to guest dockerd, ensuring the VM is running first.
pub(crate) async fn proxy(state: &AppState, uri: &Uri, req: Request<Body>) -> Result<Response> {
    proxy_to_role(state, UtilityVmRole::Native, uri, req).await
}

/// Forward a request to a selected utility VM's guest dockerd.
pub(crate) async fn proxy_to_role(
    state: &AppState,
    role: UtilityVmRole,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {e}")))?;
    proxy::proxy_to_guest_stream_for_role(state.connector.as_ref(), role, uri, req).await
}

/// Forward an upload request to guest dockerd, ensuring the VM is running first.
pub(crate) async fn proxy_upload(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    proxy_upload_to_role(state, UtilityVmRole::Native, uri, req).await
}

/// Forward an upload request to a selected utility VM's guest dockerd.
pub(crate) async fn proxy_upload_to_role(
    state: &AppState,
    role: UtilityVmRole,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {e}")))?;
    proxy::proxy_streaming_upload_for_role(state.connector.as_ref(), role, uri, req).await
}

/// Forward an upgraded request to guest dockerd, ensuring the VM is running first.
pub(crate) async fn proxy_upgrade(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    proxy_upgrade_to_role(state, UtilityVmRole::Native, uri, req).await
}

/// Forward an upgraded request to a selected utility VM's guest dockerd.
pub(crate) async fn proxy_upgrade_to_role(
    state: &AppState,
    role: UtilityVmRole,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {e}")))?;
    proxy::proxy_with_upgrade_for_role(state.connector.as_ref(), role, req, uri).await
}

mod build;
mod container;
mod events;
mod exec;
mod image;
mod network;
mod system;
mod volume;

pub use build::{build_image, build_prune, session};
pub use container::{
    attach_container, container_changes, container_logs, container_stats, container_top,
    create_container, extract_container_dns_info, inspect_container, kill_container,
    list_containers, pause_container, prune_containers, remove_container, rename_container,
    restart_container, start_container, stop_container, unpause_container, wait_container,
};
pub use events::events;
pub use exec::{exec_create, exec_inspect, exec_resize, exec_start};
pub use image::{inspect_image, list_images, load_image, pull_image, remove_image, tag_image};
pub use network::{create_network, inspect_network, list_networks, remove_network};
pub use system::{get_info, get_version, ping};
pub use volume::{create_volume, inspect_volume, list_volumes, prune_volumes, remove_volume};

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn extract_exec_id_from_simple_path() {
        assert_eq!(
            extract_exec_id(&uri("/exec/exec-abc/start")).as_deref(),
            Some("exec-abc"),
        );
    }

    #[test]
    fn extract_exec_id_from_versioned_path() {
        assert_eq!(
            extract_exec_id(&uri("/v1.51/exec/exec-xyz/resize?w=80&h=24")).as_deref(),
            Some("exec-xyz"),
        );
    }

    #[test]
    fn extract_exec_id_ignores_non_exec_paths() {
        assert_eq!(extract_exec_id(&uri("/containers/abc/start")), None);
    }

    #[test]
    fn extract_container_id_from_exec_subpath() {
        assert_eq!(
            extract_container_id(&uri("/containers/abc/exec")).as_deref(),
            Some("abc"),
        );
    }
}
