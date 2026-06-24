//! Request handlers for Docker API endpoints.
//!
//! Most handlers forward requests to guest dockerd via the smart proxy.
//! System handlers (ping, version, info) also proxy directly to guest dockerd.
//! Docker events and lifecycle endpoints are proxied directly to guest dockerd.

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
/// recorded for that container. Returns a 409 Conflict if the URI
/// resolves to multiple utility VMs (ambiguous short ID); falls back to
/// native only when no role can be determined at all.
macro_rules! container_proxy_handler {
    ($name:ident) => {
        /// Forwards the request to the container's utility VM.
        ///
        /// # Errors
        ///
        /// Returns an error if the URI is ambiguous across utility VMs,
        /// if VM readiness fails, or if proxying to guest dockerd fails.
        pub async fn $name(
            axum::extract::State(state): axum::extract::State<crate::api::AppState>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
            req: axum::http::Request<axum::body::Body>,
        ) -> crate::error::Result<axum::response::Response> {
            let role = $crate::handlers::resolve_container_role(&state, &uri).await?;
            $crate::handlers::proxy_to_role(&state, role, &uri, req).await
        }
    };
}

/// Forwards an `/exec/{id}/...` request to the utility VM role recorded for
/// the originating container. Returns a 409 Conflict if the URI resolves
/// to multiple utility VMs.
macro_rules! exec_proxy_handler {
    ($name:ident) => {
        /// Forwards the request to the exec instance's utility VM.
        ///
        /// # Errors
        ///
        /// Returns an error if the URI is ambiguous across utility VMs,
        /// if VM readiness fails, or if proxying to guest dockerd fails.
        pub async fn $name(
            axum::extract::State(state): axum::extract::State<crate::api::AppState>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
            req: axum::http::Request<axum::body::Body>,
        ) -> crate::error::Result<axum::response::Response> {
            let role = $crate::handlers::resolve_exec_role(&state, &uri).await?;
            $crate::handlers::proxy_to_role(&state, role, &uri, req).await
        }
    };
}

pub(crate) use {container_proxy_handler, exec_proxy_handler, proxy_handler};

mod admission;
mod build;
mod container;
mod events;
mod exec;
mod identity;
mod image;
mod network;
mod proxying;
mod role_resolution;
mod system;
mod volume;

pub(crate) use admission::require_amd64_runtime;
pub(crate) use identity::{extract_container_id, extract_exec_id};
pub(crate) use proxying::{
    ensure_role_ready, proxy, proxy_to_role, proxy_upgrade_to_role, proxy_upload,
    proxy_upload_to_role,
};
pub(crate) use role_resolution::{
    resolve_container_role, resolve_exec_role, resolve_role_from_uri,
};

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
