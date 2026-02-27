//! Request handlers for Docker API endpoints.
//!
//! Most handlers forward requests to guest dockerd via the smart proxy.
//! Host-only handlers (ping, version, info) respond from host state.
//! Docker events and lifecycle endpoints are proxied directly to guest dockerd.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::proxy;
use axum::body::Body;
use axum::http::{Request, Uri};
use axum::response::Response;

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

pub(crate) use proxy_handler;

/// Forward a request to guest dockerd, ensuring the VM is running first.
pub(crate) async fn proxy(state: &AppState, uri: &Uri, req: Request<Body>) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {e}")))?;
    proxy::proxy_to_guest_stream(&state.runtime, uri, req).await
}

/// Forward an upgraded request to guest dockerd, ensuring the VM is running first.
pub(crate) async fn proxy_upgrade(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {e}")))?;
    proxy::proxy_with_upgrade(&state.runtime, req, uri).await
}

mod container;
mod events;
mod exec;
mod image;
mod network;
mod system;
mod volume;

pub use container::{
    attach_container, container_changes, container_logs, container_stats, container_top,
    create_container, inspect_container, kill_container, list_containers, pause_container,
    prune_containers, remove_container, rename_container, restart_container, start_container,
    stop_container, unpause_container, wait_container,
};
pub use events::events;
pub use exec::{exec_create, exec_inspect, exec_resize, exec_start};
pub use image::{inspect_image, list_images, pull_image, remove_image, tag_image};
pub use network::{create_network, inspect_network, list_networks, remove_network};
pub use system::{get_info, get_version, ping};
pub use volume::{create_volume, inspect_volume, list_volumes, prune_volumes, remove_volume};
