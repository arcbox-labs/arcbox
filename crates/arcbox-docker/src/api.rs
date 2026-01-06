//! Docker API router.
//!
//! Implements Docker Engine API v1.43 routing.
//! See: https://docs.docker.com/engine/api/v1.43/

use crate::handlers;
use arcbox_core::Runtime;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

/// Application state shared with handlers.
#[derive(Clone)]
pub struct AppState {
    /// ArcBox runtime.
    pub runtime: Arc<Runtime>,
}

/// Creates the Docker API router with all endpoints.
#[must_use]
pub fn create_router(runtime: Arc<Runtime>) -> Router {
    let state = AppState { runtime };

    Router::new()
        // System endpoints
        .route("/version", get(handlers::get_version))
        .route("/info", get(handlers::get_info))
        .route("/_ping", get(handlers::ping))
        .route("/_ping", axum::routing::head(handlers::ping))
        // Container endpoints
        .route("/containers/json", get(handlers::list_containers))
        .route("/containers/create", post(handlers::create_container))
        .route("/containers/{id}/json", get(handlers::inspect_container))
        .route("/containers/{id}/start", post(handlers::start_container))
        .route("/containers/{id}/stop", post(handlers::stop_container))
        .route("/containers/{id}/restart", post(handlers::restart_container))
        .route("/containers/{id}/kill", post(handlers::kill_container))
        .route("/containers/{id}/wait", post(handlers::wait_container))
        .route("/containers/{id}/logs", get(handlers::container_logs))
        .route("/containers/{id}", delete(handlers::remove_container))
        // Exec endpoints
        .route("/containers/{id}/exec", post(handlers::exec_create))
        .route("/exec/{id}/start", post(handlers::exec_start))
        .route("/exec/{id}/resize", post(handlers::exec_resize))
        .route("/exec/{id}/json", get(handlers::exec_inspect))
        // Image endpoints
        .route("/images/json", get(handlers::list_images))
        .route("/images/create", post(handlers::pull_image))
        .route("/images/{id}/json", get(handlers::inspect_image))
        .route("/images/{id}", delete(handlers::remove_image))
        .route("/images/{id}/tag", post(handlers::tag_image))
        // Network endpoints
        .route("/networks", get(handlers::list_networks))
        .route("/networks/create", post(handlers::create_network))
        .route("/networks/{id}", get(handlers::inspect_network))
        .route("/networks/{id}", delete(handlers::remove_network))
        // Volume endpoints
        .route("/volumes", get(handlers::list_volumes))
        .route("/volumes/create", post(handlers::create_volume))
        .route("/volumes/{name}", get(handlers::inspect_volume))
        .route("/volumes/{name}", delete(handlers::remove_volume))
        // Versioned API routes (Docker compatibility)
        // Support versions from 1.24 (MIN_API_VERSION) to 1.43 (API_VERSION)
        .nest("/v1.43", versioned_router())
        .nest("/v1.42", versioned_router())
        .nest("/v1.41", versioned_router())
        .nest("/v1.40", versioned_router())
        .nest("/v1.39", versioned_router())
        .nest("/v1.38", versioned_router())
        .nest("/v1.37", versioned_router())
        .nest("/v1.36", versioned_router())
        .nest("/v1.35", versioned_router())
        .nest("/v1.34", versioned_router())
        .nest("/v1.33", versioned_router())
        .nest("/v1.32", versioned_router())
        .nest("/v1.31", versioned_router())
        .nest("/v1.30", versioned_router())
        .nest("/v1.29", versioned_router())
        .nest("/v1.28", versioned_router())
        .nest("/v1.27", versioned_router())
        .nest("/v1.26", versioned_router())
        .nest("/v1.25", versioned_router())
        .nest("/v1.24", versioned_router())
        .with_state(state)
}

/// Creates versioned router with same endpoints as root.
fn versioned_router() -> Router<AppState> {
    Router::new()
        // System
        .route("/version", get(handlers::get_version))
        .route("/info", get(handlers::get_info))
        .route("/_ping", get(handlers::ping))
        // Containers
        .route("/containers/json", get(handlers::list_containers))
        .route("/containers/create", post(handlers::create_container))
        .route("/containers/{id}/json", get(handlers::inspect_container))
        .route("/containers/{id}/start", post(handlers::start_container))
        .route("/containers/{id}/stop", post(handlers::stop_container))
        .route("/containers/{id}/restart", post(handlers::restart_container))
        .route("/containers/{id}/kill", post(handlers::kill_container))
        .route("/containers/{id}/wait", post(handlers::wait_container))
        .route("/containers/{id}/logs", get(handlers::container_logs))
        .route("/containers/{id}", delete(handlers::remove_container))
        // Exec
        .route("/containers/{id}/exec", post(handlers::exec_create))
        .route("/exec/{id}/start", post(handlers::exec_start))
        .route("/exec/{id}/resize", post(handlers::exec_resize))
        .route("/exec/{id}/json", get(handlers::exec_inspect))
        // Images
        .route("/images/json", get(handlers::list_images))
        .route("/images/create", post(handlers::pull_image))
        .route("/images/{id}/json", get(handlers::inspect_image))
        .route("/images/{id}", delete(handlers::remove_image))
        .route("/images/{id}/tag", post(handlers::tag_image))
        // Networks
        .route("/networks", get(handlers::list_networks))
        .route("/networks/create", post(handlers::create_network))
        .route("/networks/{id}", get(handlers::inspect_network))
        .route("/networks/{id}", delete(handlers::remove_network))
        // Volumes
        .route("/volumes", get(handlers::list_volumes))
        .route("/volumes/create", post(handlers::create_volume))
        .route("/volumes/{name}", get(handlers::inspect_volume))
        .route("/volumes/{name}", delete(handlers::remove_volume))
}
