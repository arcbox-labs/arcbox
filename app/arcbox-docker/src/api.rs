//! Docker API router.
//!
//! Implements Docker Engine API v1.43 routing.
//! See: https://docs.docker.com/engine/api/v1.43/

use crate::handlers;
use crate::proxy;
use crate::trace::trace_id_middleware;
use arcbox_core::Runtime;
use axum::{
    Router, middleware,
    routing::{delete, get, head, post},
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

    let mut router = api_routes();
    for minor in 24..=43 {
        router = router.nest(&format!("/v1.{minor}"), api_routes());
    }

    router
        .fallback(proxy::proxy_fallback)
        .layer(middleware::from_fn(trace_id_middleware))
        .with_state(state)
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/version", get(handlers::get_version))
        .route("/info", get(handlers::get_info))
        .route("/_ping", get(handlers::ping))
        .route("/_ping", head(handlers::ping))
        .route("/events", get(handlers::events))
        .route("/containers/json", get(handlers::list_containers))
        .route("/containers/create", post(handlers::create_container))
        .route("/containers/prune", post(handlers::prune_containers))
        .route("/containers/:id/json", get(handlers::inspect_container))
        .route("/containers/:id/start", post(handlers::start_container))
        .route("/containers/:id/stop", post(handlers::stop_container))
        .route("/containers/:id/restart", post(handlers::restart_container))
        .route("/containers/:id/kill", post(handlers::kill_container))
        .route("/containers/:id/pause", post(handlers::pause_container))
        .route("/containers/:id/unpause", post(handlers::unpause_container))
        .route("/containers/:id/rename", post(handlers::rename_container))
        .route("/containers/:id/wait", post(handlers::wait_container))
        .route("/containers/:id/logs", get(handlers::container_logs))
        .route("/containers/:id/top", get(handlers::container_top))
        .route("/containers/:id/stats", get(handlers::container_stats))
        .route("/containers/:id/changes", get(handlers::container_changes))
        .route("/containers/:id/attach", post(handlers::attach_container))
        .route("/containers/:id", delete(handlers::remove_container))
        .route("/containers/:id/exec", post(handlers::exec_create))
        .route("/exec/:id/start", post(handlers::exec_start))
        .route("/exec/:id/resize", post(handlers::exec_resize))
        .route("/exec/:id/json", get(handlers::exec_inspect))
        .route("/images/json", get(handlers::list_images))
        .route("/images/create", post(handlers::pull_image))
        .route("/images/:id/json", get(handlers::inspect_image))
        .route("/images/:id", delete(handlers::remove_image))
        .route("/images/:id/tag", post(handlers::tag_image))
        .route("/networks", get(handlers::list_networks))
        .route("/networks/create", post(handlers::create_network))
        .route("/networks/:id", get(handlers::inspect_network))
        .route("/networks/:id", delete(handlers::remove_network))
        .route("/volumes", get(handlers::list_volumes))
        .route("/volumes/create", post(handlers::create_volume))
        .route("/volumes/prune", post(handlers::prune_volumes))
        .route("/volumes/:name", get(handlers::inspect_volume))
        .route("/volumes/:name", delete(handlers::remove_volume))
}
