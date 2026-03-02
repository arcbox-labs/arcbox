//! Docker API router.
//!
//! Implements Docker Engine API routing for all versions. Version prefixes
//! (e.g. `/v1.51/...`) are stripped by [`strip_api_version_prefix`] before
//! requests reach the Axum router, so a single set of unversioned routes
//! handles every API version.
//! See: <https://docs.docker.com/engine/api/>

use crate::handlers;
use crate::proxy;
use crate::trace::trace_id_middleware;
use arcbox_core::Runtime;
use axum::extract::OriginalUri;
use axum::{
    Router, middleware,
    routing::{delete, get, head, post},
};
use std::sync::Arc;

/// Application state shared with handlers.
#[derive(Clone)]
pub struct AppState {
    /// `ArcBox` runtime.
    pub runtime: Arc<Runtime>,
}

/// Creates the Docker API router with all endpoints.
///
/// The returned Router expects version-free paths (`/containers/{id}/start`).
/// Use [`strip_api_version_prefix`] as a `MapRequestLayer` around this Router
/// so that versioned paths (`/v1.51/containers/{id}/start`) are normalised
/// *before* Axum route matching.
pub fn create_router(runtime: Arc<Runtime>) -> Router {
    let state = AppState { runtime };

    api_routes()
        .fallback(proxy::proxy_fallback)
        .layer(middleware::from_fn(trace_id_middleware))
        .with_state(state)
}

/// Strips the Docker Engine API version prefix from a request URI.
///
/// Transforms `/v1.47/containers/{id}/start` → `/containers/{id}/start` so that
/// a single set of routes handles every API version. The original versioned URI
/// is saved as [`OriginalUri`] so proxy handlers can forward it verbatim.
///
/// Must be applied as a `tower::util::MapRequestLayer` *around* the Router
/// (not via `Router::layer`) so it runs before route matching.
pub fn strip_api_version_prefix<B>(mut req: axum::http::Request<B>) -> axum::http::Request<B> {
    let path = req.uri().path().to_owned();
    if let Some(stripped) = strip_version_prefix(&path) {
        let query = req.uri().query().map(str::to_owned);
        let original_uri = req.uri().clone();
        let new_pq = query.as_ref().map_or_else(
            || stripped.to_string(),
            |q| format!("{stripped}?{q}"),
        );

        // Preserve the original versioned URI for proxy forwarding.
        req.extensions_mut().insert(OriginalUri(original_uri));

        if let Ok(uri) = new_pq.parse() {
            *req.uri_mut() = uri;
        }
    }
    req
}

/// Returns the path with the `/v{major}.{minor}` prefix removed, or `None` if
/// the path does not start with a valid Docker API version prefix.
fn strip_version_prefix(path: &str) -> Option<&str> {
    let after_v = path.strip_prefix("/v")?;
    let dot = after_v.find('.')?;
    let after_dot = &after_v[dot + 1..];
    let slash = after_dot.find('/')?;

    let major = &after_v[..dot];
    let minor = &after_dot[..slash];
    if !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
    {
        Some(&after_dot[slash..])
    } else {
        None
    }
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
        .route("/containers/{id}/json", get(handlers::inspect_container))
        .route("/containers/{id}/start", post(handlers::start_container))
        .route("/containers/{id}/stop", post(handlers::stop_container))
        .route("/containers/{id}/restart", post(handlers::restart_container))
        .route("/containers/{id}/kill", post(handlers::kill_container))
        .route("/containers/{id}/pause", post(handlers::pause_container))
        .route("/containers/{id}/unpause", post(handlers::unpause_container))
        .route("/containers/{id}/rename", post(handlers::rename_container))
        .route("/containers/{id}/wait", post(handlers::wait_container))
        .route("/containers/{id}/logs", get(handlers::container_logs))
        .route("/containers/{id}/top", get(handlers::container_top))
        .route("/containers/{id}/stats", get(handlers::container_stats))
        .route("/containers/{id}/changes", get(handlers::container_changes))
        .route("/containers/{id}/attach", post(handlers::attach_container))
        .route("/containers/{id}", delete(handlers::remove_container))
        .route("/containers/{id}/exec", post(handlers::exec_create))
        .route("/exec/{id}/start", post(handlers::exec_start))
        .route("/exec/{id}/resize", post(handlers::exec_resize))
        .route("/exec/{id}/json", get(handlers::exec_inspect))
        .route("/images/json", get(handlers::list_images))
        .route("/images/create", post(handlers::pull_image))
        .route("/images/{id}/json", get(handlers::inspect_image))
        .route("/images/{id}", delete(handlers::remove_image))
        .route("/images/{id}/tag", post(handlers::tag_image))
        .route("/networks", get(handlers::list_networks))
        .route("/networks/create", post(handlers::create_network))
        .route("/networks/{id}", get(handlers::inspect_network))
        .route("/networks/{id}", delete(handlers::remove_network))
        .route("/volumes", get(handlers::list_volumes))
        .route("/volumes/create", post(handlers::create_volume))
        .route("/volumes/prune", post(handlers::prune_volumes))
        .route("/volumes/{name}", get(handlers::inspect_volume))
        .route("/volumes/{name}", delete(handlers::remove_volume))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_standard_version_prefix() {
        assert_eq!(
            strip_version_prefix("/v1.51/containers/abc/start"),
            Some("/containers/abc/start")
        );
        assert_eq!(
            strip_version_prefix("/v1.24/images/json"),
            Some("/images/json")
        );
        assert_eq!(
            strip_version_prefix("/v1.99/containers/abc/start"),
            Some("/containers/abc/start")
        );
    }

    #[test]
    fn strip_preserves_unversioned_paths() {
        assert_eq!(strip_version_prefix("/containers/abc/start"), None);
        assert_eq!(strip_version_prefix("/_ping"), None);
        assert_eq!(strip_version_prefix("/version"), None);
    }

    #[test]
    fn strip_rejects_malformed_versions() {
        assert_eq!(strip_version_prefix("/v1x/containers/json"), None);
        assert_eq!(strip_version_prefix("/vabc.def/containers/json"), None);
        assert_eq!(strip_version_prefix("/v/containers/json"), None);
        assert_eq!(strip_version_prefix("/v1./containers/json"), None);
    }

    #[test]
    fn strip_rejects_version_only_path() {
        // No trailing slash after version → no route to strip to.
        assert_eq!(strip_version_prefix("/v1.51"), None);
    }

    #[test]
    fn strip_api_version_prefix_preserves_query_string() {
        let req = axum::http::Request::builder()
            .uri("/v1.51/containers/json?all=true&limit=10")
            .body(())
            .unwrap();
        let req = strip_api_version_prefix(req);
        assert_eq!(req.uri(), "/containers/json?all=true&limit=10");
    }

    #[test]
    fn strip_api_version_prefix_sets_original_uri() {
        let req = axum::http::Request::builder()
            .uri("/v1.51/containers/abc/start")
            .body(())
            .unwrap();
        let req = strip_api_version_prefix(req);
        assert_eq!(req.uri().path(), "/containers/abc/start");
        let original = req.extensions().get::<OriginalUri>().unwrap();
        assert_eq!(original.0.path(), "/v1.51/containers/abc/start");
    }

    #[test]
    fn strip_api_version_prefix_noop_for_unversioned() {
        let req = axum::http::Request::builder()
            .uri("/containers/abc/start")
            .body(())
            .unwrap();
        let req = strip_api_version_prefix(req);
        assert_eq!(req.uri().path(), "/containers/abc/start");
        assert!(req.extensions().get::<OriginalUri>().is_none());
    }
}
