//! Docker API router.
//!
//! Implements Docker Engine API routing for all versions. Version prefixes
//! (e.g. `/v1.51/...`) are stripped by [`strip_api_version_prefix`] before
//! requests reach the Axum router, so a single set of unversioned routes
//! handles every API version.
//! See: <https://docs.docker.com/engine/api/>

use crate::handlers;
use crate::proxy;
use crate::proxy::{GuestConnector, ProxyState};
use crate::trace::trace_id_middleware;
use arcbox_core::Runtime;
use axum::extract::OriginalUri;
use axum::{
    Router, middleware,
    routing::{delete, post},
};
use std::sync::Arc;

/// Application state shared with handlers.
#[derive(Clone)]
pub struct AppState {
    /// `ArcBox` runtime.
    pub runtime: Arc<Runtime>,
    /// Guest proxy transport state.
    pub proxy: Arc<ProxyState>,
}

/// Creates the Docker API router with all endpoints.
///
/// The returned Router expects version-free paths (`/containers/{id}/start`).
/// Use [`strip_api_version_prefix`] as a `MapRequestLayer` around this Router
/// so that versioned paths (`/v1.51/containers/{id}/start`) are normalised
/// *before* Axum route matching.
///
/// Only a handful of mutating operations are handled locally; everything else
/// proxies to guest dockerd via the router `fallback` (unmatched paths). The
/// `/containers/{id}` route additionally proxies unhandled *methods* on its own
/// path — see [`container_routes`] — because its `{id}` capture shadows the
/// single-segment static endpoints `GET /containers/json` and
/// `POST /containers/prune`.
pub fn create_router(runtime: Arc<Runtime>, connector: Arc<dyn GuestConnector>) -> Router {
    let state = AppState {
        runtime,
        proxy: Arc::new(ProxyState::new(connector)),
    };

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
        let new_pq = query
            .as_ref()
            .map_or_else(|| stripped.to_string(), |q| format!("{stripped}?{q}"));

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
        .merge(container_routes())
        .route("/build", post(handlers::build_image))
}

fn container_routes() -> Router<AppState> {
    Router::new()
        .route("/containers/create", post(handlers::create_container))
        .route("/containers/{id}/start", post(handlers::start_container))
        .route("/containers/{id}/stop", post(handlers::stop_container))
        .route(
            "/containers/{id}/restart",
            post(handlers::restart_container),
        )
        .route("/containers/{id}/kill", post(handlers::kill_container))
        .route("/containers/{id}/rename", post(handlers::rename_container))
        // `{id}` also matches the single-segment static endpoints
        // `GET /containers/json` (list) and `POST /containers/prune`, whose
        // methods aren't DELETE. Proxy any non-DELETE method on *this* path to
        // guest dockerd so those aren't shadowed into a 405 — scoped here so the
        // lifecycle routes above still reject wrong methods locally rather than
        // proxying them. `DELETE /containers/{id}` (incl. a container literally
        // named "json"/"prune") still routes to the local remove handler.
        .route(
            "/containers/{id}",
            delete(handlers::remove_container).fallback(proxy::proxy_fallback),
        )
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
