//! Router-level coverage for the Docker API compat layer.
//!
//! The router handles a handful of mutating container operations locally and
//! proxies everything else to guest dockerd via a `fallback`. These tests build
//! the real `create_router` and assert its *routing* (which method+path reaches
//! the proxy vs. is handled/rejected locally) — WITHOUT a guest dockerd. Route
//! matching happens before any handler runs, so a mis-routed (shadowed) request
//! returns 405 instantly, while a correctly-proxied one reaches the handler and
//! fails at guest connect — either way it is not the router's 405.
//!
//! This is the class of test that was missing: the whole `api_*.rs` suite is
//! `#[ignore]`d (needs a running daemon + guest), so the routing surface —
//! including the `GET /containers/json` shadow bug — went unverified for months.

use arcbox_core::{Config, Runtime, VmLifecycleConfig};
use arcbox_docker::api::{create_router, strip_api_version_prefix};
use arcbox_docker::proxy::VsockConnector;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;

// Builds the real router without initializing the runtime: method-vs-path
// routing is resolved before any handler runs, so a shadowed request 405s
// instantly and never touches runtime state.
fn router() -> (axum::Router, TempDir) {
    let tmp = TempDir::new().unwrap();
    let config = Config {
        data_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let vm_lifecycle_config = VmLifecycleConfig {
        skip_vm_check: true,
        ..Default::default()
    };
    let runtime = Arc::new(
        Runtime::with_vm_lifecycle_config(config, vm_lifecycle_config).expect("create runtime"),
    );
    let connector = Arc::new(VsockConnector::new(Arc::clone(&runtime)));
    (create_router(runtime, connector), tmp)
}

/// Returns the router's status for a request, or `None` if it reached the proxy
/// and blocked/timed out on guest readiness (which also means "not a router
/// 405"). `strip_version` mirrors the production `MapRequestLayer` that
/// normalises `/v1.xx/...` before route matching.
async fn status_of(method: &str, uri: &str, strip_version: bool) -> Option<StatusCode> {
    let (app, _tmp) = router();
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    if strip_version {
        request = strip_api_version_prefix(request);
    }
    tokio::time::timeout(Duration::from_secs(3), app.oneshot(request))
        .await
        .ok()
        .map(|response| response.unwrap().status())
}

/// Endpoint reaches the proxy (or a local handler) — i.e. NOT the router's 405.
async fn assert_reaches_backend(method: &str, uri: &str) {
    if let Some(status) = status_of(method, uri, false).await {
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {uri} was 405 — shadowed by a local route instead of proxied"
        );
    }
}

#[tokio::test]
async fn proxied_surface_is_not_shadowed() {
    // Single-segment collection endpoints under /containers/ that axum's
    // `{id}` capture can shadow (the historical bug was json + prune).
    assert_reaches_backend("GET", "/containers/json").await;
    assert_reaches_backend("POST", "/containers/prune").await;

    // Other resource collections fall straight through to the proxy. Asserted
    // here so that adding a future `/{images,networks,volumes}/{id}` route
    // can't silently shadow them.
    assert_reaches_backend("GET", "/images/json").await;
    assert_reaches_backend("GET", "/networks").await;
    assert_reaches_backend("GET", "/volumes").await;

    // The local /networks/{id}/connect|disconnect routes are two-segment and
    // must not shadow the single-segment or bare network endpoints.
    assert_reaches_backend("POST", "/networks/create").await;
    assert_reaches_backend("POST", "/networks/prune").await;
    assert_reaches_backend("GET", "/networks/abc").await;
    assert_reaches_backend("DELETE", "/networks/abc").await;
    assert_reaches_backend("POST", "/networks/abc/connect").await;
    assert_reaches_backend("POST", "/networks/abc/disconnect").await;

    // System + streaming endpoints.
    assert_reaches_backend("GET", "/_ping").await;
    assert_reaches_backend("HEAD", "/_ping").await;
    assert_reaches_backend("GET", "/version").await;
    assert_reaches_backend("GET", "/info").await;
    assert_reaches_backend("GET", "/events").await;

    // Two-segment container endpoints (inspect/logs/stats) don't collide with
    // the static-second-segment lifecycle routes, so they proxy.
    assert_reaches_backend("GET", "/containers/abc/json").await;
    assert_reaches_backend("GET", "/containers/abc/logs").await;
}

#[tokio::test]
async fn delete_on_collection_named_paths_is_not_shadowed() {
    // `DELETE /containers/json` removes a container literally named "json";
    // this only pins that such requests are not 405-shadowed. Whether DELETE
    // actually reaches the local remove handler (with its host teardown) is
    // asserted behaviorally in api_handlers_mock.rs — a routing-level status
    // check cannot distinguish the local handler from the proxy fallback.
    assert_reaches_backend("DELETE", "/containers/json").await;
    assert_reaches_backend("DELETE", "/containers/prune").await;
}

#[tokio::test]
async fn versioned_paths_route_after_prefix_strip() {
    // With the version prefix stripped (as production does), a versioned list
    // request must route exactly like its unversioned form.
    assert_eq!(
        status_of("GET", "/v1.43/containers/json", true).await,
        status_of("GET", "/containers/json", false).await,
    );
}

#[tokio::test]
async fn wrong_method_on_lifecycle_route_stays_405() {
    // The method-fallback is scoped to `/containers/{id}` only. A wrong method
    // on a lifecycle route is rejected locally rather than proxied, so it can't
    // bypass the local admission/networking hooks.
    assert_eq!(
        status_of("GET", "/containers/abc/start", false).await,
        Some(StatusCode::METHOD_NOT_ALLOWED),
    );
    assert_eq!(
        status_of("PUT", "/containers/abc/stop", false).await,
        Some(StatusCode::METHOD_NOT_ALLOWED),
    );
}
