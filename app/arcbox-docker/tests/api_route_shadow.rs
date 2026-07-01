//! Regression: single-segment static container endpoints must proxy, not be
//! shadowed by the `DELETE /containers/{id}` route.
//!
//! axum's `{id}` capture also matches `GET /containers/json` (list) and
//! `POST /containers/prune`; without `method_not_allowed_fallback` those return
//! `405 Method Not Allowed` instead of proxying to guest dockerd.

use arcbox_core::{Config, Runtime, VmLifecycleConfig};
use arcbox_docker::api::create_router;
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

async fn status_of(method: &str, uri: &str) -> Option<StatusCode> {
    let (app, _tmp) = router();
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    // A locally-rejected request (405) or a fast local handler returns promptly.
    // A proxied request reaches guest dockerd and — with no guest in tests —
    // errors or blocks; `None` (timeout) therefore means "reached the proxy".
    tokio::time::timeout(Duration::from_secs(3), app.oneshot(request))
        .await
        .ok()
        .map(|response| response.unwrap().status())
}

async fn assert_proxied(method: &str, uri: &str) {
    // Proxied => not the instant 405 the `/containers/{id}` shadow used to give.
    if let Some(status) = status_of(method, uri).await {
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {uri} is method-shadowed by /containers/{{id}}"
        );
    }
}

#[tokio::test]
async fn list_containers_is_proxied_not_shadowed() {
    assert_proxied("GET", "/containers/json").await;
}

#[tokio::test]
async fn prune_containers_is_proxied_not_shadowed() {
    assert_proxied("POST", "/containers/prune").await;
}

#[tokio::test]
async fn delete_container_named_like_a_static_endpoint_is_local() {
    // `DELETE /containers/json` removes a container literally named "json" and
    // must still hit the local remove handler (which does host teardown), not
    // proxy — i.e. it is not shadowed away.
    assert_proxied("DELETE", "/containers/json").await;
}

#[tokio::test]
async fn wrong_method_on_lifecycle_route_stays_405() {
    // The method-fallback is scoped to `/containers/{id}` only: a wrong method
    // on a lifecycle route is rejected locally rather than proxied, so it does
    // not silently bypass the local admission/networking hooks.
    assert_eq!(
        status_of("GET", "/containers/abc/start").await,
        Some(StatusCode::METHOD_NOT_ALLOWED),
    );
}
