//! Handler-level Docker API tests against a mock guest dockerd — run in CI.
//!
//! Unlike the `api_*.rs` suites (which need a running daemon + guest and are
//! `#[ignore]`d), these build the real `create_router` with a `skip_vm_check`
//! runtime and a mock guest serving canned responses, so the full
//! handler → readiness → proxy path executes offline, including host-side
//! effects (DNS registration, name aliases, teardown).

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

const INSPECT_WEB: &str = r#"{
    "Id": "abc123",
    "Name": "/web",
    "Config": {"Labels": {}},
    "NetworkSettings": {"IPAddress": "172.17.0.2", "Networks": {}}
}"#;

fn lifecycle_routes() -> Vec<MockRoute> {
    vec![
        MockRoute {
            method: "GET",
            path: "/containers/json",
            status: 200,
            body: "[]",
        },
        MockRoute {
            method: "GET",
            path: "/containers/abc123/json",
            status: 200,
            body: INSPECT_WEB,
        },
        MockRoute {
            method: "POST",
            path: "/containers/abc123/start",
            status: 204,
            body: "",
        },
        MockRoute {
            method: "POST",
            path: "/containers/abc123/stop",
            status: 204,
            body: "",
        },
        MockRoute {
            method: "POST",
            path: "/containers/abc123/kill",
            status: 204,
            body: "",
        },
        MockRoute {
            method: "GET",
            path: "/containers/nope/json",
            status: 404,
            body: r#"{"message":"No such container: nope"}"#,
        },
    ]
}

async fn send(router: &axum::Router, method: &str, uri: &str) -> (StatusCode, bytes::Bytes) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

#[tokio::test]
async fn ping_and_list_proxy_through() {
    let (router, _runtime, _guest, _tmp) = router_with_mock_guest(lifecycle_routes()).await;

    // /_ping is answered by the mock's echo fallback (200, empty body).
    let (status, _) = send(&router, "GET", "/_ping").await;
    assert_eq!(status, StatusCode::OK);

    // Container list proxies to the canned empty list.
    let (status, body) = send(&router, "GET", "/containers/json").await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.as_array().map(Vec::len), Some(0));

    // A versioned path proxies too (guest dockerd strips its own prefix).
    let (status, _) = send(&router, "GET", "/v1.47/containers/json").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn guest_error_status_passes_through() {
    let (router, _runtime, _guest, _tmp) = router_with_mock_guest(lifecycle_routes()).await;

    let (status, body) = send(&router, "GET", "/containers/nope/json").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(String::from_utf8_lossy(&body).contains("No such container"));
}

#[tokio::test]
async fn start_stop_cycle_manages_host_networking() {
    let (router, runtime, _guest, _tmp) = router_with_mock_guest(lifecycle_routes()).await;

    // Start: proxied 204, then the handler inspects the container and
    // registers host state — DNS keyed by canonical ID plus the name alias.
    let (status, _) = send(&router, "POST", "/containers/abc123/start").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(runtime.registered_container_ids().await.contains("abc123"));
    assert_eq!(
        runtime.resolve_registered_container("web").await.as_deref(),
        Some("abc123"),
        "name alias must resolve after start"
    );

    // Stop BY NAME: the registry resolves the alias without a guest inspect
    // and tears down the canonical entry.
    let (status, _) = send(&router, "POST", "/containers/abc123/stop").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        runtime.registered_container_ids().await.is_empty(),
        "stop must tear down host networking"
    );
    assert_eq!(runtime.resolve_registered_container("web").await, None);
}

#[tokio::test]
async fn non_fatal_kill_keeps_host_networking() {
    let (router, runtime, _guest, _tmp) = router_with_mock_guest(lifecycle_routes()).await;

    let (status, _) = send(&router, "POST", "/containers/abc123/start").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(runtime.registered_container_ids().await.contains("abc123"));

    // SIGHUP reloads the container; it keeps running — host networking must
    // survive even though Docker returns 204.
    let (status, _) = send(&router, "POST", "/containers/abc123/kill?signal=SIGHUP").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        runtime.registered_container_ids().await.contains("abc123"),
        "a non-fatal kill signal must not tear down host networking"
    );

    // Default kill (SIGKILL) terminates → teardown.
    let (status, _) = send(&router, "POST", "/containers/abc123/kill").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(runtime.registered_container_ids().await.is_empty());
}
