//! Integration tests for the Docker proxy layer.
//!
//! These tests use a mock guest dockerd on a Unix socket so they run
//! without a VM. They call proxy functions directly (bypassing the
//! handler layer's `ensure_vm_ready`) to isolate proxy forwarding logic.

mod support;
use support::mock_guest::{self, MockGuest, UnixSocketConnector};

use arcbox_docker::proxy::{
    GuestHttpClient, proxy_to_guest_pooled, proxy_to_guest_stream_pooled, proxy_with_upgrade,
};
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use bytes::Bytes;
use http_body_util::BodyExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tempfile::TempDir;

// =============================================================================
// Test helpers
// =============================================================================

async fn setup() -> (UnixSocketConnector, MockGuest, TempDir) {
    let tmp = TempDir::new().unwrap();
    let guest = mock_guest::start(tmp.path()).await;
    let connector = UnixSocketConnector::new(guest.socket_path.clone());
    (connector, guest, tmp)
}

// =============================================================================
// Tests — proxy_to_guest_pooled (buffered forwarding)
// =============================================================================

#[tokio::test]
async fn proxy_to_guest_echoes_body() {
    let (connector, guest, _tmp) = setup().await;
    let client = GuestHttpClient::new(Arc::new(connector));

    let payload = r#"{"Image":"alpine:latest"}"#;
    let resp = proxy_to_guest_pooled(
        &client,
        Method::POST,
        "/containers/create",
        &HeaderMap::new(),
        Bytes::from(payload),
    )
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, payload.as_bytes());
    guest.cancel.cancel();
}

#[tokio::test]
async fn proxy_to_guest_empty_body() {
    let (connector, guest, _tmp) = setup().await;
    let client = GuestHttpClient::new(Arc::new(connector));

    let resp = proxy_to_guest_pooled(
        &client,
        Method::GET,
        "/containers/json",
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    guest.cancel.cancel();
}

#[tokio::test]
async fn pooled_proxy_reuses_http_session_after_body_eof() {
    let (connector, guest, _tmp) = setup().await;
    let client = GuestHttpClient::new(Arc::new(connector.clone()));

    for path in ["/containers/json", "/images/json"] {
        let resp =
            proxy_to_guest_pooled(&client, Method::GET, path, &HeaderMap::new(), Bytes::new())
                .await
                .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await.unwrap();
    }

    assert_eq!(connector.connect_count.load(Ordering::Relaxed), 1);
    guest.cancel.cancel();
}

#[tokio::test]
async fn pooled_proxy_discards_session_when_body_is_dropped_early() {
    let (connector, guest, _tmp) = setup().await;
    let client = GuestHttpClient::new(Arc::new(connector.clone()));

    let resp = proxy_to_guest_pooled(
        &client,
        Method::POST,
        "/containers/create",
        &HeaderMap::new(),
        Bytes::from(vec![b'x'; 1024 * 1024]),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    drop(resp);

    let resp = proxy_to_guest_pooled(
        &client,
        Method::GET,
        "/containers/json",
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    .unwrap();
    let _ = resp.into_body().collect().await.unwrap();

    assert_eq!(connector.connect_count.load(Ordering::Relaxed), 2);
    guest.cancel.cancel();
}

// =============================================================================
// Tests — proxy_to_guest_stream_pooled (streaming forwarding)
// =============================================================================

#[tokio::test]
async fn proxy_stream_forwards_body() {
    let (connector, guest, _tmp) = setup().await;
    let client = GuestHttpClient::new(Arc::new(connector));

    let payload = r#"{"Name":"test-volume"}"#;
    let uri: Uri = "/volumes/create".parse().unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/volumes/create")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    let resp = proxy_to_guest_stream_pooled(&client, &uri, req)
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, payload.as_bytes());
    guest.cancel.cancel();
}

#[tokio::test]
async fn pooled_proxy_stream_reuses_http_session_after_body_eof() {
    let (connector, guest, _tmp) = setup().await;
    let client = GuestHttpClient::new(Arc::new(connector.clone()));

    for path in ["/volumes", "/networks"] {
        let uri: Uri = path.parse().unwrap();
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = proxy_to_guest_stream_pooled(&client, &uri, req)
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await.unwrap();
    }

    assert_eq!(connector.connect_count.load(Ordering::Relaxed), 1);
    guest.cancel.cancel();
}

// =============================================================================
// Tests — proxy_with_upgrade
// =============================================================================

#[tokio::test]
async fn upgrade_returns_101_with_correct_protocol() {
    let (connector, guest, _tmp) = setup().await;

    let uri: Uri = "/grpc".parse().unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/grpc")
        .header("connection", "Upgrade")
        .header("upgrade", "h2c")
        .body(Body::empty())
        .unwrap();

    let resp = proxy_with_upgrade(&connector, req, &uri).await.unwrap();

    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let upgrade = resp
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(upgrade, "h2c");
    guest.cancel.cancel();
}

#[tokio::test]
async fn upgrade_forwards_request_body() {
    let (connector, guest, _tmp) = setup().await;

    let payload = r#"{"Detach":false,"Tty":false}"#;
    let uri: Uri = "/exec/abc123/start".parse().unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/exec/abc123/start")
        .header("connection", "Upgrade")
        .header("upgrade", "tcp")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    let resp = proxy_with_upgrade(&connector, req, &uri).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Verify the mock guest actually received the request body.
    // Small yield to let the mock's body-capture task run.
    tokio::task::yield_now().await;
    let observed = guest.last_upgrade_body().await;
    assert_eq!(observed.as_deref(), Some(payload.as_bytes()));
    guest.cancel.cancel();
}

// =============================================================================
// Tests — activity hook (idle-thrash regression, 2026-07-15 incident)
// =============================================================================

/// Every proxied request must note VM activity, *including* when endpoint
/// readiness is already cached. The incident: with a warm readiness cache,
/// `docker` traffic bypassed `ensure_system_vm_ready` (the only path that
/// recorded activity), so the lifecycle idled a loaded VM and ballooned it
/// into an 18-hour reclaim thrash.
#[tokio::test]
async fn ensure_endpoint_verified_notes_activity_even_when_cached() {
    use arcbox_docker::proxy::ProxyState;
    use std::sync::atomic::AtomicUsize;

    let (connector, guest, _tmp) = setup().await;

    let activity = Arc::new(AtomicUsize::new(0));
    let hook: arcbox_docker::proxy::ActivityHook = {
        let activity = Arc::clone(&activity);
        Arc::new(move || {
            activity.fetch_add(1, Ordering::SeqCst);
            Box::new(()) as _
        })
    };
    let proxy = ProxyState::new(Arc::new(connector)).with_activity_hook(hook);

    let prepared = Arc::new(AtomicUsize::new(0));
    let prepare = || {
        let prepared = Arc::clone(&prepared);
        async move {
            prepared.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    };

    // First request: full verification (prepare + `_ping` against the mock).
    proxy.ensure_endpoint_verified(1, prepare()).await.unwrap();
    // Second request: readiness is cached — prepare must NOT rerun...
    proxy.ensure_endpoint_verified(1, prepare()).await.unwrap();
    assert_eq!(prepared.load(Ordering::SeqCst), 1, "readiness cache broken");

    // ...but activity must be noted on BOTH requests.
    assert_eq!(
        activity.load(Ordering::SeqCst),
        2,
        "proxied requests must note activity even with warm readiness cache"
    );
    guest.cancel.cancel();
}
