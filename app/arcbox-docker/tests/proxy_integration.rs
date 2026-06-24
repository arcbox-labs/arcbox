//! Integration tests for the Docker proxy layer.
//!
//! These tests use a mock guest dockerd on a Unix socket so they run
//! without a VM. They call proxy functions directly (bypassing the
//! handler layer's `ensure_vm_ready`) to isolate proxy forwarding logic.

mod support;
use support::mock_guest::{self, MockGuest};

use arcbox_docker::proxy::{
    GuestConnector, VsockShutdown, VsockStream, proxy_to_guest, proxy_to_guest_stream,
    proxy_with_upgrade,
};
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use tempfile::TempDir;

// =============================================================================
// UnixSocketConnector — test connector that connects to mock guest
// =============================================================================

struct UnixSocketConnector {
    socket_path: PathBuf,
}

impl GuestConnector for UnixSocketConnector {
    fn connect(
        &self,
    ) -> Pin<Box<dyn Future<Output = arcbox_docker::Result<TokioIo<VsockStream>>> + Send + '_>>
    {
        Box::pin(async {
            let stream = tokio::net::UnixStream::connect(&self.socket_path)
                .await
                .map_err(|e| arcbox_docker::DockerError::Server(e.to_string()))?;
            Ok(TokioIo::new(VsockStream::from_unix_stream_with_shutdown(
                stream,
                VsockShutdown::CloseOnDropOnly,
            )))
        })
    }
}

// =============================================================================
// Test helpers
// =============================================================================

async fn setup() -> (UnixSocketConnector, MockGuest, TempDir) {
    let tmp = TempDir::new().unwrap();
    let guest = mock_guest::start(tmp.path()).await;
    let connector = UnixSocketConnector {
        socket_path: guest.socket_path.clone(),
    };
    (connector, guest, tmp)
}

// =============================================================================
// Tests — proxy_to_guest (buffered forwarding)
// =============================================================================

#[tokio::test]
async fn proxy_to_guest_echoes_body() {
    let (connector, guest, _tmp) = setup().await;

    let payload = r#"{"Image":"alpine:latest"}"#;
    let resp = proxy_to_guest(
        &connector,
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

    let resp = proxy_to_guest(
        &connector,
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

// =============================================================================
// Tests — proxy_to_guest_stream (streaming forwarding)
// =============================================================================

#[tokio::test]
async fn proxy_stream_forwards_body() {
    let (connector, guest, _tmp) = setup().await;

    let payload = r#"{"Name":"test-volume"}"#;
    let uri: Uri = "/volumes/create".parse().unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/volumes/create")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();

    let resp = proxy_to_guest_stream(&connector, &uri, req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, payload.as_bytes());
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
