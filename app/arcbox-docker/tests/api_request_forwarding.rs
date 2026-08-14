//! What our interceptors do to a request on its way to guest dockerd
//! (ABX-292).
//!
//! **We do not parse Docker's query parameters.** No handler takes an axum
//! `Query<T>`; `remove_container` and friends take `OriginalUri` plus the raw
//! `Request<Body>` and hand both to the proxy. `?all=`, `?filters=`, `?force=`
//! are dockerd's to interpret.
//!
//! That makes forwarding fidelity the property worth testing, and it is a
//! property with teeth: a query string that arrives re-encoded, reordered, or
//! truncated silently changes what dockerd does — `docker ps --filter` returns
//! the wrong set, `docker rm -f` stops forcing — while every status code stays
//! 200 and every body-echo assertion still passes. `api_routing.rs` proves
//! requests reach the backend; these prove they arrive *unaltered*.
//!
//! The other half is the error contract: Docker clients parse
//! `{"message": "..."}`, so an error raised on our side of the boundary has to
//! carry that shape and not just a status code.

#[path = "support/api.rs"]
mod api_support;
use api_support::*;
use http_body_util::BodyExt;

/// Sends a request through the production version-stripping layer, exactly as
/// `DockerApiServer` wraps the router.
async fn send(router: &axum::Router, method: &str, uri: &str) -> (StatusCode, bytes::Bytes) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let request = arcbox_docker::api::strip_api_version_prefix(request);
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

/// The query string reaches dockerd exactly as the client sent it.
///
/// `docker rm -f -v` is `?force=true&v=true`. Dropping either turns a forced
/// removal into a polite one, or leaks the volumes — with a 204 either way.
#[tokio::test]
async fn query_string_reaches_the_guest_verbatim() {
    let (router, _runtime, guest, _tmp) = router_with_mock_guest(vec![MockRoute {
        method: "DELETE",
        path: "/containers/web",
        status: 204,
        body: "",
    }])
    .await;

    let (status, _) = send(&router, "DELETE", "/containers/web?force=true&v=true").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let seen = guest.last_request_uri().await.expect("guest saw a request");
    assert_eq!(
        seen, "/containers/web?force=true&v=true",
        "the request target must reach dockerd byte-for-byte"
    );
}

/// A percent-encoded JSON `filters` value is forwarded byte-for-byte.
///
/// This is the fragile one: `docker ps --filter label=a=b` sends
/// `?filters={"label":{"a=b":true}}` percent-encoded. Decode-then-re-encode
/// anywhere in the chain and dockerd sees a different filter — or none.
#[tokio::test]
async fn json_filters_query_is_not_re_encoded() {
    let (router, _runtime, guest, _tmp) = router_with_mock_guest(vec![MockRoute {
        method: "GET",
        path: "/containers/json",
        status: 200,
        body: "[]",
    }])
    .await;

    // {"label":{"a=b":true}}
    let filters = "%7B%22label%22%3A%7B%22a%3Db%22%3Atrue%7D%7D";
    let (status, _) = send(
        &router,
        "GET",
        &format!("/containers/json?filters={filters}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let seen = guest.last_request_uri().await.expect("guest saw a request");
    assert_eq!(
        seen,
        format!("/containers/json?filters={filters}"),
        "the percent-encoded filters value must not be rewritten, extended, or joined by \
         extra query material"
    );
}

/// A versioned request is forwarded with its prefix intact.
///
/// `strip_api_version_prefix` strips `/v1.43` for **routing**, so local
/// handlers match regardless of the client's negotiated version. It does not
/// rewrite what goes on the wire: dockerd receives the client's original
/// target, which it accepts. Asserting the full string is what pins that —
/// an `ends_with` on the query alone would pass under either behavior and
/// leave the reader guessing which one holds.
#[tokio::test]
async fn versioned_request_is_forwarded_with_its_prefix() {
    let (router, _runtime, guest, _tmp) = router_with_mock_guest(vec![MockRoute {
        method: "GET",
        path: "/containers/json",
        status: 200,
        body: "[]",
    }])
    .await;

    let (status, _) = send(&router, "GET", "/v1.43/containers/json?all=true&limit=5").await;
    assert_eq!(status, StatusCode::OK);

    let seen = guest.last_request_uri().await.expect("guest saw a request");
    assert_eq!(
        seen, "/v1.43/containers/json?all=true&limit=5",
        "the client's original target reaches dockerd unchanged, prefix included"
    );
}

/// A request with no query arrives with no query — the proxy must not invent
/// a trailing `?`, which some HTTP stacks do when rebuilding a URI.
#[tokio::test]
async fn absent_query_stays_absent() {
    let (router, _runtime, guest, _tmp) = router_with_mock_guest(vec![MockRoute {
        method: "GET",
        path: "/containers/json",
        status: 200,
        body: "[]",
    }])
    .await;

    let (status, _) = send(&router, "GET", "/containers/json").await;
    assert_eq!(status, StatusCode::OK);

    let seen = guest.last_request_uri().await.expect("guest saw a request");
    assert_eq!(
        seen, "/containers/json",
        "a query-less request must not gain an empty query"
    );
}

/// An error raised on our side of the boundary is Docker-shaped.
///
/// Docker clients read `{"message": "..."}`; a bare status code or an
/// axum-default body makes the CLI print nothing useful. The guest is stopped
/// first so the failure comes from our proxy layer rather than being relayed
/// from dockerd — `guest_error_status_passes_through` already covers the
/// relayed case, and only checks the status.
#[tokio::test]
async fn proxy_failure_returns_a_docker_shaped_error() {
    let (router, _runtime, guest, _tmp) = router_with_mock_guest(vec![]).await;

    // Take the backend away, then ask for something that must reach it.
    guest.cancel.cancel();
    let _ = std::fs::remove_file(&guest.socket_path);

    let (status, body) = send(&router, "GET", "/containers/json").await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "an unreachable backend must not report success (got {status})"
    );

    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!(
            "error body is not JSON ({e}): {:?}",
            String::from_utf8_lossy(&body)
        )
    });
    let message = parsed.get("message").and_then(serde_json::Value::as_str);
    assert!(
        message.is_some_and(|m| !m.is_empty()),
        "error body must carry a non-empty `message` field, got {parsed}"
    );
}
