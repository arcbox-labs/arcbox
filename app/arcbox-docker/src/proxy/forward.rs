//! Hyper-based request forwarding to guest dockerd.
//!
//! Standard (non-upgrade) proxy paths that use hyper's HTTP/1.1 client to
//! relay requests and stream responses back to the Docker CLI.

use super::GuestConnector;
use super::headers::{ForwardedHeaderMode, HeaderMapProxyExt};
use super::session::GuestHttpSession;
use super::uri::GuestPath;
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, Uri, header};
use bytes::Bytes;

/// Forward an HTTP request to guest dockerd and return the response.
///
/// Opens a new HTTP/1.1 connection over vsock for each request. The response
/// body is streamed lazily, so this works for both fixed-length and chunked
/// (streaming) responses like logs and events.
///
/// # Errors
///
/// Returns an error if guest connection, handshake, request forwarding,
/// or response mapping fails.
pub async fn proxy_to_guest(
    connector: &dyn GuestConnector,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    proxy_to_guest_for_role(
        connector,
        UtilityVmRole::Native,
        method,
        path_and_query,
        headers,
        body,
    )
    .await
}

/// Forward an HTTP request to a selected utility VM's guest dockerd.
///
/// Mirrors [`proxy_to_guest`] but lets the caller pick the role for
/// programmatic internal lookups (e.g. canonical-ID resolution during
/// lifecycle teardown).
///
/// # Errors
///
/// Returns an error if guest connection, handshake, request forwarding,
/// or response mapping fails.
pub async fn proxy_to_guest_for_role(
    connector: &dyn GuestConnector,
    role: UtilityVmRole,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    let mut session = GuestHttpSession::connect(connector, role).await?;

    let mut req = hyper::Request::builder()
        .method(method)
        .uri(path_and_query)
        .body(Body::from(body))
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    req.headers_mut()
        .extend(headers.forwarded_for_guest(ForwardedHeaderMode::Normal));
    req.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));

    let response = session.send_request(req, "request").await?;

    let (parts, incoming) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(incoming)))
}

/// Forward an HTTP request to guest dockerd without buffering the request body.
///
/// This is used by pass-through proxy paths so large uploads and streamed
/// payloads are relayed directly instead of being collected in memory.
///
/// # Errors
///
/// Returns an error if guest connection, handshake, request forwarding,
/// or response mapping fails.
pub async fn proxy_to_guest_stream(
    connector: &dyn GuestConnector,
    original_uri: &Uri,
    req: Request<Body>,
) -> Result<Response<Body>> {
    proxy_to_guest_stream_for_role(connector, UtilityVmRole::Native, original_uri, req).await
}

/// Forward an HTTP request to a selected utility VM's guest dockerd without buffering.
///
/// # Errors
///
/// Returns an error if guest connection, handshake, request forwarding,
/// or response mapping fails.
pub async fn proxy_to_guest_stream_for_role(
    connector: &dyn GuestConnector,
    role: UtilityVmRole,
    original_uri: &Uri,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let mut session = GuestHttpSession::connect(connector, role).await?;

    let path_and_query = GuestPath::from(original_uri);
    let method = req.method().clone();
    let forwarded_headers = req
        .headers()
        .forwarded_for_guest(ForwardedHeaderMode::Normal);
    let body = req.into_body();

    let mut guest_req = hyper::Request::builder()
        .method(method)
        .uri(path_and_query.as_ref())
        .body(body)
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    guest_req.headers_mut().extend(forwarded_headers);
    guest_req
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));

    let response = session.send_request(guest_req, "request").await?;

    let (parts, incoming) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(incoming)))
}
