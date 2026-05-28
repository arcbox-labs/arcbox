//! Hyper-based request forwarding to guest dockerd.
//!
//! Standard (non-upgrade) proxy paths that use hyper's HTTP/1.1 client to
//! relay requests and stream responses back to the Docker CLI.

use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use arcbox_error::CommonError;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri, header};
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1;

/// Forwards all non-hop-by-hop headers from the client request to the guest request.
///
/// This ensures registry auth (`X-Registry-Auth`, `X-Registry-Config`),
/// content negotiation (`Accept`), and other semantically significant
/// headers are preserved when proxying to the guest dockerd.
///
/// Per RFC 7230 §6.1, hop-by-hop headers include the fixed set plus any
/// header names listed in the `Connection` header's value.
/// Builds a forwarded header map suitable for proxying to guest dockerd.
///
/// Strips hop-by-hop headers (per RFC 7230 §6.1), the `Host` header, the
/// `Connection` header and any headers listed in `Connection`. When
/// `strip_expect` is true, also strips `Expect` (used by the upload proxy
/// so we own `100-continue` handling).
pub(super) fn forwarded_request_headers(headers: &HeaderMap, strip_expect: bool) -> HeaderMap {
    let connection_tokens = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| token.trim().parse::<HeaderName>().ok())
        .collect::<Vec<_>>();

    let mut forwarded = HeaderMap::new();
    for (name, value) in headers {
        if name == header::HOST
            || name == header::CONNECTION
            || (strip_expect && name == header::EXPECT)
            || is_hop_by_hop_header(name)
            || connection_tokens.iter().any(|token| token == name)
        {
            continue;
        }
        forwarded.append(name.clone(), value.clone());
    }
    forwarded
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

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
    let io = connector.connect_for(role).await?;

    let (mut sender, conn) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, http1::Builder::new().handshake(io))
            .await
            .map_err(|_| {
                DockerError::from(CommonError::timeout("guest docker handshake timed out"))
            })?
            .map_err(|e| DockerError::Server(format!("guest docker handshake failed: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let msg = e.to_string().to_lowercase();
            if !msg.contains("canceled") && !msg.contains("incomplete") {
                tracing::debug!("guest docker connection ended: {}", e);
            }
        }
    });

    let mut req = hyper::Request::builder()
        .method(method)
        .uri(path_and_query)
        .body(Full::new(body))
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    req.headers_mut()
        .extend(forwarded_request_headers(headers, false));
    req.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));

    let response = sender
        .send_request(req)
        .await
        .map_err(|e| DockerError::Server(format!("guest docker request failed: {e}")))?;

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
    let io = connector.connect_for(role).await?;

    let (mut sender, conn) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, http1::Builder::new().handshake(io))
            .await
            .map_err(|_| {
                DockerError::from(CommonError::timeout("guest docker handshake timed out"))
            })?
            .map_err(|e| DockerError::Server(format!("guest docker handshake failed: {e}")))?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let msg = e.to_string().to_lowercase();
            if !msg.contains("canceled") && !msg.contains("incomplete") {
                tracing::debug!("guest docker connection ended: {}", e);
            }
        }
    });

    let path_and_query = original_uri
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let method = req.method().clone();
    let forwarded_headers = forwarded_request_headers(req.headers(), false);
    let body = req.into_body();

    let mut guest_req = hyper::Request::builder()
        .method(method)
        .uri(path_and_query)
        .body(body)
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    guest_req.headers_mut().extend(forwarded_headers);
    guest_req
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));

    let response = sender
        .send_request(guest_req)
        .await
        .map_err(|e| DockerError::Server(format!("guest docker request failed: {e}")))?;

    let (parts, incoming) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(incoming)))
}
