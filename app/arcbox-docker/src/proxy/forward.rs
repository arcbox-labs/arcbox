//! Hyper-based request forwarding to guest dockerd.
//!
//! Standard (non-upgrade) proxy paths that use hyper's HTTP/1.1 client to
//! relay requests and stream responses back to the Docker CLI.

use super::GuestConnector;
use super::headers::{ForwardedHeaderMode, HeaderMapProxyExt};
use super::session::{GuestHttpClient, GuestHttpSession};
use super::uri::GuestPath;
use crate::error::{DockerError, Result};
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
#[tracing::instrument(
    name = "docker.proxy.buffered",
    skip(connector, headers, body),
    fields(method = %method, path = path_and_query, utility_vm = "native"),
    err
)]
pub async fn proxy_to_guest(
    connector: &dyn GuestConnector,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    BufferedForward {
        method,
        path_and_query,
        headers,
        body,
    }
    .send_direct(connector)
    .await
}

/// Forward an HTTP request using a reusable guest HTTP session when possible.
///
/// The underlying hyper-util client returns the connection to its pool only
/// after the response body reaches EOF; if the body is dropped early or errors,
/// the connection is discarded.
#[tracing::instrument(
    name = "docker.proxy.buffered_pooled",
    skip(client, headers, body),
    fields(method = %method, path = path_and_query, utility_vm = "native"),
    err
)]
pub async fn proxy_to_guest_pooled(
    client: &GuestHttpClient,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    BufferedForward {
        method,
        path_and_query,
        headers,
        body,
    }
    .send_pooled(client)
    .await
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
#[tracing::instrument(
    name = "docker.proxy.stream",
    skip(connector, req),
    fields(uri = %original_uri, utility_vm = "native"),
    err
)]
pub async fn proxy_to_guest_stream(
    connector: &dyn GuestConnector,
    original_uri: &Uri,
    req: Request<Body>,
) -> Result<Response<Body>> {
    StreamForward { original_uri, req }
        .send_direct(connector)
        .await
}

/// Forward a streaming HTTP request using a reusable guest HTTP session when possible.
///
/// The underlying hyper-util client returns the connection to its pool only
/// after the response body reaches EOF; if the body is dropped early or errors,
/// the connection is discarded.
#[tracing::instrument(
    name = "docker.proxy.stream_pooled",
    skip(client, req),
    fields(uri = %original_uri, utility_vm = "native"),
    err
)]
pub async fn proxy_to_guest_stream_pooled(
    client: &GuestHttpClient,
    original_uri: &Uri,
    req: Request<Body>,
) -> Result<Response<Body>> {
    StreamForward { original_uri, req }
        .send_pooled(client)
        .await
}

struct BufferedForward<'a> {
    method: Method,
    path_and_query: &'a str,
    headers: &'a HeaderMap,
    body: Bytes,
}

impl BufferedForward<'_> {
    async fn send_direct(self, connector: &dyn GuestConnector) -> Result<Response<Body>> {
        let uri = parse_guest_uri(self.path_and_query)?;
        let req = self.into_request(uri)?;
        let mut session = GuestHttpSession::connect(connector).await?;
        Ok(response_with_axum_body(
            session.send_request(req, "request").await?,
        ))
    }

    async fn send_pooled(self, client: &GuestHttpClient) -> Result<Response<Body>> {
        let uri = GuestHttpClient::uri(self.path_and_query)?;
        let req = self.into_request(uri)?;
        Ok(response_with_axum_body(client.request(req).await?))
    }

    fn into_request(self, uri: Uri) -> Result<Request<Body>> {
        build_guest_request(self.method, uri, self.headers, Body::from(self.body))
    }
}

struct StreamForward<'a> {
    original_uri: &'a Uri,
    req: Request<Body>,
}

impl StreamForward<'_> {
    async fn send_direct(self, connector: &dyn GuestConnector) -> Result<Response<Body>> {
        let path_and_query = GuestPath::from(self.original_uri);
        let uri = parse_guest_uri(path_and_query.as_ref())?;
        let req = self.into_request(uri)?;
        let mut session = GuestHttpSession::connect(connector).await?;
        Ok(response_with_axum_body(
            session.send_request(req, "request").await?,
        ))
    }

    async fn send_pooled(self, client: &GuestHttpClient) -> Result<Response<Body>> {
        let path_and_query = GuestPath::from(self.original_uri);
        let uri = GuestHttpClient::uri(path_and_query.as_ref())?;
        let req = self.into_request(uri)?;
        Ok(response_with_axum_body(client.request(req).await?))
    }

    fn into_request(self, uri: Uri) -> Result<Request<Body>> {
        let (parts, body) = self.req.into_parts();
        build_guest_request(parts.method, uri, &parts.headers, body)
    }
}

fn build_guest_request(
    method: Method,
    uri: Uri,
    headers: &HeaderMap,
    body: Body,
) -> Result<Request<Body>> {
    let mut req = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    req.headers_mut()
        .extend(headers.forwarded_for_guest(ForwardedHeaderMode::Normal));
    req.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));
    Ok(req)
}

fn parse_guest_uri(uri: &str) -> Result<Uri> {
    uri.parse()
        .map_err(|e| DockerError::Server(format!("failed to build guest request uri: {e}")))
}

fn response_with_axum_body(response: hyper::Response<hyper::body::Incoming>) -> Response<Body> {
    let (parts, incoming) = response.into_parts();
    Response::from_parts(parts, Body::new(incoming))
}
