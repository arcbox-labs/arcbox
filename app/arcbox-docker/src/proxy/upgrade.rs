//! HTTP upgrade proxy for Docker attach/exec and BuildKit gRPC/session.
//!
//! Uses a raw HTTP exchange for the guest side instead of hyper's
//! `upgrade::on()` API. hyper's client-side upgrade transfers the IO
//! through an internal oneshot channel that never delivers for
//! `TokioIo<RawFdStream>`, leaving the bridge future permanently blocked.
//! Writing the HTTP exchange directly keeps the vsock fd alive and owned
//! by the caller for the entire bridge lifetime.

use super::stream::RawFdStream;
use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use arcbox_error::CommonError;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri, header};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Send a raw HTTP/1.1 upgrade request to guest dockerd and read the
/// response headers.
///
/// After this returns successfully, the stream is positioned right after the
/// response header block and is ready for direct bidirectional bridging.
async fn send_raw_upgrade(
    stream: &mut RawFdStream,
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(StatusCode, HeaderMap)> {
    // Build HTTP/1.1 request.
    let mut raw = format!("{method} {path_and_query} HTTP/1.1\r\nHost: localhost\r\n");
    for (key, value) in headers {
        // Skip headers we override or that conflict with the body we
        // actually send (the body was already collected from the client,
        // so chunked framing no longer applies).
        if key == header::HOST || key == header::CONTENT_LENGTH || key == header::TRANSFER_ENCODING
        {
            continue;
        }
        let Ok(v) = value.to_str() else { continue };
        raw.push_str(key.as_str());
        raw.push_str(": ");
        raw.push_str(v);
        raw.push_str("\r\n");
    }
    // Always emit an accurate Content-Length for the collected body.
    use std::fmt::Write as _;
    write!(raw, "content-length: {}\r\n", body.len()).expect("write to String is infallible");
    raw.push_str("\r\n");

    stream
        .write_all(raw.as_bytes())
        .await
        .map_err(|e| DockerError::Server(format!("failed to write upgrade request: {e}")))?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .map_err(|e| DockerError::Server(format!("failed to write upgrade body: {e}")))?;
    }

    // Read response headers byte-by-byte until the blank line delimiter.
    // Upgrade responses are small (< 512 bytes), so this is fine.
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| DockerError::Server(format!("failed to read upgrade response: {e}")))?;
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            return Err(DockerError::Server(
                "upgrade response headers too large".into(),
            ));
        }
    }

    // Parse "HTTP/1.1 101 Switching Protocols\r\n..."
    let header_str = String::from_utf8_lossy(&buf);
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| DockerError::Server("empty upgrade response".into()))?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| DockerError::Server(format!("invalid status line: {status_line}")))?;
    let status = StatusCode::from_u16(status_code)
        .map_err(|_| DockerError::Server(format!("invalid status code: {status_code}")))?;

    let mut response_headers = HeaderMap::new();
    for line in header_str.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if let (Ok(name), Ok(val)) = (
                header::HeaderName::from_bytes(key.trim().as_bytes()),
                header::HeaderValue::from_str(value.trim()),
            ) {
                response_headers.insert(name, val);
            }
        }
    }

    Ok((status, response_headers))
}

/// Forward an HTTP request with upgrade support to guest dockerd.
///
/// After the 101 handshake, client and guest streams are bridged via
/// `copy_bidirectional`.
///
/// # Errors
///
/// Returns an error if guest connection, upgrade handshake, or response
/// construction fails.
pub async fn proxy_with_upgrade(
    connector: &dyn GuestConnector,
    client_req: axum::http::Request<Body>,
    original_uri: &Uri,
) -> Result<Response<Body>> {
    proxy_with_upgrade_for_role(connector, UtilityVmRole::Native, client_req, original_uri).await
}

/// Forward an HTTP request with upgrade support to a selected utility VM's
/// guest dockerd.
///
/// Mirrors [`proxy_with_upgrade`] but lets the caller pick the role for
/// per-workload upgrade endpoints (`/containers/{id}/attach`,
/// `/exec/{id}/start` interactive, BuildKit session).
///
/// # Errors
///
/// Returns an error if guest connection, upgrade handshake, or response
/// construction fails.
pub async fn proxy_with_upgrade_for_role(
    connector: &dyn GuestConnector,
    role: UtilityVmRole,
    mut client_req: axum::http::Request<Body>,
    original_uri: &Uri,
) -> Result<Response<Body>> {
    let io = connector.connect_for(role).await?;
    // Unwrap TokioIo to get the raw vsock stream — we drive the guest
    // side manually so the fd stays alive throughout the bridge.
    let mut guest_stream = io.into_inner();

    let path_and_query = original_uri
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);

    // Collect the request body so it can be forwarded to the guest.
    // Upgrade request bodies (e.g. exec-start JSON) are small.
    let body_bytes = {
        let body = std::mem::take(client_req.body_mut());
        http_body_util::BodyExt::collect(body)
            .await
            .map_err(|e| DockerError::Server(format!("failed to read request body: {e}")))?
            .to_bytes()
    };

    let (status, response_headers) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        send_raw_upgrade(
            &mut guest_stream,
            client_req.method(),
            path_and_query,
            client_req.headers(),
            &body_bytes,
        ),
    )
    .await
    .map_err(|_| DockerError::from(CommonError::timeout("guest docker upgrade timed out")))??;

    if status != StatusCode::SWITCHING_PROTOCOLS {
        // Forward the guest's actual error status and headers so the
        // client sees actionable failures instead of a generic 500.
        let mut builder = Response::builder().status(status);
        for (key, value) in &response_headers {
            builder = builder.header(key, value);
        }
        // Read whatever response body the guest sent (bounded).
        let mut error_body = vec![0u8; 8192];
        let n = guest_stream.read(&mut error_body).await.unwrap_or(0);
        error_body.truncate(n);
        return builder
            .body(Body::from(error_body))
            .map_err(|e| DockerError::Server(format!("failed to build error response: {e}")));
    }

    // Forward the guest's actual Upgrade value (h2c, tcp, etc.)
    // so the client negotiates the correct post-upgrade protocol.
    let upgrade_proto = response_headers
        .get(header::UPGRADE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("tcp"));
    let content_type = response_headers.get(header::CONTENT_TYPE).cloned();

    // Ensure no leftover request body data interferes with the upgraded stream.
    *client_req.body_mut() = Body::empty();
    let client_upgrade = hyper::upgrade::on(&mut client_req);

    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, upgrade_proto);

    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }

    let response = builder
        .body(Body::empty())
        .map_err(|e| DockerError::Server(format!("failed to build upgrade response: {e}")))?;

    // Bridge upgraded connections in background.
    tokio::spawn(async move {
        let client_io = match client_upgrade.await {
            Ok(io) => io,
            Err(e) => {
                tracing::debug!("upgrade bridging setup failed: {}", e);
                return;
            }
        };
        let mut client_io = TokioIo::new(client_io);
        if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut guest_stream).await {
            let msg = e.to_string().to_lowercase();
            if !msg.contains("broken pipe")
                && !msg.contains("connection reset")
                && !msg.contains("not connected")
            {
                tracing::debug!("upgrade bridge error: {}", e);
            }
        }
    });

    Ok(response)
}
