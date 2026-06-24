//! HTTP upgrade proxy for Docker attach/exec and BuildKit gRPC/session.
//!
//! Uses a raw HTTP exchange for the guest side instead of hyper's
//! `upgrade::on()` API. hyper's client-side upgrade transfers the IO
//! through an internal oneshot channel that never delivers for
//! `TokioIo<VsockStream>`, leaving the bridge future permanently blocked.
//! Writing the HTTP exchange directly keeps the vsock fd alive and owned
//! by the caller for the entire bridge lifetime.

use super::uri::GuestPath;
use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use arcbox_error::CommonError;
use arcbox_transport::vsock::VsockStream;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri, header};
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_UPGRADE_RESPONSE_HEADERS: usize = 64;
const MAX_UPGRADE_RESPONSE_HEAD_BYTES: usize = 8192;

struct RawUpgradeRequest<'a> {
    method: &'a Method,
    path_and_query: &'a str,
    headers: &'a HeaderMap,
    body: &'a [u8],
}

impl RawUpgradeRequest<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(256 + self.body.len());
        raw.extend_from_slice(self.method.as_str().as_bytes());
        raw.extend_from_slice(b" ");
        raw.extend_from_slice(self.path_and_query.as_bytes());
        raw.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\n");

        for (key, value) in self.headers {
            // Skip headers we override or that conflict with the body we
            // actually send (the body was already collected from the client,
            // so chunked framing no longer applies).
            if key == header::HOST
                || key == header::CONTENT_LENGTH
                || key == header::TRANSFER_ENCODING
            {
                continue;
            }
            let Ok(value) = value.to_str() else {
                continue;
            };
            raw.extend_from_slice(key.as_str().as_bytes());
            raw.extend_from_slice(b": ");
            raw.extend_from_slice(value.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }

        raw.extend_from_slice(b"content-length: ");
        raw.extend_from_slice(self.body.len().to_string().as_bytes());
        raw.extend_from_slice(b"\r\n\r\n");
        raw.extend_from_slice(self.body);
        raw
    }
}

/// Send a raw HTTP/1.1 upgrade request to guest dockerd and read the
/// response headers.
///
/// After this returns successfully, the stream is positioned right after the
/// response header block and is ready for direct bidirectional bridging.
async fn send_raw_upgrade(
    stream: &mut VsockStream,
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let raw = RawUpgradeRequest {
        method,
        path_and_query,
        headers,
        body,
    }
    .encode();

    stream
        .write_all(&raw)
        .await
        .map_err(|e| DockerError::Server(format!("failed to write upgrade request: {e}")))?;

    // Read response headers in chunks. A chunked read may consume bytes that
    // belong to the upgraded stream, so return the over-read tail to the
    // bridge caller.
    let mut buf = Vec::with_capacity(1024);
    let (header_end_index, status, response_headers) = loop {
        let mut chunk = [0_u8; 1024];
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| DockerError::Server(format!("failed to read upgrade response: {e}")))?;
        if n == 0 {
            return Err(DockerError::Server(
                "guest closed connection before upgrade response".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(parsed) = parse_response_head(&buf)? {
            break parsed;
        }
        if buf.len() > MAX_UPGRADE_RESPONSE_HEAD_BYTES {
            return Err(DockerError::Server(
                "upgrade response headers too large".into(),
            ));
        }
    };

    let extra = Bytes::copy_from_slice(&buf[header_end_index..]);

    Ok((status, response_headers, extra))
}

fn parse_response_head(buf: &[u8]) -> Result<Option<(usize, StatusCode, HeaderMap)>> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_UPGRADE_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let header_end_index = match response.parse(buf) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(err) => Err(DockerError::Server(format!(
            "failed to parse upgrade response: {err}"
        )))?,
    };

    let status = response
        .code
        .ok_or_else(|| DockerError::Server("upgrade response missing status code".into()))?;

    let status = StatusCode::from_u16(status)
        .map_err(|_| DockerError::Server(format!("invalid status code: {status}")))?;

    let mut response_headers = HeaderMap::new();
    for parsed in response.headers.iter() {
        let Ok(name) = HeaderName::from_bytes(parsed.name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(parsed.value) else {
            continue;
        };
        response_headers.append(name, value);
    }

    Ok(Some((header_end_index, status, response_headers)))
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
#[tracing::instrument(
    name = "docker.proxy.upgrade",
    skip(connector, client_req),
    fields(uri = %original_uri, utility_vm = UtilityVmRole::Native.as_str()),
    err
)]
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
#[tracing::instrument(
    name = "docker.proxy.upgrade",
    skip(connector, client_req),
    fields(uri = %original_uri, utility_vm = role.as_str()),
    err
)]
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

    let path_and_query = GuestPath::from(original_uri);

    // Collect the request body so it can be forwarded to the guest.
    // Upgrade request bodies (e.g. exec-start JSON) are small.
    let body_bytes = {
        let body = std::mem::take(client_req.body_mut());
        http_body_util::BodyExt::collect(body)
            .await
            .map_err(|e| DockerError::Server(format!("failed to read request body: {e}")))?
            .to_bytes()
    };

    let (status, response_headers, upgraded_prefix) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        send_raw_upgrade(
            &mut guest_stream,
            client_req.method(),
            path_and_query.as_ref(),
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
        let mut error_body = upgraded_prefix.to_vec();
        error_body.resize(8192, 0);
        let n = guest_stream
            .read(&mut error_body[upgraded_prefix.len()..])
            .await
            .unwrap_or(0);
        let total = upgraded_prefix.len() + n;
        error_body.truncate(total);
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
        if !upgraded_prefix.is_empty() {
            if let Err(e) = client_io.write_all(&upgraded_prefix).await {
                tracing::debug!("failed to forward buffered upgrade bytes: {}", e);
                return;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_upgrade_request_skips_non_utf8_header_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-good", HeaderValue::from_static("ok"));
        headers.insert(
            "x-binary",
            HeaderValue::from_bytes(&[0xff]).expect("HeaderValue accepts opaque bytes"),
        );

        let raw = RawUpgradeRequest {
            method: &Method::POST,
            path_and_query: "/session",
            headers: &headers,
            body: b"{}",
        }
        .encode();
        let raw = String::from_utf8(raw).expect("non-UTF-8 header should be omitted");

        assert!(raw.contains("x-good: ok\r\n"));
        assert!(!raw.contains("x-binary"));
    }

    #[test]
    fn parse_response_head_returns_header_end_and_overread_boundary() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tcp\r\n\r\nextra";

        let (len, status, headers) = parse_response_head(response)
            .unwrap()
            .expect("response head is complete");

        assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(headers.get(header::UPGRADE).unwrap(), "tcp");
        assert_eq!(&response[len..], b"extra");
    }
}
