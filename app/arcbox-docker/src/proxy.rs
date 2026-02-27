//! Smart proxy for forwarding Docker API requests to guest dockerd.
//!
//! Provides HTTP/1.1 client over vsock to forward requests, with support
//! for streaming responses and HTTP upgrades (attach, exec).

use crate::api::AppState;
use crate::error::{DockerError, Result};
use arcbox_core::Runtime;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, header};
use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// =============================================================================
// RawFdStream — async I/O wrapper around a raw vsock file descriptor
// =============================================================================

struct RawFdWrapper(OwnedFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

pub(crate) struct RawFdStream {
    inner: AsyncFd<RawFdWrapper>,
}

impl RawFdStream {
    pub(crate) fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file descriptor",
            ));
        }

        Self::set_nonblocking(fd)?;
        // SAFETY: fd is a valid, newly-opened vsock file descriptor owned by us.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let inner = AsyncFd::new(RawFdWrapper(owned))?;
        Ok(Self { inner })
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY: F_GETFL/F_SETFL are safe on valid fds.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsyncRead for RawFdStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let slice = buf.initialize_unfilled();
                // SAFETY: reading into our buffer from a valid fd.
                let n = unsafe { libc::read(fd, slice.as_mut_ptr().cast(), slice.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    // n >= 0 is enforced above.
                    #[allow(clippy::cast_sign_loss)]
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncWrite for RawFdStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: writing from our buffer to a valid fd.
                let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    // n >= 0 is enforced above.
                    #[allow(clippy::cast_sign_loss)]
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.inner.get_ref().as_raw_fd();
        // SAFETY: shutdown on a valid fd.
        let result = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
        if result == 0 {
            return Poll::Ready(Ok(()));
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTCONN) {
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(Err(err))
    }
}

// =============================================================================
// Guest connection
// =============================================================================

/// Opens a vsock connection to guest dockerd.
fn connect_guest(runtime: &Runtime) -> Result<TokioIo<RawFdStream>> {
    let port = runtime.guest_docker_vsock_port();
    let machine_name = runtime.default_machine_name();
    let fd = runtime
        .machine_manager()
        .connect_vsock_port(machine_name, port)
        .map_err(|e| DockerError::Server(format!("failed to connect to guest docker: {e}")))?;
    let stream = RawFdStream::from_raw_fd(fd)
        .map_err(|e| DockerError::Server(format!("failed to create guest stream: {e}")))?;
    Ok(TokioIo::new(stream))
}

// =============================================================================
// Proxy helpers
// =============================================================================

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
    runtime: &Runtime,
    method: Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    let io = connect_guest(runtime)?;

    let (mut sender, conn) = http1::Builder::new()
        .handshake(io)
        .await
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

    // Forward content-type so the guest dockerd can parse JSON bodies.
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        req.headers_mut().insert(header::CONTENT_TYPE, ct.clone());
    }
    req.headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));
    req.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));

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
    runtime: &Runtime,
    original_uri: &Uri,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let io = connect_guest(runtime)?;

    let (mut sender, conn) = http1::Builder::new()
        .handshake(io)
        .await
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
    let content_type = req.headers().get(header::CONTENT_TYPE).cloned();
    let body = req.into_body();

    let mut guest_req = hyper::Request::builder()
        .method(method)
        .uri(path_and_query)
        .body(body)
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    if let Some(ct) = content_type {
        guest_req.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    guest_req
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));
    guest_req
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));

    let response = sender
        .send_request(guest_req)
        .await
        .map_err(|e| DockerError::Server(format!("guest docker request failed: {e}")))?;

    let (parts, incoming) = response.into_parts();
    Ok(Response::from_parts(parts, Body::new(incoming)))
}

/// Forward an HTTP request with upgrade support to guest dockerd.
///
/// Used for attach and exec endpoints that use HTTP upgrade (101 Switching
/// Protocols) for bidirectional streaming. After the upgrade, client and
/// guest streams are bridged via `copy_bidirectional`.
///
/// # Errors
///
/// Returns an error if guest connection, handshake, request forwarding,
/// or response construction fails.
pub async fn proxy_with_upgrade(
    runtime: &Runtime,
    mut client_req: axum::http::Request<Body>,
    original_uri: &Uri,
) -> Result<Response<Body>> {
    let io = connect_guest(runtime)?;

    let (mut sender, conn) = http1::Builder::new()
        .handshake(io)
        .await
        .map_err(|e| DockerError::Server(format!("guest docker handshake failed: {e}")))?;

    // The connection task must keep running for the upgrade to work.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            let msg = e.to_string().to_lowercase();
            if !msg.contains("canceled") && !msg.contains("incomplete") {
                tracing::debug!("guest docker upgrade connection ended: {}", e);
            }
        }
    });

    let path_and_query = original_uri
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let req_body = std::mem::take(client_req.body_mut());

    let mut guest_req = hyper::Request::builder()
        .method(client_req.method())
        .uri(path_and_query)
        .body(req_body)
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    // Forward all headers except Host.
    for (key, value) in client_req.headers() {
        if key != header::HOST {
            guest_req.headers_mut().insert(key.clone(), value.clone());
        }
    }
    guest_req
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));

    let guest_response = sender
        .send_request(guest_req)
        .await
        .map_err(|e| DockerError::Server(format!("guest docker request failed: {e}")))?;

    if guest_response.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Guest didn't upgrade — return its response as-is.
        let (parts, incoming) = guest_response.into_parts();
        return Ok(Response::from_parts(parts, Body::new(incoming)));
    }

    // Preserve content-type from guest's 101 (raw-stream vs multiplexed-stream).
    let content_type = guest_response.headers().get(header::CONTENT_TYPE).cloned();

    // Prepare both upgrade futures BEFORE returning the 101 to the client.
    let client_upgrade = hyper::upgrade::on(&mut client_req);
    let guest_upgrade = hyper::upgrade::on(guest_response);

    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "tcp");

    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }

    let response = builder
        .body(Body::empty())
        .map_err(|e| DockerError::Server(format!("failed to build upgrade response: {e}")))?;

    // Bridge upgraded connections in background.
    tokio::spawn(async move {
        let (client_io, guest_io) = match tokio::try_join!(client_upgrade, guest_upgrade) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("upgrade bridging setup failed: {}", e);
                return;
            }
        };
        let mut client_io = TokioIo::new(client_io);
        let mut guest_io = TokioIo::new(guest_io);
        if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut guest_io).await {
            let msg = e.to_string().to_lowercase();
            if !msg.contains("broken pipe") && !msg.contains("connection reset") {
                tracing::debug!("upgrade bridge error: {}", e);
            }
        }
    });

    Ok(response)
}

// =============================================================================
// Fallback handler — catches any unmatched route and proxies to guest
// =============================================================================

/// Catch-all handler that proxies unmatched requests to guest dockerd.
///
/// Ensures forward compatibility with newer Docker API versions — any endpoint
/// we don't explicitly handle gets forwarded transparently.
///
/// # Errors
///
/// Returns an error if VM readiness fails or guest proxying fails.
pub async fn proxy_fallback(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: axum::http::Request<Body>,
) -> Result<Response<Body>> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {e}")))?;

    // Detect upgrade requests (attach, exec).
    let wants_upgrade = req.headers().get(header::UPGRADE).is_some()
        || req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));

    if wants_upgrade {
        return proxy_with_upgrade(&state.runtime, req, &uri).await;
    }

    proxy_to_guest_stream(&state.runtime, &uri, req).await
}

// =============================================================================
// Port binding parsing (for post-hook port forwarding)
// =============================================================================

/// A parsed port binding from Docker inspect JSON.
#[derive(Debug, Clone)]
pub struct PortBindingInfo {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

/// Parse port bindings from a Docker container inspect JSON response.
///
/// Extracts `NetworkSettings.Ports` and `HostConfig.PortBindings` into a flat
/// list of `PortBindingInfo` structs suitable for port forwarding setup.
#[must_use]
pub fn parse_port_bindings(inspect_json: &[u8]) -> Vec<PortBindingInfo> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(inspect_json) else {
        return vec![];
    };

    // Prefer NetworkSettings.Ports (reflects runtime state).
    let ports = value
        .pointer("/NetworkSettings/Ports")
        .or_else(|| value.pointer("/HostConfig/PortBindings"));

    let Some(ports) = ports.and_then(|v| v.as_object()) else {
        return vec![];
    };

    let mut bindings = Vec::new();

    for (container_port_proto, host_bindings) in ports {
        // Parse "80/tcp" or "53/udp"
        let (container_port, protocol) =
            if let Some((port_str, proto)) = container_port_proto.split_once('/') {
                let port: u16 = match port_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                (port, proto.to_string())
            } else {
                let port: u16 = match container_port_proto.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                (port, "tcp".to_string())
            };

        let Some(bindings_arr) = host_bindings.as_array() else {
            continue;
        };

        for binding in bindings_arr {
            let host_ip = binding
                .get("HostIp")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let host_port: u16 = binding
                .get("HostPort")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if host_port > 0 {
                bindings.push(PortBindingInfo {
                    host_ip,
                    host_port,
                    container_port,
                    protocol: protocol.clone(),
                });
            }
        }
    }

    bindings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_bindings_from_network_settings() {
        let json = serde_json::json!({
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
                    "443/tcp": [{"HostIp": "", "HostPort": "8443"}]
                }
            }
        });
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert_eq!(bindings.len(), 2);

        let b80 = bindings.iter().find(|b| b.container_port == 80).unwrap();
        assert_eq!(b80.host_port, 8080);
        assert_eq!(b80.protocol, "tcp");
        assert_eq!(b80.host_ip, "0.0.0.0");

        let b443 = bindings.iter().find(|b| b.container_port == 443).unwrap();
        assert_eq!(b443.host_port, 8443);
    }

    #[test]
    fn parse_port_bindings_empty_ports() {
        let json = serde_json::json!({"NetworkSettings": {"Ports": {}}});
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert!(bindings.is_empty());
    }

    #[test]
    fn parse_port_bindings_null_host_bindings() {
        let json = serde_json::json!({
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": null
                }
            }
        });
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert!(bindings.is_empty());
    }

    #[test]
    fn parse_port_bindings_udp() {
        let json = serde_json::json!({
            "NetworkSettings": {
                "Ports": {
                    "53/udp": [{"HostIp": "", "HostPort": "5353"}]
                }
            }
        });
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].protocol, "udp");
        assert_eq!(bindings[0].container_port, 53);
        assert_eq!(bindings[0].host_port, 5353);
    }
}
