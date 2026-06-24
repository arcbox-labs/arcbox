//! Streaming upload proxy for large Docker API uploads.
//!
//! Used for endpoints like `POST /images/load` where the proxy must own
//! `Expect` handling and request-body draining semantics.

use super::GuestConnector;
use super::headers::{ForwardedHeaderMode, HeaderMapProxyExt};
use super::session::GuestHttpSession;
use super::uri::GuestPath;
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use axum::body::{Body, BodyDataStream};
use axum::http::{HeaderValue, Method, Uri, header};
use bytes::Bytes;
use futures::StreamExt as _;
use std::io;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Buffer size for upload body chunks proxied to guest dockerd.
const UPLOAD_BODY_BUFFER: usize = 16;

/// Forward a large upload request to guest dockerd.
///
/// Opens a new connection and relays the request body through a bounded
/// channel so backpressure is propagated correctly. `Expect: 100-continue`
/// is stripped from the forwarded request.
///
/// # Errors
///
/// Returns an error if guest connection, handshake, request forwarding,
/// or response mapping fails.
#[tracing::instrument(
    name = "docker.proxy.upload",
    skip(connector, req),
    fields(uri = %original_uri, utility_vm = UtilityVmRole::Native.as_str()),
    err
)]
pub async fn proxy_streaming_upload(
    connector: &dyn GuestConnector,
    original_uri: &Uri,
    req: axum::http::Request<Body>,
) -> Result<axum::http::Response<Body>> {
    proxy_streaming_upload_for_role(connector, UtilityVmRole::Native, original_uri, req).await
}

/// Forward a large upload request to a selected utility VM's guest dockerd.
///
/// # Errors
///
/// Returns an error if guest connection, handshake, request forwarding,
/// or response mapping fails.
#[tracing::instrument(
    name = "docker.proxy.upload",
    skip(connector, req),
    fields(uri = %original_uri, utility_vm = role.as_str()),
    err
)]
pub async fn proxy_streaming_upload_for_role(
    connector: &dyn GuestConnector,
    role: UtilityVmRole,
    original_uri: &Uri,
    req: axum::http::Request<Body>,
) -> Result<axum::http::Response<Body>> {
    let mut session = GuestHttpSession::connect(connector, role).await?;

    let had_expect = req.headers().contains_key(header::EXPECT);
    let had_content_length = req.headers().contains_key(header::CONTENT_LENGTH);
    tracing::debug!(
        method = %req.method(),
        had_expect,
        had_content_length,
        "proxying Docker upload request to guest"
    );

    let path_and_query = GuestPath::from(original_uri);
    let method = req.method().clone();
    let forwarded_headers = req
        .headers()
        .forwarded_for_guest(ForwardedHeaderMode::Upload);
    let (tx, rx) = mpsc::channel::<std::result::Result<Bytes, io::Error>>(UPLOAD_BODY_BUFFER);
    let guest_body = Body::from_stream(ReceiverStream::new(rx));

    let mut guest_req = hyper::Request::builder()
        .method(method)
        .uri(path_and_query.as_ref())
        .body(guest_body)
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    guest_req.headers_mut().extend(forwarded_headers);
    guest_req
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));

    let body_stream = req.into_body().into_data_stream();
    let body_pump = tokio::spawn(async move { pump_upload_body(body_stream, tx).await });

    let response = match session.send_request(guest_req, "upload request").await {
        Ok(response) => response,
        Err(e) => {
            body_pump.abort();
            tracing::debug!("guest upload request failed before response headers");
            return Err(e);
        }
    };

    // Once response headers are available from guest dockerd, return them to
    // the Docker client immediately. Some dockerd endpoints can reject or
    // complete an upload before consuming the whole request body; waiting for
    // the client-side tar stream to drain here turns that valid early response
    // into a Docker CLI timeout.
    tokio::spawn(async move {
        match join_upload_pump(body_pump).await {
            Ok(uploaded_bytes) => {
                tracing::debug!(uploaded_bytes, "completed Docker upload body pump");
            }
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "upload body pump ended with error after response headers; treating as non-fatal"
                );
            }
        }
    });

    let (parts, incoming) = response.into_parts();
    Ok(axum::http::Response::from_parts(parts, Body::new(incoming)))
}

/// Returns `true` if the request is a streaming upload that should be routed
/// through [`proxy_streaming_upload`] instead of the default stream proxy.
pub fn is_streaming_upload_request(method: &Method, uri: &Uri) -> bool {
    if *method != Method::POST {
        return false;
    }

    let path = uri.path();
    path == "/images/load"
        || path.ends_with("/images/load")
        || path == "/build"
        || path.ends_with("/build")
}

async fn pump_upload_body(
    mut body_stream: BodyDataStream,
    tx: mpsc::Sender<std::result::Result<Bytes, io::Error>>,
) -> Result<u64> {
    let mut uploaded_bytes = 0_u64;
    let mut receiver_dropped = false;

    while let Some(chunk) = body_stream.next().await {
        match chunk {
            Ok(bytes) => {
                uploaded_bytes = uploaded_bytes.saturating_add(bytes.len() as u64);
                if receiver_dropped {
                    continue;
                }

                if tx.send(Ok(bytes)).await.is_err() {
                    receiver_dropped = true;
                    tracing::debug!("guest upload body receiver closed, draining client upload");
                }
            }
            Err(error) => {
                let io_error = io::Error::other(error.to_string());
                if !receiver_dropped {
                    let _ = tx.send(Err(io_error)).await;
                }
                return Err(DockerError::Server(format!(
                    "failed to read client upload body: {error}"
                )));
            }
        }
    }

    drop(tx);

    if receiver_dropped {
        Err(DockerError::Server(
            "guest upload body receiver closed before request completed".into(),
        ))
    } else {
        Ok(uploaded_bytes)
    }
}

async fn join_upload_pump(handle: tokio::task::JoinHandle<Result<u64>>) -> Result<u64> {
    handle
        .await
        .map_err(|e| DockerError::Server(format!("upload body pump task failed: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
    use http_body_util::{BodyExt as _, Full};
    use hyper::body::Incoming;
    use hyper::server::conn::http1 as server_http1;
    use hyper_util::rt::TokioIo;
    use serde_json::Value;
    use tokio::net::TcpListener;

    use super::super::headers::{ForwardedHeaderMode, HeaderMapProxyExt};
    use arcbox_transport::vsock::{VsockShutdown, VsockStream};

    /// Test connector that connects to a TCP address (used for unit tests).
    struct TcpTestConnector {
        addr: std::net::SocketAddr,
    }

    impl GuestConnector for TcpTestConnector {
        fn connect(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<TokioIo<VsockStream>>> + Send + '_>,
        > {
            let addr = self.addr;
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|e| DockerError::Server(format!("test connect failed: {e}")))?;
                let owned_fd = {
                    use std::os::fd::FromRawFd;
                    use std::os::fd::IntoRawFd;
                    // Convert TcpStream → OwnedFd via raw fd round-trip.
                    let raw = stream.into_std().unwrap().into_raw_fd();
                    // SAFETY: we just extracted this fd from a valid TcpStream.
                    unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) }
                };
                Ok(TokioIo::new(VsockStream::from_fd_with_shutdown(
                    owned_fd,
                    VsockShutdown::CloseOnDropOnly,
                )?))
            })
        }
    }

    #[tokio::test]
    async fn proxy_streaming_upload_forwards_headers_and_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service =
                hyper::service::service_fn(|request: hyper::Request<Incoming>| async move {
                    let headers = request
                        .headers()
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.as_str().to_string(),
                                value.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<std::collections::HashMap<_, _>>();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let payload = serde_json::json!({
                        "headers": headers,
                        "body": String::from_utf8_lossy(&body),
                    });
                    let response = hyper::Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(payload.to_string())))
                        .unwrap();
                    Ok::<_, std::convert::Infallible>(response)
                });

            server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let connector = TcpTestConnector { addr };
        let request = Request::builder()
            .method(Method::POST)
            .uri("/images/load?quiet=1")
            .header(header::CONTENT_TYPE, "application/x-tar")
            .header(header::CONTENT_LENGTH, "4")
            .header(header::EXPECT, "100-continue")
            .header(header::CONNECTION, "keep-alive, x-custom-hop")
            .header("x-custom-hop", "drop-me")
            .header("x-forward-me", "yes")
            .body(Body::from("data"))
            .unwrap();
        let original_uri = Uri::from_static("/v1.47/images/load?quiet=1");

        let response = proxy_streaming_upload(&connector, &original_uri, request)
            .await
            .unwrap();
        let payload = response.into_body().collect().await.unwrap().to_bytes();
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        let headers = payload.get("headers").unwrap();
        assert_eq!(headers.get("host").unwrap(), "localhost");
        assert_eq!(headers.get("content-type").unwrap(), "application/x-tar");
        assert_eq!(headers.get("content-length").unwrap(), "4");
        assert!(headers.get("expect").is_none());
        assert_eq!(headers.get("x-forward-me").unwrap(), "yes");
        assert!(headers.get("connection").is_none());
        assert!(headers.get("x-custom-hop").is_none());
        assert_eq!(payload.get("body").unwrap(), "data");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_streaming_upload_returns_guest_response_before_client_body_drains() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(|_request: hyper::Request<Incoming>| async {
                let response = hyper::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from_static(b"rejected early")))
                    .unwrap();
                Ok::<_, std::convert::Infallible>(response)
            });

            server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let connector = TcpTestConnector { addr };
        let (tx, rx) = mpsc::channel::<std::result::Result<Bytes, io::Error>>(1);
        tx.send(Ok(Bytes::from_static(b"partial"))).await.unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/images/load")
            .header(header::CONTENT_TYPE, "application/x-tar")
            .body(Body::from_stream(ReceiverStream::new(rx)))
            .unwrap();
        let original_uri = Uri::from_static("/v1.47/images/load");

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            proxy_streaming_upload(&connector, &original_uri, request),
        )
        .await
        .expect("proxy should return before the client body stream closes")
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let payload = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&payload[..], b"rejected early");

        drop(tx);
        server.await.unwrap();
    }

    #[test]
    fn detects_image_load_upload_requests() {
        assert!(is_streaming_upload_request(
            &Method::POST,
            &Uri::from_static("/v1.47/images/load?quiet=1")
        ));
        assert!(!is_streaming_upload_request(
            &Method::GET,
            &Uri::from_static("/v1.47/images/load?quiet=1")
        ));
        assert!(!is_streaming_upload_request(
            &Method::POST,
            &Uri::from_static("/v1.47/images/json")
        ));
    }

    #[test]
    fn detects_build_upload_requests() {
        // Unversioned /build
        assert!(is_streaming_upload_request(
            &Method::POST,
            &Uri::from_static("/build")
        ));
        // Versioned /build
        assert!(is_streaming_upload_request(
            &Method::POST,
            &Uri::from_static("/v1.47/build")
        ));
        // With query parameters
        assert!(is_streaming_upload_request(
            &Method::POST,
            &Uri::from_static("/v1.47/build?t=myimage:latest&dockerfile=Dockerfile")
        ));
        // GET should not match
        assert!(!is_streaming_upload_request(
            &Method::GET,
            &Uri::from_static("/build")
        ));
        // /build/prune is NOT a streaming upload — it goes through the standard proxy
        assert!(!is_streaming_upload_request(
            &Method::POST,
            &Uri::from_static("/build/prune")
        ));
    }

    #[test]
    fn forwarded_headers_preserve_end_to_end_fields() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-tar"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("4"));
        headers.insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-custom-hop"),
        );
        headers.insert(
            HeaderName::from_static("x-custom-hop"),
            HeaderValue::from_static("secret"),
        );
        headers.insert(
            HeaderName::from_static("x-forward-me"),
            HeaderValue::from_static("yes"),
        );

        let forwarded = headers.forwarded_for_guest(ForwardedHeaderMode::Normal);
        assert_eq!(
            forwarded.get(header::CONTENT_TYPE).unwrap(),
            "application/x-tar"
        );
        assert_eq!(forwarded.get(header::CONTENT_LENGTH).unwrap(), "4");
        assert_eq!(forwarded.get(header::EXPECT).unwrap(), "100-continue");
        assert_eq!(forwarded.get("x-forward-me").unwrap(), "yes");
        assert!(forwarded.get(header::CONNECTION).is_none());
        assert!(forwarded.get("x-custom-hop").is_none());
    }

    #[test]
    fn forwarded_upload_headers_strip_expect() {
        let mut headers = HeaderMap::new();
        headers.insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-tar"),
        );

        let forwarded = headers.forwarded_for_guest(ForwardedHeaderMode::Upload);
        assert!(forwarded.get(header::EXPECT).is_none());
        assert_eq!(
            forwarded.get(header::CONTENT_TYPE).unwrap(),
            "application/x-tar"
        );
    }
}
