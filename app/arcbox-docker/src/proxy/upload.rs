//! Streaming upload proxy for large Docker API uploads.
//!
//! Used for endpoints like `POST /images/load` where the proxy must own
//! `Expect` handling and request-body draining semantics.

use super::forward::forwarded_request_headers;
use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use arcbox_error::CommonError;
use axum::body::{Body, BodyDataStream};
use axum::http::{HeaderValue, Method, Uri, header};
use bytes::Bytes;
use futures::StreamExt as _;
use hyper::client::conn::http1;
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
pub async fn proxy_streaming_upload(
    connector: &dyn GuestConnector,
    original_uri: &Uri,
    req: axum::http::Request<Body>,
) -> Result<axum::http::Response<Body>> {
    let io = connector.connect().await?;

    let had_expect = req.headers().contains_key(header::EXPECT);
    let had_content_length = req.headers().contains_key(header::CONTENT_LENGTH);
    tracing::debug!(
        method = %req.method(),
        uri = %original_uri,
        had_expect,
        had_content_length,
        "proxying Docker upload request to guest"
    );

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
    let forwarded_headers = forwarded_request_headers(req.headers(), true);
    let body_stream = req.into_body().into_data_stream();
    let (tx, rx) = mpsc::channel::<std::result::Result<Bytes, io::Error>>(UPLOAD_BODY_BUFFER);
    let body_pump = tokio::spawn(async move { pump_upload_body(body_stream, tx).await });
    let guest_body = Body::from_stream(ReceiverStream::new(rx));

    let mut guest_req = hyper::Request::builder()
        .method(method)
        .uri(path_and_query)
        .body(guest_body)
        .map_err(|e| DockerError::Server(format!("failed to build guest request: {e}")))?;

    guest_req.headers_mut().extend(forwarded_headers);
    guest_req
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static("localhost"));

    let response = match sender.send_request(guest_req).await {
        Ok(response) => response,
        Err(e) => {
            let drain_result = join_upload_pump(body_pump).await;
            tracing::debug!(
                drain_ok = drain_result.is_ok(),
                "guest upload request failed before response headers"
            );
            return Err(DockerError::Server(format!(
                "guest docker upload request failed: {e}"
            )));
        }
    };

    // Once response headers are available from guest dockerd, a pump failure
    // (e.g. receiver dropped because the guest closed the request body early)
    // should not prevent returning the response to the client.
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

    use super::super::forward::forwarded_request_headers;
    use super::super::stream::RawFdStream;

    /// Test connector that connects to a TCP address (used for unit tests).
    struct TcpTestConnector {
        addr: std::net::SocketAddr,
    }

    impl GuestConnector for TcpTestConnector {
        fn connect(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<TokioIo<RawFdStream>>> + Send + '_>,
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
                Ok(TokioIo::new(RawFdStream::new(owned_fd)?))
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

        let forwarded = forwarded_request_headers(&headers, false);
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

        let forwarded = forwarded_request_headers(&headers, true);
        assert!(forwarded.get(header::EXPECT).is_none());
        assert_eq!(
            forwarded.get(header::CONTENT_TYPE).unwrap(),
            "application/x-tar"
        );
    }
}
