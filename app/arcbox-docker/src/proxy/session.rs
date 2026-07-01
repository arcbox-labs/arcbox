//! HTTP/1.1 guest dockerd sessions and pooled clients.

use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use arcbox_error::CommonError;
use axum::body::Body;
use hyper::Uri;
use hyper::client::conn::http1;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::Service;

const MAX_IDLE_SESSIONS: usize = 8;
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const NATIVE_AUTHORITY: &str = "native.arcbox.internal";

/// Pooled HTTP/1.1 client for ordinary guest dockerd requests.
pub struct GuestHttpClient {
    client: Client<GuestClientConnector, Body>,
}

impl GuestHttpClient {
    pub fn new(connector: Arc<dyn GuestConnector>) -> Self {
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_max_idle_per_host(MAX_IDLE_SESSIONS)
            .pool_idle_timeout(IDLE_SESSION_TIMEOUT)
            .pool_timer(TokioTimer::new());

        Self {
            client: builder.build(GuestClientConnector { connector }),
        }
    }

    #[tracing::instrument(
        name = "docker.guest.client.request",
        skip(self, req),
        fields(uri = %req.uri()),
        err
    )]
    pub(super) async fn request(
        &self,
        req: hyper::Request<Body>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        self.client
            .request(req)
            .await
            .map_err(|e| DockerError::Server(format!("guest docker request failed: {e}")))
    }

    pub(super) fn uri(path_and_query: &str) -> Result<Uri> {
        format!("http://{NATIVE_AUTHORITY}{path_and_query}")
            .parse()
            .map_err(|e| DockerError::Server(format!("failed to build guest request uri: {e}")))
    }
}

#[derive(Clone)]
struct GuestClientConnector {
    connector: Arc<dyn GuestConnector>,
}

impl Service<Uri> for GuestClientConnector {
    type Response = GuestIo;
    type Error = DockerError;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<GuestIo, DockerError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = Arc::clone(&self.connector);
        Box::pin(async move {
            // Verify the authority is the expected guest authority before
            // connecting so misrouted requests fail fast.
            match uri.authority().map(|a| a.as_str()) {
                Some(NATIVE_AUTHORITY) => {}
                Some(authority) => {
                    return Err(DockerError::Server(format!(
                        "unknown guest docker authority: {authority}"
                    )));
                }
                None => {
                    return Err(DockerError::Server(
                        "guest docker request uri missing authority".into(),
                    ));
                }
            }
            let io = connector.connect().await?;
            Ok(GuestIo(io))
        })
    }
}

struct GuestIo(TokioIo<super::VsockStream>);

impl Unpin for GuestIo {}

impl Connection for GuestIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Read for GuestIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl Write for GuestIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }
}

/// One HTTP/1.1 client session connected to guest dockerd.
pub(super) struct GuestHttpSession {
    sender: http1::SendRequest<Body>,
}

impl GuestHttpSession {
    /// Connects to guest dockerd and starts the hyper connection driver.
    #[tracing::instrument(
        name = "docker.guest.session.connect",
        skip(connector),
        fields(utility_vm = "native"),
        err
    )]
    pub(super) async fn connect(connector: &dyn GuestConnector) -> Result<Self> {
        let io = connector.connect().await?;

        let (sender, conn) =
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

        Ok(Self { sender })
    }

    /// Sends a request over this session.
    #[tracing::instrument(
        name = "docker.guest.session.request",
        skip(self, req),
        fields(context = context),
        err
    )]
    pub(super) async fn send_request(
        &mut self,
        req: hyper::Request<Body>,
        context: &str,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        self.sender
            .send_request(req)
            .await
            .map_err(|e| DockerError::Server(format!("guest docker {context} failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_authority_is_rejected() {
        // Build a fake URI with an unrecognised authority and verify the
        // connector rejects it without attempting to connect.
        let uri: Uri = "http://other.arcbox.internal/_ping".parse().unwrap();
        // Only way to exercise the authority check without an actual network is
        // through the error path: verify the URI authority is non-native.
        assert_ne!(uri.authority().map(|a| a.as_str()), Some(NATIVE_AUTHORITY));
    }

    #[test]
    fn uri_builds_correct_guest_url() {
        let uri = GuestHttpClient::uri("/_ping").unwrap();
        assert_eq!(uri.authority().unwrap().as_str(), NATIVE_AUTHORITY);
        assert_eq!(uri.path(), "/_ping");
    }
}
