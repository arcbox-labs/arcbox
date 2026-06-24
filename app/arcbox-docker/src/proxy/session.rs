//! HTTP/1.1 guest dockerd sessions and pooled clients.

use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
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

const MAX_IDLE_SESSIONS_PER_ROLE: usize = 8;
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const NATIVE_AUTHORITY: &str = "native.arcbox.internal";
const ROSETTA_AUTHORITY: &str = "rosetta.arcbox.internal";

/// Pooled HTTP/1.1 client for ordinary guest dockerd requests.
pub struct GuestHttpClient {
    client: Client<GuestClientConnector, Body>,
}

impl GuestHttpClient {
    pub fn new(connector: Arc<dyn GuestConnector>) -> Self {
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_max_idle_per_host(MAX_IDLE_SESSIONS_PER_ROLE)
            .pool_idle_timeout(IDLE_SESSION_TIMEOUT)
            .pool_timer(TokioTimer::new());

        Self {
            client: builder.build(GuestClientConnector { connector }),
        }
    }

    pub(super) async fn request(
        &self,
        req: hyper::Request<Body>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        self.client
            .request(req)
            .await
            .map_err(|e| DockerError::Server(format!("guest docker request failed: {e}")))
    }

    pub(super) fn uri(role: UtilityVmRole, path_and_query: &str) -> Result<Uri> {
        let authority = match role {
            UtilityVmRole::Native => NATIVE_AUTHORITY,
            UtilityVmRole::Rosetta => ROSETTA_AUTHORITY,
        };
        format!("http://{authority}{path_and_query}")
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
            let role = role_from_uri(&uri)?;
            let io = connector.connect_for(role).await?;
            Ok(GuestIo(io))
        })
    }
}

fn role_from_uri(uri: &Uri) -> Result<UtilityVmRole> {
    match uri.authority().map(|authority| authority.as_str()) {
        Some(NATIVE_AUTHORITY) => Ok(UtilityVmRole::Native),
        Some(ROSETTA_AUTHORITY) => Ok(UtilityVmRole::Rosetta),
        Some(authority) => Err(DockerError::Server(format!(
            "unknown guest docker authority: {authority}"
        ))),
        None => Err(DockerError::Server(
            "guest docker request uri missing authority".into(),
        )),
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
    pub(super) async fn connect(
        connector: &dyn GuestConnector,
        role: UtilityVmRole,
    ) -> Result<Self> {
        let io = connector.connect_for(role).await?;

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
    fn role_from_uri_accepts_known_authorities() {
        let native: Uri = "http://native.arcbox.internal/_ping".parse().unwrap();
        let rosetta: Uri = "http://rosetta.arcbox.internal/_ping".parse().unwrap();

        assert_eq!(role_from_uri(&native).unwrap(), UtilityVmRole::Native);
        assert_eq!(role_from_uri(&rosetta).unwrap(), UtilityVmRole::Rosetta);
    }

    #[test]
    fn role_from_uri_rejects_unknown_authority() {
        let uri: Uri = "http://other.arcbox.internal/_ping".parse().unwrap();

        let err = role_from_uri(&uri).unwrap_err().to_string();

        assert!(err.contains("unknown guest docker authority"));
    }

    #[test]
    fn role_from_uri_rejects_missing_authority() {
        let uri = Uri::from_static("/_ping");

        let err = role_from_uri(&uri).unwrap_err().to_string();

        assert!(err.contains("missing authority"));
    }
}
