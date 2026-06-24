//! HTTP/1.1 guest dockerd sessions.

use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use arcbox_error::CommonError;
use axum::body::Body;
use hyper::client::conn::http1;

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
