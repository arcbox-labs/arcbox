//! HTTP/1.1 guest dockerd sessions.

use super::{GuestConnector, HANDSHAKE_TIMEOUT};
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use arcbox_error::CommonError;
use axum::body::Body;
use bytes::Bytes;
use http_body::Frame;
use hyper::client::conn::http1;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

const MAX_IDLE_SESSIONS_PER_ROLE: usize = 8;

/// Idle guest HTTP/1.1 sessions keyed by utility VM role.
#[derive(Default)]
pub struct GuestHttpPool {
    native: Mutex<Vec<GuestHttpSession>>,
    rosetta: Mutex<Vec<GuestHttpSession>>,
}

impl GuestHttpPool {
    pub(super) fn take(&self, role: UtilityVmRole) -> Option<GuestHttpSession> {
        self.sessions(role).lock().ok()?.pop()
    }

    fn put(&self, role: UtilityVmRole, session: GuestHttpSession) {
        let Ok(mut sessions) = self.sessions(role).lock() else {
            return;
        };
        if sessions.len() < MAX_IDLE_SESSIONS_PER_ROLE {
            sessions.push(session);
        }
    }

    fn sessions(&self, role: UtilityVmRole) -> &Mutex<Vec<GuestHttpSession>> {
        match role {
            UtilityVmRole::Native => &self.native,
            UtilityVmRole::Rosetta => &self.rosetta,
        }
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

    pub(super) async fn ready(&mut self) -> bool {
        !self.sender.is_closed() && self.sender.ready().await.is_ok()
    }

    pub(super) fn reusable_body(
        self,
        incoming: hyper::body::Incoming,
        pool: Arc<GuestHttpPool>,
        role: UtilityVmRole,
    ) -> Body {
        Body::new(ReusableIncoming {
            incoming,
            session: Some(self),
            pool,
            role,
        })
    }
}

struct ReusableIncoming {
    incoming: hyper::body::Incoming,
    session: Option<GuestHttpSession>,
    pool: Arc<GuestHttpPool>,
    role: UtilityVmRole,
}

impl ReusableIncoming {
    fn return_session(&mut self) {
        if let Some(session) = self.session.take() {
            self.pool.put(self.role, session);
        }
    }
}

impl http_body::Body for ReusableIncoming {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.incoming).poll_frame(cx) {
            Poll::Ready(None) => {
                self.return_session();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.session.take();
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if self.incoming.is_end_stream() {
                    self.return_session();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.incoming.size_hint()
    }
}
