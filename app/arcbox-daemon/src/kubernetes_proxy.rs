//! Kubernetes API proxy: host TCP → guest vsock.
//!
//! Listens on a configured loopback port and forwards each connection to the
//! k3s API server inside the guest VM via vsock port 16443.

use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_constants::ports::KUBERNETES_API_VSOCK_PORT;
use arcbox_core::Runtime;
use arcbox_docker::proxy::{VsockShutdown, VsockStream};
use tokio::net::TcpListener;
use tracing::info;

/// A bound Kubernetes API TCP→vsock proxy.
pub struct KubernetesProxy {
    listener: TcpListener,
    host_port: u16,
}

impl KubernetesProxy {
    /// Binds the loopback listener. Port `0` asks the OS for an unused port.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot be bound or queried. Callers
    /// must treat this as a startup failure so they never advertise another
    /// daemon's endpoint.
    pub async fn bind(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .with_context(|| format!("Kubernetes API proxy failed to bind 127.0.0.1:{port}"))?;
        let host_port = listener
            .local_addr()
            .context("Failed to read Kubernetes API proxy address")?
            .port();

        info!(host_port, "Kubernetes API proxy bound");
        Ok(Self {
            listener,
            host_port,
        })
    }

    /// Returns the actual host port selected by the bound listener.
    #[must_use]
    pub const fn host_port(&self) -> u16 {
        self.host_port
    }

    /// Starts accepting and forwarding connections.
    #[must_use]
    pub fn start(self, runtime: Arc<Runtime>) -> tokio::task::JoinHandle<()> {
        let listener = self.listener;

        tokio::spawn(async move {
            loop {
                let Ok((mut host_stream, _)) = listener.accept().await else {
                    continue;
                };
                let runtime = Arc::clone(&runtime);
                tokio::spawn(async move {
                    let fd = match runtime.connect_vsock_port(
                        runtime.default_machine_name(),
                        KUBERNETES_API_VSOCK_PORT,
                    ) {
                        Ok(fd) => fd,
                        Err(e) => {
                            tracing::debug!("failed to connect Kubernetes API vsock: {}", e);
                            return;
                        }
                    };

                    // SAFETY: fd is a valid, newly-opened vsock socket owned by us.
                    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                    let mut guest_stream = match VsockStream::from_fd_with_shutdown(
                        owned,
                        VsockShutdown::CloseOnDropOnly,
                    ) {
                        Ok(stream) => stream,
                        Err(e) => {
                            tracing::debug!("failed to wrap Kubernetes API fd: {}", e);
                            return;
                        }
                    };

                    if let Err(e) =
                        tokio::io::copy_bidirectional(&mut host_stream, &mut guest_stream).await
                    {
                        tracing::debug!("Kubernetes API proxy connection ended: {}", e);
                    }
                });
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::KubernetesProxy;

    #[tokio::test]
    async fn ephemeral_bind_reports_and_owns_the_actual_port() {
        let proxy = KubernetesProxy::bind(0).await.unwrap();
        let port = proxy.host_port();

        assert_ne!(port, 0);
        assert!(KubernetesProxy::bind(port).await.is_err());
    }
}
