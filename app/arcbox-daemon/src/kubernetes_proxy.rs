//! Kubernetes API proxy: host TCP → guest vsock.
//!
//! Listens on `127.0.0.1:16443` and forwards each connection to the k3s
//! API server inside the guest VM via vsock port 16443.

use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;

use arcbox_constants::ports::{KUBERNETES_API_HOST_PORT, KUBERNETES_API_VSOCK_PORT};
use arcbox_core::Runtime;
use arcbox_docker::proxy::{VsockShutdown, VsockStream};
use tokio::net::TcpListener;
use tracing::{info, warn};

/// Starts the Kubernetes API TCP→vsock proxy.
///
/// Returns `None` if the listening port is already in use (non-fatal).
pub async fn start(runtime: Arc<Runtime>) -> Option<tokio::task::JoinHandle<()>> {
    let listener = match TcpListener::bind(("127.0.0.1", KUBERNETES_API_HOST_PORT)).await {
        Ok(listener) => listener,
        Err(e) => {
            warn!(
                "Failed to bind Kubernetes API proxy on 127.0.0.1:{}: {}",
                KUBERNETES_API_HOST_PORT, e
            );
            return None;
        }
    };

    info!(
        "Kubernetes API proxy listening on 127.0.0.1:{}",
        KUBERNETES_API_HOST_PORT
    );

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut host_stream, _)) = listener.accept().await else {
                continue;
            };
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move {
                let fd = match runtime
                    .connect_vsock_port(runtime.default_machine_name(), KUBERNETES_API_VSOCK_PORT)
                {
                    Ok(fd) => fd,
                    Err(e) => {
                        tracing::debug!("failed to connect Kubernetes API vsock: {}", e);
                        return;
                    }
                };

                // SAFETY: fd is a valid, newly-opened vsock socket owned by us.
                let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                let mut guest_stream =
                    match VsockStream::from_fd_with_shutdown(owned, VsockShutdown::CloseOnDropOnly)
                    {
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
    });

    Some(handle)
}
