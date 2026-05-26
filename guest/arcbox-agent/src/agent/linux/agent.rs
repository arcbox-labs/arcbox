//! Agent entry point: vsock listener, connection accept loop, and process-wide
//! singletons (sandbox service, API proxies).

use anyhow::Result;

use arcbox_constants::ports::AGENT_PORT;

use super::disk::fstrim_loop;
use super::proxy::{run_docker_api_proxy, run_kubernetes_api_proxy};
use super::rpc::handle_connection;
use super::sandbox::sandbox_service;
use super::vsock::{bind_vsock_listener_with_retry, is_peer_closed_error};

/// The Guest Agent.
///
/// Listens on vsock and handles RPC requests from the host.
pub struct Agent;

impl Agent {
    /// Creates a new agent.
    pub fn new() -> Self {
        Self
    }

    /// Runs the agent, listening on vsock.
    pub async fn run(&self) -> Result<()> {
        // Mount standard VirtioFS shares if not already mounted.
        crate::mount::mount_standard_shares();

        // Eagerly initialise the sandbox service so its first-time
        // NetworkManager setup (which requires root) happens at startup
        // rather than on the first sandbox request.
        let _ = sandbox_service();

        // Start guest-side Docker API proxy (vsock -> unix socket).
        tokio::spawn(async {
            if let Err(e) = run_docker_api_proxy().await {
                tracing::warn!("Docker API proxy exited: {}", e);
            }
        });

        // Start guest-side Kubernetes API proxy (vsock -> localhost:6443).
        tokio::spawn(async {
            if let Err(e) = run_kubernetes_api_proxy().await {
                tracing::warn!("Kubernetes API proxy exited: {}", e);
            }
        });

        // Periodic fstrim to reclaim sparse file space on the host.
        tokio::spawn(fstrim_loop());

        let mut listener = bind_vsock_listener_with_retry(AGENT_PORT, "agent rpc listener").await?;

        tracing::info!("Agent listening on vsock port {}", AGENT_PORT);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    tracing::info!("Accepted connection from {:?}", peer_addr);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream).await {
                            // A routine daemon-side teardown (host closes the
                            // socketpair while the agent is writing a response)
                            // surfaces as BrokenPipe / ConnectionReset /
                            // UnexpectedEof. Log at warn — the daemon will
                            // reopen on its next poll iteration.
                            if is_peer_closed_error(&e) {
                                tracing::warn!("Connection closed by peer: {}", e);
                            } else {
                                tracing::error!("Connection error: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Accept error: {}", e);
                }
            }
        }
    }
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}
