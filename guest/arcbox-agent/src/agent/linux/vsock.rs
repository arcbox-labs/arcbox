//! vsock listener helpers shared by the Agent and the API proxies.

use std::time::Duration;

use anyhow::Result;
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

pub(super) async fn bind_vsock_listener_with_retry(
    port: u32,
    component: &str,
) -> Result<VsockListener> {
    const INITIAL_DELAY_MS: u64 = 120;
    const MAX_DELAY_MS: u64 = 2_000;

    let mut delay_ms = INITIAL_DELAY_MS;

    loop {
        let addr = VsockAddr::new(VMADDR_CID_ANY, port);
        match VsockListener::bind(addr) {
            Ok(listener) => {
                tracing::info!(port, component, "vsock listener bound");
                return Ok(listener);
            }
            Err(e) => {
                tracing::warn!(
                    port,
                    component,
                    retry_delay_ms = delay_ms,
                    error = %e,
                    "failed to bind vsock listener, retrying"
                );
            }
        }

        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        delay_ms = (delay_ms * 3 / 2).min(MAX_DELAY_MS);
    }
}

/// True when `err`'s chain contains an `io::Error` whose kind indicates
/// that the peer closed the socket. These are routine during daemon
/// shutdown or retry-driven teardown, not agent-side faults.
pub(super) fn is_peer_closed_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| {
                matches!(
                    io_err.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                )
            })
    })
}
