use arcbox_transport::Transport;
use arcbox_transport::vsock::{BlockingVsockTransport, VsockTransport};
use bytes::Bytes;
use std::time::Duration;

/// Transport backend for agent RPC.
///
/// `Async` is the default for Linux AF_VSOCK and macOS VZ backend (real vsock
/// fds that tokio/kqueue handles correctly).
///
/// `Blocking` is used for macOS HV backend socketpair fds (AF_UNIX). These fds
/// trigger a tokio/kqueue reactor stall when rapidly created and torn down in a
/// retry loop, causing timer wakeups to stop firing. The blocking transport
/// uses `libc::poll` + `std::os::unix::net::UnixStream` and never touches the
/// tokio reactor — so it is constructed only on macOS, though its arms stay
/// compiled everywhere to keep the RPC bodies platform-free.
pub(super) enum AgentTransport {
    Async(VsockTransport),
    #[cfg_attr(
        not(target_os = "macos"),
        allow(
            dead_code,
            reason = "the HV socketpair is macOS-only, so its sole constructor \
                      `AgentClient::from_fd_blocking` is too"
        )
    )]
    Blocking(BlockingVsockTransport),
}

/// Default RPC deadline for blocking transport operations.
pub(super) const BLOCKING_RPC_TIMEOUT: Duration = Duration::from_secs(5);

impl AgentTransport {
    /// Async send — only valid for `Async` variant. Streaming RPCs that
    /// consume `self` and spawn async tasks must go through the async path.
    pub(super) async fn async_send(
        &mut self,
        data: Bytes,
    ) -> std::result::Result<(), arcbox_transport::error::TransportError> {
        match self {
            Self::Async(t) => t.send(data).await,
            Self::Blocking(_) => Err(arcbox_transport::error::TransportError::Protocol(
                "streaming RPCs not supported on blocking transport".into(),
            )),
        }
    }

    /// Async recv — only valid for `Async` variant.
    pub(super) async fn async_recv(
        &mut self,
    ) -> std::result::Result<Bytes, arcbox_transport::error::TransportError> {
        match self {
            Self::Async(t) => t.recv().await,
            Self::Blocking(_) => Err(arcbox_transport::error::TransportError::Protocol(
                "streaming RPCs not supported on blocking transport".into(),
            )),
        }
    }

    /// Split into send/recv halves — only valid for `Async` variant.
    pub(super) fn into_split(
        self,
    ) -> std::result::Result<
        (
            arcbox_transport::vsock::VsockSender,
            arcbox_transport::vsock::VsockReceiver,
        ),
        arcbox_transport::error::TransportError,
    > {
        match self {
            Self::Async(t) => t.into_split(),
            Self::Blocking(_) => Err(arcbox_transport::error::TransportError::Protocol(
                "split not supported on blocking transport".into(),
            )),
        }
    }
}
