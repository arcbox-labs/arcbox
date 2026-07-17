use super::addr::DEFAULT_AGENT_PORT;
use super::transport::VsockTransport;
use crate::TransportListener;
use crate::error::{Result, TransportError};
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

/// Vsock listener for accepting connections.
///
/// On Linux, this uses `AF_VSOCK` sockets directly.
/// On macOS, this requires a channel connected to `VZVirtioSocketDevice`.
pub struct VsockListener {
    port: u32,
    #[cfg(target_os = "linux")]
    listener_fd: Option<OwnedFd>,
    #[cfg(target_os = "macos")]
    handle: Option<super::darwin::VsockListenerHandle>,
}

impl VsockListener {
    /// Creates a new vsock listener on the given port.
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: After calling `bind()`, the listener will be ready to accept connections.
    /// - **macOS**: Use `from_channel()` instead to provide a channel connected to
    ///   `VZVirtioSocketDevice`. Calling `bind()` on this listener will fail.
    #[must_use]
    pub const fn new(port: u32) -> Self {
        Self {
            port,
            #[cfg(target_os = "linux")]
            listener_fd: None,
            #[cfg(target_os = "macos")]
            handle: None,
        }
    }

    /// Creates a listener from a channel (macOS).
    ///
    /// On macOS, vsock listening is done through `VZVirtioSocketDevice`.
    /// This method creates a listener that receives connections from a channel
    /// bridged to the Virtualization.framework layer.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub const fn from_channel(
        port: u32,
        receiver: tokio::sync::mpsc::UnboundedReceiver<super::darwin::IncomingVsockConnection>,
    ) -> Self {
        Self {
            port,
            handle: Some(super::darwin::VsockListenerHandle::new(port, receiver)),
        }
    }

    /// Creates a listener on the default agent port.
    #[must_use]
    pub const fn default_agent() -> Self {
        Self::new(DEFAULT_AGENT_PORT)
    }

    /// Returns the port number.
    #[must_use]
    pub const fn port(&self) -> u32 {
        self.port
    }
}

#[async_trait]
impl TransportListener for VsockListener {
    type Transport = VsockTransport;

    async fn bind(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let fd = super::linux::bind_vsock(self.port)?;
            self.listener_fd = Some(fd);
        }

        #[cfg(target_os = "macos")]
        {
            if self.handle.is_none() {
                return Err(TransportError::Protocol(
                    "macOS vsock requires VZVirtioSocketDevice. Use VsockListener::from_channel() \
                     with a channel fed by a caller-provided accept source."
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    async fn accept(&mut self) -> Result<Self::Transport> {
        #[cfg(target_os = "linux")]
        {
            let listener_fd = self
                .listener_fd
                .as_ref()
                .ok_or(TransportError::NotConnected)?;

            let (stream, addr) = super::linux::accept_vsock(listener_fd)?;
            Ok(VsockTransport::from_stream(stream, addr))
        }

        #[cfg(target_os = "macos")]
        {
            let handle = self.handle.as_mut().ok_or_else(|| {
                TransportError::Protocol(
                    "macOS vsock listener not initialized. Use VsockListener::from_channel()."
                        .to_string(),
                )
            })?;

            let (stream, addr) = handle.accept().await?;
            Ok(VsockTransport::from_stream(stream, addr))
        }
    }

    async fn close(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.listener_fd.take();
        }

        #[cfg(target_os = "macos")]
        {
            self.handle.take();
        }

        Ok(())
    }
}
