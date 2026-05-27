use super::addr::{DEFAULT_AGENT_PORT, VsockAddr};
use super::stream::VsockStream;
use crate::Transport;
use crate::error::{Result, TransportError};
use async_trait::async_trait;
use bytes::Bytes;
use std::io;
use std::os::fd::RawFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

/// Maximum allowed frame payload size (16 MiB).
///
/// Frames larger than this are rejected before allocation to prevent a
/// misbehaving or compromised guest from triggering unbounded memory growth on
/// the host.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Reads one length-prefixed frame from `reader`.
///
/// Returns the complete framed bytes (4-byte BE length prefix + payload).
/// Rejects frames larger than [`MAX_FRAME_SIZE`] before allocating.
async fn read_framed<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Bytes> {
    // Read 4-byte big-endian length prefix.
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(TransportError::io)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(TransportError::Protocol(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }
    tracing::debug!("vsock read_framed: message length={}", len);

    // Single allocation: length prefix + payload.
    let mut buf = vec![0u8; 4 + len];
    buf[..4].copy_from_slice(&len_buf);
    reader
        .read_exact(&mut buf[4..])
        .await
        .map_err(TransportError::io)?;
    Ok(Bytes::from(buf))
}

/// Write half of a split [`VsockTransport`].
///
/// Obtained via [`VsockTransport::into_split`]. Owns the write side of the
/// underlying stream. The caller is responsible for providing already-framed
/// data (e.g. from `AgentClient::build_message`).
pub struct VsockSender {
    writer: WriteHalf<VsockStream>,
}

impl VsockSender {
    /// Sends a framed message.
    ///
    /// `data` must already include the wire framing produced by the upper
    /// layer (e.g. `AgentClient::build_message`).
    pub async fn send(&mut self, data: Bytes) -> Result<()> {
        self.writer
            .write_all(&data)
            .await
            .map_err(TransportError::io)
    }
}

/// Read half of a split [`VsockTransport`].
///
/// Obtained via [`VsockTransport::into_split`]. Owns the read side of the
/// underlying stream and reads one length-prefixed frame per call, matching
/// the framing of [`VsockTransport::recv`].
pub struct VsockReceiver {
    reader: ReadHalf<VsockStream>,
}

impl VsockReceiver {
    /// Receives one framed message.
    ///
    /// Returns the complete framed bytes (4-byte BE length prefix + payload),
    /// matching the format returned by [`VsockTransport::recv`].
    pub async fn recv(&mut self) -> Result<Bytes> {
        read_framed(&mut self.reader).await
    }
}

/// Vsock transport for host-guest communication.
pub struct VsockTransport {
    addr: VsockAddr,
    stream: Option<VsockStream>,
}

impl VsockTransport {
    /// Creates a new vsock transport for the given address.
    #[must_use]
    pub const fn new(addr: VsockAddr) -> Self {
        Self { addr, stream: None }
    }

    /// Creates a transport to the host on the default agent port.
    #[must_use]
    pub const fn to_host() -> Self {
        Self::new(VsockAddr::host(DEFAULT_AGENT_PORT))
    }

    /// Returns the vsock address.
    #[must_use]
    pub const fn addr(&self) -> VsockAddr {
        self.addr
    }

    /// Creates a transport from an existing stream.
    #[must_use]
    pub fn from_stream(stream: VsockStream, addr: VsockAddr) -> Self {
        Self {
            addr,
            stream: Some(stream),
        }
    }

    /// Creates a transport from a raw file descriptor (macOS).
    ///
    /// On macOS, vsock connections are obtained through the hypervisor layer
    /// (`DarwinVm::connect_vsock`). This method allows wrapping that fd into
    /// a transport.
    ///
    /// # Arguments
    /// * `fd` - A connected vsock file descriptor from the hypervisor
    /// * `addr` - The vsock address (for tracking purposes)
    ///
    /// Creates a transport from a raw file descriptor (macOS).
    ///
    /// For HV backend, the fd is a Unix SOCK_STREAM socketpair end. We wrap
    /// it in `tokio::net::UnixStream` (well-tested async I/O) rather than
    /// our custom `VsockStream` (which uses raw `AsyncFd` and has intermittent
    /// timeout cancellation issues with fd reuse across connection retries).
    #[cfg(target_os = "macos")]
    pub fn from_raw_fd(fd: RawFd, addr: VsockAddr) -> Result<Self> {
        if fd < 0 {
            return Err(TransportError::io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid raw vsock file descriptor",
            )));
        }
        // SAFETY: fd is a valid socketpair fd from connect_vsock_hv.
        use std::os::unix::io::FromRawFd as _;
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std_stream
            .set_nonblocking(true)
            .map_err(TransportError::io)?;
        let tokio_stream =
            tokio::net::UnixStream::from_std(std_stream).map_err(TransportError::io)?;
        let stream = VsockStream::from_unix_stream(tokio_stream);
        Ok(Self {
            addr,
            stream: Some(stream),
        })
    }

    /// Splits the transport into independent send and receive halves.
    ///
    /// Consumes `self`. The returned [`VsockSender`] and [`VsockReceiver`] can
    /// be moved into separate tasks for full-duplex communication. Tokio may
    /// use internal synchronization to coordinate access to the underlying
    /// stream.
    ///
    /// # Errors
    /// Returns [`TransportError::NotConnected`] if the transport is not
    /// connected.
    pub fn into_split(self) -> Result<(VsockSender, VsockReceiver)> {
        let stream = self.stream.ok_or(TransportError::NotConnected)?;
        let (reader, writer) = tokio::io::split(stream);
        Ok((VsockSender { writer }, VsockReceiver { reader }))
    }
}

#[async_trait]
impl Transport for VsockTransport {
    async fn connect(&mut self) -> Result<()> {
        if self.stream.is_some() {
            return Err(TransportError::AlreadyConnected);
        }

        #[cfg(target_os = "linux")]
        {
            let stream = super::linux::connect_vsock(self.addr)?;
            self.stream = Some(stream);
        }

        #[cfg(target_os = "macos")]
        {
            let stream = super::darwin::connect_vsock(self.addr)?;
            self.stream = Some(stream);
        }

        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.stream.take();
        Ok(())
    }

    async fn send(&mut self, data: Bytes) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        // Data already carries the wire framing (length prefix + type + payload).
        stream.write_all(&data).await.map_err(TransportError::io)
    }

    async fn recv(&mut self) -> Result<Bytes> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;
        read_framed(stream).await
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}
