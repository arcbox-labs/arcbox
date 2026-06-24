use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Async vsock stream.
///
/// Two modes:
/// - `Fd`: Raw `AsyncFd<OwnedFd>` for real vsock connections (VZ backend,
///   Linux `AF_VSOCK`). Uses kqueue/epoll directly.
/// - `Unix`: `tokio::net::UnixStream` for HV backend socketpairs. Delegates
///   to tokio's well-tested Unix stream implementation, avoiding intermittent
///   timeout cancellation issues with raw AsyncFd on reused fd numbers.
pub struct VsockStream {
    inner: VsockStreamInner,
    shutdown: VsockShutdown,
}

/// Shutdown behavior for [`VsockStream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsockShutdown {
    /// Call `shutdown(SHUT_WR)` when Tokio asks to shut down the write half.
    HalfClose,
    /// Treat Tokio shutdown as a no-op and close only when the fd is dropped.
    ///
    /// Some macOS vsock backends tear down the full connection on half-close,
    /// which breaks HTTP upgrade tunnels that need to keep the fd alive after
    /// the response handshake.
    CloseOnDropOnly,
}

enum VsockStreamInner {
    Fd(AsyncFd<OwnedFd>),
    Unix(tokio::net::UnixStream),
}

impl VsockStream {
    /// Sets a file descriptor to non-blocking mode.
    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        // SAFETY: fd is valid for the duration of the fcntl calls.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is valid; O_NONBLOCK is a safe flag to set.
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Creates a vsock stream from an [`OwnedFd`] (Fd mode).
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        Self::from_fd_with_shutdown(fd, VsockShutdown::HalfClose)
    }

    /// Creates a vsock stream from an [`OwnedFd`] (Fd mode) with explicit
    /// shutdown behavior.
    pub fn from_fd_with_shutdown(fd: OwnedFd, shutdown: VsockShutdown) -> io::Result<Self> {
        Self::set_nonblocking(fd.as_raw_fd())?;
        Ok(Self {
            inner: VsockStreamInner::Fd(AsyncFd::new(fd)?),
            shutdown,
        })
    }

    /// Creates a vsock stream from a raw file descriptor, taking ownership.
    ///
    /// # Safety
    /// The caller must ensure `fd` is a valid connected vsock file descriptor.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        Self::from_fd(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Creates a vsock stream from a raw file descriptor, taking ownership,
    /// with explicit shutdown behavior.
    ///
    /// # Safety
    /// The caller must ensure `fd` is a valid connected vsock file descriptor.
    pub unsafe fn from_raw_fd_with_shutdown(
        fd: RawFd,
        shutdown: VsockShutdown,
    ) -> io::Result<Self> {
        Self::from_fd_with_shutdown(unsafe { OwnedFd::from_raw_fd(fd) }, shutdown)
    }

    /// Creates a vsock stream wrapping a `tokio::net::UnixStream` (Unix mode).
    /// Used for HV backend socketpairs.
    pub fn from_unix_stream(stream: tokio::net::UnixStream) -> Self {
        Self::from_unix_stream_with_shutdown(stream, VsockShutdown::HalfClose)
    }

    /// Creates a vsock stream wrapping a `tokio::net::UnixStream` (Unix mode)
    /// with explicit shutdown behavior.
    pub fn from_unix_stream_with_shutdown(
        stream: tokio::net::UnixStream,
        shutdown: VsockShutdown,
    ) -> Self {
        Self {
            inner: VsockStreamInner::Unix(stream),
            shutdown,
        }
    }

    /// Returns the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        match &self.inner {
            VsockStreamInner::Fd(afd) => afd.as_raw_fd(),
            VsockStreamInner::Unix(us) => us.as_raw_fd(),
        }
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            VsockStreamInner::Unix(us) => Pin::new(us).poll_read(cx, buf),
            VsockStreamInner::Fd(inner) => loop {
                let mut guard = ready!(inner.poll_read_ready(cx))?;
                let unfilled = buf.initialize_unfilled();
                match guard.try_io(|inner| {
                    loop {
                        let n = unsafe {
                            libc::read(
                                inner.as_raw_fd(),
                                unfilled.as_mut_ptr().cast::<libc::c_void>(),
                                unfilled.len(),
                            )
                        };
                        if n >= 0 {
                            return Ok(n as usize);
                        }
                        let err = io::Error::last_os_error();
                        if err.kind() != io::ErrorKind::Interrupted {
                            return Err(err);
                        }
                    }
                }) {
                    Ok(Ok(n)) => {
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_would_block) => {}
                }
            },
        }
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            VsockStreamInner::Unix(us) => Pin::new(us).poll_write(cx, buf),
            VsockStreamInner::Fd(inner) => loop {
                let mut guard = ready!(inner.poll_write_ready(cx))?;
                match guard.try_io(|inner| {
                    loop {
                        let n = unsafe {
                            libc::write(
                                inner.as_raw_fd(),
                                buf.as_ptr().cast::<libc::c_void>(),
                                buf.len(),
                            )
                        };
                        if n >= 0 {
                            return Ok(n as usize);
                        }
                        let err = io::Error::last_os_error();
                        if err.kind() != io::ErrorKind::Interrupted {
                            return Err(err);
                        }
                    }
                }) {
                    Ok(result) => return Poll::Ready(result),
                    Err(_would_block) => {}
                }
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            VsockStreamInner::Unix(us) => Pin::new(us).poll_flush(cx),
            VsockStreamInner::Fd(_) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutdown == VsockShutdown::CloseOnDropOnly {
            return Poll::Ready(Ok(()));
        }

        match &mut this.inner {
            VsockStreamInner::Unix(us) => Pin::new(us).poll_shutdown(cx),
            VsockStreamInner::Fd(inner) => loop {
                let mut guard = ready!(inner.poll_write_ready(cx))?;
                match guard.try_io(|inner| {
                    let ret = unsafe { libc::shutdown(inner.as_raw_fd(), libc::SHUT_WR) };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        if matches!(err.raw_os_error(), Some(libc::ENOTCONN | libc::EINVAL)) {
                            Ok(())
                        } else {
                            Err(err)
                        }
                    } else {
                        Ok(())
                    }
                }) {
                    Ok(result) => return Poll::Ready(result),
                    Err(_would_block) => {}
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn half_close_shutdown_closes_write_half() {
        let (stream, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let mut stream =
            VsockStream::from_unix_stream_with_shutdown(stream, VsockShutdown::HalfClose);

        stream.shutdown().await.unwrap();

        let mut buf = [0_u8; 1];
        let n = peer.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn close_on_drop_only_shutdown_keeps_connection_open_until_drop() {
        let (stream, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let mut stream =
            VsockStream::from_unix_stream_with_shutdown(stream, VsockShutdown::CloseOnDropOnly);

        stream.shutdown().await.unwrap();

        let mut buf = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(20), peer.read(&mut buf)).await;
        assert!(read.is_err(), "shutdown must not half-close the peer");

        drop(stream);

        let n = peer.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }
}
