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
        Self::set_nonblocking(fd.as_raw_fd())?;
        Ok(Self {
            inner: VsockStreamInner::Fd(AsyncFd::new(fd)?),
        })
    }

    /// Creates a vsock stream from a raw file descriptor, taking ownership.
    ///
    /// # Safety
    /// The caller must ensure `fd` is a valid connected vsock file descriptor.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        Self::from_fd(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Creates a vsock stream wrapping a `tokio::net::UnixStream` (Unix mode).
    /// Used for HV backend socketpairs.
    pub fn from_unix_stream(stream: tokio::net::UnixStream) -> Self {
        Self {
            inner: VsockStreamInner::Unix(stream),
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
        match &mut self.get_mut().inner {
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
