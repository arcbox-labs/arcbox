//! The frame ingest seam.
//!
//! [`FrameClassifier`](crate::classifier::FrameClassifier) is fed frames
//! rather than owning an fd; a [`FrameSource`] is "an fd to await for read
//! readiness plus a non-blocking `drain` that yields each available frame".
//! Both the VM datapath (over a socketpair) and the host tunnel (over a
//! `utun`, via the [`shim`](crate::shim)) supply a [`FrameSource`].

use std::io;
use std::os::fd::RawFd;

/// Largest L2 frame we read from a source in a single `read`.
const MAX_FRAME_SIZE: usize = 65535;

/// A source of inbound L2 Ethernet frames.
///
/// The datapath loop registers [`as_raw_fd`](FrameSource::as_raw_fd) with its
/// async runtime for read readiness, then calls [`drain`](FrameSource::drain)
/// to consume every currently-available frame without blocking.
///
/// The trait is generic over the per-frame callback (so the hot loop
/// monomorphizes — no per-frame virtual dispatch) and is therefore not
/// dyn-compatible, which is intentional: callers hold a concrete source.
pub trait FrameSource {
    /// The fd to register for read readiness.
    fn as_raw_fd(&self) -> RawFd;

    /// Drains all currently-available frames, invoking `f` once per frame.
    /// Returns when the source would block (or hits EOF/error).
    fn drain(&mut self, f: impl FnMut(&[u8]));
}

/// A [`FrameSource`] backed by a raw fd read with `libc::read`.
///
/// Suitable for any fd that delivers whole L2 frames per read — the VM's
/// `SOCK_DGRAM` socketpair, or a `utun` once wrapped by the
/// [`shim`](crate::shim). The fd must already be non-blocking; the datapath
/// sets `O_NONBLOCK` before registering it for readiness.
pub struct FdFrameSource {
    fd: RawFd,
    read_buf: Vec<u8>,
}

impl FdFrameSource {
    /// Wraps a (non-blocking) raw fd. The fd is not owned — its lifetime is
    /// managed by the caller (typically an `AsyncFd<OwnedFd>` registered for
    /// readiness on the same descriptor).
    #[must_use]
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            read_buf: vec![0u8; MAX_FRAME_SIZE],
        }
    }
}

impl FrameSource for FdFrameSource {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    fn drain(&mut self, mut f: impl FnMut(&[u8])) {
        loop {
            match fd_read(self.fd, &mut self.read_buf) {
                Ok(n) if n > 0 => f(&self.read_buf[..n]),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    tracing::warn!("frame source read error: {e}");
                    break;
                }
            }
        }
    }
}

/// Reads from a file descriptor into `buf`, returning the number of bytes read.
fn fd_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: reading into our own buffer from a valid fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
    }
}
