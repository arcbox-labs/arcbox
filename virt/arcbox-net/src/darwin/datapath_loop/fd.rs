use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// Wraps an `OwnedFd` so it can be registered with `AsyncFd`.
pub(super) struct FdWrapper(pub(super) OwnedFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Writes data to a raw file descriptor, returning bytes written or an error.
pub(super) fn fd_write(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    // SAFETY: writing from our buffer to a valid socketpair fd.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
    }
}

/// Writes a frame to the guest FD (best-effort, non-blocking).
///
/// Used in tests for direct FD write verification.
#[cfg(test)]
pub(super) fn write_to_guest(guest_async: &tokio::io::unix::AsyncFd<FdWrapper>, data: &[u8]) {
    let fd = guest_async.get_ref().as_raw_fd();
    // SAFETY: writing from our buffer to a valid socketpair fd.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            tracing::warn!("Guest write WouldBlock: {} bytes dropped", data.len());
        } else {
            tracing::warn!("Guest write error: {}", err);
        }
    } else {
        tracing::debug!("Guest write OK: {}/{} bytes", n, data.len());
    }
}

/// Reads from a file descriptor into `buf`, returning number of bytes read.
#[allow(dead_code)]
pub(super) fn fd_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: reading into our buffer from a valid fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
    }
}

/// Sets a file descriptor to non-blocking mode.
pub(super) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl on a valid fd.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
