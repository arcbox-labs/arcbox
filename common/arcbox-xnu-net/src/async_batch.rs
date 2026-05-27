//! Async batch datagram I/O, integrating [`BatchDgram`] with tokio's
//! [`AsyncFd`] for readiness notification.
//!
//! Requires the `tokio` feature.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;

use crate::batch::{BatchDgram, RxEntry};

/// Async batch datagram I/O backed by tokio's [`AsyncFd`].
///
/// Combines [`BatchDgram`] with readiness-based I/O polling. The FD is
/// set to `O_NONBLOCK` during construction.
pub struct AsyncBatchDgram {
    inner: AsyncFd<OwnedFd>,
    batch: BatchDgram,
}

impl AsyncBatchDgram {
    /// Creates a new async batch context, registering `fd` with the tokio
    /// reactor.
    ///
    /// Sets `O_NONBLOCK` on `fd` — required for the readiness-based polling
    /// model and to keep batch syscalls from blocking the reactor thread.
    ///
    /// # Errors
    ///
    /// Returns an error if `fcntl(F_GETFL|F_SETFL)` fails or the tokio
    /// reactor registration fails.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(fd.as_raw_fd())?;
        Ok(Self {
            inner: AsyncFd::new(fd)?,
            batch: BatchDgram::new(),
        })
    }

    /// Returns the underlying raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }

    /// Waits for the FD to become readable, then receives a batch.
    ///
    /// Returns a slice of [`RxEntry`] mirroring [`BatchDgram::recv_batch`].
    /// `entries.len()` is the number of datagrams received and
    /// `entries[i].len` is the byte length written into `bufs[i]`.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors from the underlying batch receive. `WouldBlock`
    /// is handled internally by clearing readiness and re-awaiting.
    #[allow(clippy::future_not_send)] // intentional: contains raw pointers from iovec arrays
    pub async fn recv_batch(&mut self, bufs: &mut [&mut [u8]]) -> io::Result<&[RxEntry]> {
        // Drive readiness in an inner scope that yields just the datagram
        // count; re-borrow entries from self.batch afterwards. The detour
        // avoids the NLL/Polonius limitation where returning a borrow from
        // a loop iteration prevents the next iteration's reborrow.
        let n = {
            let Self { inner, batch } = self;
            loop {
                let mut guard = inner.readable().await?;
                let fd = guard.get_inner().as_raw_fd();
                match batch.recv_batch(fd, bufs) {
                    Ok(entries) => break entries.len(),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        guard.clear_ready();
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        Ok(self.batch.last_entries(n))
    }

    /// Sends `bufs` in full, looping over readiness as needed.
    ///
    /// Partial sends (where the kernel accepts only some datagrams before
    /// the buffer fills) are handled internally — this returns only once
    /// every datagram has been queued or an unrecoverable error is hit.
    /// `WouldBlock` causes the loop to clear readiness and re-await.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors from the underlying batch send other than
    /// `WouldBlock`. On error, any datagrams sent before the failure are
    /// already on the wire — there is no rollback.
    #[allow(clippy::future_not_send)] // intentional: contains raw pointers from iovec arrays
    pub async fn send_batch(&mut self, bufs: &[&[u8]]) -> io::Result<()> {
        let Self { inner, batch } = self;
        let mut sent = 0;
        while sent < bufs.len() {
            let mut guard = inner.writable().await?;
            let fd = guard.get_inner().as_raw_fd();
            match batch.send_batch(fd, &bufs[sent..]) {
                Ok(n) if n > 0 => sent += n,
                Ok(_) => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Provides read access to the inner [`AsyncFd`] for use in custom
    /// `tokio::select!` loops.
    pub fn inner(&self) -> &AsyncFd<OwnedFd> {
        &self.inner
    }
}

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

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    /// Creates a socketpair with 1 MB buffers. `O_NONBLOCK` is set later
    /// by [`AsyncBatchDgram::new`].
    fn socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds: [i32; 2] = [0; 2];
        // SAFETY: fds is a valid 2-element array; AF_UNIX SOCK_DGRAM is universally supported.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed: {}", io::Error::last_os_error());
        // SAFETY: fds[0]/fds[1] are freshly allocated by socketpair, owned by us.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [a.as_raw_fd(), b.as_raw_fd()] {
            set_buf_size(fd, libc::SO_SNDBUF, 1024 * 1024);
            set_buf_size(fd, libc::SO_RCVBUF, 1024 * 1024);
        }
        (a, b)
    }

    fn set_buf_size(fd: RawFd, name: libc::c_int, size: libc::c_int) {
        // SAFETY: fd is valid for the duration of the setsockopt call.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                std::ptr::from_ref(&size).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        };
        assert_eq!(
            ret,
            0,
            "setsockopt(name={name}) failed for fd {fd}: {}",
            io::Error::last_os_error()
        );
    }

    #[tokio::test]
    async fn test_async_roundtrip() {
        let (a, b) = socketpair();

        let mut sender = AsyncBatchDgram::new(a).unwrap();
        let mut receiver = AsyncBatchDgram::new(b).unwrap();

        let payloads: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 100]).collect();
        let bufs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        sender.send_batch(&bufs).await.unwrap();

        let mut recv_buffers: Vec<Vec<u8>> = (0..5).map(|_| vec![0u8; 256]).collect();
        let mut recv_bufs: Vec<&mut [u8]> =
            recv_buffers.iter_mut().map(|b| b.as_mut_slice()).collect();
        let entries = receiver.recv_batch(&mut recv_bufs).await.unwrap();
        assert_eq!(entries.len(), 5);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.len, 100);
            assert_eq!(recv_buffers[i][0], i as u8);
        }
    }

    #[tokio::test]
    async fn test_async_concurrent() {
        let (a, b) = socketpair();

        let mut sender = AsyncBatchDgram::new(a).unwrap();
        let mut receiver = AsyncBatchDgram::new(b).unwrap();

        let payloads: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 64]).collect();
        let bufs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        sender.send_batch(&bufs).await.unwrap();

        let mut total = 0;
        while total < 50 {
            let mut buffers: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 128]).collect();
            let mut bufs: Vec<&mut [u8]> = buffers.iter_mut().map(|b| b.as_mut_slice()).collect();
            let entries = receiver.recv_batch(&mut bufs).await.unwrap();
            total += entries.len();
        }
        assert_eq!(total, 50);
    }
}
