//! Async batch datagram I/O, integrating [`BatchDgram`] with tokio's
//! [`AsyncFd`] for readiness notification.
//!
//! Requires the `tokio` feature.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;

use crate::batch::BatchDgram;

/// Newtype so `AsyncFd` can track a raw `OwnedFd`.
pub struct FdWrapper(OwnedFd);

impl AsRawFd for FdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// Async batch datagram I/O backed by tokio's [`AsyncFd`].
///
/// Combines [`BatchDgram`] with readiness-based I/O polling. The FD must
/// be non-blocking (`O_NONBLOCK`) before constructing this type.
pub struct AsyncBatchDgram {
    inner: AsyncFd<FdWrapper>,
    batch: BatchDgram,
}

impl AsyncBatchDgram {
    /// Creates a new async batch context, registering `fd` with the tokio
    /// reactor.
    ///
    /// # Errors
    ///
    /// Returns an error if the tokio reactor registration fails.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(FdWrapper(fd))?,
            batch: BatchDgram::new(),
        })
    }

    /// Returns the underlying raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }

    /// Waits for the FD to become readable, then receives a batch.
    ///
    /// Returns the number of datagrams received. Per-datagram lengths are
    /// accessible via the returned count and the internal entries.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors from the underlying batch receive.
    #[allow(clippy::future_not_send)] // intentional: contains raw pointers from iovec arrays
    pub async fn recv_batch(&mut self, bufs: &mut [&mut [u8]]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                self.batch.recv_batch(fd, bufs).map(|(_, n)| n)
            }) {
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }

    /// Waits for the FD to become writable, then sends a batch.
    ///
    /// Returns the number of datagrams sent.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors from the underlying batch send.
    #[allow(clippy::future_not_send)] // intentional: contains raw pointers from iovec arrays
    pub async fn send_batch(&mut self, bufs: &[&[u8]]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                self.batch.send_batch(fd, bufs)
            }) {
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }

    /// Provides read access to the inner [`AsyncFd`] for use in custom
    /// `tokio::select!` loops.
    pub fn inner(&self) -> &AsyncFd<FdWrapper> {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    /// Creates a non-blocking socketpair with 1 MB buffers.
    fn socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds: [i32; 2] = [0; 2];
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0);
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let buf_size: libc::c_int = 1024 * 1024;
        for fd in [a.as_raw_fd(), b.as_raw_fd()] {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    std::ptr::from_ref(&buf_size).cast(),
                    std::mem::size_of_val(&buf_size) as libc::socklen_t,
                );
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    std::ptr::from_ref(&buf_size).cast(),
                    std::mem::size_of_val(&buf_size) as libc::socklen_t,
                );
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        (a, b)
    }

    #[tokio::test]
    async fn test_async_roundtrip() {
        let (a, b) = socketpair();

        let mut sender = AsyncBatchDgram::new(a).unwrap();
        let mut receiver = AsyncBatchDgram::new(b).unwrap();

        let payloads: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 100]).collect();
        let bufs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let sent = sender.send_batch(&bufs).await.unwrap();
        assert_eq!(sent, 5);

        let mut recv_buffers: Vec<Vec<u8>> = (0..5).map(|_| vec![0u8; 256]).collect();
        let mut recv_bufs: Vec<&mut [u8]> =
            recv_buffers.iter_mut().map(|b| b.as_mut_slice()).collect();
        let count = receiver.recv_batch(&mut recv_bufs).await.unwrap();
        assert_eq!(count, 5);
        for i in 0..5u8 {
            assert_eq!(recv_buffers[i as usize][0], i);
        }
    }

    #[tokio::test]
    async fn test_async_concurrent() {
        let (a, b) = socketpair();

        let mut sender = AsyncBatchDgram::new(a).unwrap();
        let mut receiver = AsyncBatchDgram::new(b).unwrap();

        let payloads: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 64]).collect();
        let bufs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
        let sent = sender.send_batch(&bufs).await.unwrap();
        assert_eq!(sent, 50);

        let mut total = 0;
        while total < 50 {
            let mut buffers: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 128]).collect();
            let mut bufs: Vec<&mut [u8]> = buffers.iter_mut().map(|b| b.as_mut_slice()).collect();
            let count = receiver.recv_batch(&mut bufs).await.unwrap();
            total += count;
        }
        assert_eq!(total, 50);
    }
}
