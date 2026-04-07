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
    pub async fn recv_batch(&mut self, bufs: &mut [&mut [u8]]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                self.batch.recv_batch(fd, bufs).map(|(_, n)| n)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
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
    pub async fn send_batch(&mut self, bufs: &[&[u8]]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                self.batch.send_batch(fd, bufs)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Provides read access to the inner [`AsyncFd`] for use in custom
    /// `tokio::select!` loops.
    pub fn inner(&self) -> &AsyncFd<FdWrapper> {
        &self.inner
    }
}
