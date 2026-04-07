//! Synchronous batch datagram I/O on raw file descriptors.

use std::io;
use std::os::fd::RawFd;

/// Maximum datagrams per batch call. Matches XNU's default
/// `kern.ipc.maxrecvmsgx` sysctl (256).
pub const MAX_BATCH: usize = 256;

/// Result of a single datagram within a batch receive.
#[derive(Debug, Clone, Copy)]
pub struct RxEntry {
    /// Number of bytes received into the corresponding buffer.
    pub len: usize,
}

/// Batch datagram I/O on a non-blocking `SOCK_DGRAM` file descriptor.
///
/// Manages pre-allocated header and iovec arrays internally. The caller
/// provides buffer slices; this type handles the platform-specific batch
/// syscall and returns per-datagram metadata.
///
/// Does **not** own the file descriptor. The FD must outlive this struct
/// and must be set to `O_NONBLOCK` before use.
pub struct BatchDgram {
    #[cfg(target_os = "macos")]
    hdrs: Vec<crate::ffi::darwin::msghdr_x>,
    #[cfg(target_os = "linux")]
    hdrs: Vec<libc::mmsghdr>,

    iovecs: Vec<libc::iovec>,
    entries: Vec<RxEntry>,
}

impl BatchDgram {
    /// Creates a new batch I/O context with pre-allocated arrays for up to
    /// [`MAX_BATCH`] datagrams.
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            hdrs: vec![crate::ffi::darwin::msghdr_x::zeroed(); MAX_BATCH],
            #[cfg(target_os = "linux")]
            // SAFETY: zeroed mmsghdr is valid (null pointers, zero lengths).
            hdrs: vec![unsafe { std::mem::zeroed() }; MAX_BATCH],

            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                MAX_BATCH
            ],
            entries: vec![RxEntry { len: 0 }; MAX_BATCH],
        }
    }

    /// Receives up to `bufs.len()` datagrams (capped at [`MAX_BATCH`]) from `fd`.
    ///
    /// Returns `(entries, count)` where `count` is the number of datagrams
    /// received and `entries[..count]` contains per-datagram metadata.
    ///
    /// Returns `Ok((_, 0))` when the FD has no pending data (`WouldBlock`).
    /// `EINTR` is retried internally.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` for syscall failures other than `WouldBlock`/`EINTR`.
    pub fn recv_batch(
        &mut self,
        fd: RawFd,
        bufs: &mut [&mut [u8]],
    ) -> io::Result<(&[RxEntry], usize)> {
        let count = bufs.len().min(MAX_BATCH);
        if count == 0 {
            return Ok((&[], 0));
        }

        self.setup_recv(bufs, count);

        let n = self.platform_recv(fd, count)?;

        self.collect_recv(n);

        Ok((&self.entries[..n], n))
    }

    /// Sends up to `bufs.len()` datagrams (capped at [`MAX_BATCH`]) on `fd`.
    ///
    /// Returns the number of datagrams actually sent. Returns `Ok(0)` when
    /// the FD's send buffer is full (`WouldBlock`). `EINTR` is retried
    /// internally.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` for syscall failures other than `WouldBlock`/`EINTR`.
    pub fn send_batch(&mut self, fd: RawFd, bufs: &[&[u8]]) -> io::Result<usize> {
        let count = bufs.len().min(MAX_BATCH);
        if count == 0 {
            return Ok(0);
        }

        self.setup_send(bufs, count);

        self.platform_send(fd, count)
    }

    // ── Buffer setup ───────────────────────────────────────────────────

    fn setup_recv(&mut self, bufs: &mut [&mut [u8]], count: usize) {
        for (i, buf) in bufs.iter_mut().enumerate().take(count) {
            self.iovecs[i] = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
        }
        self.setup_hdrs_recv(count);
    }

    fn setup_send(&mut self, bufs: &[&[u8]], count: usize) {
        for (i, buf) in bufs.iter().enumerate().take(count) {
            self.iovecs[i] = libc::iovec {
                iov_base: buf.as_ptr().cast_mut().cast(),
                iov_len: buf.len(),
            };
        }
        self.setup_hdrs_send(count);
    }

    // ── macOS implementation ───────────────────────────────────────────

    #[cfg(target_os = "macos")]
    fn setup_hdrs_recv(&mut self, count: usize) {
        for i in 0..count {
            // Full zero is required — older XNU validates all fields.
            self.hdrs[i] = crate::ffi::darwin::msghdr_x::zeroed();
            self.hdrs[i].msg_iov = &raw mut self.iovecs[i];
            self.hdrs[i].msg_iovlen = 1;
        }
    }

    #[cfg(target_os = "macos")]
    fn setup_hdrs_send(&mut self, count: usize) {
        for i in 0..count {
            self.hdrs[i] = crate::ffi::darwin::msghdr_x::zeroed();
            self.hdrs[i].msg_iov = &raw mut self.iovecs[i];
            self.hdrs[i].msg_iovlen = 1;
        }
    }

    #[cfg(target_os = "macos")]
    fn platform_recv(&mut self, fd: RawFd, count: usize) -> io::Result<usize> {
        loop {
            // SAFETY: hdrs and iovecs are valid, count is bounded by
            // MAX_BATCH, fd is a valid non-blocking SOCK_DGRAM descriptor.
            let n = unsafe {
                crate::ffi::darwin::recvmsg_x(
                    fd,
                    self.hdrs.as_mut_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(0),
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn platform_send(&mut self, fd: RawFd, count: usize) -> io::Result<usize> {
        loop {
            // SAFETY: hdrs and iovecs are valid, count bounded, fd valid.
            let n = unsafe {
                crate::ffi::darwin::sendmsg_x(
                    fd,
                    self.hdrs.as_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(0),
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn collect_recv(&mut self, n: usize) {
        for i in 0..n {
            self.entries[i] = RxEntry {
                len: self.hdrs[i].msg_datalen,
            };
        }
    }

    // ── Linux implementation ───────────────────────────────────────────

    #[cfg(target_os = "linux")]
    fn setup_hdrs_recv(&mut self, count: usize) {
        for i in 0..count {
            // SAFETY: zeroed mmsghdr is valid (null pointers, zero lengths).
            self.hdrs[i] = unsafe { std::mem::zeroed() };
            self.hdrs[i].msg_hdr.msg_iov = &raw mut self.iovecs[i];
            self.hdrs[i].msg_hdr.msg_iovlen = 1;
        }
    }

    #[cfg(target_os = "linux")]
    fn setup_hdrs_send(&mut self, count: usize) {
        for i in 0..count {
            // SAFETY: zeroed mmsghdr is valid.
            self.hdrs[i] = unsafe { std::mem::zeroed() };
            self.hdrs[i].msg_hdr.msg_iov = &raw mut self.iovecs[i];
            self.hdrs[i].msg_hdr.msg_iovlen = 1;
        }
    }

    #[cfg(target_os = "linux")]
    fn platform_recv(&mut self, fd: RawFd, count: usize) -> io::Result<usize> {
        loop {
            // SAFETY: hdrs and iovecs valid, count bounded, fd valid.
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    self.hdrs.as_mut_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(0),
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn platform_send(&mut self, fd: RawFd, count: usize) -> io::Result<usize> {
        loop {
            // SAFETY: hdrs and iovecs valid, count bounded, fd valid.
            let n = unsafe {
                libc::sendmmsg(
                    fd,
                    self.hdrs.as_mut_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(0),
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn collect_recv(&mut self, n: usize) {
        for i in 0..n {
            self.entries[i] = RxEntry {
                len: self.hdrs[i].msg_len as usize,
            };
        }
    }
}

impl Default for BatchDgram {
    fn default() -> Self {
        Self::new()
    }
}
