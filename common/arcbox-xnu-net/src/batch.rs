//! Synchronous batch datagram I/O on raw file descriptors.

use std::io;
use std::os::fd::RawFd;

/// Maximum datagrams per batch call.
///
/// Matches the **default** `kern.ipc.maxrecvmsgx` / `kern.ipc.maxsendmsgx`
/// sysctl values (256) on macOS. Both sysctls are tunable: an operator —
/// or a hardened system image — can lower them, in which case calling
/// `recvmsg_x`/`sendmsg_x` with `cnt > maxrecvmsgx` returns `EINVAL`
/// rather than degrading to a smaller batch. Linux has no equivalent
/// kernel cap on `recvmmsg`/`sendmmsg`, but this constant is shared for
/// uniform buffer pre-allocation.
///
/// If you target hosts that may carry non-default sysctls, clamp your
/// per-call `bufs.len()` to a value you know is safe.
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

// SAFETY: BatchDgram contains raw pointers in its iovec/msghdr arrays, which
// is why the auto-impl of `Send` is denied. Those pointers are only valid
// for the duration of a single recv_batch/send_batch call — they alias the
// caller-supplied buffer slices, get filled in by `setup_recv`/`setup_send`,
// and are passed to the kernel by the immediately-following syscall under
// `&mut self`. Between calls they are stale and never dereferenced by Rust.
// Moving the struct across threads therefore moves no live aliases. We
// implement Send explicitly so the type is Send on both macOS and Linux
// (the Linux `libc::mmsghdr` is otherwise `!Send`).
#[allow(
    clippy::non_send_fields_in_send_ty,
    reason = "raw pointers in iovec/msghdr are stale between syscalls; see SAFETY above"
)]
unsafe impl Send for BatchDgram {}

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
    /// On success returns a slice of [`RxEntry`] whose length equals the
    /// number of datagrams received; `entries[i].len` is the byte length
    /// written into `bufs[i]`.
    ///
    /// `EINTR` is retried internally. Returns `Err(WouldBlock)` when the FD
    /// has no pending data — callers integrating with a readiness reactor
    /// rely on this to clear readiness.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` for syscall failures, including `WouldBlock`.
    pub fn recv_batch(&mut self, fd: RawFd, bufs: &mut [&mut [u8]]) -> io::Result<&[RxEntry]> {
        let count = bufs.len().min(MAX_BATCH);
        if count == 0 {
            return Ok(&[]);
        }

        self.setup_recv(bufs, count);

        let n = self.platform_recv(fd, count)?;

        self.collect_recv(n);

        Ok(&self.entries[..n])
    }

    /// Returns the first `count` [`RxEntry`] slots from the last
    /// [`recv_batch`](Self::recv_batch) call.
    ///
    /// Used by the async wrapper to re-borrow entries after the readiness
    /// loop releases its mutable borrow. Callers must pass the count
    /// returned by the latest `recv_batch`; passing a larger value reveals
    /// stale data from prior batches.
    #[cfg(any(feature = "tokio", test))]
    #[must_use]
    pub(crate) fn last_entries(&self, count: usize) -> &[RxEntry] {
        &self.entries[..count]
    }

    /// Sends up to `bufs.len()` datagrams (capped at [`MAX_BATCH`]) on `fd`.
    ///
    /// Returns the number of datagrams actually sent. `EINTR` is retried
    /// internally. Returns `Err(WouldBlock)` when the FD's send buffer is
    /// full — callers integrating with a readiness reactor rely on this to
    /// clear readiness.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` for syscall failures, including `WouldBlock`.
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
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
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
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
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
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
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
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
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

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    /// Creates a non-blocking `AF_UNIX SOCK_DGRAM` socketpair with enlarged
    /// buffers (1 MB each direction).
    fn socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds: [i32; 2] = [0; 2];
        // SAFETY: fds is a valid 2-element array; AF_UNIX SOCK_DGRAM is universally supported.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed: {}", io::Error::last_os_error());
        // SAFETY: fds[0]/fds[1] are freshly allocated by socketpair, owned by us.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // Enlarge socket buffers so tests with many/large datagrams don't
        // hit ENOBUFS or partial sends.
        for fd in [a.as_raw_fd(), b.as_raw_fd()] {
            set_buf_size(fd, libc::SO_SNDBUF, 1024 * 1024);
            set_buf_size(fd, libc::SO_RCVBUF, 1024 * 1024);
            set_nonblocking(fd);
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

    fn set_nonblocking(fd: RawFd) {
        // SAFETY: fd is valid; F_GETFL/F_SETFL are safe fcntl operations.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(
            flags >= 0,
            "fcntl(F_GETFL) failed for fd {fd}: {}",
            io::Error::last_os_error()
        );
        // SAFETY: same as above.
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert!(
            ret >= 0,
            "fcntl(F_SETFL, O_NONBLOCK) failed for fd {fd}: {}",
            io::Error::last_os_error()
        );
    }

    #[test]
    fn test_batch_dgram_is_send() {
        // Static assertion: BatchDgram must be Send on both macOS and
        // Linux so callers can move it across `tokio::spawn`.
        const fn require_send<T: Send>() {}
        require_send::<BatchDgram>();
    }

    fn write_datagram(fd: RawFd, data: &[u8]) {
        // SAFETY: writing to a valid socketpair fd.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        assert_eq!(n as usize, data.len(), "write_datagram short write");
    }

    fn read_datagram(fd: RawFd, buf: &mut [u8]) -> usize {
        // SAFETY: reading from a valid socketpair fd.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n >= 0, "read_datagram failed");
        n as usize
    }

    #[test]
    fn test_recv_send_single() {
        let (a, b) = socketpair();

        let payload = b"hello batch";
        write_datagram(a.as_raw_fd(), payload);

        let mut batch = BatchDgram::new();
        let mut buf = vec![0u8; 128];
        let mut bufs: Vec<&mut [u8]> = vec![buf.as_mut_slice()];
        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].len, payload.len());
        assert_eq!(&buf[..payload.len()], payload);
    }

    #[test]
    fn test_recv_send_batch() {
        let (a, b) = socketpair();

        for i in 0..10u8 {
            write_datagram(a.as_raw_fd(), &[i; 64]);
        }

        let mut batch = BatchDgram::new();
        let mut buffers: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; 128]).collect();
        let mut bufs: Vec<&mut [u8]> = buffers.iter_mut().map(|b| b.as_mut_slice()).collect();

        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();

        assert_eq!(entries.len(), 10);
        for i in 0..10u8 {
            assert_eq!(entries[i as usize].len, 64);
            assert_eq!(buffers[i as usize][0], i);
        }
    }

    #[test]
    fn test_send_batch_roundtrip() {
        let (a, b) = socketpair();

        let payloads: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 100]).collect();
        let bufs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();

        let mut batch = BatchDgram::new();
        let sent = batch.send_batch(a.as_raw_fd(), &bufs).unwrap();
        assert_eq!(sent, 10);

        let mut buf = [0u8; 256];
        for i in 0..10u8 {
            let n = read_datagram(b.as_raw_fd(), &mut buf);
            assert_eq!(n, 100);
            assert_eq!(buf[0], i);
        }
    }

    #[test]
    fn test_full_roundtrip() {
        let (a, b) = socketpair();

        let payloads: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i; 200]).collect();
        let send_bufs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();

        let mut batch = BatchDgram::new();
        let sent = batch.send_batch(a.as_raw_fd(), &send_bufs).unwrap();
        assert_eq!(sent, 20);

        let mut recv_buffers: Vec<Vec<u8>> = (0..20).map(|_| vec![0u8; 256]).collect();
        let mut recv_bufs: Vec<&mut [u8]> =
            recv_buffers.iter_mut().map(|b| b.as_mut_slice()).collect();

        let entries = batch.recv_batch(b.as_raw_fd(), &mut recv_bufs).unwrap();
        assert_eq!(entries.len(), 20);
        for i in 0..20u8 {
            assert_eq!(entries[i as usize].len, 200);
            assert_eq!(recv_buffers[i as usize][0], i);
        }
    }

    #[test]
    fn test_wouldblock_empty() {
        let (_a, b) = socketpair();

        let mut batch = BatchDgram::new();
        let mut buf = vec![0u8; 128];
        let mut bufs: Vec<&mut [u8]> = vec![buf.as_mut_slice()];

        let err = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_partial_batch() {
        let (a, b) = socketpair();

        for i in 0..3u8 {
            write_datagram(a.as_raw_fd(), &[i; 50]);
        }

        let mut batch = BatchDgram::new();
        let mut buffers: Vec<Vec<u8>> = (0..10).map(|_| vec![0u8; 128]).collect();
        let mut bufs: Vec<&mut [u8]> = buffers.iter_mut().map(|b| b.as_mut_slice()).collect();

        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();
        assert_eq!(entries.len(), 3);
        for entry in entries.iter().take(3) {
            assert_eq!(entry.len, 50);
        }
    }

    #[test]
    fn test_zero_length_datagram() {
        let (a, b) = socketpair();

        write_datagram(a.as_raw_fd(), &[]);

        let mut batch = BatchDgram::new();
        let mut buf = vec![0u8; 128];
        let mut bufs: Vec<&mut [u8]> = vec![buf.as_mut_slice()];

        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].len, 0);
    }

    #[test]
    fn test_recv_empty_socket_is_wouldblock() {
        let (_a, b) = socketpair();

        let mut buffers: Vec<Vec<u8>> = (0..300).map(|_| vec![0u8; 64]).collect();
        let mut bufs: Vec<&mut [u8]> = buffers.iter_mut().map(|b| b.as_mut_slice()).collect();

        let mut batch = BatchDgram::new();
        let err = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_max_batch_cap() {
        // With more queued datagrams than `MAX_BATCH` and a longer `bufs`
        // slice, a single `recv_batch` should return exactly `MAX_BATCH`
        // entries — not the full `bufs.len()` and not less.
        let (a, b) = socketpair();

        let extra = 10;
        for _ in 0..MAX_BATCH + extra {
            write_datagram(a.as_raw_fd(), &[0xAA; 8]);
        }

        let mut buffers: Vec<Vec<u8>> = (0..MAX_BATCH + extra * 2).map(|_| vec![0u8; 64]).collect();
        let mut bufs: Vec<&mut [u8]> = buffers.iter_mut().map(|b| b.as_mut_slice()).collect();

        let mut batch = BatchDgram::new();
        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();
        assert_eq!(
            entries.len(),
            MAX_BATCH,
            "first call must return exactly MAX_BATCH ({MAX_BATCH}) entries"
        );
        for entry in entries {
            assert_eq!(entry.len, 8);
        }

        // The remaining `extra` datagrams stay queued for a follow-up call.
        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();
        assert_eq!(entries.len(), extra);
    }

    #[test]
    fn test_varying_sizes() {
        let (a, b) = socketpair();

        let sizes = [1, 100, 1000, 4000];
        for &size in &sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            write_datagram(a.as_raw_fd(), &data);
        }

        let mut batch = BatchDgram::new();
        let mut buffers: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 8192]).collect();
        let mut bufs: Vec<&mut [u8]> = buffers.iter_mut().map(|b| b.as_mut_slice()).collect();

        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();
        assert_eq!(entries.len(), 4);
        for (i, &size) in sizes.iter().enumerate() {
            assert_eq!(entries[i].len, size, "datagram {i} size mismatch");
        }
    }

    #[test]
    fn test_empty_bufs() {
        let (_a, b) = socketpair();

        let mut batch = BatchDgram::new();
        let mut bufs: Vec<&mut [u8]> = vec![];
        let entries = batch.recv_batch(b.as_raw_fd(), &mut bufs).unwrap();
        assert!(entries.is_empty());

        let send_bufs: Vec<&[u8]> = vec![];
        let sent = batch.send_batch(b.as_raw_fd(), &send_bufs).unwrap();
        assert_eq!(sent, 0);
    }

    #[test]
    fn test_threaded_correctness() {
        let (a, b) = socketpair();
        let fd_a = a.as_raw_fd();
        let fd_b = b.as_raw_fd();

        // Fds must outlive both threads. Move OwnedFds into a shared
        // scope that drops after both threads join.
        let sender = std::thread::spawn(move || {
            let mut batch = BatchDgram::new();
            for chunk_start in (0u16..200).step_by(10) {
                let payloads: Vec<Vec<u8>> = (chunk_start..chunk_start + 10)
                    .map(|i| i.to_le_bytes().to_vec())
                    .collect();
                let bufs: Vec<&[u8]> = payloads.iter().map(|p| p.as_slice()).collect();
                loop {
                    match batch.send_batch(fd_a, &bufs) {
                        Ok(n) if n > 0 => break,
                        Ok(_) => std::thread::yield_now(),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::yield_now();
                        }
                        Err(e) => panic!("send error: {e}"),
                    }
                }
            }
        });

        let receiver = std::thread::spawn(move || {
            let mut batch = BatchDgram::new();
            let mut received = 0usize;
            while received < 200 {
                let mut buffers: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 64]).collect();
                let mut bufs: Vec<&mut [u8]> =
                    buffers.iter_mut().map(|b| b.as_mut_slice()).collect();
                match batch.recv_batch(fd_b, &mut bufs) {
                    Ok(entries) => {
                        if entries.is_empty() {
                            std::thread::yield_now();
                        }
                        received += entries.len();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(e) => panic!("recv error: {e}"),
                }
            }
            received
        });

        sender.join().unwrap();
        let total = receiver.join().unwrap();
        assert!(total >= 200, "expected >= 200 datagrams, got {total}");
        drop(a);
        drop(b);
    }
}
