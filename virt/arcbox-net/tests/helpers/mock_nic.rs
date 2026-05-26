//! Mock guest NIC using a Unix socketpair.
//!
//! Provides a socketpair-based mock for the guest VM's network device FD.
//! The host end is passed to `NetworkDatapath`, while the "guest" end is used
//! by tests to inject L2 Ethernet frames and read responses.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// Creates a `SOCK_DGRAM` socketpair and returns `(host_fd, guest_fd)`.
///
/// The host FD is passed into `NetworkDatapath` (or `FrameClassifier`).
/// The guest FD is used by the test to write/read raw Ethernet frames.
pub fn mock_guest_nic() -> (OwnedFd, OwnedFd) {
    let mut fds: [i32; 2] = [0; 2];
    // SAFETY: valid pointer to 2-element array.
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "socketpair() failed");
    // SAFETY: fds are valid file descriptors returned by socketpair.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// Sets a file descriptor to non-blocking mode.
pub fn set_nonblocking(fd: RawFd) {
    // SAFETY: fcntl on a valid fd.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Writes a raw frame to a file descriptor (blocking, for test setup).
pub fn fd_write(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    // SAFETY: writing from a valid buffer to a valid fd.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
    }
}

/// Reads a raw frame from a file descriptor (non-blocking).
///
/// Returns `Ok(vec)` with the frame data, or `Err` if no data is available
/// or the read fails.
pub fn fd_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: reading into a valid buffer from a valid fd.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(clippy::cast_sign_loss)]
        Ok(n as usize)
    }
}

/// Reads all available frames from a non-blocking FD, returning them as
/// a `Vec<Vec<u8>>`. Stops on `EWOULDBLOCK`.
pub fn drain_frames(fd: RawFd) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut buf = vec![0u8; 65535];
    loop {
        match fd_read(fd, &mut buf) {
            Ok(n) if n > 0 => frames.push(buf[..n].to_vec()),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    frames
}

/// Helper to wait for at least one frame to appear on the guest FD,
/// with a timeout. Returns all frames read.
pub async fn recv_frames_timeout(fd: RawFd, timeout: std::time::Duration) -> Vec<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let frames = drain_frames(fd);
        if !frames.is_empty() {
            return frames;
        }
        if tokio::time::Instant::now() >= deadline {
            return Vec::new();
        }
        // Yield briefly to let the datapath task run.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}
