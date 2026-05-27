//! Blocking vsock transport for macOS HV backend.
//!
//! Uses `std::os::unix::net::UnixStream` with `libc::poll`-based deadlines.
//! No tokio dependency — safe to use from any thread without risking reactor
//! or timer driver interference.
//!
//! Wire format is identical to [`VsockTransport`]: 4-byte BE length prefix
//! followed by payload. Messages produced by `AgentClient::build_message`
//! work unchanged.

use bytes::Bytes;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use crate::error::{Result, TransportError};

/// Maximum frame size (must match async transport).
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Blocking vsock transport over a Unix domain socketpair.
///
/// All I/O uses `libc::poll` for deadline enforcement. The underlying fd
/// is set to non-blocking; `poll` + `read`/`write` loops handle partial
/// transfers and `EAGAIN`.
pub struct BlockingVsockTransport {
    stream: UnixStream,
}

impl BlockingVsockTransport {
    /// Creates a transport from a raw fd (takes ownership).
    ///
    /// # Safety
    /// `fd` must be a valid, connected Unix socket fd.
    pub unsafe fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: caller guarantees fd is a valid, connected Unix socket.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        stream.set_nonblocking(true)?;
        Ok(Self { stream })
    }

    /// Sends a framed message with a deadline.
    ///
    /// `data` must already include the 4-byte length prefix (as produced by
    /// `AgentClient::build_message`).
    pub fn send(&mut self, data: &[u8], deadline: Instant) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            self.poll_ready(libc::POLLOUT, deadline)?;
            match self.stream.write(&data[offset..]) {
                Ok(0) => {
                    return Err(TransportError::io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned 0",
                    )));
                }
                Ok(n) => offset += n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(TransportError::io(e)),
            }
        }
        Ok(())
    }

    /// Receives a framed message with a deadline.
    ///
    /// Returns the full frame (4-byte length prefix + payload), matching
    /// the async transport's `read_framed` semantics.
    pub fn recv(&mut self, deadline: Instant) -> Result<Bytes> {
        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf, deadline)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(TransportError::Protocol(format!(
                "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
            )));
        }

        // Read payload.
        let mut buf = vec![0u8; 4 + len];
        buf[..4].copy_from_slice(&len_buf);
        self.read_exact(&mut buf[4..], deadline)?;
        Ok(Bytes::from(buf))
    }

    /// Reads exactly `buf.len()` bytes with a deadline.
    fn read_exact(&mut self, buf: &mut [u8], deadline: Instant) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            self.poll_ready(libc::POLLIN, deadline)?;
            match self.stream.read(&mut buf[offset..]) {
                Ok(0) => {
                    return Err(TransportError::io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "early eof",
                    )));
                }
                Ok(n) => offset += n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(TransportError::io(e)),
            }
        }
        Ok(())
    }

    /// Polls the fd for readiness with a deadline.
    fn poll_ready(&self, events: i16, deadline: Instant) -> Result<()> {
        let now = Instant::now();
        if now >= deadline {
            return Err(TransportError::io(io::Error::new(
                io::ErrorKind::TimedOut,
                "transport deadline exceeded",
            )));
        }
        let timeout_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;

        let mut pfd = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: pfd is valid, initialized, and points to our owned fd.
        let ret = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                // EINTR — caller will retry.
                return Ok(());
            }
            return Err(TransportError::io(err));
        }
        if ret == 0 {
            return Err(TransportError::io(io::Error::new(
                io::ErrorKind::TimedOut,
                "transport deadline exceeded",
            )));
        }
        // POLLNVAL means the fd itself is invalid -- return an error
        // immediately rather than letting a subsequent read/write surface it.
        if pfd.revents & libc::POLLNVAL != 0 {
            return Err(TransportError::io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "poll: POLLNVAL -- file descriptor is not valid",
            )));
        }
        // POLLERR/POLLHUP: the fd is valid but the peer hung up or an error
        // occurred. Fall through — the subsequent read/write will surface the
        // actual error.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::FromRawFd;
    use std::time::Duration;

    #[test]
    fn test_blocking_roundtrip() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed: {}", io::Error::last_os_error());
        let mut client = unsafe { BlockingVsockTransport::from_raw_fd(fds[0]).unwrap() };
        let mut server = unsafe { BlockingVsockTransport::from_raw_fd(fds[1]).unwrap() };

        let deadline = Instant::now() + Duration::from_secs(2);

        // Build a framed message: 4-byte BE length + payload.
        let payload = b"hello";
        let len = (payload.len() as u32).to_be_bytes();
        let mut frame = Vec::new();
        frame.extend_from_slice(&len);
        frame.extend_from_slice(payload);

        client.send(&frame, deadline).unwrap();
        let received = server.recv(deadline).unwrap();
        assert_eq!(&received[4..], b"hello");
    }

    #[test]
    fn test_blocking_timeout() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed: {}", io::Error::last_os_error());
        let mut client = unsafe { BlockingVsockTransport::from_raw_fd(fds[0]).unwrap() };
        // Don't write anything on fds[1] — recv should timeout.
        let _server_fd = unsafe { UnixStream::from_raw_fd(fds[1]) };

        let deadline = Instant::now() + Duration::from_millis(50);
        let result = client.recv(deadline);
        assert!(result.is_err());
    }

    #[test]
    fn test_blocking_peer_close_eof() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed: {}", io::Error::last_os_error());
        let mut client = unsafe { BlockingVsockTransport::from_raw_fd(fds[0]).unwrap() };
        // Close peer immediately.
        unsafe { libc::close(fds[1]) };

        let deadline = Instant::now() + Duration::from_secs(2);
        let result = client.recv(deadline);
        assert!(result.is_err());
    }
}
