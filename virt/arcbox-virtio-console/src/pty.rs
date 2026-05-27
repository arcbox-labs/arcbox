//! PTY (pseudo-terminal) console backend.
//!
//! Provides a real terminal interface that can be connected to by terminal
//! emulators or the host shell.

use std::os::unix::io::RawFd;

use crate::ConsoleIo;

/// PTY (pseudo-terminal) console backend.
///
/// Provides a real terminal interface that can be connected to
/// by terminal emulators or the host shell.
pub struct PtyConsole {
    /// Master file descriptor.
    master_fd: RawFd,
    /// Slave file descriptor (opened for the guest).
    slave_fd: RawFd,
    /// Path to the slave PTY device.
    slave_path: String,
    /// Non-blocking mode.
    nonblocking: bool,
}

impl PtyConsole {
    /// Creates a new PTY console.
    ///
    /// # Errors
    ///
    /// Returns an error if PTY allocation fails.
    pub fn new() -> std::io::Result<Self> {
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;

        // SAFETY: openpty writes the new master/slave fds via the out-pointers
        // we provided. Any failure is reported via the return code, in which
        // case we propagate `last_os_error()` without using the (uninitialised) fds.
        let ret = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: ttyname returns a pointer into a static buffer owned by libc;
        // we only borrow it long enough to copy into an owned String. On error
        // (null pointer) we close the fds before returning.
        let slave_path = unsafe {
            let path_ptr = libc::ttyname(slave_fd);
            if path_ptr.is_null() {
                libc::close(master_fd);
                libc::close(slave_fd);
                return Err(std::io::Error::last_os_error());
            }
            std::ffi::CStr::from_ptr(path_ptr)
                .to_string_lossy()
                .into_owned()
        };

        tracing::info!(
            "Created PTY console: master_fd={}, slave={}",
            master_fd,
            slave_path
        );

        Ok(Self {
            master_fd,
            slave_fd,
            slave_path,
            nonblocking: false,
        })
    }

    /// Returns the path to the slave PTY device.
    ///
    /// Users can connect to this path with a terminal emulator:
    /// - `screen /dev/pts/X`
    /// - `minicom -D /dev/pts/X`
    #[must_use]
    pub fn slave_path(&self) -> &str {
        &self.slave_path
    }

    /// Returns the master file descriptor.
    #[must_use]
    pub const fn master_fd(&self) -> RawFd {
        self.master_fd
    }

    /// Sets non-blocking mode on the master.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        // SAFETY: F_GETFL/F_SETFL on a fd we own; fcntl is signal-safe and
        // the only side effect on success is updating the fd's status flags.
        let flags = unsafe { libc::fcntl(self.master_fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        // SAFETY: see above — fcntl on our owned fd.
        let ret = unsafe { libc::fcntl(self.master_fd, libc::F_SETFL, new_flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.nonblocking = nonblocking;
        Ok(())
    }

    /// Sets terminal size.
    pub fn set_window_size(&self, rows: u16, cols: u16) -> std::io::Result<()> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // SAFETY: TIOCSWINSZ takes a `&winsize` we borrow on the stack; the
        // ioctl reads it and does not retain the pointer.
        let ret = unsafe { libc::ioctl(self.master_fd, libc::TIOCSWINSZ, &ws) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Checks if data is available to read.
    #[must_use]
    pub fn has_data(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.master_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: poll borrows our pollfd for the duration of the call (timeout 0).
        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ret > 0 && (pollfd.revents & libc::POLLIN) != 0
    }
}

impl Drop for PtyConsole {
    fn drop(&mut self) {
        // SAFETY: closing fds we exclusively own (no aliases handed out).
        if self.master_fd >= 0 {
            unsafe { libc::close(self.master_fd) };
        }
        if self.slave_fd >= 0 {
            unsafe { libc::close(self.slave_fd) };
        }
    }
}

impl ConsoleIo for PtyConsole {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: read into a buffer borrowed mutably from `buf`; libc only
        // writes within `buf.len()` bytes of `buf.as_mut_ptr()`.
        let ret = unsafe {
            libc::read(
                self.master_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(err)
            }
        } else {
            Ok(ret as usize)
        }
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: write reads `buf.len()` bytes starting at `buf.as_ptr()`,
        // both borrowed from the caller for the duration of the call.
        let ret = unsafe {
            libc::write(
                self.master_fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // PTY doesn't need explicit flush
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_console_creation() {
        let pty = PtyConsole::new().unwrap();
        assert!(!pty.slave_path().is_empty());
        assert!(pty.master_fd() >= 0);
    }

    #[test]
    fn test_pty_console_write_read() {
        let mut pty = PtyConsole::new().unwrap();
        pty.set_nonblocking(true).unwrap();

        let written = pty.write(b"test\n").unwrap();
        assert!(written > 0);

        // Note: Reading from PTY may not return data immediately — the slave
        // side has to echo back first.
    }

    #[test]
    fn test_pty_console_nonblocking() {
        let mut pty = PtyConsole::new().unwrap();

        pty.set_nonblocking(true).unwrap();
        assert!(pty.nonblocking);

        let mut buf = [0u8; 10];
        let n = pty.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_pty_console_window_size() {
        let pty = PtyConsole::new().unwrap();

        assert!(pty.set_window_size(24, 80).is_ok());
        assert!(pty.set_window_size(50, 132).is_ok());
    }

    #[test]
    fn test_pty_console_has_data() {
        let pty = PtyConsole::new().unwrap();
        assert!(!pty.has_data());
    }

    #[test]
    fn test_pty_console_flush() {
        let mut pty = PtyConsole::new().unwrap();
        assert!(pty.flush().is_ok());
    }
}
