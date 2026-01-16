//! PTY (pseudo-terminal) support for container processes.
//!
//! This module provides PTY allocation, process association, and resize handling
//! for interactive container sessions.

use anyhow::{Context, Result};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::{OpenptyResult, Winsize, openpty};
use nix::sys::termios::{self, SetArg, Termios};
use nix::unistd::{close, dup2, read, setsid, write};
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

/// PTY master/slave pair.
pub struct Pty {
    /// Master side of the PTY (for the host to read/write).
    master: OwnedFd,
    /// Slave side of the PTY (for the child process).
    slave: Option<OwnedFd>,
    /// Original terminal settings (for restoration).
    /// Wrapped in Mutex for thread-safety (Termios contains RefCell).
    original_termios: Mutex<Option<Termios>>,
}

impl Pty {
    /// Opens a new PTY pair.
    pub fn open() -> Result<Self> {
        let OpenptyResult { master, slave } = openpty(None, None).context("failed to open PTY")?;

        // Set master to non-blocking for async I/O
        let flags =
            fcntl(master.as_raw_fd(), FcntlArg::F_GETFL).context("failed to get PTY flags")?;
        let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(master.as_raw_fd(), FcntlArg::F_SETFL(new_flags))
            .context("failed to set PTY flags")?;

        Ok(Self {
            master,
            slave: Some(slave),
            original_termios: Mutex::new(None),
        })
    }

    /// Opens a new PTY pair with specified window size.
    pub fn open_with_size(cols: u16, rows: u16) -> Result<Self> {
        let winsize = Winsize {
            ws_col: cols,
            ws_row: rows,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let OpenptyResult { master, slave } = match openpty(Some(&winsize), None) {
            Ok(res) => res,
            Err(err) => {
                tracing::warn!(
                    "openpty with size {}x{} failed ({}), falling back to default",
                    cols,
                    rows,
                    err
                );
                openpty(None, None).context("failed to open PTY after fallback")?
            }
        };

        // Set master to non-blocking
        let flags =
            fcntl(master.as_raw_fd(), FcntlArg::F_GETFL).context("failed to get PTY flags")?;
        let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(master.as_raw_fd(), FcntlArg::F_SETFL(new_flags))
            .context("failed to set PTY flags")?;

        Ok(Self {
            master,
            slave: Some(slave),
            original_termios: Mutex::new(None),
        })
    }

    /// Returns the master file descriptor.
    pub fn master_fd(&self) -> RawFd {
        self.master.as_raw_fd()
    }

    /// Returns the slave file descriptor (or -1 if closed).
    pub fn slave_fd(&self) -> RawFd {
        self.slave.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1)
    }

    /// Resizes the PTY window.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let winsize = libc::winsize {
            ws_col: cols,
            ws_row: rows,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // SAFETY: TIOCSWINSZ is a valid ioctl for PTY resize
        let ret = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };

        if ret < 0 {
            anyhow::bail!("failed to resize PTY: {}", std::io::Error::last_os_error());
        }

        tracing::debug!("PTY resized to {}x{}", cols, rows);
        Ok(())
    }

    /// Gets the current PTY window size.
    pub fn get_size(&self) -> Result<(u16, u16)> {
        let mut winsize = libc::winsize {
            ws_col: 0,
            ws_row: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        // SAFETY: TIOCGWINSZ is a valid ioctl for getting PTY size
        let ret = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCGWINSZ, &mut winsize) };

        if ret < 0 {
            anyhow::bail!(
                "failed to get PTY size: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok((winsize.ws_col, winsize.ws_row))
    }

    /// Configures the slave for a child process (should be called after fork).
    ///
    /// This sets up the slave as the controlling terminal for the child process.
    ///
    /// # Safety
    ///
    /// Must be called after fork() in the child process.
    pub unsafe fn setup_slave_for_child(&self) -> Result<()> {
        // Create a new session
        setsid().context("failed to create new session")?;

        // Set the slave as the controlling terminal
        // SAFETY: TIOCSCTTY is a valid ioctl for setting controlling terminal
        let slave_fd = self
            .slave
            .as_ref()
            .context("PTY slave not available for child setup")?
            .as_raw_fd();

        #[cfg(target_os = "linux")]
        let ret = unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) };
        #[cfg(target_os = "macos")]
        let ret = unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0) };
        if ret < 0 {
            anyhow::bail!(
                "failed to set controlling terminal: {}",
                std::io::Error::last_os_error()
            );
        }

        // Duplicate slave to stdin, stdout, stderr
        dup2(slave_fd, libc::STDIN_FILENO).context("failed to dup2 stdin")?;
        dup2(slave_fd, libc::STDOUT_FILENO).context("failed to dup2 stdout")?;
        dup2(slave_fd, libc::STDERR_FILENO).context("failed to dup2 stderr")?;

        // Close original fds if they're not 0, 1, or 2
        if slave_fd > libc::STDERR_FILENO {
            let _ = unsafe { libc::close(slave_fd) };
        }

        Ok(())
    }

    /// Closes the slave side (should be done in parent after fork).
    pub fn close_slave(&mut self) -> Result<()> {
        // Drop the slave fd so EOF can propagate to the master.
        self.slave.take();
        Ok(())
    }

    /// Sets raw mode on the PTY slave.
    pub fn set_raw_mode(&self) -> Result<()> {
        let slave = self
            .slave
            .as_ref()
            .context("PTY slave not available for raw mode")?;

        let mut termios =
            termios::tcgetattr(slave).context("failed to get terminal attributes")?;

        // Save original settings
        if let Ok(mut guard) = self.original_termios.lock() {
            *guard = Some(termios.clone());
        }

        // Set raw mode
        termios::cfmakeraw(&mut termios);

        termios::tcsetattr(slave, SetArg::TCSANOW, &termios)
            .context("failed to set raw mode")?;

        Ok(())
    }

    /// Restores original terminal settings.
    pub fn restore_termios(&self) -> Result<()> {
        if let Ok(guard) = self.original_termios.lock() {
            if let Some(ref original) = *guard {
                if let Some(slave) = self.slave.as_ref() {
                    termios::tcsetattr(slave, SetArg::TCSANOW, original)
                        .context("failed to restore terminal settings")?;
                }
            }
        }
        Ok(())
    }

    /// Writes data to the PTY master (input to the child).
    pub fn write_input(&self, data: &[u8]) -> Result<usize> {
        let n = write(&self.master, data).context("failed to write to PTY")?;
        Ok(n)
    }

    /// Reads data from the PTY master (output from the child).
    pub fn read_output(&self, buf: &mut [u8]) -> Result<usize> {
        match read(self.master.as_raw_fd(), buf) {
            Ok(n) => Ok(n),
            Err(nix::errno::Errno::EAGAIN) => Ok(0),
            Err(e) => Err(e).context("failed to read from PTY"),
        }
    }
}

/// PTY handle for managing a container's PTY session.
pub struct PtyHandle {
    /// The PTY pair.
    pty: Pty,
    /// Whether the PTY is in use.
    active: bool,
}

impl PtyHandle {
    /// Creates a new PTY handle.
    pub fn new(cols: u16, rows: u16) -> Result<Self> {
        let pty = Pty::open_with_size(cols, rows)?;
        Ok(Self { pty, active: true })
    }

    /// Returns whether the PTY is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivates the PTY.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Resizes the PTY.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        if self.active {
            self.pty.resize(cols, rows)
        } else {
            Ok(())
        }
    }

    /// Returns the master file descriptor.
    pub fn master_fd(&self) -> RawFd {
        self.pty.master_fd()
    }

    /// Returns the slave file descriptor.
    pub fn slave_fd(&self) -> RawFd {
        self.pty.slave_fd()
    }

    /// Gets a reference to the inner PTY.
    pub fn pty(&self) -> &Pty {
        &self.pty
    }

    /// Gets a mutable reference to the inner PTY.
    pub fn pty_mut(&mut self) -> &mut Pty {
        &mut self.pty
    }

    /// Writes data to the PTY master (input to the child).
    pub fn write_input(&self, data: &[u8]) -> Result<usize> {
        self.pty.write_input(data)
    }

    /// Reads data from the PTY master (output from the child).
    pub fn read_output(&self, buf: &mut [u8]) -> Result<usize> {
        self.pty.read_output(buf)
    }
}

/// Exec session with PTY.
pub struct ExecSession {
    /// Session ID.
    pub id: String,
    /// PTY handle (if TTY mode).
    pub pty: Option<PtyHandle>,
    /// Process ID.
    pub pid: Option<u32>,
    /// Exit code (if exited).
    pub exit_code: Option<i32>,
    /// Whether the session is running.
    pub running: bool,
}

impl ExecSession {
    /// Creates a new exec session.
    pub fn new(id: String, tty: bool, cols: u16, rows: u16) -> Result<Self> {
        let pty = if tty {
            Some(PtyHandle::new(cols, rows)?)
        } else {
            None
        };

        Ok(Self {
            id,
            pty,
            pid: None,
            exit_code: None,
            running: false,
        })
    }

    /// Returns whether this session has a TTY.
    pub fn has_tty(&self) -> bool {
        self.pty.is_some()
    }

    /// Resizes the session's TTY.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        if let Some(ref pty) = self.pty {
            pty.resize(cols, rows)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pty_open() {
        let pty = Pty::open();
        assert!(pty.is_ok());

        let pty = pty.unwrap();
        assert!(pty.master_fd() >= 0);
        assert!(pty.slave_fd() >= 0);
    }

    #[test]
    fn test_pty_open_with_size() {
        let pty = Pty::open_with_size(80, 24);
        assert!(pty.is_ok());

        let pty = pty.unwrap();
        let (cols, rows) = pty.get_size().unwrap();
        assert_eq!(cols, 80);
        assert_eq!(rows, 24);
    }

    #[test]
    fn test_pty_resize() {
        let pty = Pty::open_with_size(80, 24).unwrap();

        pty.resize(120, 40).unwrap();

        let (cols, rows) = pty.get_size().unwrap();
        assert_eq!(cols, 120);
        assert_eq!(rows, 40);
    }

    #[test]
    fn test_pty_handle() {
        let handle = PtyHandle::new(100, 30);
        assert!(handle.is_ok());

        let handle = handle.unwrap();
        assert!(handle.is_active());
        assert!(handle.master_fd() >= 0);
        assert!(handle.slave_fd() >= 0);
    }

    #[test]
    fn test_exec_session_with_tty() {
        let session = ExecSession::new("test-session".to_string(), true, 80, 24);
        assert!(session.is_ok());

        let session = session.unwrap();
        assert!(session.has_tty());
        assert!(!session.running);
        assert!(session.pid.is_none());
    }

    #[test]
    fn test_exec_session_without_tty() {
        let session = ExecSession::new("test-session".to_string(), false, 80, 24);
        assert!(session.is_ok());

        let session = session.unwrap();
        assert!(!session.has_tty());
    }
}
