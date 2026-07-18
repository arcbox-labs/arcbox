//! PTY session primitives shared by ArcBox guest agents.
//!
//! Both interactive-exec implementations — the sandbox microVM's `vm-agent`
//! and the machine-level session in `arcbox-agent` — need the same subtle,
//! security-relevant steps: allocating a sized PTY, wiring the slave as the
//! child's controlling terminal, and dropping privileges in the one order
//! that works. This crate is the single home for those steps; everything the
//! consumers legitimately differ on (process reaping, sync vs async pumps,
//! wire framing) stays with them.
//!
//! Linux-only: on other targets the crate compiles to nothing so host-side
//! workspace builds stay unaffected.

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, OwnedFd};

    /// Terminal dimensions in character cells.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WinSize {
        pub cols: u16,
        pub rows: u16,
    }

    impl WinSize {
        const fn to_libc(self) -> libc::winsize {
            libc::winsize {
                ws_col: self.cols,
                ws_row: self.rows,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }
        }
    }

    /// An allocated PTY pair. The slave is handed to the child (via
    /// [`child_terminal_setup`]); the parent keeps the master and must close
    /// its slave copy after spawning.
    #[derive(Debug)]
    pub struct PtyPair {
        pub master: OwnedFd,
        pub slave: OwnedFd,
    }

    /// Allocates a PTY, optionally applying an initial window size.
    ///
    /// # Errors
    /// Returns an error if the kernel refuses a PTY (e.g. devpts missing).
    pub fn openpty_sized(size: Option<WinSize>) -> io::Result<PtyPair> {
        let pty = nix::pty::openpty(None, None).map_err(io::Error::from)?;
        if let Some(size) = size {
            resize(&pty.master, size)?;
        }
        Ok(PtyPair {
            master: pty.master,
            slave: pty.slave,
        })
    }

    /// Applies a window size to a PTY master (initial or mid-session).
    ///
    /// # Errors
    /// Returns an error if the ioctl fails (master closed).
    pub fn resize(master: &impl AsRawFd, size: WinSize) -> io::Result<()> {
        let ws = size.to_libc();
        // SAFETY: the fd is a live PTY master owned by the caller and `ws`
        // is a valid winsize.
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Credentials to drop to before exec, resolved via [`resolve_user`].
    #[derive(Debug, Clone, Copy)]
    pub struct RunAs {
        pub uid: libc::uid_t,
        pub gid: libc::gid_t,
    }

    /// Resolves a username or numeric UID to run-as credentials.
    ///
    /// A numeric string is taken as a UID with GID equal to it — matching the
    /// behavior both agents shipped historically.
    ///
    /// # Errors
    /// Returns an error for an unknown user name.
    pub fn resolve_user(user: &str) -> io::Result<RunAs> {
        if let Ok(uid) = user.parse::<libc::uid_t>() {
            return Ok(RunAs { uid, gid: uid });
        }
        let entry = nix::unistd::User::from_name(user)
            .map_err(io::Error::from)?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("unknown user: {user}"))
            })?;
        Ok(RunAs {
            uid: entry.uid.as_raw(),
            gid: entry.gid.as_raw(),
        })
    }

    /// Builds a `pre_exec`-compatible closure that turns the child into an
    /// interactive session leader on `slave` and optionally drops privileges.
    ///
    /// Steps, in load-bearing order:
    /// 1. `setsid` — new session, detached from the agent's controlling TTY.
    /// 2. `TIOCSCTTY` — the PTY slave becomes the controlling terminal.
    /// 3. `dup2` the slave over stdin/stdout/stderr (and close the original
    ///    when it lies above fd 2).
    /// 4. `setgroups → setgid → setuid` — the reverse order would drop the
    ///    right to change groups before using it. Any failure aborts the
    ///    exec rather than running the workload with the wrong identity.
    ///
    /// The returned closure is async-signal-safe: raw syscalls only.
    ///
    /// Must only be used with `Command::pre_exec` (it runs post-fork,
    /// pre-exec); `slave` must remain open in the parent until after spawn.
    #[must_use]
    pub fn child_terminal_setup(
        slave: libc::c_int,
        run_as: Option<RunAs>,
    ) -> impl FnMut() -> io::Result<()> + Send + 'static {
        move || {
            // SAFETY: post-fork child; every call below is async-signal-safe.
            unsafe {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::ioctl(slave, libc::TIOCSCTTY, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                    if libc::dup2(slave, fd) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if slave > libc::STDERR_FILENO && libc::close(slave) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some(RunAs { uid, gid }) = run_as {
                    if libc::setgroups(1, &raw const gid) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};

        #[test]
        fn openpty_applies_initial_size_and_resize() {
            let pty = openpty_sized(Some(WinSize {
                cols: 120,
                rows: 40,
            }))
            .unwrap();
            let mut ws = libc::winsize {
                ws_col: 0,
                ws_row: 0,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: live master fd; ws is a valid out-param.
            unsafe { libc::ioctl(pty.master.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
            assert_eq!((ws.ws_col, ws.ws_row), (120, 40));

            resize(&pty.master, WinSize { cols: 80, rows: 24 }).unwrap();
            // SAFETY: as above.
            unsafe { libc::ioctl(pty.master.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
            assert_eq!((ws.ws_col, ws.ws_row), (80, 24));
        }

        #[test]
        fn pty_pair_round_trips_bytes() {
            let pty = openpty_sized(None).unwrap();
            let mut master = std::fs::File::from(pty.master);
            let mut slave = std::fs::File::from(pty.slave);
            master.write_all(b"ping\n").unwrap();
            let mut buf = [0u8; 8];
            let n = slave.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping\n");
        }

        #[test]
        fn resolve_user_accepts_numeric_and_rejects_unknown() {
            let run_as = resolve_user("1234").unwrap();
            assert_eq!((run_as.uid, run_as.gid), (1234, 1234));
            assert!(resolve_user("no-such-user-arcbox").is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{
    PtyPair, RunAs, WinSize, child_terminal_setup, openpty_sized, resize, resolve_user,
};
