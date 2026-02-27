//! `vmm-guest-agent` — in-VM daemon that accepts exec/run sessions over vsock.
//!
//! The agent listens on AF_VSOCK port 52.  For each connection it:
//!
//! 1. Reads an initial `MSG_START` frame carrying a JSON [`StartCommand`].
//! 2. Spawns the requested process (with pipes for non-TTY, with openpty for TTY).
//! 3. Streams `MSG_STDOUT` / `MSG_STDERR` frames back to the host.
//! 4. For interactive sessions, forwards `MSG_STDIN` / `MSG_RESIZE` frames to
//!    the process.
//! 5. Sends a final `MSG_EXIT` frame when the process terminates.
//!
//! ## Frame format
//!
//! ```text
//! [u8: msg_type][u32 LE: payload_len][payload_len bytes]
//! ```
//!
//! | Type | Direction   | Payload                          |
//! |------|-------------|----------------------------------|
//! | 0x01 | Host→Agent  | JSON `StartCommand`              |
//! | 0x02 | Host→Agent  | raw stdin bytes                  |
//! | 0x03 | Host→Agent  | `[u16 LE width][u16 LE height]`  |
//! | 0x04 | Host→Agent  | empty — stdin EOF                |
//! | 0x10 | Agent→Host  | raw stdout bytes                 |
//! | 0x11 | Agent→Host  | raw stderr bytes                 |
//! | 0x12 | Agent→Host  | `[i32 LE exit_code]`             |
//!
//! This binary requires Linux — it uses AF_VSOCK, accept4, openpty, and fork,
//! none of which are available on other platforms.  The workspace compiles the
//! crate everywhere, but the implementation is gated on `target_os = "linux"`.

// =============================================================================
// Linux implementation
// =============================================================================

#[cfg(target_os = "linux")]
mod agent {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::os::unix::io::RawFd;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use serde::Deserialize;

    // -------------------------------------------------------------------------
    // Protocol constants
    // -------------------------------------------------------------------------

    pub const AGENT_PORT: u32 = 52;

    const MSG_START: u8 = 0x01;
    const MSG_STDIN: u8 = 0x02;
    const MSG_RESIZE: u8 = 0x03;
    const MSG_EOF: u8 = 0x04;
    const MSG_STDOUT: u8 = 0x10;
    const MSG_STDERR: u8 = 0x11;
    const MSG_EXIT: u8 = 0x12;

    // -------------------------------------------------------------------------
    // Protocol types
    // -------------------------------------------------------------------------

    #[derive(Debug, Deserialize)]
    struct StartCommand {
        cmd: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default)]
        working_dir: String,
        #[serde(default)]
        user: String,
        #[serde(default)]
        tty: bool,
        #[serde(default = "default_tty_width")]
        tty_width: u16,
        #[serde(default = "default_tty_height")]
        tty_height: u16,
        #[serde(default)]
        timeout_seconds: u32,
    }

    fn default_tty_width() -> u16 {
        80
    }
    fn default_tty_height() -> u16 {
        24
    }

    // -------------------------------------------------------------------------
    // Framed I/O over a raw socket fd
    // -------------------------------------------------------------------------

    struct VsockStream {
        fd: RawFd,
    }

    impl VsockStream {
        /// # Safety
        /// `fd` must be a valid, open, connected socket file descriptor.
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            Self { fd }
        }
    }

    impl Read for VsockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // SAFETY: buf is a valid mutable slice; fd is a valid socket.
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    impl Write for VsockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // SAFETY: buf is a valid slice; fd is a valid socket.
            let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Drop for VsockStream {
        fn drop(&mut self) {
            // SAFETY: fd is valid and owned by this struct.
            unsafe { libc::close(self.fd) };
        }
    }

    // -------------------------------------------------------------------------
    // Frame helpers
    // -------------------------------------------------------------------------

    fn read_frame(r: &mut impl Read) -> std::io::Result<(u8, Vec<u8>)> {
        let mut type_buf = [0u8; 1];
        r.read_exact(&mut type_buf)?;
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut payload)?;
        }
        Ok((type_buf[0], payload))
    }

    /// Write all bytes in a single call to avoid interleaving across threads.
    fn write_frame(w: &mut impl Write, msg_type: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.push(msg_type);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        w.write_all(&buf)
    }

    // -------------------------------------------------------------------------
    // Per-connection handler
    // -------------------------------------------------------------------------

    fn handle_connection(conn_fd: RawFd) {
        // SAFETY: conn_fd is a freshly accepted socket fd.
        let mut conn = unsafe { VsockStream::from_raw_fd(conn_fd) };

        let (msg_type, payload) = match read_frame(&mut conn) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("agent: read MSG_START: {e}");
                return;
            }
        };
        if msg_type != MSG_START {
            eprintln!("agent: expected MSG_START (0x01), got 0x{msg_type:02x}");
            return;
        }
        let start: StartCommand = match serde_json::from_slice(&payload) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("agent: parse StartCommand: {e}");
                return;
            }
        };

        if start.tty {
            handle_tty(conn, start);
        } else {
            handle_piped(conn, start);
        }
    }

    // -------------------------------------------------------------------------
    // Non-interactive execution (piped stdio)
    // -------------------------------------------------------------------------

    fn handle_piped(conn: VsockStream, start: StartCommand) {
        use std::process::{Command, Stdio};

        let mut cmd = Command::new(start.cmd.first().expect("empty cmd"));
        cmd.args(start.cmd.get(1..).unwrap_or(&[]));
        cmd.envs(&start.env);
        if !start.working_dir.is_empty() {
            cmd.current_dir(&start.working_dir);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("agent: spawn {:?}: {e}", start.cmd);
                return;
            }
        };

        let mut child_stdin = child.stdin.take().unwrap();
        let child_stdout = child.stdout.take().unwrap();
        let child_stderr = child.stderr.take().unwrap();

        // Shared writer so the stdout and stderr threads don't interleave frames.
        let writer: Arc<Mutex<VsockStream>> = Arc::new(Mutex::new(conn));

        let w1 = Arc::clone(&writer);
        let t_stdout = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut out = child_stdout;
            loop {
                match out.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = write_frame(&mut *w1.lock().unwrap(), MSG_STDOUT, &buf[..n]);
                    }
                }
            }
        });

        let w2 = Arc::clone(&writer);
        let t_stderr = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut err = child_stderr;
            loop {
                match err.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = write_frame(&mut *w2.lock().unwrap(), MSG_STDERR, &buf[..n]);
                    }
                }
            }
        });

        if start.timeout_seconds > 0 {
            let pid = child.id();
            let timeout = start.timeout_seconds;
            thread::spawn(move || {
                thread::sleep(std::time::Duration::from_secs(timeout as u64));
                // SAFETY: pid is a valid process id from std::process::Child.
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            });
        }

        // Read stdin frames from the host and forward to the child.
        // SAFETY: dup gives us a second fd for reading while the Arc owns the write fd.
        let read_fd = unsafe { libc::dup((*writer.lock().unwrap()).fd) };
        let mut reader = unsafe { VsockStream::from_raw_fd(read_fd) };
        loop {
            match read_frame(&mut reader) {
                Ok((MSG_STDIN, data)) => {
                    if child_stdin.write_all(&data).is_err() {
                        break;
                    }
                }
                Ok((MSG_EOF, _)) | Err(_) => {
                    drop(child_stdin);
                    break;
                }
                Ok(_) => {}
            }
        }

        let _ = t_stdout.join();
        let _ = t_stderr.join();
        let exit_code = child.wait().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
        let _ = write_frame(
            &mut *writer.lock().unwrap(),
            MSG_EXIT,
            &(exit_code as i32).to_le_bytes(),
        );
    }

    // -------------------------------------------------------------------------
    // Interactive execution (pseudo-TTY)
    // -------------------------------------------------------------------------

    fn handle_tty(conn: VsockStream, start: StartCommand) {
        use nix::pty::OpenptyResult;
        use nix::unistd::{ForkResult, fork, setsid};
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let OpenptyResult { master, slave } = match nix::pty::openpty(None, None) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("agent: openpty: {e}");
                return;
            }
        };

        if start.tty_width > 0 && start.tty_height > 0 {
            let winsize = libc::winsize {
                ws_col: start.tty_width,
                ws_row: start.tty_height,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: master is a valid PTY master fd.
            unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
        }

        let master_fd: RawFd = master.as_raw_fd();
        let slave_fd: RawFd = slave.as_raw_fd();

        match unsafe { fork() } {
            Err(e) => eprintln!("agent: fork: {e}"),

            Ok(ForkResult::Child) => {
                drop(master);
                let _ = setsid();
                // SAFETY: all fds are valid in the child process.
                unsafe {
                    libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
                    libc::dup2(slave_fd, libc::STDIN_FILENO);
                    libc::dup2(slave_fd, libc::STDOUT_FILENO);
                    libc::dup2(slave_fd, libc::STDERR_FILENO);
                    if slave_fd > libc::STDERR_FILENO {
                        libc::close(slave_fd);
                    }
                }

                let cstrings: Vec<std::ffi::CString> = start
                    .cmd
                    .iter()
                    .filter_map(|s| std::ffi::CString::new(s.as_str()).ok())
                    .collect();
                let mut argv: Vec<*const libc::c_char> =
                    cstrings.iter().map(|s| s.as_ptr()).collect();
                argv.push(std::ptr::null());

                for (k, v) in &start.env {
                    if let (Ok(ck), Ok(cv)) = (
                        std::ffi::CString::new(k.as_str()),
                        std::ffi::CString::new(v.as_str()),
                    ) {
                        // SAFETY: setenv is safe with valid C strings.
                        unsafe { libc::setenv(ck.as_ptr(), cv.as_ptr(), 1) };
                    }
                }
                if !start.working_dir.is_empty() {
                    if let Ok(cwd) = std::ffi::CString::new(start.working_dir.as_str()) {
                        // SAFETY: cwd is a valid C string.
                        unsafe { libc::chdir(cwd.as_ptr()) };
                    }
                }

                // SAFETY: exec replaces the process image; argv is null-terminated.
                unsafe { libc::execvp(argv[0], argv.as_ptr()) };
                unsafe { libc::_exit(127) };
            }

            Ok(ForkResult::Parent { child }) => {
                drop(slave);
                let writer: Arc<Mutex<VsockStream>> = Arc::new(Mutex::new(conn));

                let w_read = Arc::clone(&writer);
                let t_pty = thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    // SAFETY: dup of master_fd owned by this thread.
                    let mut r = unsafe { VsockStream::from_raw_fd(libc::dup(master_fd)) };
                    loop {
                        match r.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = write_frame(
                                    &mut *w_read.lock().unwrap(),
                                    MSG_STDOUT,
                                    &buf[..n],
                                );
                            }
                        }
                    }
                });

                let read_fd = unsafe { libc::dup((*writer.lock().unwrap()).fd) };
                let mut reader = unsafe { VsockStream::from_raw_fd(read_fd) };
                // SAFETY: master_fd is valid; File takes ownership for writes.
                let mut master_writer = unsafe { std::fs::File::from_raw_fd(master_fd) };

                loop {
                    match read_frame(&mut reader) {
                        Ok((MSG_STDIN, data)) => {
                            let _ = master_writer.write_all(&data);
                        }
                        Ok((MSG_RESIZE, data)) if data.len() >= 4 => {
                            let winsize = libc::winsize {
                                ws_col: u16::from_le_bytes([data[0], data[1]]),
                                ws_row: u16::from_le_bytes([data[2], data[3]]),
                                ws_xpixel: 0,
                                ws_ypixel: 0,
                            };
                            // SAFETY: master_fd is valid.
                            unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &winsize) };
                        }
                        Ok((MSG_EOF, _)) | Err(_) => break,
                        Ok(_) => {}
                    }
                }

                let _ = t_pty.join();

                let mut status: libc::c_int = 0;
                // SAFETY: child.as_raw() is a valid pid returned from fork.
                unsafe { libc::waitpid(child.as_raw(), &mut status, 0) };
                let exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    -1
                };
                let _ = write_frame(
                    &mut *writer.lock().unwrap(),
                    MSG_EXIT,
                    &(exit_code as i32).to_le_bytes(),
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // vsock listener
    // -------------------------------------------------------------------------

    pub fn run() {
        eprintln!("vmm-guest-agent: listening on vsock port {AGENT_PORT}");
        let server_fd = create_vsock_listener(AGENT_PORT);
        loop {
            let conn_fd = accept_connection(server_fd);
            thread::spawn(move || handle_connection(conn_fd));
        }
    }

    fn create_vsock_listener(port: u32) -> RawFd {
        // SAFETY: socket(2) with valid AF_VSOCK constants.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        assert!(
            fd >= 0,
            "socket(AF_VSOCK): {}",
            std::io::Error::last_os_error()
        );

        let addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: libc::VMADDR_CID_ANY,
            ..unsafe { std::mem::zeroed() }
        };
        // SAFETY: addr is valid; fd is a live socket.
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        assert!(
            ret == 0,
            "bind vsock port {port}: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: fd is a bound socket.
        unsafe { libc::listen(fd, 128) };
        fd
    }

    fn accept_connection(server_fd: RawFd) -> RawFd {
        loop {
            // SAFETY: server_fd is a listening vsock socket.
            let conn_fd =
                unsafe { libc::accept(server_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if conn_fd >= 0 {
                return conn_fd;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                panic!("accept: {err}");
            }
        }
    }
}

// =============================================================================
// Entry point
// =============================================================================

fn main() {
    #[cfg(target_os = "linux")]
    agent::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("vmm-guest-agent requires Linux (AF_VSOCK)");
        std::process::exit(1);
    }
}
