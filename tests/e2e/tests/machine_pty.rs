//! Interactive PTY e2e: `abctl machine ssh` driven through a real
//! pseudo-terminal against a live VZ daemon.
//!
//! This is the one path no other layer exercises. `machine.rs` proves the
//! `ExecSession` RPC at the wire level; the daemon tests prove the split
//! bidi stream reaches the handler; but the CLI binary's own terminal
//! plumbing — raw mode, the stdin pump, the SIGWINCH resize pump, the
//! Connect split-bidi client, and exit-code propagation — only runs when a
//! human types into a terminal. Here the terminal is ours:
//!
//! spawn `abctl machine ssh default` on a PTY → type a command and read its
//! output back through the guest shell → resize the terminal and verify the
//! guest PTY saw the new size → `exit 7` and verify the CLI process exits
//! with 7.
//!
//! The session targets the System VM (booted with the daemon), so unlike
//! the machine lifecycle e2e there is no distro pull and no CDN dependency.

use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::metrics::RunMetrics;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Budget for one interaction with the shell (type → observe output).
const SHELL_BUDGET: Duration = Duration::from_secs(30);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

#[test]
#[ignore = "boots a real VZ daemon and drives an interactive abctl PTY session"]
fn interactive_pty_session_end_to_end() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(
            shell,
            "cargo build --release -p arcbox-cli -p arcbox-daemon"
        )
        .run()?;
        xshell::cmd!(
            shell,
            "cargo build --release -p arcbox-agent --target aarch64-unknown-linux-musl"
        )
        .run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-machine-pty-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            ("ARCBOX_DNS_PORT".to_owned(), "0".to_owned()),
        ],
    })?;

    let mut metrics = RunMetrics::new("machine_pty", Some("vz"));
    let result = scenario(&root, &mut daemon, &mut metrics);
    metrics.passed = result.is_ok();
    if let Err(error) = metrics.write(Some(data_dir.path())) {
        tracing::warn!("writing run metrics failed: {error:#}");
    }
    if result.is_err() {
        let kept = data_dir.keep();
        tracing::warn!(path = %kept.display(), "preserving test directory");
    }
    result
}

fn scenario(
    root: &std::path::Path,
    daemon: &mut DaemonHandle,
    metrics: &mut RunMetrics,
) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;

    // A real PTY, sized so the resize below is an observable change.
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("opening pty")?;

    let mut cmd = CommandBuilder::new(root.join("target/release/abctl"));
    cmd.args(["machine", "ssh", "default"]);
    cmd.env("ARCBOX_GRPC_SOCKET", daemon.grpc_socket());
    cmd.env("TERM", "xterm");
    let mut child = pty
        .slave
        .spawn_command(cmd)
        .context("spawning abctl on the pty")?;
    // The slave stays open in the child; dropping our handle avoids the
    // reader below blocking on our own copy after the child exits.
    drop(pty.slave);

    let mut writer = pty.master.take_writer().context("taking pty writer")?;
    let reader = pty
        .master
        .try_clone_reader()
        .context("cloning pty reader")?;
    let output = spawn_reader(reader);

    // 1. Round-trip: a command typed into the local terminal must come back
    //    as guest shell output. The marker is split in the input (`AAA""BBB`)
    //    so the terminal's echo of our own typing can never satisfy the
    //    assertion — only the shell's expansion can.
    metrics.time("pty_roundtrip", || {
        writer.write_all(b"echo pty-e2e-\"\"-marker\r")?;
        writer.flush()?;
        output.wait_for("pty-e2e--marker", SHELL_BUDGET)
    })?;

    // 2. Resize: SIGWINCH on the CLI must travel resize pump → daemon →
    //    agent → guest PTY. The guest busybox ships no `stty`, so instead
    //    of reading the dimensions back, the shell itself witnesses the
    //    kernel's SIGWINCH — which the guest PTY only delivers when the
    //    resize ioctl actually reached it. Two shell-isms shape the probe:
    //    the trap's marker is split for the same echo-vs-output reason as
    //    above, and the shell parks in the `wait` builtin — a foreground
    //    simple command would put ITSELF in the tty's foreground process
    //    group and swallow the SIGWINCH, while during `wait` the shell
    //    stays foreground and POSIX requires a trapped signal to interrupt
    //    the wait and run the trap at once.
    metrics.time("pty_resize", || {
        writer.write_all(b"trap 'echo re\"\"sized-by-winch' WINCH\r")?;
        writer.write_all(b"sleep 30 & wait\r")?;
        writer.flush()?;
        std::thread::sleep(Duration::from_millis(1000));
        pty.master
            .resize(PtySize {
                rows: 37,
                cols: 91,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("resizing pty")?;
        output.wait_for("resized-by-winch", SHELL_BUDGET)
    })?;

    // 3. Exit-code propagation: the shell's exit status must become the CLI
    //    process's own.
    let status = metrics.time("pty_exit_code", || {
        writer.write_all(b"exit 7\r")?;
        writer.flush()?;
        let deadline = Instant::now() + SHELL_BUDGET;
        loop {
            if let Some(status) = child.try_wait().context("waiting for abctl")? {
                return Ok(status);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                bail!("abctl did not exit within {SHELL_BUDGET:?}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })?;
    if status.exit_code() != 7 {
        bail!(
            "expected the shell's exit 7 to become abctl's exit code, got {}\noutput:\n{}",
            status.exit_code(),
            output.snapshot()
        );
    }

    tracing::info!("interactive PTY session verified: roundtrip, resize, exit code");
    Ok(())
}

/// Accumulates PTY output on a thread so assertions can poll for substrings
/// with a deadline while the child keeps producing.
struct OutputBuffer {
    rx: mpsc::Receiver<Vec<u8>>,
    seen: std::cell::RefCell<String>,
}

fn spawn_reader(mut reader: Box<dyn Read + Send>) -> OutputBuffer {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        // EOF or error both mean the session ended; the buffer keeps
        // whatever arrived before that.
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    OutputBuffer {
        rx,
        seen: std::cell::RefCell::new(String::new()),
    }
}

impl OutputBuffer {
    /// Blocks until `needle` appears in the accumulated output.
    fn wait_for(&self, needle: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            if self.seen.borrow().contains(needle) {
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .with_context(|| {
                    format!(
                        "PTY output never contained {needle:?} within {budget:?}\noutput:\n{}",
                        self.seen.borrow()
                    )
                })?;
            match self
                .rx
                .recv_timeout(remaining.min(Duration::from_millis(200)))
            {
                Ok(chunk) => self
                    .seen
                    .borrow_mut()
                    .push_str(&String::from_utf8_lossy(&chunk)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if !self.seen.borrow().contains(needle) {
                        bail!(
                            "PTY closed before {needle:?} appeared\noutput:\n{}",
                            self.seen.borrow()
                        );
                    }
                    return Ok(());
                }
            }
        }
    }

    fn snapshot(&self) -> String {
        while let Ok(chunk) = self.rx.try_recv() {
            self.seen
                .borrow_mut()
                .push_str(&String::from_utf8_lossy(&chunk));
        }
        self.seen.borrow().clone()
    }
}
