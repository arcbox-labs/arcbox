//! Daemon command implementation.
//!
//! This command controls the lifecycle of the `arcbox-daemon` binary:
//! - start in background (`arcbox daemon start`)
//! - run in foreground (`arcbox daemon start -f`)
//! - stop a running daemon (`arcbox daemon stop`)
//! - inspect daemon status (`arcbox daemon status`)

use super::machine::UnixConnector;
use anyhow::{Context, Result, bail};
use arcbox_constants::paths::{ArcboxProfile, HostLayout};
use clap::{Args, ValueEnum};
use humantime::format_duration;
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use tokio::time::{Instant, sleep, timeout};
use tonic::transport::Endpoint;
use tracing::warn;

/// Arguments for the daemon command.
#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Daemon action.
    #[arg(value_name = "ACTION")]
    pub action: DaemonAction,

    /// Unix socket path for Docker API (default: ~/.arcbox/run/docker.sock).
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// Unix socket path for gRPC API (default: ~/.arcbox/run/arcbox.sock).
    #[arg(long)]
    pub grpc_socket: Option<PathBuf>,

    /// Data directory for ArcBox.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Runtime profile (production or development).
    #[arg(long)]
    pub profile: Option<ArcboxProfile>,

    /// Custom kernel path for VM boot.
    #[arg(long)]
    pub kernel: Option<PathBuf>,

    /// Run in foreground (don't daemonize).
    #[arg(long, short = 'f')]
    pub foreground: bool,

    /// Automatically enable Docker CLI integration.
    #[arg(long)]
    pub docker_integration: bool,

    /// Guest dockerd API vsock port.
    #[arg(long)]
    pub guest_docker_vsock_port: Option<u32>,
}

/// Daemon actions.
#[derive(Debug, Clone, ValueEnum)]
pub enum DaemonAction {
    Start,
    Stop,
    Status,
}

/// Executes the daemon command.
pub async fn execute(args: DaemonArgs) -> Result<()> {
    match args.action {
        DaemonAction::Start if args.foreground => exec_foreground(&args),
        DaemonAction::Start => spawn_background(&args),
        DaemonAction::Stop => execute_stop(&args).await,
        DaemonAction::Status => execute_status(&args).await,
    }
}

fn exec_foreground(args: &DaemonArgs) -> Result<()> {
    let daemon_binary = resolve_daemon_binary()?;
    let daemon_args = build_daemon_args(args);

    #[cfg(unix)]
    {
        let err = Command::new(&daemon_binary).args(&daemon_args).exec();
        Err(anyhow::Error::from(err)).with_context(|| {
            format!(
                "Failed to exec daemon binary at {}",
                daemon_binary.display()
            )
        })
    }

    #[cfg(not(unix))]
    {
        let status = Command::new(&daemon_binary)
            .args(&daemon_args)
            .status()
            .with_context(|| {
                format!("Failed to run daemon binary at {}", daemon_binary.display())
            })?;
        if status.success() {
            Ok(())
        } else {
            bail!("Daemon exited with status {}", status);
        }
    }
}

async fn execute_stop(args: &DaemonArgs) -> Result<()> {
    let layout = resolve_layout(args);
    let lock_file = &layout.lock_file;
    let grpc_socket = &layout.grpc_socket;

    if !daemon_is_alive(lock_file) {
        println!("Daemon is not running");
        return Ok(());
    }

    let Some(pid) = read_lock_file(lock_file)? else {
        bail!("Daemon is alive (lock held) but lock file has no valid PID");
    };

    send_sigterm(pid)?;
    println!("Stopping ArcBox daemon (PID {pid})...");

    let timeout_window = Duration::from_secs(40);
    let deadline = Instant::now() + timeout_window;
    loop {
        let still_alive = daemon_is_alive(lock_file);
        let grpc_socket_removed = !grpc_socket.exists();
        if !still_alive && grpc_socket_removed {
            println!("ArcBox daemon stopped");
            return Ok(());
        }

        if Instant::now() >= deadline {
            bail!(
                "ArcBox daemon (PID {pid}) did not fully stop within {}s (lock_held={}, grpc_socket_present={})",
                timeout_window.as_secs(),
                still_alive,
                !grpc_socket_removed,
            );
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn execute_status(args: &DaemonArgs) -> Result<()> {
    let layout = resolve_layout(args);
    let lock_file = &layout.lock_file;
    let docker_socket = &layout.docker_socket;
    let grpc_socket = &layout.grpc_socket;

    let running = daemon_is_alive(lock_file);
    let pid = if running {
        read_lock_file(lock_file)?
    } else {
        None
    };
    let status = if running { "running" } else { "stopped" };
    let uptime = if running {
        lock_file_uptime(lock_file).map_or_else(
            || "unknown".to_string(),
            |duration| format_duration(duration).to_string(),
        )
    } else {
        "n/a".to_string()
    };
    let grpc_responsive = if running {
        grpc_daemon_is_responsive(grpc_socket).await
    } else {
        false
    };

    println!("ArcBox daemon status: {status}");
    println!(
        "PID: {}",
        pid.map_or_else(|| "n/a".to_string(), |value| value.to_string())
    );
    println!("Docker socket: {}", docker_socket.display());
    println!("gRPC socket: {}", grpc_socket.display());
    println!("Uptime: {uptime}");
    println!(
        "gRPC responsive: {}",
        if grpc_responsive { "yes" } else { "no" }
    );
    Ok(())
}

async fn grpc_daemon_is_responsive(socket_path: &Path) -> bool {
    if !socket_path.exists() {
        return false;
    }

    let endpoint =
        Endpoint::from_static("http://[::]:50051").connect_timeout(Duration::from_secs(1));
    let connect_future =
        endpoint.connect_with_connector(UnixConnector::new(socket_path.to_path_buf()));
    matches!(
        timeout(Duration::from_secs(2), connect_future).await,
        Ok(Ok(_))
    )
}

fn lock_file_uptime(lock_file: &Path) -> Option<Duration> {
    let modified_at = std::fs::metadata(lock_file).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified_at).ok()
}

fn spawn_background(args: &DaemonArgs) -> Result<()> {
    let layout = resolve_layout(args);

    std::fs::create_dir_all(&layout.run_dir).context("Failed to create daemon run directory")?;
    std::fs::create_dir_all(&layout.log_dir).context("Failed to create daemon log directory")?;

    if daemon_is_alive(&layout.lock_file) {
        let pid = read_lock_file(&layout.lock_file)?;
        let pid_str = pid.map_or_else(|| "unknown".to_string(), |p| p.to_string());
        bail!("Daemon already running (PID {pid_str})");
    }

    let daemon_binary = resolve_daemon_binary()?;
    let daemon_args = build_daemon_args(args);

    // Daemon writes its own log files via tracing-appender — no fd
    // redirection needed. Discard stdout/stderr to avoid launchd capturing
    // duplicate output.
    let child = Command::new(&daemon_binary)
        .args(&daemon_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| {
            format!(
                "Failed to launch ArcBox daemon binary at {}",
                daemon_binary.display()
            )
        })?;

    // The daemon acquires the flock and writes its own PID into
    // daemon.lock (see startup::lock::DaemonLock::acquire). The CLI
    // must not write to the lock file — it is the daemon's resource.

    println!("ArcBox daemon started (PID {})", child.id());
    println!("  Lock file: {}", layout.lock_file.display());
    println!("  Logs:     {}", layout.daemon_log.display());
    Ok(())
}

fn resolve_daemon_binary() -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("Failed to resolve current executable")?;

    if let Some(parent) = current_exe.parent() {
        let sibling = parent.join("arcbox-daemon");
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    if let Some(path) = find_in_path("arcbox-daemon") {
        return Ok(path);
    }

    bail!("Failed to locate `arcbox-daemon` next to `arcbox` or in PATH");
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|entry| entry.join(binary))
        .find(|candidate| candidate.is_file())
}

fn build_daemon_args(args: &DaemonArgs) -> Vec<OsString> {
    let mut daemon_args = Vec::new();

    if let Some(socket) = &args.socket {
        daemon_args.push(OsString::from("--socket"));
        daemon_args.push(socket.as_os_str().to_os_string());
    }
    if let Some(grpc_socket) = &args.grpc_socket {
        daemon_args.push(OsString::from("--grpc-socket"));
        daemon_args.push(grpc_socket.as_os_str().to_os_string());
    }
    if let Some(data_dir) = &args.data_dir {
        daemon_args.push(OsString::from("--data-dir"));
        daemon_args.push(data_dir.as_os_str().to_os_string());
    }
    if let Some(profile) = args.profile {
        daemon_args.push(OsString::from("--profile"));
        daemon_args.push(OsString::from(profile.as_str()));
    }
    if let Some(kernel) = &args.kernel {
        daemon_args.push(OsString::from("--kernel"));
        daemon_args.push(kernel.as_os_str().to_os_string());
    }
    if args.foreground {
        daemon_args.push(OsString::from("--foreground"));
    }
    if args.docker_integration {
        daemon_args.push(OsString::from("--docker-integration"));
    }
    if let Some(port) = args.guest_docker_vsock_port {
        daemon_args.push(OsString::from("--guest-docker-vsock-port"));
        daemon_args.push(OsString::from(port.to_string()));
    }
    daemon_args
}

fn resolve_layout(args: &DaemonArgs) -> HostLayout {
    let profile = args
        .profile
        .unwrap_or_else(ArcboxProfile::from_env_or_default);
    let mut layout = HostLayout::resolve_for_profile_from_env(profile, args.data_dir.as_deref());
    if let Some(socket) = &args.socket {
        layout.docker_socket.clone_from(socket);
    }
    if let Some(grpc) = &args.grpc_socket {
        layout.grpc_socket.clone_from(grpc);
    }
    layout
}

fn read_lock_file(lock_file: &Path) -> Result<Option<i32>> {
    if !lock_file.exists() {
        return Ok(None);
    }

    let pid_text = std::fs::read_to_string(lock_file).with_context(|| {
        format!(
            "Failed to read daemon lock file from {}",
            lock_file.display()
        )
    })?;

    match pid_text.trim().parse::<i32>() {
        Ok(pid) if pid > 0 => Ok(Some(pid)),
        _ => {
            warn!("Invalid PID in daemon lock file {}", lock_file.display());
            Ok(None)
        }
    }
}

/// Probe whether the daemon is alive by attempting a non-blocking flock
/// on `daemon.lock`. If the lock is held (EWOULDBLOCK), the daemon is
/// alive. This is immune to PID reuse — the kernel manages the lock.
fn daemon_is_alive(lock_file: &Path) -> bool {
    use std::os::unix::io::AsRawFd;
    let file = match std::fs::OpenOptions::new().read(true).open(lock_file) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // SAFETY: flock on a valid fd with LOCK_EX|LOCK_NB is safe.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        // Lock acquired — daemon is dead. Release immediately.
        // SAFETY: unlocking a lock we just acquired.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    } else {
        // EWOULDBLOCK or EAGAIN both mean "lock is held by another process".
        let err = std::io::Error::last_os_error();
        let raw = err.raw_os_error();
        if raw == Some(libc::EWOULDBLOCK) || raw == Some(libc::EAGAIN) {
            return true;
        }
        warn!(%err, "Unexpected flock error probing daemon lock, assuming not running");
    }
    false
}

fn send_sigterm(pid: i32) -> Result<()> {
    // SAFETY: libc::kill is called with a validated positive PID and SIGTERM
    // to request graceful daemon shutdown.
    let result = unsafe { libc::kill(pid, libc::SIGTERM) };
    if result == 0 {
        return Ok(());
    }

    Err(std::io::Error::last_os_error())
        .with_context(|| format!("Failed to send SIGTERM to daemon process {pid}"))
}

#[cfg(test)]
mod tests {
    use super::read_lock_file;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn read_lock_file_returns_none_when_missing() {
        let dir = tempdir().expect("failed to create temp dir");
        let lock_file = dir.path().join("daemon.lock");
        let pid = read_lock_file(&lock_file).expect("read_lock_file should succeed");
        assert_eq!(pid, None);
    }

    #[test]
    fn read_lock_file_parses_valid_pid() {
        let dir = tempdir().expect("failed to create temp dir");
        let lock_file = dir.path().join("daemon.lock");
        fs::write(&lock_file, "12345\n").expect("failed to write lock file");

        let pid = read_lock_file(&lock_file).expect("read_lock_file should succeed");
        assert_eq!(pid, Some(12345));
        assert!(lock_file.exists());
    }

    #[test]
    fn read_lock_file_returns_none_for_invalid_content() {
        let dir = tempdir().expect("failed to create temp dir");
        let lock_file = dir.path().join("daemon.lock");
        fs::write(&lock_file, "not-a-pid").expect("failed to write lock file");

        let pid = read_lock_file(&lock_file).expect("read_lock_file should succeed");
        assert_eq!(pid, None);
        // Lock file is kept on disk; stale content is harmless.
        assert!(lock_file.exists());
    }
}
