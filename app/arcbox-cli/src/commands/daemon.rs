//! Daemon command implementation.
//!
//! This command controls the lifecycle of the `arcbox-daemon` binary:
//! - start in background (default)
//! - run in foreground (`-f`)
//! - stop a running daemon (`arcbox daemon stop`)
//! - inspect daemon status (`arcbox daemon status`)

use super::machine::UnixConnector;
use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use humantime::format_duration;
use std::ffi::OsString;
use std::fs::OpenOptions;
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
    /// Optional daemon action.
    #[arg(value_name = "ACTION")]
    pub action: Option<DaemonAction>,

    /// Unix socket path for Docker API (default: ~/.arcbox/docker.sock).
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// Unix socket path for gRPC API (desktop/GUI clients).
    #[arg(long)]
    pub grpc_socket: Option<PathBuf>,

    /// Data directory for ArcBox.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Custom kernel path for VM boot.
    #[arg(long)]
    pub kernel: Option<PathBuf>,

    /// Custom initramfs path for VM boot.
    #[arg(long)]
    pub initramfs: Option<PathBuf>,

    /// Run in foreground (don't daemonize).
    #[arg(long, short = 'f')]
    pub foreground: bool,

    /// Automatically enable Docker CLI integration.
    #[arg(long)]
    pub docker_integration: bool,

    /// Guest runtime provisioning mode.
    #[arg(long, value_enum)]
    pub container_provision: Option<ContainerProvisionArg>,

    /// Guest dockerd API vsock port.
    #[arg(long)]
    pub guest_docker_vsock_port: Option<u32>,
}

/// Daemon actions.
#[derive(Debug, Clone, ValueEnum)]
pub enum DaemonAction {
    Stop,
    Status,
}

/// CLI argument values for provisioning mode.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ContainerProvisionArg {
    BundledAssets,
    DistroEngine,
}

impl ContainerProvisionArg {
    fn as_arg_value(self) -> &'static str {
        match self {
            Self::BundledAssets => "bundled-assets",
            Self::DistroEngine => "distro-engine",
        }
    }
}

/// Executes the daemon command.
pub async fn execute(args: DaemonArgs) -> Result<()> {
    match args.action {
        Some(DaemonAction::Stop) => execute_stop(&args).await,
        Some(DaemonAction::Status) => execute_status(&args).await,
        None if args.foreground => exec_foreground(&args),
        None => spawn_background(&args),
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
    let data_dir = resolve_data_dir(args.data_dir.as_ref());
    let pid_file = data_dir.join("daemon.pid");
    let grpc_socket = args
        .grpc_socket
        .clone()
        .unwrap_or_else(|| data_dir.join("arcbox.sock"));

    let Some(pid) = read_pid_file(&pid_file)? else {
        println!("Daemon is not running");
        return Ok(());
    };

    if !process_is_running(pid) {
        let _ = std::fs::remove_file(&pid_file);
        println!("Daemon is not running");
        return Ok(());
    }

    send_sigterm(pid)?;
    println!("Stopping ArcBox daemon (PID {pid})...");

    let timeout_window = Duration::from_secs(30);
    let deadline = Instant::now() + timeout_window;
    loop {
        let process_exited = !process_is_running(pid);
        let grpc_socket_removed = !grpc_socket.exists();
        if process_exited && grpc_socket_removed {
            println!("ArcBox daemon stopped");
            let _ = std::fs::remove_file(&pid_file);
            return Ok(());
        }

        if Instant::now() >= deadline {
            bail!(
                "ArcBox daemon (PID {pid}) did not fully stop within {}s (process_running={}, grpc_socket_present={})",
                timeout_window.as_secs(),
                !process_exited,
                !grpc_socket_removed,
            );
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn execute_status(args: &DaemonArgs) -> Result<()> {
    let data_dir = resolve_data_dir(args.data_dir.as_ref());
    let pid_file = data_dir.join("daemon.pid");
    let docker_socket = args
        .socket
        .clone()
        .unwrap_or_else(|| data_dir.join("docker.sock"));
    let grpc_socket = args
        .grpc_socket
        .clone()
        .unwrap_or_else(|| data_dir.join("arcbox.sock"));

    let mut pid = read_pid_file(&pid_file)?;
    if let Some(value) = pid {
        if !process_is_running(value) {
            let _ = std::fs::remove_file(&pid_file);
            pid = None;
        }
    }

    let running = pid.is_some();
    let status = if running { "running" } else { "not running" };
    let uptime = if running {
        pid_file_uptime(&pid_file)
            .map(|duration| format_duration(duration).to_string())
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "n/a".to_string()
    };
    let grpc_responsive = if running {
        grpc_daemon_is_responsive(&grpc_socket).await
    } else {
        false
    };

    println!("ArcBox daemon status: {status}");
    println!(
        "PID: {}",
        pid.map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
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

fn pid_file_uptime(pid_file: &Path) -> Option<Duration> {
    let modified_at = std::fs::metadata(pid_file).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified_at).ok()
}

fn spawn_background(args: &DaemonArgs) -> Result<()> {
    let data_dir = resolve_data_dir(args.data_dir.as_ref());
    let logs_dir = data_dir.join("logs");
    let pid_file = data_dir.join("daemon.pid");
    let stdout_path = logs_dir.join("daemon.stdout.log");
    let stderr_path = logs_dir.join("daemon.stderr.log");

    std::fs::create_dir_all(&logs_dir).context("Failed to create daemon log directory")?;

    if let Some(pid) = read_pid_file(&pid_file)? {
        if process_is_running(pid) {
            bail!("Daemon already running (PID {pid})");
        }

        warn!("Removing stale daemon PID file for PID {}", pid);
        let _ = std::fs::remove_file(&pid_file);
    }

    let daemon_binary = resolve_daemon_binary()?;
    let daemon_args = build_daemon_args(args);

    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stdout_path)
        .context("Failed to open daemon stdout log file")?;
    let stderr_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stderr_path)
        .context("Failed to open daemon stderr log file")?;

    let child = Command::new(&daemon_binary)
        .args(&daemon_args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .with_context(|| {
            format!(
                "Failed to launch ArcBox daemon binary at {}",
                daemon_binary.display()
            )
        })?;

    std::fs::write(&pid_file, format!("{}\n", child.id()))
        .context("Failed to write daemon PID file")?;

    println!("ArcBox daemon started (PID {})", child.id());
    println!("  PID file: {}", pid_file.display());
    println!("  Stdout:   {}", stdout_path.display());
    println!("  Stderr:   {}", stderr_path.display());
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
    if let Some(kernel) = &args.kernel {
        daemon_args.push(OsString::from("--kernel"));
        daemon_args.push(kernel.as_os_str().to_os_string());
    }
    if let Some(initramfs) = &args.initramfs {
        daemon_args.push(OsString::from("--initramfs"));
        daemon_args.push(initramfs.as_os_str().to_os_string());
    }
    if args.docker_integration {
        daemon_args.push(OsString::from("--docker-integration"));
    }
    if let Some(mode) = args.container_provision {
        daemon_args.push(OsString::from("--container-provision"));
        daemon_args.push(OsString::from(mode.as_arg_value()));
    }
    if let Some(port) = args.guest_docker_vsock_port {
        daemon_args.push(OsString::from("--guest-docker-vsock-port"));
        daemon_args.push(OsString::from(port.to_string()));
    }
    daemon_args
}

fn resolve_data_dir(data_dir: Option<&PathBuf>) -> PathBuf {
    data_dir.cloned().unwrap_or_else(|| {
        dirs::home_dir()
            .map(|home| home.join(".arcbox"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/arcbox"))
    })
}

fn read_pid_file(pid_file: &Path) -> Result<Option<i32>> {
    if !pid_file.exists() {
        return Ok(None);
    }

    let pid_text = std::fs::read_to_string(pid_file)
        .with_context(|| format!("Failed to read daemon PID file from {}", pid_file.display()))?;

    match pid_text.trim().parse::<i32>() {
        Ok(pid) if pid > 0 => Ok(Some(pid)),
        _ => {
            warn!("Invalid daemon PID file, removing {}", pid_file.display());
            let _ = std::fs::remove_file(pid_file);
            Ok(None)
        }
    }
}

fn process_is_running(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }

    // SAFETY: libc::kill is called with a validated positive PID and signal 0,
    // which performs existence/permission checks without sending a signal.
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }

    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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
    use super::read_pid_file;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn read_pid_file_returns_none_when_missing() {
        let dir = tempdir().expect("failed to create temp dir");
        let pid_file = dir.path().join("daemon.pid");
        let pid = read_pid_file(&pid_file).expect("read_pid_file should succeed");
        assert_eq!(pid, None);
    }

    #[test]
    fn read_pid_file_parses_valid_pid() {
        let dir = tempdir().expect("failed to create temp dir");
        let pid_file = dir.path().join("daemon.pid");
        fs::write(&pid_file, "12345\n").expect("failed to write pid file");

        let pid = read_pid_file(&pid_file).expect("read_pid_file should succeed");
        assert_eq!(pid, Some(12345));
        assert!(pid_file.exists());
    }

    #[test]
    fn read_pid_file_removes_invalid_content() {
        let dir = tempdir().expect("failed to create temp dir");
        let pid_file = dir.path().join("daemon.pid");
        fs::write(&pid_file, "not-a-pid").expect("failed to write pid file");

        let pid = read_pid_file(&pid_file).expect("read_pid_file should succeed");
        assert_eq!(pid, None);
        assert!(!pid_file.exists());
    }
}
