//! Daemon command implementation.
//!
//! Starts the ArcBox daemon which provides:
//! - Docker-compatible REST API on a Unix socket
//! - gRPC API on a Unix socket (for desktop/GUI clients)
//! - VM and container lifecycle management
//! - Image management

use anyhow::{Context, Result, bail};
use arcbox_api::{MachineServiceImpl, machine_service_server::MachineServiceServer};
use arcbox_core::{Config, ContainerProvisionMode, Runtime};
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use clap::{Args, ValueEnum};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::signal;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::{info, warn};

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
}

/// CLI argument values for provisioning mode.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ContainerProvisionArg {
    BundledAssets,
    DistroEngine,
}

impl From<ContainerProvisionArg> for ContainerProvisionMode {
    fn from(value: ContainerProvisionArg) -> Self {
        match value {
            ContainerProvisionArg::BundledAssets => Self::BundledAssets,
            ContainerProvisionArg::DistroEngine => Self::DistroEngine,
        }
    }
}

/// Executes the daemon command.
pub async fn execute(args: DaemonArgs) -> Result<()> {
    if let Some(DaemonAction::Stop) = args.action {
        return execute_stop(&args);
    }

    if !args.foreground {
        return spawn_background(&args);
    }

    info!("Starting ArcBox daemon...");

    // Determine data directory.
    let data_dir = resolve_data_dir(args.data_dir.as_ref());
    let pid_file = data_dir.join("daemon.pid");
    std::fs::create_dir_all(&data_dir).context("Failed to create data directory")?;
    std::fs::write(&pid_file, format!("{}\n", std::process::id()))
        .context("Failed to write daemon PID file")?;
    let socket_path = args.socket.unwrap_or_else(|| data_dir.join("docker.sock"));

    // Determine gRPC socket path (defaults to same directory as data_dir).
    let grpc_socket = args
        .grpc_socket
        .unwrap_or_else(|| data_dir.join("arcbox.sock"));

    // Create configuration.
    let mut config = Config {
        data_dir: data_dir.clone(),
        ..Default::default()
    };
    if let Some(mode) = args.container_provision {
        config.container.provision = mode.into();
    }
    if let Some(port) = args.guest_docker_vsock_port {
        config.container.guest_docker_vsock_port = port;
    }
    let selected_provision = config.container.provision;
    let selected_guest_docker_port = config.container.guest_docker_vsock_port;

    // Build VM lifecycle config with custom kernel/initramfs if provided.
    let mut vm_lifecycle_config = arcbox_core::VmLifecycleConfig::default();

    // Propagate config.vm to VM lifecycle defaults.
    vm_lifecycle_config.default_vm.cpus = config.vm.cpus;
    vm_lifecycle_config.default_vm.memory_mb = config.vm.memory_mb;
    if let Some(ref kernel) = config.vm.kernel_path {
        vm_lifecycle_config.default_vm.kernel = Some(kernel.clone());
    }
    if let Some(ref initrd) = config.vm.initrd_path {
        vm_lifecycle_config.default_vm.initramfs = Some(initrd.clone());
    }

    // CLI args override config file values.
    if let Some(kernel) = args.kernel {
        vm_lifecycle_config.default_vm.kernel = Some(kernel);
    }
    if let Some(initramfs) = args.initramfs {
        vm_lifecycle_config.default_vm.initramfs = Some(initramfs);
    }

    // Initialize runtime with custom VM lifecycle config.
    let runtime = Arc::new(
        Runtime::with_vm_lifecycle_config(config, vm_lifecycle_config)
            .context("Failed to create runtime")?,
    );
    runtime
        .init()
        .await
        .context("Failed to initialize runtime")?;

    info!(
        data_dir = %data_dir.display(),
        provision = ?selected_provision,
        guest_docker_vsock_port = selected_guest_docker_port,
        "Runtime initialized"
    );

    // Configure Docker API server.
    let server_config = ServerConfig {
        socket_path: socket_path.clone(),
    };

    let docker_server = DockerApiServer::new(server_config, Arc::clone(&runtime));

    // Start Docker API server in background.
    let docker_handle = tokio::spawn(async move {
        if let Err(e) = docker_server.run().await {
            tracing::error!("Docker API server error: {}", e);
        }
    });

    // Start gRPC server on Unix socket.
    let grpc_handle = start_grpc_server(Arc::clone(&runtime), grpc_socket.clone()).await?;

    // Enable Docker CLI integration if requested.
    if args.docker_integration {
        match DockerContextManager::new(socket_path.clone()) {
            Ok(ctx_manager) => {
                if let Err(e) = ctx_manager.enable() {
                    warn!("Failed to enable Docker integration: {}", e);
                } else {
                    info!("Docker CLI integration enabled");
                }
            }
            Err(e) => {
                warn!("Failed to create Docker context manager: {}", e);
            }
        }
    }

    // Check DNS resolver status.
    super::dns::check_resolver_installed();

    // Print startup info.
    println!("ArcBox daemon started");
    println!("  Docker API: {}", socket_path.display());
    println!("  gRPC API:   {}", grpc_socket.display());
    println!("  Data:       {}", data_dir.display());
    println!();
    println!("Use 'arcbox docker enable' to configure Docker CLI integration.");
    println!("Press Ctrl+C to stop.");

    // Wait for shutdown signal.
    shutdown_signal().await;
    info!("Shutdown signal received");

    // Cleanup.
    info!("Shutting down...");

    // Abort server tasks.
    docker_handle.abort();
    grpc_handle.abort();

    runtime
        .shutdown()
        .await
        .context("Failed to shutdown runtime")?;

    let socket_path_clone = socket_path.clone();

    // Disable Docker integration if it was enabled.
    if args.docker_integration {
        if let Ok(ctx_manager) = DockerContextManager::new(socket_path) {
            let _ = ctx_manager.disable();
        }
    }

    // Clean up socket files.
    for path in [&socket_path_clone, &grpc_socket] {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Failed to remove socket {}: {}", path.display(), e);
            }
        }
    }

    if let Err(e) = std::fs::remove_file(&pid_file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!("Failed to remove PID file {}: {}", pid_file.display(), e);
        }
    }

    info!("ArcBox daemon stopped");
    Ok(())
}

fn execute_stop(args: &DaemonArgs) -> Result<()> {
    let data_dir = resolve_data_dir(args.data_dir.as_ref());
    let pid_file = data_dir.join("daemon.pid");

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

    for _ in 0..50 {
        if !process_is_running(pid) {
            println!("ArcBox daemon stopped");
            let _ = std::fs::remove_file(&pid_file);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    println!("ArcBox daemon (PID {pid}) is still running after 5s");
    println!("Try: kill -9 {pid}");
    Ok(())
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

    let mut child_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    child_args.push(OsString::from("--foreground"));

    let current_exe = std::env::current_exe().context("Failed to resolve current executable")?;
    let child = Command::new(current_exe)
        .args(child_args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .context("Failed to launch ArcBox daemon in background")?;

    std::fs::write(&pid_file, format!("{}\n", child.id()))
        .context("Failed to write daemon PID file")?;

    println!("ArcBox daemon started (PID {})", child.id());
    println!("  PID file: {}", pid_file.display());
    println!("  Stdout:   {}", stdout_path.display());
    println!("  Stderr:   {}", stderr_path.display());
    Ok(())
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

/// Starts the gRPC server on a Unix socket.
async fn start_grpc_server(
    runtime: Arc<Runtime>,
    socket_path: PathBuf,
) -> Result<tokio::task::JoinHandle<()>> {
    // Remove existing socket file.
    let _ = std::fs::remove_file(&socket_path);

    // Create parent directory if needed.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
    }

    // Bind Unix socket.
    let listener = UnixListener::bind(&socket_path).context(format!(
        "Failed to bind gRPC socket: {}",
        socket_path.display()
    ))?;
    let incoming = UnixListenerStream::new(listener);

    info!(socket = %socket_path.display(), "gRPC server listening");

    // Create gRPC services.
    let machine_service = MachineServiceImpl::new(Arc::clone(&runtime));

    // Build and run gRPC server.
    let handle = tokio::spawn(async move {
        let result = Server::builder()
            .add_service(MachineServiceServer::new(machine_service))
            .serve_with_incoming(incoming)
            .await;

        if let Err(e) = result {
            tracing::error!("gRPC server error: {}", e);
        }
    });

    Ok(handle)
}

/// Waits for a shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
