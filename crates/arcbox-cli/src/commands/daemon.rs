//! Daemon command implementation.
//!
//! Starts the ArcBox daemon which provides:
//! - Docker-compatible REST API on a Unix socket
//! - gRPC API on a Unix socket (for desktop/GUI clients)
//! - VM and container lifecycle management
//! - Image management

use anyhow::{Context, Result};
use arcbox_api::{
    ContainerServiceImpl, ImageServiceImpl, MachineServiceImpl, SystemServiceImpl,
    container_service_server::ContainerServiceServer, image_service_server::ImageServiceServer,
    machine_service_server::MachineServiceServer, system_service_server::SystemServiceServer,
};
use arcbox_core::{Config, ContainerBackendMode, ContainerProvisionMode, Runtime};
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use clap::{Args, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::{info, warn};

/// Arguments for the daemon command.
#[derive(Debug, Args)]
pub struct DaemonArgs {
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
    #[arg(long, short = 'f', default_value = "true")]
    pub foreground: bool,

    /// Automatically enable Docker CLI integration.
    #[arg(long)]
    pub docker_integration: bool,

    /// Container backend mode.
    #[arg(long, value_enum)]
    pub container_backend: Option<ContainerBackendArg>,

    /// Guest runtime provisioning mode.
    #[arg(long, value_enum)]
    pub container_provision: Option<ContainerProvisionArg>,

    /// Guest dockerd API vsock port.
    #[arg(long)]
    pub guest_docker_vsock_port: Option<u32>,
}

/// CLI argument values for container backend mode.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ContainerBackendArg {
    NativeControlPlane,
    GuestDocker,
}

impl From<ContainerBackendArg> for ContainerBackendMode {
    fn from(value: ContainerBackendArg) -> Self {
        match value {
            ContainerBackendArg::NativeControlPlane => Self::NativeControlPlane,
            ContainerBackendArg::GuestDocker => Self::GuestDocker,
        }
    }
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
    info!("Starting ArcBox daemon...");

    // Determine data directory.
    let data_dir = args.data_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".arcbox"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/arcbox"))
    });
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
    if let Some(mode) = args.container_backend {
        config.container.backend = mode.into();
    }
    if let Some(mode) = args.container_provision {
        config.container.provision = mode.into();
    }
    if let Some(port) = args.guest_docker_vsock_port {
        config.container.guest_docker_vsock_port = port;
    }
    let selected_backend = config.container.backend;
    let selected_provision = config.container.provision;
    let selected_guest_docker_port = config.container.guest_docker_vsock_port;

    // Build VM lifecycle config with custom kernel/initramfs if provided.
    let mut vm_lifecycle_config = arcbox_core::VmLifecycleConfig::default();
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
        backend = ?selected_backend,
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

    // Disable Docker integration if it was enabled.
    if args.docker_integration {
        if let Ok(ctx_manager) = DockerContextManager::new(socket_path) {
            let _ = ctx_manager.disable();
        }
    }

    info!("ArcBox daemon stopped");
    Ok(())
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
    let container_service = ContainerServiceImpl::new(Arc::clone(&runtime));
    let machine_service = MachineServiceImpl::new(Arc::clone(&runtime));
    let image_service = ImageServiceImpl::new(Arc::clone(&runtime));
    let system_service = SystemServiceImpl::new(Arc::clone(&runtime));

    // Build and run gRPC server.
    let handle = tokio::spawn(async move {
        let result = Server::builder()
            .add_service(ContainerServiceServer::new(container_service))
            .add_service(MachineServiceServer::new(machine_service))
            .add_service(ImageServiceServer::new(image_service))
            .add_service(SystemServiceServer::new(system_service))
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
