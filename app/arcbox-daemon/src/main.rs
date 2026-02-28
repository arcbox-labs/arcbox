use anyhow::{Context, Result};
use arcbox_api::{MachineServiceImpl, machine_service_server::MachineServiceServer};
use arcbox_core::{Config, ContainerProvisionMode, Runtime, VmLifecycleConfig};
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use clap::{Parser, ValueEnum};
use macos_resolver::{FileResolver, to_env_prefix};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const DNS_PREFIX: &str = "arcbox";
const DEFAULT_DNS_DOMAIN: &str = "arcbox.local";

#[derive(Debug, Parser)]
#[command(name = "arcbox-daemon")]
#[command(author, version, about, long_about = None)]
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arcbox=info,arcbox_daemon=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    run(DaemonArgs::parse()).await
}

async fn run(args: DaemonArgs) -> Result<()> {
    info!("Starting ArcBox daemon...");

    let data_dir = resolve_data_dir(args.data_dir.as_ref());
    let pid_file = data_dir.join("daemon.pid");
    std::fs::create_dir_all(&data_dir).context("Failed to create data directory")?;
    std::fs::write(&pid_file, format!("{}\n", std::process::id()))
        .context("Failed to write daemon PID file")?;

    let socket_path = args.socket.unwrap_or_else(|| data_dir.join("docker.sock"));
    let grpc_socket = args
        .grpc_socket
        .unwrap_or_else(|| data_dir.join("arcbox.sock"));

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

    let mut vm_lifecycle_config = VmLifecycleConfig::default();
    vm_lifecycle_config.default_vm.cpus = config.vm.cpus;
    vm_lifecycle_config.default_vm.memory_mb = config.vm.memory_mb;
    if let Some(ref kernel) = config.vm.kernel_path {
        vm_lifecycle_config.default_vm.kernel = Some(kernel.clone());
    }

    if let Some(kernel) = args.kernel {
        vm_lifecycle_config.default_vm.kernel = Some(kernel);
    }

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

    let docker_server = DockerApiServer::new(
        ServerConfig {
            socket_path: socket_path.clone(),
        },
        Arc::clone(&runtime),
    );

    let docker_handle = tokio::spawn(async move {
        if let Err(e) = docker_server.run().await {
            tracing::error!("Docker API server error: {}", e);
        }
    });

    let grpc_handle = start_grpc_server(Arc::clone(&runtime), grpc_socket.clone()).await?;

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

    check_resolver_installed();

    println!("ArcBox daemon started");
    println!("  Docker API: {}", socket_path.display());
    println!("  gRPC API:   {}", grpc_socket.display());
    println!("  Data:       {}", data_dir.display());
    println!();
    println!("Use 'arcbox docker enable' to configure Docker CLI integration.");
    println!("Press Ctrl+C to stop.");

    shutdown_signal().await;
    info!("Shutdown signal received");

    info!("Shutting down...");
    docker_handle.abort();
    grpc_handle.abort();

    runtime
        .shutdown()
        .await
        .context("Failed to shutdown runtime")?;

    if args.docker_integration {
        if let Ok(ctx_manager) = DockerContextManager::new(socket_path.clone()) {
            let _ = ctx_manager.disable();
        }
    }

    for path in [&socket_path, &grpc_socket] {
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

fn resolve_data_dir(data_dir: Option<&PathBuf>) -> PathBuf {
    data_dir.cloned().unwrap_or_else(|| {
        dirs::home_dir()
            .map(|home| home.join(".arcbox"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/arcbox"))
    })
}

async fn start_grpc_server(
    runtime: Arc<Runtime>,
    socket_path: PathBuf,
) -> Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(&socket_path);

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
    }

    let listener = UnixListener::bind(&socket_path).context(format!(
        "Failed to bind gRPC socket: {}",
        socket_path.display()
    ))?;
    let incoming = UnixListenerStream::new(listener);

    info!(socket = %socket_path.display(), "gRPC server listening");

    let machine_service = MachineServiceImpl::new(Arc::clone(&runtime));

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

fn dns_domain() -> String {
    let key = format!("{}_DNS_DOMAIN", to_env_prefix(DNS_PREFIX));
    std::env::var(key).unwrap_or_else(|_| DEFAULT_DNS_DOMAIN.to_string())
}

fn check_resolver_installed() {
    let resolver = FileResolver::new(DNS_PREFIX);
    let domain = dns_domain();
    if !resolver.is_registered(&domain) {
        println!("Hint: Run 'sudo arcbox dns install' to enable *.{domain} DNS resolution.");
    }
}
