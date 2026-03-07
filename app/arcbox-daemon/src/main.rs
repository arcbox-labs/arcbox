mod dns_service;

use anyhow::{Context, Result};
use arcbox_api::{
    MachineServiceImpl, SandboxServiceImpl, SandboxServiceServer, SandboxSnapshotServiceImpl,
    SandboxSnapshotServiceServer, machine_service_server::MachineServiceServer,
};
use arcbox_core::{Config, Runtime, VmLifecycleConfig};
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use clap::Parser;
use dns_service::DnsService;
use macos_resolver::{FileResolver, to_env_prefix};
use std::net::{IpAddr, Ipv4Addr};
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

    /// Guest dockerd API vsock port.
    #[arg(long)]
    pub guest_docker_vsock_port: Option<u32>,
}

fn main() -> Result<()> {
    // Sentry must be initialized before the tokio runtime so that spawned
    // threads inherit the Hub from the main thread.
    // When SENTRY_DSN is unset, this is a no-op with zero overhead.
    let _sentry_guard = sentry::init(sentry::ClientOptions {
        dsn: std::env::var("ARCBOX_DAEMON_SENTRY_DSN")
            .or_else(|_| std::env::var("SENTRY_DSN"))
            .ok()
            .and_then(|s| s.parse().ok()),
        release: Some(env!("CARGO_PKG_VERSION").into()),
        environment: std::env::var("ARCBOX_DAEMON_SENTRY_ENVIRONMENT")
            .or_else(|_| std::env::var("SENTRY_ENVIRONMENT"))
            .ok()
            .map(Into::into),
        traces_sample_rate: 0.2,
        sample_rate: 1.0,
        attach_stacktrace: true,
        ..Default::default()
    });

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arcbox=info,arcbox_daemon=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(sentry::integrations::tracing::layer())
        .init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime")
        .block_on(run(DaemonArgs::parse()))
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
    if let Some(port) = args.guest_docker_vsock_port {
        config.container.guest_docker_vsock_port = port;
    }
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
        guest_docker_vsock_port = selected_guest_docker_port,
        "Runtime initialized"
    );

    // Bind DNS socket eagerly — failure aborts the daemon.
    let dns_service = DnsService::bind(Arc::clone(runtime.network_manager()))
        .await
        .context("Failed to start DNS service")?;

    // Register host.arcbox.local → gateway IP.
    let gateway_ip = runtime
        .config()
        .network
        .gateway
        .as_ref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::new(192, 168, 64, 1));
    runtime
        .network_manager()
        .register_dns("host", IpAddr::V4(gateway_ip));

    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_service.run().await {
            tracing::error!("DNS service error: {}", e);
        }
    });

    // Recover DNS entries for containers already running in the guest VM
    // (handles daemon restart without VM restart).
    recover_dns_entries(&runtime).await;

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
    println!("  DNS:        127.0.0.1:5553");
    println!("  Data:       {}", data_dir.display());
    println!();
    println!("Use 'arcbox docker enable' to configure Docker CLI integration.");
    println!("Press Ctrl+C to stop.");

    shutdown_signal().await;
    info!("Shutdown signal received");

    info!("Shutting down...");
    dns_handle.abort();
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
        dirs::home_dir().map_or_else(
            || PathBuf::from("/var/lib/arcbox"),
            |home| home.join(".arcbox"),
        )
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
    let sandbox_service = SandboxServiceImpl::new(Arc::clone(&runtime));
    let sandbox_snapshot_service = SandboxSnapshotServiceImpl::new(Arc::clone(&runtime));

    let handle = tokio::spawn(async move {
        let result = Server::builder()
            .add_service(MachineServiceServer::new(machine_service))
            .add_service(SandboxServiceServer::new(sandbox_service))
            .add_service(SandboxSnapshotServiceServer::new(sandbox_snapshot_service))
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
        () = ctrl_c => {},
        () = terminate => {},
    }
}

/// Re-registers DNS entries for all running containers in the guest VM.
///
/// Called after daemon startup to handle the case where the daemon restarts
/// but the VM (and its containers) are still running.
async fn recover_dns_entries(runtime: &Arc<Runtime>) {
    use axum::http::{HeaderMap, Method};
    use bytes::Bytes;

    let resp = match arcbox_docker::proxy::proxy_to_guest(
        runtime,
        Method::GET,
        "/containers/json",
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            tracing::debug!("Container list returned status {}", resp.status());
            return;
        }
        Err(e) => {
            tracing::debug!("Failed to list containers for DNS recovery: {}", e);
            return;
        }
    };

    let body_bytes = match http_body_util::BodyExt::collect(resp.into_body()).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::debug!("Failed to read container list body: {}", e);
            return;
        }
    };

    let containers: Vec<serde_json::Value> = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("Failed to parse container list JSON: {}", e);
            return;
        }
    };

    let mut recovered = 0u32;
    for container in &containers {
        let Some(id) = container.get("Id").and_then(|v| v.as_str()) else {
            continue;
        };

        // Inspect each running container to get name + IP.
        let inspect_path = format!("/containers/{id}/json");
        let inspect_resp = match arcbox_docker::proxy::proxy_to_guest(
            runtime,
            Method::GET,
            &inspect_path,
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await
        {
            Ok(resp) if resp.status().is_success() => resp,
            _ => continue,
        };

        let inspect_body = match http_body_util::BodyExt::collect(inspect_resp.into_body()).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => continue,
        };

        // Extract name and IP using the same logic as container start.
        let v: serde_json::Value = match serde_json::from_slice(&inspect_body) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let Some(name) = v.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        let name = name.trim_start_matches('/');
        if name.is_empty() {
            continue;
        }

        // IP extraction with fallback chain.
        let ip_str = v
            .pointer("/NetworkSettings/IPAddress")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                v.pointer("/NetworkSettings/Networks")?
                    .as_object()?
                    .values()
                    .find_map(|net| net.get("IPAddress")?.as_str().filter(|s| !s.is_empty()))
            });

        let Some(ip) = ip_str.and_then(|s| s.parse::<IpAddr>().ok()) else {
            continue;
        };

        runtime.register_dns(id, name, ip).await;
        recovered += 1;
    }

    if recovered > 0 {
        info!(
            count = recovered,
            "Recovered DNS entries for running containers"
        );
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
