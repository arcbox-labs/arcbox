//! Service startup: DNS, Docker API, gRPC servers.
//!
//! gRPC is started once with all services. Machine/Sandbox/Snapshot services
//! use `SharedRuntime` (backed by `OnceLock`) and return `UNAVAILABLE` until
//! `init_runtime()` fills it. This avoids restarting the gRPC server mid-boot.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::{
    IconServiceImpl, IconServiceServer, KubernetesServiceImpl, MachineServiceImpl,
    MigrationServiceImpl, MigrationServiceServer, SandboxServiceImpl, SandboxServiceServer,
    SandboxSnapshotServiceImpl, SandboxSnapshotServiceServer, SharedRuntime, SystemServiceImpl,
    SystemServiceServer, kubernetes_service_server::KubernetesServiceServer,
    machine_service_server::MachineServiceServer,
};
use arcbox_core::Runtime;
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::{info, warn};

use crate::context::{DaemonContext, ServiceHandles};
use crate::dns_service::DnsService;

/// Starts the gRPC server with all services.
///
/// Called before `init_runtime()` — Machine/Sandbox/Snapshot services will
/// return `UNAVAILABLE` until the runtime is set. SystemService works
/// immediately so clients can observe setup progress.
pub async fn start_grpc(
    ctx: &DaemonContext,
    shared_runtime: SharedRuntime,
) -> Result<tokio::task::JoinHandle<()>> {
    let socket_path = &ctx.layout.grpc_socket;
    let _ = std::fs::remove_file(socket_path);

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
    }

    let listener = UnixListener::bind(socket_path).context(format!(
        "Failed to bind gRPC socket: {}",
        socket_path.display()
    ))?;
    let incoming = UnixListenerStream::new(listener);

    info!(socket = %socket_path.display(), "gRPC server listening");

    let machine_service = MachineServiceImpl::new(Arc::clone(&shared_runtime));
    let kubernetes_service = KubernetesServiceImpl::new(Arc::clone(&shared_runtime));
    let migration_service = MigrationServiceImpl::new(Arc::clone(&shared_runtime));
    let sandbox_service = SandboxServiceImpl::new(Arc::clone(&shared_runtime));
    let sandbox_snapshot_service = SandboxSnapshotServiceImpl::new(Arc::clone(&shared_runtime));
    let system_service = SystemServiceImpl::new(Arc::clone(&ctx.setup_state));
    let icon_service = IconServiceImpl::new();

    let shutdown = ctx.shutdown.clone();
    let handle = tokio::spawn(async move {
        let result = Server::builder()
            .add_service(MachineServiceServer::new(machine_service))
            .add_service(KubernetesServiceServer::new(kubernetes_service))
            .add_service(MigrationServiceServer::new(migration_service))
            .add_service(SandboxServiceServer::new(sandbox_service))
            .add_service(SandboxSnapshotServiceServer::new(sandbox_snapshot_service))
            .add_service(SystemServiceServer::new(system_service))
            .add_service(IconServiceServer::new(icon_service))
            .serve_with_incoming_shutdown(incoming, shutdown.cancelled())
            .await;

        if let Err(e) = result {
            tracing::error!("gRPC server error: {}", e);
        }
    });

    Ok(handle)
}

/// Starts DNS, Docker API, and Docker CLI integration.
///
/// Called after `init_runtime()` — the runtime must be available.
pub async fn start_services(
    ctx: &DaemonContext,
    runtime: &Arc<Runtime>,
    grpc: tokio::task::JoinHandle<()>,
) -> Result<ServiceHandles> {
    // DNS service.
    let dns_service = DnsService::bind(Arc::clone(runtime.network_manager()), ctx.dns_port)
        .await
        .context("Failed to start DNS service")?;

    register_host_dns(runtime);

    let dns_shutdown = ctx.shutdown.clone();
    let dns = tokio::spawn(async move {
        if let Err(e) = dns_service.run(dns_shutdown).await {
            tracing::error!("DNS service error: {}", e);
        }
    });

    // Docker API server.
    let docker_server = DockerApiServer::new(
        ServerConfig {
            socket_path: ctx.layout.docker_socket.clone(),
        },
        Arc::clone(runtime),
    );

    let docker_shutdown = ctx.shutdown.clone();
    let docker = tokio::spawn(async move {
        if let Err(e) = docker_server.run(docker_shutdown).await {
            tracing::error!("Docker API server error: {}", e);
        }
    });

    // Docker CLI integration (optional).
    if ctx.docker_integration {
        match DockerContextManager::new(ctx.layout.docker_socket.clone()) {
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

    // Kubernetes API proxy (TCP 127.0.0.1:16443 → guest vsock).
    let kubernetes_proxy = crate::kubernetes_proxy::start(Arc::clone(runtime)).await;

    Ok(ServiceHandles {
        dns,
        docker,
        grpc,
        kubernetes_proxy,
    })
}

// =============================================================================
// Helpers
// =============================================================================

fn register_host_dns(runtime: &Arc<Runtime>) {
    let network_cfg = &runtime.config().network;
    let gateway_ip = network_cfg
        .gateway
        .as_ref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .or_else(|| first_address_in_subnet(&network_cfg.subnet))
        .unwrap_or(Ipv4Addr::new(10, 0, 2, 1));
    let ip = IpAddr::V4(gateway_ip);
    runtime.network_manager().register_dns("host", ip);
    // Docker compatibility: containers use these to reach host services.
    runtime
        .network_manager()
        .register_dns("host.docker.internal", ip);
    runtime
        .network_manager()
        .register_dns("gateway.docker.internal", ip);
}

fn first_address_in_subnet(subnet: &str) -> Option<Ipv4Addr> {
    let (ip_str, prefix_str) = subnet.split_once('/')?;
    let base: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix == 0 || prefix >= 32 {
        return None;
    }
    let mask: u32 = (!0u32) << (32 - prefix);
    let network = u32::from(base) & mask;
    let first = network.checked_add(1)?;
    let broadcast = network | !mask;
    if first > broadcast {
        None
    } else {
        Some(Ipv4Addr::from(first))
    }
}
