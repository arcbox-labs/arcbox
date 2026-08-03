//! Service startup: DNS, Docker API, gRPC servers.
//!
//! gRPC is started once with all services. Machine/Sandbox/Snapshot services
//! use `SharedRuntime` (backed by `OnceLock`) and return `UNAVAILABLE` until
//! `init_runtime()` fills it. This avoids restarting the gRPC server mid-boot.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::{SharedRuntime, SystemServiceImpl};
use arcbox_core::{Runtime, VmLifecycleState};
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use tokio::sync::watch;
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
    let listener = crate::control_plane::bind(socket_path)?;

    info!(socket = %socket_path.display(), "control plane listening (Connect + gRPC + gRPC-Web)");

    let system_service = SystemServiceImpl::new(
        Arc::clone(&ctx.setup_state),
        Arc::clone(&shared_runtime),
        Arc::clone(&ctx.early_runtime),
    );
    // Every service is served over Connect (CORE-53, CORE-68). The sandbox
    // control/data-plane split (CORE-57) is preserved inside it, so a cloud
    // deployment can still host those halves in different processes.
    // Reflection rides along and answers over all three wire formats.
    let app = crate::control_plane::into_app(crate::control_plane::connect_router(
        Arc::clone(&shared_runtime),
        system_service,
    )?);

    let shutdown = ctx.shutdown.clone();
    let handle = tokio::spawn(crate::control_plane::serve(listener, app, shutdown));

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

    register_host_dns(runtime).await;

    let dns_shutdown = ctx.shutdown.clone();
    let dns = tokio::spawn(async move {
        if let Err(e) = dns_service.run(dns_shutdown).await {
            tracing::error!("DNS service error: {}", e);
        }
    });

    // VM-host-only mode: the Docker API, Docker CLI integration, and the
    // Kubernetes proxy all depend on the Linux VM, so they are skipped when it
    // is not booted.
    let linux_vm = runtime.config().vm.autostart;

    // Docker API server. Bound here rather than inside the spawned task so a
    // bind failure fails startup: the Docker socket is the daemon's primary
    // API, and a task that only logs the error would leave the pipeline
    // publishing READY for a daemon no client can reach (CORE-71). DNS above
    // already works this way.
    let docker = if linux_vm {
        let docker_server = DockerApiServer::new(
            ServerConfig {
                socket_path: ctx.layout.docker_socket.clone(),
            },
            Arc::clone(runtime),
        );
        let listener = docker_server.bind().with_context(|| {
            format!(
                "Failed to bind the Docker API socket: {}",
                ctx.layout.docker_socket.display()
            )
        })?;
        let docker_shutdown = ctx.shutdown.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = docker_server.serve(listener, docker_shutdown).await {
                tracing::error!("Docker API server error: {}", e);
            }
        }))
    } else {
        None
    };

    // Docker CLI integration (optional).
    if linux_vm && ctx.docker_integration {
        match DockerContextManager::new_with_context_name(
            ctx.layout.docker_socket.clone(),
            ctx.profile.docker_context_name(),
        ) {
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
    let kubernetes_proxy = if linux_vm {
        crate::kubernetes_proxy::start(Arc::clone(runtime)).await
    } else {
        None
    };

    #[cfg(target_os = "macos")]
    let route_controller = linux_vm.then(|| {
        crate::container_route::spawn(
            Arc::clone(runtime),
            Arc::clone(&ctx.setup_state),
            ctx.shutdown.clone(),
        )
    });
    #[cfg(not(target_os = "macos"))]
    let route_controller = None;

    Ok(ServiceHandles {
        dns,
        docker,
        grpc,
        kubernetes_proxy,
        route_controller,
    })
}

// =============================================================================
// Helpers
// =============================================================================

/// Starts the `vm_running` mirror for the System VM.
///
/// Spawned from `init_runtime`, not from [`start_services`]: the VM reaches
/// `VmLifecycleState::Running` partway through `Runtime::init` — that is what
/// publishes `VM_READY` — and `init` then waits for the guest container
/// runtime. A mirror started once `boot_runtime` has returned would report
/// `vm_running = false` across that whole window while the agent is already
/// answering, which is exactly what the field promises it is not.
pub fn spawn_vm_running_mirror(ctx: &DaemonContext, runtime: &Arc<Runtime>) {
    let state = runtime.subscribe_system_vm_state();
    let setup_state = Arc::clone(&ctx.setup_state);
    let shutdown = ctx.shutdown.clone();
    drop(tokio::spawn(async move {
        vm_running_loop(state, setup_state, shutdown).await;
    }));
}

/// Mirrors the System VM's lifecycle state into `SetupState.vm_running`.
///
/// The flag reports readiness level 2 — `VmLifecycleState::is_ready`, the
/// agent has answered a ping — which is the level that matches what a client
/// reads the field to mean. Level 1 (`MachineState::Running`) counts a VM
/// whose agent is not up, so RPCs against it fail; level 3 (guest dockerd)
/// is narrower than "the VM is running" and already has its own signal.
///
/// Driven from the lifecycle watch rather than set once on a successful guest
/// query, so it tracks both edges: idle stop, backend switch, and crash
/// recovery all move it without anything else having to remember to.
async fn vm_running_loop(
    mut state: watch::Receiver<VmLifecycleState>,
    setup_state: Arc<arcbox_api::SetupState>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    loop {
        setup_state.set_vm_running(state.borrow_and_update().is_ready());
        tokio::select! {
            () = shutdown.cancelled() => break,
            // The sender lives as long as the runtime; an error means it is
            // gone, so there is nothing left to mirror.
            changed = state.changed() => if changed.is_err() { break },
        }
    }
}

async fn register_host_dns(runtime: &Arc<Runtime>) {
    let network_cfg = &runtime.config().network;
    let gateway_ip = network_cfg
        .gateway
        .as_ref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .or_else(|| first_address_in_subnet(&network_cfg.subnet))
        .unwrap_or(Ipv4Addr::new(10, 0, 2, 1));
    let ip = IpAddr::V4(gateway_ip);
    runtime
        .register_host_dns(
            &[
                "host".into(),
                "host.docker.internal".into(),
                "gateway.docker.internal".into(),
            ],
            ip,
        )
        .await;
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use arcbox_api::SetupState;

    /// Polls until `vm_running` matches `want` or times out.
    async fn wait_for_vm_running(state: &SetupState, want: bool) -> bool {
        for _ in 0..200 {
            if state.current().vm_running == want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    /// The flag has to fall as well as rise. Its predecessor was set once by
    /// cold-start recovery and never cleared, so a client saw `vm_running`
    /// stay true for the rest of the daemon's life after any VM stop.
    #[tokio::test]
    async fn vm_running_loop_follows_the_lifecycle_both_ways() {
        let (lifecycle, rx) = watch::channel(VmLifecycleState::Stopped);
        let setup_state = Arc::new(SetupState::new());
        let shutdown = tokio_util::sync::CancellationToken::new();

        let task = tokio::spawn(vm_running_loop(
            rx,
            Arc::clone(&setup_state),
            shutdown.clone(),
        ));

        assert!(wait_for_vm_running(&setup_state, false).await);

        lifecycle.send(VmLifecycleState::Running).expect("receiver");
        assert!(wait_for_vm_running(&setup_state, true).await);

        // Idle still counts as running: the VM is up, just quiet.
        lifecycle.send(VmLifecycleState::Idle).expect("receiver");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(setup_state.current().vm_running);

        // The regression this test exists for.
        lifecycle.send(VmLifecycleState::Stopped).expect("receiver");
        assert!(wait_for_vm_running(&setup_state, false).await);

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("loop exits on shutdown")
            .expect("loop task panicked");
    }
}
