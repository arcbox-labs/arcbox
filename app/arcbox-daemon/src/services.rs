//! Service startup: DNS, Docker API, gRPC servers.
//!
//! gRPC is started once with all services. Machine/Sandbox/Snapshot services
//! use `SharedRuntime` (backed by `OnceLock`) and return `UNAVAILABLE` until
//! `init_runtime()` fills it. This avoids restarting the gRPC server mid-boot.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::{
    MachineServiceImpl, SharedRuntime, SystemServiceImpl,
    machine_service_server::MachineServiceServer,
};
#[cfg(target_os = "macos")]
use arcbox_api::{MacosServiceImpl, macos_service_server::MacosServiceServer};
use arcbox_core::Runtime;
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use tonic::service::Routes;
use tracing::{info, warn};

use crate::context::{DaemonContext, ServiceHandles};
use crate::dns_service::DnsService;

#[cfg(target_os = "macos")]
const ROUTE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(target_os = "macos")]
const ROUTE_EVENT_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(250);

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

    let machine_service = MachineServiceImpl::new(Arc::clone(&shared_runtime));
    #[cfg(target_os = "macos")]
    let macos_service = MacosServiceImpl::new(Arc::clone(&shared_runtime));
    let system_service = SystemServiceImpl::new(
        Arc::clone(&ctx.setup_state),
        Arc::clone(&shared_runtime),
        Arc::clone(&ctx.early_runtime),
    );
    // The Connect half: the four sandbox services (CORE-53), whose
    // control/data-plane split (CORE-57) is preserved so a cloud deployment
    // can host them in different processes, plus the daemon's own services
    // as they migrate off tonic (CORE-68). Reflection rides along so it
    // answers over all three wire formats rather than gRPC alone.
    let connect =
        crate::control_plane::connect_router(Arc::clone(&shared_runtime), system_service)?;

    let routes = Routes::default().add_service(MachineServiceServer::new(machine_service));
    // macOS guests are served only on Apple Silicon hosts; on other
    // platforms the service is simply absent (the CLI `macos` noun is
    // likewise macOS-only).
    #[cfg(target_os = "macos")]
    let routes = routes.add_service(MacosServiceServer::new(macos_service));

    let app = crate::control_plane::compose(routes, connect);

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

    register_host_dns(runtime);

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

    // Docker API server.
    let docker = linux_vm.then(|| {
        let docker_server = DockerApiServer::new(
            ServerConfig {
                socket_path: ctx.layout.docker_socket.clone(),
            },
            Arc::clone(runtime),
        );
        let docker_shutdown = ctx.shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = docker_server.run(docker_shutdown).await {
                tracing::error!("Docker API server error: {}", e);
            }
        })
    });

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

    // Mirror route-install events into SetupStatus. VM (re)starts install
    // the container route from vm_lifecycle, outside the cold-start
    // recovery path that sets the flag directly — without this bridge,
    // route_installed would stay stale until the next daemon restart.
    let route_events = runtime.event_bus().subscribe();
    let route_state = Arc::clone(&ctx.setup_state);
    let route_shutdown = ctx.shutdown.clone();
    drop(tokio::spawn(async move {
        route_status_loop(route_events, route_state, route_shutdown).await;
    }));

    #[cfg(target_os = "macos")]
    let route_guard = linux_vm.then(|| {
        let runtime = Arc::clone(runtime);
        let setup_state = Arc::clone(&ctx.setup_state);
        let shutdown = ctx.shutdown.clone();
        tokio::spawn(async move {
            container_route_guard(runtime, setup_state, shutdown).await;
        })
    });
    #[cfg(not(target_os = "macos"))]
    let route_guard = None;

    Ok(ServiceHandles {
        dns,
        docker,
        grpc,
        kubernetes_proxy,
        route_guard,
    })
}

// =============================================================================
// Helpers
// =============================================================================

/// Mirrors VM lifecycle events into `SetupState.route_installed`.
///
/// `ContainerRouteInstalled` sets the flag; `MachineStopped` clears it
/// (the bridge interface — and with it the host route — dies with the VM).
async fn route_status_loop(
    mut events: tokio::sync::broadcast::Receiver<arcbox_core::event::Event>,
    setup_state: Arc<arcbox_api::SetupState>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    use arcbox_core::event::Event;
    use tokio::sync::broadcast::error::RecvError;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            event = events.recv() => match event {
                Ok(Event::ContainerRouteInstalled { .. }) => {
                    setup_state.set_route_installed(true);
                }
                Ok(Event::MachineStopped { .. }) => {
                    setup_state.set_route_installed(false);
                }
                Ok(_) => {}
                // Missed events under load; state converges on the next
                // route-install or stop event.
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
        }
    }
}

#[cfg(target_os = "macos")]
async fn container_route_guard(
    runtime: Arc<Runtime>,
    setup_state: Arc<arcbox_api::SetupState>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    use arcbox_core::route_reconciler::RouteMode;

    let mut ticker = tokio::time::interval(ROUTE_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut watcher = open_route_watcher();
    let mut active: Option<(String, RouteMode)> = None;
    let mut consecutive_failures = 0u32;

    loop {
        let route_event = tokio::select! {
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => false,
            event = next_managed_route_event(watcher.as_ref()) => {
                match event {
                    Ok(()) => true,
                    Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                        tracing::debug!(
                            "route event queue overflowed; reconciling current state"
                        );
                        true
                    }
                    Err(error) => {
                        tracing::warn!(%error, "route event watcher failed; polling remains active");
                        watcher = None;
                        false
                    }
                }
            }
        };

        if route_event {
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(ROUTE_EVENT_DEBOUNCE) => {}
            }
            if let Some(watcher) = watcher.as_ref() {
                drain_route_events(watcher);
            }
        } else if watcher.is_none() {
            watcher = open_route_watcher();
        }

        let runtime_for_bridge = Arc::clone(&runtime);
        let bridge = match tokio::task::spawn_blocking(move || {
            resolve_container_bridge(&runtime_for_bridge)
        })
        .await
        {
            Ok(bridge) => bridge,
            Err(error) => {
                tracing::warn!(%error, "container bridge resolution task failed");
                None
            }
        };
        let Some(bridge) = bridge else {
            active = None;
            setup_state.set_route_installed(false);
            consecutive_failures = 0;
            continue;
        };

        let current_mode = active
            .as_ref()
            .filter(|(active_bridge, _)| active_bridge == &bridge)
            .map(|(_, mode)| *mode);
        let result = match current_mode {
            Some(mode) => {
                arcbox_core::route_reconciler::reconcile_route_for_bridge(&bridge, mode).await
            }
            None => arcbox_core::route_reconciler::initialize_route_for_bridge(&bridge).await,
        };

        match result {
            Ok(mode) => {
                let was_installed = setup_state.current().route_installed;
                active = Some((bridge, mode));
                setup_state.set_route_installed(true);
                consecutive_failures = 0;
                if !was_installed {
                    runtime.event_bus().publish(
                        arcbox_core::event::Event::ContainerRouteInstalled {
                            name: arcbox_core::DEFAULT_MACHINE_NAME.to_string(),
                        },
                    );
                }
            }
            Err(error) => {
                setup_state.set_route_installed(false);
                consecutive_failures = consecutive_failures.saturating_add(1);
                if should_log_route_failure(consecutive_failures) {
                    tracing::warn!(
                        %error,
                        %bridge,
                        consecutive_failures,
                        "container route reconciliation failed"
                    );
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn open_route_watcher() -> Option<tokio::io::unix::AsyncFd<arcbox_route::RouteWatcher>> {
    match arcbox_route::RouteWatcher::open().and_then(tokio::io::unix::AsyncFd::new) {
        Ok(watcher) => Some(watcher),
        Err(error) => {
            tracing::warn!(%error, "route event watcher unavailable; using polling");
            None
        }
    }
}

#[cfg(target_os = "macos")]
async fn next_managed_route_event(
    watcher: Option<&tokio::io::unix::AsyncFd<arcbox_route::RouteWatcher>>,
) -> std::io::Result<()> {
    let Some(watcher) = watcher else {
        return std::future::pending().await;
    };

    loop {
        let mut ready = watcher.readable().await?;
        match ready.try_io(|inner| inner.get_ref().read_event()) {
            Ok(Ok(Some(event))) if event.network.is_some_and(is_managed_route) => return Ok(()),
            Ok(Ok(_)) => {}
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
                tracing::debug!(%error, "ignored malformed route event");
            }
            Ok(Err(error)) => return Err(error),
            Err(_would_block) => {}
        }
    }
}

#[cfg(target_os = "macos")]
fn drain_route_events(watcher: &tokio::io::unix::AsyncFd<arcbox_route::RouteWatcher>) {
    for _ in 0..256 {
        match watcher.get_ref().read_event() {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "macos")]
fn is_managed_route(network: arcbox_route::Ipv4Net) -> bool {
    let network = network.to_string();
    network == arcbox_core::route_reconciler::CONTAINER_SUBNET
        || arcbox_core::route_reconciler::CONTAINER_SPLIT_SUBNETS
            .iter()
            .any(|candidate| network == *candidate)
}

#[cfg(all(target_os = "macos", feature = "vmnet"))]
fn resolve_container_bridge(runtime: &Runtime) -> Option<String> {
    let machine = runtime
        .machine_manager()
        .get(arcbox_core::DEFAULT_MACHINE_NAME)?;
    if !matches!(
        machine.state,
        arcbox_core::machine::MachineState::Starting | arcbox_core::machine::MachineState::Running
    ) {
        return None;
    }
    runtime
        .machine_manager()
        .vmnet_bridge_name(arcbox_core::DEFAULT_MACHINE_NAME)
}

#[cfg(all(target_os = "macos", not(feature = "vmnet")))]
fn resolve_container_bridge(runtime: &Runtime) -> Option<String> {
    let machine = runtime
        .machine_manager()
        .get(arcbox_core::DEFAULT_MACHINE_NAME)?;
    if !matches!(
        machine.state,
        arcbox_core::machine::MachineState::Starting | arcbox_core::machine::MachineState::Running
    ) {
        return None;
    }
    let mac = runtime
        .machine_manager()
        .bridge_mac(arcbox_core::DEFAULT_MACHINE_NAME)?;
    arcbox_core::bridge_discovery::resolve_bridge_by_mac(&mac).map(|bridge| bridge.name)
}

#[cfg(target_os = "macos")]
fn should_log_route_failure(consecutive_failures: u32) -> bool {
    consecutive_failures == 1 || consecutive_failures.is_multiple_of(30)
}

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use arcbox_api::SetupState;
    use arcbox_core::event::{Event, EventBus};

    use super::*;

    /// Polls until `route_installed` matches `want` or times out.
    async fn wait_for_route_installed(state: &SetupState, want: bool) -> bool {
        for _ in 0..200 {
            if state.current().route_installed == want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    #[tokio::test]
    async fn route_status_loop_mirrors_events_into_setup_state() {
        let bus = EventBus::new();
        let setup_state = Arc::new(SetupState::new());
        let shutdown = tokio_util::sync::CancellationToken::new();

        let task = tokio::spawn(route_status_loop(
            bus.subscribe(),
            Arc::clone(&setup_state),
            shutdown.clone(),
        ));

        assert!(!setup_state.current().route_installed);

        bus.publish(Event::ContainerRouteInstalled {
            name: "default".into(),
        });
        assert!(wait_for_route_installed(&setup_state, true).await);

        // Unrelated events leave the flag untouched.
        bus.publish(Event::MachineIdle {
            name: "default".into(),
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(setup_state.current().route_installed);

        // The bridge dies with the VM, so MachineStopped clears the flag.
        bus.publish(Event::MachineStopped {
            name: "default".into(),
        });
        assert!(wait_for_route_installed(&setup_state, false).await);

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("loop exits on shutdown")
            .expect("loop task panicked");
    }
}
