//! Service startup: DNS, Docker API, gRPC servers.
//!
//! gRPC is started once with all services. Machine/Sandbox/Snapshot services
//! use `SharedRuntime` (backed by `OnceLock`) and return `UNAVAILABLE` until
//! `init_runtime()` fills it. This avoids restarting the gRPC server mid-boot.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::{SharedRuntime, SystemServiceImpl};
#[cfg(target_os = "macos")]
use arcbox_constants::container_network::ContainerNetwork;
use arcbox_constants::ports::KUBERNETES_API_HOST_PORT;
use arcbox_core::{Runtime, VmLifecycleState};
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use tokio::sync::watch;
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

/// Starts DNS, Docker API, and Kubernetes services.
///
/// Called after `init_runtime()` — the runtime must be available.
pub async fn start_services(
    ctx: &DaemonContext,
    runtime: &Arc<Runtime>,
    grpc: tokio::task::JoinHandle<()>,
) -> Result<ServiceHandles> {
    let linux_vm = runtime.config().vm.autostart;

    // A custom instance pool must be routable before any API reports ready.
    // Production keeps its existing best-effort recovery semantics.
    #[cfg(target_os = "macos")]
    if linux_vm {
        ensure_isolated_container_route(
            runtime,
            &ctx.setup_state,
            &ctx.container_network_lease_slot,
        )
        .await?;
    }

    // DNS service.
    let dns_service = DnsService::bind(Arc::clone(runtime.network_manager()), ctx.dns_port)
        .await
        .context("Failed to start DNS service")?;
    let dns_port = dns_service.host_port()?;

    // VM-host-only mode: the Docker API, Docker CLI integration, and the
    // Kubernetes proxy all depend on the Linux VM, so they are skipped when it
    // is not booted.
    // Bind every promised endpoint before publishing the Runtime or spawning a
    // server task. A failure then leaves no partially-ready control plane, and
    // an ephemeral port can be recorded from the socket that actually owns it.
    let docker_service = if linux_vm {
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
        Some((docker_server, listener))
    } else {
        None
    };

    let kubernetes_proxy = if linux_vm {
        let port = ctx.kubernetes_port.unwrap_or(KUBERNETES_API_HOST_PORT);
        match crate::kubernetes_proxy::KubernetesProxy::bind(port).await {
            Ok(proxy) => {
                runtime.set_kubernetes_host_endpoint(
                    proxy.host_port(),
                    ctx.kubernetes_context.clone(),
                )?;
                Some(proxy)
            }
            Err(error) if ctx.kubernetes_port.is_some() => {
                return Err(error).context("Failed to start Kubernetes API proxy");
            }
            Err(error) => {
                tracing::warn!(%error, "Kubernetes API proxy unavailable");
                None
            }
        }
    } else {
        None
    };

    // Normal RPCs become available only after their advertised listeners are
    // bound. Kubernetes RPCs remain unavailable when its best-effort default
    // listener could not bind; an explicit listener is required to succeed.
    ctx.shared_runtime
        .set(Arc::clone(runtime))
        .map_err(|_| anyhow::anyhow!("start_services called twice"))?;

    register_host_dns(runtime).await;

    let dns_shutdown = ctx.shutdown.clone();
    let dns = tokio::spawn(async move {
        if let Err(e) = dns_service.run(dns_shutdown).await {
            tracing::error!("DNS service error: {}", e);
        }
    });

    let docker = docker_service.map(|(docker_server, listener)| {
        let docker_shutdown = ctx.shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = docker_server.serve(listener, docker_shutdown).await {
                tracing::error!("Docker API server error: {}", e);
            }
        })
    });

    let kubernetes_proxy = kubernetes_proxy.map(|proxy| proxy.start(Arc::clone(runtime)));

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
        let container_network_lease = Arc::clone(&ctx.container_network_lease_slot);
        tokio::spawn(async move {
            container_route_guard(runtime, setup_state, shutdown, container_network_lease).await;
        })
    });
    #[cfg(not(target_os = "macos"))]
    let route_guard = None;

    Ok(ServiceHandles {
        dns,
        dns_port,
        docker,
        grpc,
        kubernetes_proxy,
        route_guard,
    })
}

/// Enables the production Docker context after critical recovery succeeds.
pub fn enable_docker_integration(ctx: &DaemonContext) {
    if ctx.docker_integration {
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

/// Mirrors VM lifecycle events into `SetupState.route_installed`.
///
/// `ContainerRouteInstalled` sets the flag; `MachineStopped` clears it.
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
    container_network_lease: crate::context::SharedContainerNetworkLease,
) {
    use arcbox_core::route_reconciler::RouteMode;

    let container_network = runtime.config().container.cidr;
    let mut ticker = tokio::time::interval(ROUTE_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut watcher = open_route_watcher();
    let mut active: Option<(String, RouteMode)> = None;
    let mut consecutive_failures = 0u32;

    loop {
        let route_event = tokio::select! {
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => false,
            event = next_managed_route_event(watcher.as_ref(), container_network) => {
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
            if active.take().is_some()
                && let Some(lease) = container_network_lease.get()
                && let Err(error) = lease.cleanup_route().await
            {
                tracing::warn!(%error, "failed to remove stopped VM container route");
            }
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
                arcbox_core::route_reconciler::reconcile_route_for_bridge_with_network(
                    &bridge,
                    container_network,
                    mode,
                )
                .await
            }
            None => {
                arcbox_core::route_reconciler::initialize_route_for_bridge_with_network(
                    &bridge,
                    container_network,
                )
                .await
            }
        };

        match result {
            Ok(mode) => {
                if let Some(lease) = container_network_lease.get()
                    && let Err(error) = lease.record_route(bridge.clone())
                {
                    setup_state.set_failed(&format!("failed to record container route: {error}"));
                    shutdown.cancel();
                    break;
                }
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
            Err(error) if is_route_ownership_conflict(&error) => {
                if let Some(lease) = container_network_lease.get()
                    && let Err(cleanup_error) = lease.cleanup_route().await
                {
                    tracing::warn!(%cleanup_error, "failed to remove conflicting container route");
                }
                setup_state.set_failed(&format!(
                    "container network {container_network} now conflicts with a host route: {error}"
                ));
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                shutdown.cancel();
                break;
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
fn is_route_ownership_conflict(error: &arcbox_core::route_reconciler::RouteError) -> bool {
    matches!(
        error,
        arcbox_core::route_reconciler::RouteError::RouteConflict { .. }
            | arcbox_core::route_reconciler::RouteError::RouteOverlap { .. }
    )
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
    container_network: ContainerNetwork,
) -> std::io::Result<()> {
    let Some(watcher) = watcher else {
        return std::future::pending().await;
    };

    loop {
        let mut ready = watcher.readable().await?;
        match ready.try_io(|inner| inner.get_ref().read_event()) {
            Ok(Ok(Some(event)))
                if event
                    .network
                    .is_some_and(|network| is_relevant_route(network, container_network)) =>
            {
                return Ok(());
            }
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
fn is_relevant_route(route: arcbox_route::Ipv4Net, container_network: ContainerNetwork) -> bool {
    let preferred =
        arcbox_route::Ipv4Net::new(container_network.addr(), container_network.prefix())
            .expect("ContainerNetwork is always a valid Ipv4Net");
    if container_network == ContainerNetwork::default() {
        return route == preferred
            || route.prefix() == preferred.prefix() + 1 && route.overlaps(preferred);
    }

    route.prefix() != 0 && route.overlaps(preferred)
}

#[cfg(target_os = "macos")]
async fn ensure_isolated_container_route(
    runtime: &Arc<Runtime>,
    setup_state: &Arc<arcbox_api::SetupState>,
    container_network_lease: &crate::context::SharedContainerNetworkLease,
) -> Result<()> {
    let container_network = runtime.config().container.cidr;
    if container_network == ContainerNetwork::default() {
        return Ok(());
    }

    let machine_manager = runtime.machine_manager();
    let machine_is_running = machine_manager
        .get(arcbox_core::DEFAULT_MACHINE_NAME)
        .is_some_and(|machine| {
            matches!(
                machine.state,
                arcbox_core::machine::MachineState::Starting
                    | arcbox_core::machine::MachineState::Running
            )
        });
    anyhow::ensure!(
        machine_is_running,
        "container bridge is not ready for {container_network}"
    );

    #[cfg(feature = "vmnet")]
    if let Some(bridge) = {
        use arcbox_core::bridge_discovery::MachineBridgeExt as _;
        machine_manager.vmnet_bridge_name(arcbox_core::DEFAULT_MACHINE_NAME)
    } {
        arcbox_core::route_reconciler::ensure_route_for_bridge_with_network(
            &bridge,
            container_network,
        )
        .await
        .with_context(|| {
            format!("failed to install isolated container route {container_network}")
        })?;
        container_network_lease
            .get()
            .context("isolated container network lease is missing")?
            .record_route(bridge)?;
        setup_state.set_route_installed(true);
        return Ok(());
    }

    let bridge_mac = machine_manager
        .bridge_mac(arcbox_core::DEFAULT_MACHINE_NAME)
        .with_context(|| format!("container bridge MAC is not ready for {container_network}"))?;
    arcbox_core::route_reconciler::ensure_route_with_retry_for_network(
        &bridge_mac,
        container_network,
    )
    .await
    .with_context(|| format!("failed to install isolated container route {container_network}"))?;
    let bridge = resolve_container_bridge(runtime)
        .with_context(|| format!("container bridge is not ready for {container_network}"))?;
    container_network_lease
        .get()
        .context("isolated container network lease is missing")?
        .record_route(bridge)?;
    setup_state.set_route_installed(true);
    Ok(())
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
    use arcbox_core::bridge_discovery::MachineBridgeExt as _;
    if let Some(bridge) = runtime
        .machine_manager()
        .vmnet_bridge_name(arcbox_core::DEFAULT_MACHINE_NAME)
    {
        return Some(bridge);
    }

    // The binary may include vmnet support while this signed daemon is using
    // VZ NAT (notably development builds without com.apple.vm.networking).
    let mac = runtime
        .machine_manager()
        .bridge_mac(arcbox_core::DEFAULT_MACHINE_NAME)?;
    arcbox_core::bridge_discovery::resolve_bridge_by_mac(&mac).map(|bridge| bridge.name)
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

    use arcbox_api::SetupState;
    use arcbox_core::event::{Event, EventBus};

    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn route_event_filter_tracks_all_instance_network_overlaps() {
        let network: ContainerNetwork = "10.64.32.0/20".parse().unwrap();
        let preferred = arcbox_route::Ipv4Net::new(network.addr(), network.prefix()).unwrap();
        let covering: arcbox_route::Ipv4Net = "10.64.0.0/16".parse().unwrap();
        let contained: arcbox_route::Ipv4Net = "10.64.35.0/24".parse().unwrap();
        let default: arcbox_route::Ipv4Net = "0.0.0.0/0".parse().unwrap();
        let other: arcbox_route::Ipv4Net = "10.64.64.0/20".parse().unwrap();

        assert!(is_relevant_route(preferred, network));
        assert!(is_relevant_route(covering, network));
        assert!(is_relevant_route(contained, network));
        assert!(!is_relevant_route(default, network));
        assert!(!is_relevant_route(other, network));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn every_route_ownership_conflict_is_fatal() {
        use arcbox_core::route_reconciler::RouteError;

        assert!(is_route_ownership_conflict(&RouteError::RouteConflict {
            subnet: "10.64.32.0/20".into(),
        }));
        assert!(is_route_ownership_conflict(&RouteError::RouteOverlap {
            network: "10.64.32.0/20".parse().unwrap(),
            route: "10.64.0.0/16".parse().unwrap(),
        }));
        assert!(!is_route_ownership_conflict(&RouteError::BridgeNotReady));
    }

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

        // A stopped VM cannot own a usable container route.
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
