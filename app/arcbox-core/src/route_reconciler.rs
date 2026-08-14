//! Route lifecycle management for L3 direct routing (macOS).
//!
//! The daemon owns all route intelligence:
//! - Bridge discovery via `ifbridge` (kernel FDB, no text parsing)
//! - Route state decisions (add, replace, remove)
//!
//! `arcbox-helper` is a pure mutation executor — the daemon tells it
//! exactly which interface to add/remove a route for via tarpc RPC.

use std::time::Duration;

use arcbox_constants::container_network::ContainerNetwork;
use arcbox_helper::client::{Client, ClientError};
use arcbox_helper::error::HelperError;
use arcbox_route::{Ipv4Net, RouteEntry, RouteInfo};

use crate::bridge_discovery;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerRoutes {
    network: ContainerNetwork,
    preferred: Ipv4Net,
    split: [Ipv4Net; 2],
}

impl From<ContainerNetwork> for ContainerRoutes {
    fn from(network: ContainerNetwork) -> Self {
        let preferred = Ipv4Net::new(network.addr(), network.prefix())
            .expect("ContainerNetwork is always a valid Ipv4Net");
        let split_prefix = network.prefix() + 1;
        let upper_addr =
            std::net::Ipv4Addr::from(u32::from(network.addr()) + (1_u32 << (32 - split_prefix)));
        Self {
            network,
            preferred,
            split: [
                Ipv4Net::new(network.addr(), split_prefix)
                    .expect("the lower half of a ContainerNetwork is always valid"),
                Ipv4Net::new(upper_addr, split_prefix)
                    .expect("the upper half of a ContainerNetwork is always valid"),
            ],
        }
    }
}

/// Maximum retry attempts for transient route installation failures.
const MAX_ROUTE_ATTEMPTS: u32 = 5;

/// Delay between retry attempts.
const ROUTE_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Errors from route installation.
///
/// All variants are retryable — the caller decides whether to retry via
/// [`ensure_route_with_retry_for_network`].
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// Bridge MAC not found in kernel FDB. Retryable — the bridge/FDB may
    /// not have stabilized yet (VM just started, vmenet member not learned).
    #[error("bridge not found in kernel FDB")]
    BridgeNotReady,
    /// Helper daemon not reachable. Retryable.
    #[error("helper unavailable: {0}")]
    HelperUnavailable(String),
    /// The routing API returned an unexpected error. Retryable.
    #[error("route operation failed: {0}")]
    RouteFailed(String),
    /// A more-specific fallback route is already owned by another service.
    #[error("route {subnet} is owned by another network service")]
    RouteConflict {
        /// Exact subnet ArcBox left untouched.
        subnet: String,
    },
    /// A custom container pool overlaps a route owned outside this instance.
    #[error("container network {network} overlaps external route {route}")]
    RouteOverlap {
        /// Container pool requested by this instance.
        network: ContainerNetwork,
        /// Existing route that overlaps the container pool.
        route: Ipv4Net,
    },
}

impl From<ClientError> for RouteError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Connection(_)
            | ClientError::Rpc(_)
            | ClientError::UnrecognizedVersion(_)
            | ClientError::IncompatibleVersion { .. } => Self::HelperUnavailable(e.to_string()),
            ClientError::Helper(err) => Self::RouteFailed(err.to_string()),
        }
    }
}

fn route_matches_bridge(route: Option<&RouteInfo>, bridge_ifindex: u16) -> bool {
    matches!(
        route,
        Some(route)
            if route.ifindex == bridge_ifindex && route.flags & libc::RTF_GATEWAY == 0
    )
}

/// Container route shape maintained for the current VM lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    /// One exact route for the complete container pool.
    Preferred,
    /// Two equal child routes, leaving an external preferred route untouched.
    SplitFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactRouteState {
    Missing,
    Owned,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteSnapshot {
    preferred: ExactRouteState,
    split: [ExactRouteState; 2],
}

impl RouteSnapshot {
    fn initial_mode(self) -> RouteMode {
        if self
            .split
            .iter()
            .all(|state| *state == ExactRouteState::Owned)
        {
            RouteMode::SplitFallback
        } else if self.preferred == ExactRouteState::Owned {
            RouteMode::Preferred
        } else if self.preferred == ExactRouteState::External
            || self.split.contains(&ExactRouteState::Owned)
        {
            RouteMode::SplitFallback
        } else {
            RouteMode::Preferred
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileAction {
    Healthy(RouteMode),
    AddPreferred,
    EnsureSplit,
    Conflict(usize),
}

fn plan_reconciliation(mode: RouteMode, snapshot: RouteSnapshot) -> ReconcileAction {
    if let Some(index) = snapshot
        .split
        .iter()
        .position(|state| *state == ExactRouteState::External)
    {
        return ReconcileAction::Conflict(index);
    }
    if mode == RouteMode::SplitFallback {
        return if snapshot
            .split
            .iter()
            .all(|state| *state == ExactRouteState::Owned)
        {
            ReconcileAction::Healthy(RouteMode::SplitFallback)
        } else {
            ReconcileAction::EnsureSplit
        };
    }
    match snapshot.preferred {
        ExactRouteState::Owned => ReconcileAction::Healthy(RouteMode::Preferred),
        ExactRouteState::External => ReconcileAction::EnsureSplit,
        ExactRouteState::Missing => ReconcileAction::AddPreferred,
    }
}

fn isolated_preferred_route_conflicts(routes: ContainerRoutes, snapshot: RouteSnapshot) -> bool {
    routes.network != ContainerNetwork::default() && snapshot.preferred == ExactRouteState::External
}

fn classify_route(route: Option<&RouteInfo>, bridge_ifindex: u16) -> ExactRouteState {
    match route {
        None => ExactRouteState::Missing,
        Some(route) if route_matches_bridge(Some(route), bridge_ifindex) => ExactRouteState::Owned,
        Some(_) => ExactRouteState::External,
    }
}

fn external_overlap(
    entries: &[RouteEntry],
    preferred: Ipv4Net,
    managed: [Ipv4Net; 3],
    bridge_ifindex: u16,
) -> Option<Ipv4Net> {
    entries.iter().find_map(|entry| {
        if !entry.network.overlaps(preferred)
            || managed.contains(&entry.network)
                && route_matches_bridge(Some(&entry.info), bridge_ifindex)
        {
            None
        } else {
            Some(entry.network)
        }
    })
}

fn inspect_routes_sync(
    bridge_name: &str,
    routes: ContainerRoutes,
) -> Result<RouteSnapshot, RouteError> {
    let bridge_ifindex =
        arcbox_route::interface_index(bridge_name).map_err(|_| RouteError::BridgeNotReady)?;
    let preferred = routes.preferred;
    let split = routes.split;
    if routes.network != ContainerNetwork::default() {
        let entries = arcbox_route::overlapping(preferred).map_err(RouteError::RouteFailed)?;
        if let Some(route) = external_overlap(
            &entries,
            preferred,
            [preferred, split[0], split[1]],
            bridge_ifindex,
        ) {
            return Err(RouteError::RouteOverlap {
                network: routes.network,
                route,
            });
        }
    }
    let query = |network| {
        arcbox_route::get(network)
            .map(|route| classify_route(route.as_ref(), bridge_ifindex))
            .map_err(RouteError::RouteFailed)
    };
    Ok(RouteSnapshot {
        preferred: query(preferred)?,
        split: [query(split[0])?, query(split[1])?],
    })
}

async fn inspect_routes(
    bridge_name: &str,
    routes: ContainerRoutes,
) -> Result<RouteSnapshot, RouteError> {
    let bridge_name = bridge_name.to_string();
    tokio::task::spawn_blocking(move || inspect_routes_sync(&bridge_name, routes))
        .await
        .map_err(|error| RouteError::RouteFailed(format!("route check task failed: {error}")))?
}

async fn add_route(
    client: &Client,
    subnet: Ipv4Net,
    bridge_name: &str,
) -> Result<bool, RouteError> {
    let subnet = subnet.to_string();
    match client.route_add(&subnet, bridge_name).await {
        Ok(()) => Ok(true),
        Err(ClientError::Helper(HelperError::RouteConflict { .. })) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn ensure_split_routes(
    bridge_name: &str,
    routes: ContainerRoutes,
    mut snapshot: RouteSnapshot,
) -> Result<(), RouteError> {
    if let Some(index) = snapshot
        .split
        .iter()
        .position(|state| *state == ExactRouteState::External)
    {
        return Err(RouteError::RouteConflict {
            subnet: routes.split[index].to_string(),
        });
    }
    if snapshot
        .split
        .iter()
        .all(|state| *state == ExactRouteState::Owned)
    {
        return Ok(());
    }

    let client = Client::connect().await?;
    for (index, subnet) in routes.split.into_iter().enumerate() {
        if snapshot.split[index] == ExactRouteState::Owned {
            continue;
        }
        if add_route(&client, subnet, bridge_name).await? {
            snapshot.split[index] = ExactRouteState::Owned;
            continue;
        }

        snapshot = inspect_routes(bridge_name, routes).await?;
        if snapshot.split[index] != ExactRouteState::Owned {
            return Err(RouteError::RouteConflict {
                subnet: subnet.to_string(),
            });
        }
    }
    Ok(())
}

async fn reconcile_with_snapshot(
    bridge_name: &str,
    routes: ContainerRoutes,
    mode: RouteMode,
    mut snapshot: RouteSnapshot,
) -> Result<RouteMode, RouteError> {
    if isolated_preferred_route_conflicts(routes, snapshot) {
        return Err(RouteError::RouteConflict {
            subnet: routes.preferred.to_string(),
        });
    }
    match plan_reconciliation(mode, snapshot) {
        ReconcileAction::Healthy(mode) => return Ok(mode),
        ReconcileAction::Conflict(index) => {
            return Err(RouteError::RouteConflict {
                subnet: routes.split[index].to_string(),
            });
        }
        ReconcileAction::EnsureSplit => {}
        ReconcileAction::AddPreferred => {
            let client = Client::connect().await?;
            if add_route(&client, routes.preferred, bridge_name).await? {
                if routes.network != ContainerNetwork::default() {
                    // Close the useful part of the check/add race. Route changes
                    // after this point are caught by the daemon route watcher.
                    inspect_routes(bridge_name, routes).await?;
                }
                return Ok(RouteMode::Preferred);
            }
            // Another service won the add race. Re-query before deciding: an
            // ArcBox route added by a concurrent reconciler is already good.
            snapshot = inspect_routes(bridge_name, routes).await?;
            if snapshot.preferred == ExactRouteState::Owned {
                return Ok(RouteMode::Preferred);
            }
            if isolated_preferred_route_conflicts(routes, snapshot) {
                return Err(RouteError::RouteConflict {
                    subnet: routes.preferred.to_string(),
                });
            }
        }
    }

    ensure_split_routes(bridge_name, routes, snapshot).await?;
    tracing::info!(
        preferred = %routes.preferred,
        lower = %routes.split[0],
        upper = %routes.split[1],
        bridge = bridge_name,
        "external container route detected; switched to sticky split fallback"
    );
    Ok(RouteMode::SplitFallback)
}

/// Reconciles the container routes while preserving a sticky lifecycle mode.
pub async fn reconcile_route_for_bridge_with_network(
    bridge_name: &str,
    network: ContainerNetwork,
    mode: RouteMode,
) -> Result<RouteMode, RouteError> {
    let routes = ContainerRoutes::from(network);
    let snapshot = inspect_routes(bridge_name, routes).await?;
    reconcile_with_snapshot(bridge_name, routes, mode, snapshot).await
}

/// Detects the route shape left by this VM lifecycle and reconciles it.
pub async fn initialize_route_for_bridge_with_network(
    bridge_name: &str,
    network: ContainerNetwork,
) -> Result<RouteMode, RouteError> {
    let routes = ContainerRoutes::from(network);
    let snapshot = inspect_routes(bridge_name, routes).await?;
    reconcile_with_snapshot(bridge_name, routes, snapshot.initial_mode(), snapshot).await
}

/// Performs one route installation attempt through a known bridge interface.
///
/// Callers that need retries own the retry cadence. Keeping this operation
/// single-shot prevents a continuous route guard from blocking inside a nested
/// retry loop when another network service replaces the route.
pub async fn repair_route_for_bridge_with_network(
    bridge_name: &str,
    network: ContainerNetwork,
) -> Result<(), RouteError> {
    initialize_route_for_bridge_with_network(bridge_name, network)
        .await
        .map(|_| ())
}

/// Ensures the container subnet route points to the correct bridge.
///
/// 1. Resolves bridge MAC → bridge interface via kernel FDB (`ifbridge`)
/// 2. Calls helper via tarpc to add the route
///
/// Called on: VM ready, VM recovery, daemon cold-start reconcile.
async fn ensure_route(bridge_mac: &str, network: ContainerNetwork) -> Result<(), RouteError> {
    // Step 1: Resolve MAC → bridge via kernel FDB (typed API, no text parsing).
    let mac = bridge_mac.to_string();
    let bridge = tokio::task::spawn_blocking(move || bridge_discovery::resolve_bridge_by_mac(&mac))
        .await
        .unwrap_or(None)
        .ok_or(RouteError::BridgeNotReady)?;

    // Step 2: Tell helper to add the route.
    repair_route_for_bridge_with_network(&bridge.name, network).await?;

    tracing::info!(
        bridge = %bridge.name,
        %bridge_mac,
        "container route ensured"
    );
    Ok(())
}

/// Ensures the selected container address-pool route with transient retries.
///
/// All [`RouteError`] variants are treated as retryable. Retries up to 5 times
/// with 2-second intervals (~10s total). This covers:
/// - Bridge FDB not yet populated after VM start (~1-2s to learn MAC)
/// - Helper daemon not yet started by launchd (first connection)
pub async fn ensure_route_with_retry_for_network(
    bridge_mac: &str,
    network: ContainerNetwork,
) -> Result<(), RouteError> {
    for attempt in 1..=MAX_ROUTE_ATTEMPTS {
        match ensure_route(bridge_mac, network).await {
            Ok(()) => return Ok(()),
            Err(ref e) if attempt < MAX_ROUTE_ATTEMPTS => {
                tracing::debug!(
                    attempt,
                    max_attempts = MAX_ROUTE_ATTEMPTS,
                    error = %e,
                    "route install failed, retrying"
                );
                tokio::time::sleep(ROUTE_RETRY_INTERVAL).await;
            }
            Err(e) => {
                tracing::warn!(
                    attempt,
                    error = %e,
                    "route install failed after all attempts"
                );
                return Err(e);
            }
        }
    }
    unreachable!()
}

/// Ensures the selected container address-pool route through a known bridge.
///
/// When vmnet.framework creates the bridge, we know the interface immediately —
/// no need to scan the kernel FDB. Only retries for helper readiness.
#[cfg(all(feature = "vmnet", target_os = "macos"))]
pub async fn ensure_route_for_bridge_with_network(
    bridge_name: &str,
    network: ContainerNetwork,
) -> Result<(), RouteError> {
    for attempt in 1..=2 {
        match repair_route_for_bridge_with_network(bridge_name, network).await {
            Ok(()) => {
                tracing::info!(
                    bridge = bridge_name,
                    "container route ensured (vmnet direct)"
                );
                return Ok(());
            }
            Err(ref e) if attempt < 2 => {
                tracing::debug!(attempt, error = %e, "vmnet route install retry");
                tokio::time::sleep(ROUTE_RETRY_INTERVAL).await;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Builds the composer-side route hook for a machine's lifecycle.
///
/// The lifecycle engine fires it after the VM starts; it resolves the
/// bridge (vmnet interface name, or a kernel-FDB scan by MAC) and installs
/// the container-subnet route, publishing `ContainerRouteInstalled` on
/// success. Non-blocking: route failures never gate VM readiness.
///
/// `machine_name` is keyed to whichever lifecycle installs the hook — today
/// that is always the System VM (`Runtime::new` passes
/// [`crate::vm_lifecycle::DEFAULT_MACHINE_NAME`]), but a future per-role
/// lifecycle built via `VmLifecycleManager::for_machine` must pass its own
/// name so bridge lookup and the published event stay keyed on the right
/// machine.
pub fn system_vm_route_hook(
    machine_manager: &std::sync::Arc<crate::machine::MachineManager>,
    event_bus: &crate::event::EventBus,
    machine_name: &str,
) -> crate::vm_lifecycle::RouteHook {
    let mm = std::sync::Arc::clone(machine_manager);
    let bus = event_bus.clone();
    let machine_name = machine_name.to_string();
    let network = ContainerNetwork::default();
    crate::vm_lifecycle::RouteHook::new(std::sync::Arc::new(move || {
        #[cfg(feature = "vmnet")]
        {
            // vmnet path: bridge name is known instantly, only need
            // helper retry (1-2 attempts for XPC readiness).
            use crate::bridge_discovery::MachineBridgeExt as _;
            if let Some(bridge) = mm.vmnet_bridge_name(&machine_name) {
                let bus = bus.clone();
                let name = machine_name.clone();
                drop(tokio::spawn(async move {
                    match ensure_route_for_bridge_with_network(&bridge, network).await {
                        Ok(()) => {
                            bus.publish(crate::event::Event::ContainerRouteInstalled { name });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to install container route (vmnet)");
                        }
                    }
                }));
            }
        }
        #[cfg(not(feature = "vmnet"))]
        {
            // Discover the bridge by scanning the kernel FDB (retries up
            // to ~10s for FDB learning).
            if let Some(mac) = mm.bridge_mac(&machine_name) {
                let bus = bus.clone();
                let name = machine_name.clone();
                drop(tokio::spawn(async move {
                    match ensure_route_with_retry_for_network(&mac, network).await {
                        Ok(()) => {
                            bus.publish(crate::event::Event::ContainerRouteInstalled { name });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to install container route");
                        }
                    }
                }));
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_interface_route_matches() {
        let route = RouteInfo {
            ifindex: 26,
            flags: libc::RTF_UP | libc::RTF_STATIC,
        };

        assert!(route_matches_bridge(Some(&route), 26));
    }

    #[test]
    fn gateway_route_on_expected_interface_does_not_match() {
        let route = RouteInfo {
            ifindex: 26,
            flags: libc::RTF_UP | libc::RTF_STATIC | libc::RTF_GATEWAY,
        };

        assert!(!route_matches_bridge(Some(&route), 26));
    }

    #[test]
    fn absent_or_wrong_interface_route_does_not_match() {
        let route = RouteInfo {
            ifindex: 7,
            flags: libc::RTF_UP | libc::RTF_STATIC,
        };

        assert!(!route_matches_bridge(None, 26));
        assert!(!route_matches_bridge(Some(&route), 26));
    }

    #[test]
    fn external_preferred_route_selects_split_fallback() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::External,
            split: [ExactRouteState::Missing; 2],
        };

        assert_eq!(snapshot.initial_mode(), RouteMode::SplitFallback);
    }

    #[test]
    fn complete_split_routes_restore_sticky_mode_after_restart() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::Missing,
            split: [ExactRouteState::Owned; 2],
        };

        assert_eq!(snapshot.initial_mode(), RouteMode::SplitFallback);
    }

    #[test]
    fn owned_preferred_route_is_selected_without_split_evidence() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::Owned,
            split: [ExactRouteState::Missing; 2],
        };

        assert_eq!(snapshot.initial_mode(), RouteMode::Preferred);
    }

    #[test]
    fn healthy_preferred_mode_is_a_noop() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::Owned,
            split: [ExactRouteState::Missing; 2],
        };

        assert_eq!(
            plan_reconciliation(RouteMode::Preferred, snapshot),
            ReconcileAction::Healthy(RouteMode::Preferred)
        );
    }

    #[test]
    fn external_preferred_route_plans_split_fallback() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::External,
            split: [ExactRouteState::Missing; 2],
        };

        assert_eq!(
            plan_reconciliation(RouteMode::Preferred, snapshot),
            ReconcileAction::EnsureSplit
        );
    }

    #[test]
    fn isolated_pool_never_steals_an_external_preferred_route() {
        let routes = ContainerRoutes::from("10.64.32.0/20".parse::<ContainerNetwork>().unwrap());
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::External,
            split: [ExactRouteState::Missing; 2],
        };

        assert!(isolated_preferred_route_conflicts(routes, snapshot));
        assert!(!isolated_preferred_route_conflicts(
            ContainerRoutes::from(ContainerNetwork::default()),
            snapshot
        ));
    }

    #[test]
    fn smallest_pool_derives_valid_route_halves() {
        let routes = ContainerRoutes::from("192.168.100.0/24".parse::<ContainerNetwork>().unwrap());

        assert_eq!(routes.split[0], "192.168.100.0/25".parse().unwrap());
        assert_eq!(routes.split[1], "192.168.100.128/25".parse().unwrap());
    }

    #[test]
    fn isolated_pool_rejects_covering_and_contained_external_routes() {
        let routes = ContainerRoutes::from("10.64.32.0/20".parse::<ContainerNetwork>().unwrap());
        let preferred = routes.preferred;
        let managed = [preferred, routes.split[0], routes.split[1]];
        let owned = RouteInfo {
            ifindex: 26,
            flags: libc::RTF_UP | libc::RTF_STATIC,
        };
        let external = RouteInfo {
            ifindex: 7,
            flags: libc::RTF_UP | libc::RTF_GATEWAY,
        };

        assert_eq!(
            external_overlap(
                &[RouteEntry {
                    network: "10.64.0.0/16".parse().unwrap(),
                    info: external,
                }],
                preferred,
                managed,
                26,
            ),
            Some("10.64.0.0/16".parse().unwrap())
        );
        assert_eq!(
            external_overlap(
                &[RouteEntry {
                    network: "10.64.35.0/24".parse().unwrap(),
                    info: external,
                }],
                preferred,
                managed,
                26,
            ),
            Some("10.64.35.0/24".parse().unwrap())
        );
        assert_eq!(
            external_overlap(
                &[
                    RouteEntry {
                        network: managed[0],
                        info: owned,
                    },
                    RouteEntry {
                        network: managed[1],
                        info: owned,
                    },
                    RouteEntry {
                        network: "10.64.48.0/20".parse().unwrap(),
                        info: external,
                    },
                ],
                preferred,
                managed,
                26,
            ),
            None
        );
    }

    #[test]
    fn split_mode_never_reverts_to_preferred() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::Missing,
            split: [ExactRouteState::Owned; 2],
        };

        assert_eq!(
            plan_reconciliation(RouteMode::SplitFallback, snapshot),
            ReconcileAction::Healthy(RouteMode::SplitFallback)
        );
    }

    #[test]
    fn external_split_route_is_never_replaced() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::External,
            split: [ExactRouteState::Owned, ExactRouteState::External],
        };

        assert_eq!(
            plan_reconciliation(RouteMode::SplitFallback, snapshot),
            ReconcileAction::Conflict(1)
        );
    }
}
