//! Route lifecycle management for L3 direct routing (macOS).
//!
//! The daemon owns all route intelligence:
//! - Bridge discovery via `ifbridge` (kernel FDB, no text parsing)
//! - Route state decisions (add, replace, remove)
//!
//! `arcbox-helper` is a pure mutation executor — the daemon tells it
//! exactly which interface to add/remove a route for via tarpc RPC.

use arcbox_helper::client::{Client, ClientError};
use arcbox_helper::error::HelperError;
use arcbox_route::{Ipv4Net, RouteInfo};

use crate::bridge_discovery::BridgeTarget;

/// Preferred route covering the complete container address range.
pub const CONTAINER_SUBNET: &str = "172.16.0.0/12";

/// More-specific routes used when another network service owns the exact `/12`.
pub const CONTAINER_SPLIT_SUBNETS: [&str; 2] = ["172.16.0.0/13", "172.24.0.0/13"];

/// Errors from route installation.
///
/// All variants are retryable — the route controller owns the retry cadence.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// The expected bridge identity is not currently available.
    #[error("bridge identity is not ready")]
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
}

impl From<ClientError> for RouteError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Connection(_)
            | ClientError::Rpc(_)
            | ClientError::UnrecognizedVersion(_)
            | ClientError::IncompatibleVersion { .. } => Self::HelperUnavailable(e.to_string()),
            ClientError::Helper(HelperError::RouteInterfaceChanged { .. }) => Self::BridgeNotReady,
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
    /// One exact `/12` interface route through the ArcBox bridge.
    Preferred,
    /// Two more-specific `/13` routes, leaving an external `/12` untouched.
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
    fn is_healthy(self) -> bool {
        (self.preferred == ExactRouteState::Owned
            && !self.split.contains(&ExactRouteState::External))
            || self
                .split
                .iter()
                .all(|state| *state == ExactRouteState::Owned)
    }

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
    Conflict(&'static str),
}

fn plan_reconciliation(mode: RouteMode, snapshot: RouteSnapshot) -> ReconcileAction {
    if let Some(index) = snapshot
        .split
        .iter()
        .position(|state| *state == ExactRouteState::External)
    {
        return ReconcileAction::Conflict(CONTAINER_SPLIT_SUBNETS[index]);
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

fn parse_network(value: &str) -> Result<Ipv4Net, RouteError> {
    value.parse().map_err(|error| {
        RouteError::RouteFailed(format!("invalid container network {value}: {error}"))
    })
}

fn classify_route(route: Option<&RouteInfo>, bridge_ifindex: u16) -> ExactRouteState {
    match route {
        None => ExactRouteState::Missing,
        Some(route) if route_matches_bridge(Some(route), bridge_ifindex) => ExactRouteState::Owned,
        Some(_) => ExactRouteState::External,
    }
}

fn inspect_routes_sync(
    bridge_name: &str,
    expected_ifindex: Option<u16>,
) -> Result<RouteSnapshot, RouteError> {
    let bridge_ifindex =
        arcbox_route::interface_index(bridge_name).map_err(|_| RouteError::BridgeNotReady)?;
    if expected_ifindex.is_some_and(|expected| expected != bridge_ifindex) {
        return Err(RouteError::BridgeNotReady);
    }
    let preferred = parse_network(CONTAINER_SUBNET)?;
    let split = [
        parse_network(CONTAINER_SPLIT_SUBNETS[0])?,
        parse_network(CONTAINER_SPLIT_SUBNETS[1])?,
    ];
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
    expected_ifindex: Option<u16>,
) -> Result<RouteSnapshot, RouteError> {
    let bridge_name = bridge_name.to_string();
    tokio::task::spawn_blocking(move || inspect_routes_sync(&bridge_name, expected_ifindex))
        .await
        .map_err(|error| RouteError::RouteFailed(format!("route check task failed: {error}")))?
}

async fn add_route(
    client: &Client,
    subnet: &str,
    target: &BridgeTarget,
) -> Result<bool, RouteError> {
    match client
        .route_add_for_interface(subnet, &target.name, target.ifindex)
        .await
    {
        Ok(()) => Ok(true),
        Err(ClientError::Helper(HelperError::RouteConflict { .. })) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

async fn ensure_split_routes(
    target: &BridgeTarget,
    mut snapshot: RouteSnapshot,
) -> Result<(), RouteError> {
    if let Some(index) = snapshot
        .split
        .iter()
        .position(|state| *state == ExactRouteState::External)
    {
        return Err(RouteError::RouteConflict {
            subnet: CONTAINER_SPLIT_SUBNETS[index].to_string(),
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
    for (index, subnet) in CONTAINER_SPLIT_SUBNETS.iter().enumerate() {
        if snapshot.split[index] == ExactRouteState::Owned {
            continue;
        }
        if add_route(&client, subnet, target).await? {
            snapshot.split[index] = ExactRouteState::Owned;
            continue;
        }

        snapshot = inspect_routes(&target.name, Some(target.ifindex)).await?;
        if snapshot.split[index] != ExactRouteState::Owned {
            return Err(RouteError::RouteConflict {
                subnet: (*subnet).to_string(),
            });
        }
    }
    Ok(())
}

async fn reconcile_with_snapshot(
    target: &BridgeTarget,
    mode: RouteMode,
    mut snapshot: RouteSnapshot,
) -> Result<RouteMode, RouteError> {
    match plan_reconciliation(mode, snapshot) {
        ReconcileAction::Healthy(mode) => return Ok(mode),
        ReconcileAction::Conflict(subnet) => {
            return Err(RouteError::RouteConflict {
                subnet: subnet.to_string(),
            });
        }
        ReconcileAction::EnsureSplit => {}
        ReconcileAction::AddPreferred => {
            let client = Client::connect().await?;
            if add_route(&client, CONTAINER_SUBNET, target).await? {
                return Ok(RouteMode::Preferred);
            }
            // Another service won the add race. Re-query before deciding: an
            // ArcBox route added by a concurrent reconciler is already good.
            snapshot = inspect_routes(&target.name, Some(target.ifindex)).await?;
            if snapshot.preferred == ExactRouteState::Owned {
                return Ok(RouteMode::Preferred);
            }
        }
    }

    ensure_split_routes(target, snapshot).await?;
    tracing::info!(
        preferred = CONTAINER_SUBNET,
        lower = CONTAINER_SPLIT_SUBNETS[0],
        upper = CONTAINER_SPLIT_SUBNETS[1],
        bridge = target.name,
        "external container route detected; switched to sticky split fallback"
    );
    Ok(RouteMode::SplitFallback)
}

/// Reconciles the container routes for a bridge identity while preserving its mode.
pub async fn reconcile_route_for_target(
    target: &BridgeTarget,
    mode: RouteMode,
) -> Result<RouteMode, RouteError> {
    let snapshot = inspect_routes(&target.name, Some(target.ifindex)).await?;
    reconcile_with_snapshot(target, mode, snapshot).await
}

/// Detects and reconciles the route shape for a newly attached bridge identity.
pub async fn initialize_route_for_target(target: &BridgeTarget) -> Result<RouteMode, RouteError> {
    let snapshot = inspect_routes(&target.name, Some(target.ifindex)).await?;
    reconcile_with_snapshot(target, snapshot.initial_mode(), snapshot).await
}

/// Returns the healthy route shape currently installed through `bridge_name`.
pub async fn container_route_mode(bridge_name: &str) -> Result<Option<RouteMode>, RouteError> {
    let snapshot = inspect_routes(bridge_name, None).await?;
    if !snapshot.is_healthy() {
        return Ok(None);
    }
    Ok(Some(snapshot.initial_mode()))
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
        assert!(!snapshot.is_healthy());
    }

    #[test]
    fn complete_split_routes_restore_sticky_mode_after_restart() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::Missing,
            split: [ExactRouteState::Owned; 2],
        };

        assert_eq!(snapshot.initial_mode(), RouteMode::SplitFallback);
        assert!(snapshot.is_healthy());
    }

    #[test]
    fn owned_preferred_route_is_selected_without_split_evidence() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::Owned,
            split: [ExactRouteState::Missing; 2],
        };

        assert_eq!(snapshot.initial_mode(), RouteMode::Preferred);
        assert!(snapshot.is_healthy());
    }

    #[test]
    fn external_more_specific_route_makes_preferred_shape_unhealthy() {
        let snapshot = RouteSnapshot {
            preferred: ExactRouteState::Owned,
            split: [ExactRouteState::External, ExactRouteState::Missing],
        };

        assert!(!snapshot.is_healthy());
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
            ReconcileAction::Conflict("172.24.0.0/13")
        );
    }
}
