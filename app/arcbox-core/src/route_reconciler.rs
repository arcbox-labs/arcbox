//! Route lifecycle management for L3 direct routing (macOS).
//!
//! The daemon owns all route intelligence:
//! - Bridge discovery via `ifbridge` (kernel FDB, no text parsing)
//! - Route state decisions (add, replace, remove)
//!
//! `arcbox-helper` is a pure mutation executor — the daemon tells it
//! exactly which interface to add/remove a route for via tarpc RPC.

use std::time::Duration;

use arcbox_helper::client::{Client, ClientError};

use crate::bridge_discovery;

/// Container subnet to route.
const CONTAINER_SUBNET: &str = "172.16.0.0/12";

/// Maximum retry attempts for transient route installation failures.
const MAX_ROUTE_ATTEMPTS: u32 = 5;

/// Delay between retry attempts.
const ROUTE_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Errors from route installation.
///
/// All variants are retryable — the caller decides whether to retry via
/// [`ensure_route_with_retry`].
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// Bridge MAC not found in kernel FDB. Retryable — the bridge/FDB may
    /// not have stabilized yet (VM just started, vmenet member not learned).
    #[error("bridge not found in kernel FDB")]
    BridgeNotReady,
    /// Helper daemon not reachable. Retryable.
    #[error("helper unavailable: {0}")]
    HelperUnavailable(String),
    /// `/sbin/route` returned an unexpected error. Retryable.
    #[error("route command failed: {0}")]
    RouteFailed(String),
}

impl From<ClientError> for RouteError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Connection(_) | ClientError::Rpc(_) => {
                Self::HelperUnavailable(e.to_string())
            }
            ClientError::Helper(err) => Self::RouteFailed(err.to_string()),
        }
    }
}

/// Ensures the container subnet route points to the correct bridge.
///
/// 1. Resolves bridge MAC → bridge interface via kernel FDB (`ifbridge`)
/// 2. Calls helper via tarpc to add the route
///
/// Called on: VM ready, VM recovery, daemon cold-start reconcile.
async fn ensure_route(bridge_mac: &str) -> Result<(), RouteError> {
    // Step 1: Resolve MAC → bridge via kernel FDB (typed API, no text parsing).
    let mac = bridge_mac.to_string();
    let bridge = tokio::task::spawn_blocking(move || bridge_discovery::resolve_bridge_by_mac(&mac))
        .await
        .unwrap_or(None)
        .ok_or(RouteError::BridgeNotReady)?;

    // Step 2: Tell helper to add the route.
    let client = Client::connect().await?;
    client.route_add(CONTAINER_SUBNET, &bridge.name).await?;

    tracing::info!(
        subnet = CONTAINER_SUBNET,
        bridge = %bridge.name,
        %bridge_mac,
        "route ensured"
    );
    Ok(())
}

/// Ensures the container subnet route with automatic retry on transient failures.
///
/// All [`RouteError`] variants are treated as retryable. Retries up to 5 times
/// with 2-second intervals (~10s total). This covers:
/// - Bridge FDB not yet populated after VM start (~1-2s to learn MAC)
/// - Helper daemon not yet started by launchd (first connection)
pub async fn ensure_route_with_retry(bridge_mac: &str) -> Result<(), RouteError> {
    for attempt in 1..=MAX_ROUTE_ATTEMPTS {
        match ensure_route(bridge_mac).await {
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

/// Ensures the container subnet route using a known bridge interface name.
///
/// When vmnet.framework creates the bridge, we know the interface immediately —
/// no need to scan the kernel FDB. Only retries for helper readiness.
#[cfg(all(feature = "vmnet", target_os = "macos"))]
pub async fn ensure_route_for_bridge(bridge_name: &str) -> Result<(), RouteError> {
    for attempt in 1..=2 {
        match async {
            let client = Client::connect().await?;
            client.route_add(CONTAINER_SUBNET, bridge_name).await?;
            Ok::<(), RouteError>(())
        }
        .await
        {
            Ok(()) => {
                tracing::info!(
                    subnet = CONTAINER_SUBNET,
                    bridge = bridge_name,
                    "route ensured (vmnet direct)"
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

/// Removes the container subnet route.
///
/// Called on: VM stop, daemon shutdown.
pub async fn remove_route() {
    let client = match Client::connect().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "arcbox-helper not reachable for route cleanup");
            return;
        }
    };

    match client.route_remove(CONTAINER_SUBNET).await {
        Ok(()) => {
            tracing::info!(subnet = CONTAINER_SUBNET, "route removed");
        }
        Err(ClientError::Helper(err)) if err.to_string().contains("not in table") => {
            tracing::debug!(subnet = CONTAINER_SUBNET, "route already absent");
        }
        Err(e) => {
            tracing::debug!(
                subnet = CONTAINER_SUBNET,
                error = %e,
                "route remove failed"
            );
        }
    }
}
