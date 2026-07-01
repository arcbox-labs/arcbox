//! Network handlers that keep host DNS in sync.
//!
//! `POST /networks/{id}/connect` and `/disconnect` change a running
//! container's IP and reachable aliases, so after proxying them to guest
//! dockerd the container's host DNS entry must be refreshed — otherwise
//! resolving the container by name keeps returning the pre-connect address.
//! All other network operations proxy through the fallback untouched (host
//! routing uses one static container-subnet route, not per-network state).

use super::container::{
    canonical_id_or_fallback, extract_container_dns_info, extract_container_name,
};
use super::proxying::proxy_to_system_vm;
use crate::api::AppState;
use crate::error::{DockerError, Result};
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{Request, Uri};
use axum::response::Response;

/// Connect a container to a network, then refresh its host DNS entry.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.network.connect",
    skip(state, req),
    fields(uri = %uri, utility_vm = "native"),
    err
)]
pub async fn network_connect(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy_then_refresh_dns(&state, &uri, req).await
}

/// Disconnect a container from a network, then refresh its host DNS entry.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.network.disconnect",
    skip(state, req),
    fields(uri = %uri, utility_vm = "native"),
    err
)]
pub async fn network_disconnect(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy_then_refresh_dns(&state, &uri, req).await
}

/// Buffers the request body (to learn which container is affected), proxies
/// the operation, and on success re-derives the container's DNS entry from a
/// fresh inspect.
async fn proxy_then_refresh_dns(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    let (parts, body) = req.into_parts();
    let body_bytes = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| DockerError::Server(format!("failed to read body: {e}")))?
        .to_bytes();
    let container = container_from_network_body(&body_bytes);

    let req = Request::from_parts(parts, Body::from(body_bytes));
    let response = proxy_to_system_vm(state, uri, req).await?;

    if response.status().is_success() {
        match container {
            Some(token) => refresh_container_dns(state, &token).await,
            None => tracing::debug!(
                uri = %uri,
                "network operation body had no Container field; skipping DNS refresh"
            ),
        }
    }

    Ok(response)
}

/// Re-derives a container's host DNS entry from a fresh inspect.
///
/// The old entry is removed first: after a disconnect the container may have
/// no IP left at all, in which case nothing is re-registered (a stale address
/// would otherwise linger).
async fn refresh_container_dns(state: &AppState, token: &str) {
    let Some(inspect) = crate::guest_query::inspect_container(state.proxy.client(), token).await
    else {
        tracing::debug!(
            container = token,
            "could not inspect container after network change; DNS entry left unchanged"
        );
        return;
    };
    let canonical = canonical_id_or_fallback(token, &inspect);
    state.runtime.deregister_dns_by_id(&canonical).await;
    // Deregistration also cleared the name alias — re-register it so later
    // lifecycle calls by name still resolve.
    if let Some(name) = extract_container_name(&inspect) {
        state
            .runtime
            .register_container_alias(&name, &canonical)
            .await;
    }
    if let Some((aliases, ip)) = extract_container_dns_info(&inspect) {
        state.runtime.register_dns(&canonical, &aliases, ip).await;
    }
}

/// Extracts the `Container` field (name or ID) from a network
/// connect/disconnect request body.
fn container_from_network_body(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get("Container")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_field_from_connect_body() {
        let body = br#"{"Container":"web","EndpointConfig":{"IPAMConfig":{}}}"#;
        assert_eq!(container_from_network_body(body).as_deref(), Some("web"));
    }

    #[test]
    fn container_field_from_disconnect_body() {
        let body = br#"{"Container":"abc123","Force":true}"#;
        assert_eq!(container_from_network_body(body).as_deref(), Some("abc123"));
    }

    #[test]
    fn missing_or_empty_container_field_is_none() {
        assert_eq!(container_from_network_body(br#"{"Force":true}"#), None);
        assert_eq!(container_from_network_body(br#"{"Container":""}"#), None);
        assert_eq!(container_from_network_body(b"not json"), None);
    }
}
