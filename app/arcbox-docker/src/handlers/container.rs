use super::{proxy, proxy_upgrade};
use crate::api::AppState;
use crate::error::Result;
use crate::proxy::{parse_port_bindings, proxy_to_guest};
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, Uri};
use axum::response::Response;
use bytes::Bytes;
use std::net::IpAddr;

crate::handlers::proxy_handler!(list_containers);
crate::handlers::proxy_handler!(inspect_container);
crate::handlers::proxy_handler!(container_logs);
crate::handlers::proxy_handler!(wait_container);
crate::handlers::proxy_handler!(pause_container);
crate::handlers::proxy_handler!(unpause_container);
crate::handlers::proxy_handler!(container_top);
crate::handlers::proxy_handler!(container_stats);
crate::handlers::proxy_handler!(container_changes);
crate::handlers::proxy_handler!(prune_containers);
crate::handlers::proxy_handler!(create_container);
crate::handlers::proxy_handler!(kill_container);
crate::handlers::proxy_handler!(restart_container);

/// Extract container ID from URI path.
///
/// Matches patterns like `/containers/{id}/start`, `/v1.43/containers/{id}/stop`,
/// or `/containers/{id}` (for DELETE).
fn extract_container_id(uri: &Uri) -> Option<String> {
    let segments: Vec<&str> = uri.path().split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segments.iter().enumerate() {
        if *seg == "containers" && i + 1 < segments.len() {
            let id = segments[i + 1];
            // Skip collection endpoints (no container ID).
            if !matches!(id, "json" | "create" | "prune") {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Start a container, then set up host-side port forwarding and DNS.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
pub async fn start_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    let container_id = extract_container_id(&uri);

    // Proxy start request to guest.
    let response = proxy(&state, &uri, req).await?;

    // On success, inspect the container and set up port forwarding + DNS.
    if response.status().is_success() {
        if let Some(ref id) = container_id {
            setup_container_networking(&state, id).await;
        }
    }

    Ok(response)
}

/// Stop a container and tear down its port forwarding + DNS.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
pub async fn stop_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    // Resolve canonical ID before proxy — the name/short-id is still valid now
    // but may become stale after stop (e.g. --rm containers).
    let canonical = if let Some(id) = extract_container_id(&uri) {
        Some(resolve_canonical_id(&state, &id).await.unwrap_or(id))
    } else {
        None
    };

    let response = proxy(&state, &uri, req).await?;

    // Only tear down networking after a successful stop.
    if response.status().is_success() {
        if let Some(canonical) = canonical {
            state.runtime.stop_port_forwarding_by_id(&canonical).await;
            state.runtime.deregister_dns_by_id(&canonical).await;
        }
    }

    Ok(response)
}

/// Remove a container and tear down its port forwarding + DNS.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
pub async fn remove_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    // Resolve canonical ID before proxy — the name/short-id is still valid now.
    let canonical = if let Some(id) = extract_container_id(&uri) {
        Some(resolve_canonical_id(&state, &id).await.unwrap_or(id))
    } else {
        None
    };

    let response = proxy(&state, &uri, req).await?;

    // Only tear down networking after a successful remove.
    if response.status().is_success() {
        if let Some(canonical) = canonical {
            state.runtime.stop_port_forwarding_by_id(&canonical).await;
            state.runtime.deregister_dns_by_id(&canonical).await;
        }
    }

    Ok(response)
}

/// Inspect a started container and configure port forwarding + DNS registration.
///
/// Shares a single inspect call for both port forwarding and DNS setup.
async fn setup_container_networking(state: &AppState, container_id: &str) {
    let Some(body_bytes) = inspect_container_body(state, container_id).await else {
        return;
    };

    // Use the canonical full container ID from inspect (not the URI token which
    // may be a name or short ID) so that stop/remove can reliably match the key.
    let canonical_id = canonical_id_or_fallback(container_id, &body_bytes);

    // Port forwarding.
    setup_port_forwarding_from_inspect(state, &canonical_id, &body_bytes).await;

    // DNS registration.
    if let Some((name, ip)) = extract_container_dns_info(&body_bytes) {
        state.runtime.register_dns(&canonical_id, &name, ip).await;
    }
}

/// Fetches the inspect JSON body for a container from guest dockerd.
async fn inspect_container_body(state: &AppState, container_id: &str) -> Option<Bytes> {
    let inspect_path = format!("/containers/{container_id}/json");
    let inspect_resp = match proxy_to_guest(
        &state.runtime,
        Method::GET,
        &inspect_path,
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            tracing::debug!(
                "Inspect container {} returned status {}",
                container_id,
                resp.status()
            );
            return None;
        }
        Err(e) => {
            tracing::debug!("Failed to inspect container {}: {}", container_id, e);
            return None;
        }
    };

    match http_body_util::BodyExt::collect(inspect_resp.into_body()).await {
        Ok(collected) => Some(collected.to_bytes()),
        Err(e) => {
            tracing::debug!("Failed to read inspect body for {}: {}", container_id, e);
            None
        }
    }
}

/// Configures port forwarding from pre-fetched inspect JSON.
async fn setup_port_forwarding_from_inspect(
    state: &AppState,
    canonical_id: &str,
    body_bytes: &[u8],
) {
    let bindings = parse_port_bindings(body_bytes);
    if bindings.is_empty() {
        tracing::debug!("No port bindings found for container {}", canonical_id);
        return;
    }

    tracing::info!(
        "Port forwarding: {} bindings for container {}",
        bindings.len(),
        canonical_id,
    );
    for b in &bindings {
        tracing::info!(
            "  bind {}:{} → container:{}/{}",
            b.host_ip,
            b.host_port,
            b.container_port,
            b.protocol,
        );
    }

    let rules: Vec<_> = bindings
        .iter()
        .map(|b| {
            (
                b.host_ip.clone(),
                b.host_port,
                b.container_port,
                b.protocol.clone(),
            )
        })
        .collect();

    let machine_name = state.runtime.default_machine_name();
    if let Err(e) = state
        .runtime
        .start_port_forwarding_for(machine_name, canonical_id, &rules)
        .await
    {
        tracing::warn!(
            "Failed to start port forwarding for {}: {}",
            canonical_id,
            e
        );
    }
}

/// Extracts container name and IP address from Docker inspect JSON.
///
/// Returns `(name, ip)` where `name` is the container name without leading `/`.
/// Falls back through `/NetworkSettings/IPAddress` → per-network IPs.
fn extract_container_dns_info(inspect_json: &[u8]) -> Option<(String, IpAddr)> {
    let v: serde_json::Value = serde_json::from_slice(inspect_json).ok()?;
    let name = v.get("Name")?.as_str()?.trim_start_matches('/').to_string();

    if name.is_empty() {
        return None;
    }

    // Primary: top-level IPAddress.
    let ip_str = v
        .pointer("/NetworkSettings/IPAddress")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        // Fallback: first non-empty IP from Networks map.
        .or_else(|| {
            v.pointer("/NetworkSettings/Networks")?
                .as_object()?
                .values()
                .find_map(|net| net.get("IPAddress")?.as_str().filter(|s| !s.is_empty()))
        })?;

    Some((name, ip_str.parse().ok()?))
}

/// Rename a container and update its DNS entry.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
pub async fn rename_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    // Resolve canonical ID BEFORE proxy — the old name/short-id is still valid
    // now but will be invalid after a successful rename.
    let canonical = if let Some(id) = extract_container_id(&uri) {
        Some(resolve_canonical_id(&state, &id).await.unwrap_or(id))
    } else {
        None
    };

    // Proxy rename to guest.
    let response = proxy(&state, &uri, req).await?;

    if response.status().is_success() {
        if let Some(ref canonical) = canonical {
            // 1. Remove old DNS entry.
            state.runtime.deregister_dns_by_id(canonical).await;

            // 2. Inspect (using canonical ID which survives rename) to get
            //    new name + IP, then register.
            if let Some(body_bytes) = inspect_container_body(&state, canonical).await {
                if let Some((new_name, ip)) = extract_container_dns_info(&body_bytes) {
                    state.runtime.register_dns(canonical, &new_name, ip).await;
                }
            }
        }
    }

    Ok(response)
}

/// Attach to a container.
///
/// # Errors
///
/// Returns an error if upgrade proxying to guest dockerd fails.
pub async fn attach_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy_upgrade(&state, &uri, req).await
}

/// Extracts the canonical full container ID from a Docker inspect JSON response.
fn extract_canonical_id_from_inspect(inspect_json: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(inspect_json).ok()?;
    value.get("Id")?.as_str().map(String::from)
}

/// Returns the canonical container ID from inspect JSON, falling back to the
/// original request token when the inspect payload does not contain a usable ID.
fn canonical_id_or_fallback(container_id: &str, inspect_json: &[u8]) -> String {
    extract_canonical_id_from_inspect(inspect_json).unwrap_or_else(|| container_id.to_string())
}

/// Resolves a container name, short ID, or full ID to the canonical full ID
/// by inspecting the container on the guest.
async fn resolve_canonical_id(state: &AppState, id: &str) -> Option<String> {
    let inspect_path = format!("/containers/{id}/json");
    let resp = proxy_to_guest(
        &state.runtime,
        Method::GET,
        &inspect_path,
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .ok()?
        .to_bytes();

    extract_canonical_id_from_inspect(&body_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    #[test]
    fn extract_id_from_start_path() {
        let u = uri("/containers/abc123/start");
        assert_eq!(extract_container_id(&u).as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_id_from_versioned_path() {
        let u = uri("/v1.43/containers/def456/stop");
        assert_eq!(extract_container_id(&u).as_deref(), Some("def456"));
    }

    #[test]
    fn extract_id_from_delete_path() {
        let u = uri("/containers/xyz789");
        assert_eq!(extract_container_id(&u).as_deref(), Some("xyz789"));
    }

    #[test]
    fn extract_id_skips_collection_endpoints() {
        assert_eq!(extract_container_id(&uri("/containers/json")), None);
        assert_eq!(extract_container_id(&uri("/containers/create")), None);
        assert_eq!(extract_container_id(&uri("/containers/prune")), None);
    }

    #[test]
    fn extract_id_no_containers_segment() {
        assert_eq!(extract_container_id(&uri("/images/abc/json")), None);
    }

    #[test]
    fn extract_canonical_id_from_inspect_json() {
        let json = br#"{"Id":"abc123def456789","Name":"/my-nginx","State":{}}"#;
        assert_eq!(
            extract_canonical_id_from_inspect(json).as_deref(),
            Some("abc123def456789")
        );
    }

    #[test]
    fn extract_canonical_id_missing_field() {
        let json = br#"{"Name":"/my-nginx"}"#;
        assert_eq!(extract_canonical_id_from_inspect(json), None);
    }

    #[test]
    fn extract_canonical_id_invalid_json() {
        assert_eq!(extract_canonical_id_from_inspect(b"not json"), None);
    }

    #[test]
    fn canonical_id_or_fallback_uses_canonical() {
        let json = br#"{"Id":"canonical-abcdef","Name":"/my-nginx"}"#;
        assert_eq!(
            canonical_id_or_fallback("web", json),
            "canonical-abcdef".to_string()
        );
    }

    #[test]
    fn canonical_id_or_fallback_falls_back_when_missing() {
        let json = br#"{"Name":"/my-nginx"}"#;
        assert_eq!(canonical_id_or_fallback("web", json), "web".to_string());
    }

    #[test]
    fn canonical_id_or_fallback_falls_back_on_invalid_json() {
        assert_eq!(
            canonical_id_or_fallback("web", b"not json"),
            "web".to_string()
        );
    }

    #[test]
    fn test_extract_container_dns_info_basic() {
        let json = serde_json::json!({
            "Id": "abc123",
            "Name": "/my-nginx",
            "NetworkSettings": {
                "IPAddress": "172.17.0.2",
                "Networks": {}
            }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let (name, ip) = extract_container_dns_info(&bytes).unwrap();
        assert_eq!(name, "my-nginx");
        assert_eq!(ip, "172.17.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_container_dns_info_network_fallback() {
        let json = serde_json::json!({
            "Id": "abc123",
            "Name": "/web-app",
            "NetworkSettings": {
                "IPAddress": "",
                "Networks": {
                    "bridge": {
                        "IPAddress": "172.18.0.3"
                    }
                }
            }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let (name, ip) = extract_container_dns_info(&bytes).unwrap();
        assert_eq!(name, "web-app");
        assert_eq!(ip, "172.18.0.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_container_dns_info_no_ip() {
        let json = serde_json::json!({
            "Id": "abc123",
            "Name": "/isolated",
            "NetworkSettings": {
                "IPAddress": "",
                "Networks": {}
            }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        assert!(extract_container_dns_info(&bytes).is_none());
    }

    #[test]
    fn test_extract_container_dns_info_invalid_json() {
        assert!(extract_container_dns_info(b"not json").is_none());
    }

    #[test]
    fn test_extract_container_dns_info_no_name() {
        let json = serde_json::json!({
            "Id": "abc123",
            "NetworkSettings": {
                "IPAddress": "172.17.0.2"
            }
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        assert!(extract_container_dns_info(&bytes).is_none());
    }
}
