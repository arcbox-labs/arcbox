use super::{proxy, proxy_upgrade};
use crate::api::AppState;
use crate::error::Result;
use crate::proxy::{parse_port_bindings, proxy_to_guest};
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, Uri};
use axum::response::Response;
use bytes::Bytes;

crate::handlers::proxy_handler!(list_containers);
crate::handlers::proxy_handler!(inspect_container);
crate::handlers::proxy_handler!(container_logs);
crate::handlers::proxy_handler!(wait_container);
crate::handlers::proxy_handler!(pause_container);
crate::handlers::proxy_handler!(unpause_container);
crate::handlers::proxy_handler!(rename_container);
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

/// Start a container, then set up host-side port forwarding.
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

    // On success, inspect the container and set up port forwarding.
    if response.status().is_success() {
        if let Some(ref id) = container_id {
            setup_port_forwarding(&state, id).await;
        }
    }

    Ok(response)
}

/// Stop a container and tear down its port forwarding rules.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
pub async fn stop_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    if let Some(id) = extract_container_id(&uri) {
        state.runtime.stop_port_forwarding_by_id(&id).await;
    }
    proxy(&state, &uri, req).await
}

/// Remove a container and tear down its port forwarding rules.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
pub async fn remove_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    if let Some(id) = extract_container_id(&uri) {
        state.runtime.stop_port_forwarding_by_id(&id).await;
    }
    proxy(&state, &uri, req).await
}

/// Inspect a started container and configure port forwarding from its bindings.
async fn setup_port_forwarding(state: &AppState, container_id: &str) {
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
            return;
        }
        Err(e) => {
            tracing::debug!("Failed to inspect container {}: {}", container_id, e);
            return;
        }
    };

    let body_bytes = match http_body_util::BodyExt::collect(inspect_resp.into_body()).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::debug!("Failed to read inspect body for {}: {}", container_id, e);
            return;
        }
    };

    let bindings = parse_port_bindings(&body_bytes);
    if bindings.is_empty() {
        return;
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
        .start_port_forwarding_for(machine_name, container_id, &rules)
        .await
    {
        tracing::warn!(
            "Failed to start port forwarding for {}: {}",
            container_id,
            e
        );
    }
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
}
