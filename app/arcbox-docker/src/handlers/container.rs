use super::{HOOK_BUFFER_LIMIT_BYTES, proxy as proxy_request, proxy_upgrade};
use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::proxy;
use arcbox_core::event::Event;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use std::collections::HashMap;

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

struct InspectMetadata {
    name: String,
    image: String,
    labels: HashMap<String, String>,
}

impl InspectMetadata {
    fn fallback(container_id: &str) -> Self {
        Self {
            name: container_id.to_string(),
            image: String::new(),
            labels: HashMap::new(),
        }
    }
}

/// Create container (pre-hook: ensure VM ready).
pub async fn create_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;

    let response = proxy::proxy_to_guest_stream(&state.runtime, &uri, req).await?;

    if response.status() == StatusCode::CREATED {
        let (parts, resp_body) = response.into_parts();
        let resp_bytes = axum::body::to_bytes(resp_body, HOOK_BUFFER_LIMIT_BYTES)
            .await
            .map_err(|e| DockerError::Server(e.to_string()))?;

        if let Some(id) = extract_container_id(&resp_bytes) {
            let metadata = fetch_container_metadata(&state, &id).await;
            let fallback_name = uri
                .query()
                .and_then(|q| {
                    q.split('&')
                        .find_map(|p| p.strip_prefix("name=").map(String::from))
                })
                .unwrap_or_else(|| id.chars().take(12).collect());
            let name = if metadata.name == id {
                fallback_name
            } else {
                metadata.name
            };

            state.runtime.event_bus().publish(Event::ContainerCreated {
                id: id.clone(),
                name,
                image: metadata.image,
                labels: metadata.labels,
            });
        }

        return Ok(Response::from_parts(parts, Body::from(resp_bytes)));
    }

    Ok(response)
}

/// Start container (post-hook: port forwarding + event).
pub async fn start_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Path(id): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response> {
    let response = proxy_request(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        if let Some(metadata) = setup_port_forwarding(&state, &id).await {
            state.runtime.event_bus().publish(Event::ContainerStarted {
                id,
                name: metadata.name,
                image: metadata.image,
                labels: metadata.labels,
            });
        }
    }

    Ok(response)
}

/// Stop container (post-hook: stop port forwarding + event).
pub async fn stop_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Path(id): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response> {
    let metadata = fetch_container_metadata(&state, &id).await;
    let response = proxy_request(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        state.runtime.stop_port_forwarding_by_id(&id).await;
        state.runtime.event_bus().publish(Event::ContainerStopped {
            id: id.clone(),
            name: metadata.name.clone(),
            image: metadata.image.clone(),
            labels: metadata.labels.clone(),
            exit_code: None,
        });
        state.runtime.event_bus().publish(Event::ContainerDied {
            id,
            name: metadata.name,
            image: metadata.image,
            labels: metadata.labels,
            exit_code: None,
        });
    }

    Ok(response)
}

/// Kill container (post-hook: stop port forwarding + event).
pub async fn kill_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    req: Request<Body>,
) -> Result<Response> {
    let signal = params
        .get("signal")
        .cloned()
        .unwrap_or_else(|| "SIGKILL".to_string());
    let metadata = fetch_container_metadata(&state, &id).await;
    let response = proxy_request(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        state.runtime.stop_port_forwarding_by_id(&id).await;
        state.runtime.event_bus().publish(Event::ContainerKilled {
            id: id.clone(),
            name: metadata.name.clone(),
            image: metadata.image.clone(),
            labels: metadata.labels.clone(),
            signal,
            exit_code: None,
        });
        state.runtime.event_bus().publish(Event::ContainerDied {
            id,
            name: metadata.name,
            image: metadata.image,
            labels: metadata.labels,
            exit_code: None,
        });
    }

    Ok(response)
}

/// Restart container (post-hook: re-evaluate port forwarding + events).
pub async fn restart_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Path(id): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response> {
    let response = proxy_request(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        state.runtime.stop_port_forwarding_by_id(&id).await;

        if let Some(metadata) = setup_port_forwarding(&state, &id).await {
            state.runtime.event_bus().publish(Event::ContainerStarted {
                id,
                name: metadata.name,
                image: metadata.image,
                labels: metadata.labels,
            });
        }
    }

    Ok(response)
}

/// Remove container (post-hook: stop port forwarding + event).
pub async fn remove_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    axum::extract::Path(id): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response> {
    let metadata = fetch_container_metadata(&state, &id).await;
    let response = proxy_request(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        state.runtime.stop_port_forwarding_by_id(&id).await;
        state.runtime.event_bus().publish(Event::ContainerRemoved {
            id,
            name: metadata.name,
            image: metadata.image,
            labels: metadata.labels,
        });
    }

    Ok(response)
}

/// Attach to a container.
pub async fn attach_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy_upgrade(&state, &uri, req).await
}

/// Fetch container name, image, and labels from guest dockerd.
async fn fetch_container_metadata(state: &AppState, container_id: &str) -> InspectMetadata {
    let inspect_path = format!("/v1.43/containers/{}/json", container_id);
    let resp = proxy::proxy_to_guest(
        &state.runtime,
        Method::GET,
        &inspect_path,
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await;
    let Ok(resp) = resp else {
        return InspectMetadata::fallback(container_id);
    };
    if resp.status() != StatusCode::OK {
        return InspectMetadata::fallback(container_id);
    }
    let Ok(body) = axum::body::to_bytes(resp.into_body(), HOOK_BUFFER_LIMIT_BYTES).await else {
        return InspectMetadata::fallback(container_id);
    };

    extract_metadata_from_inspect(&body, container_id)
}

/// Inspect container, set up forwarding if needed, and return parsed metadata.
async fn setup_port_forwarding(state: &AppState, id: &str) -> Option<InspectMetadata> {
    let inspect_path = format!("/v1.43/containers/{}/json", id);
    let inspect_resp = proxy::proxy_to_guest(
        &state.runtime,
        Method::GET,
        &inspect_path,
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    .ok()?;

    if inspect_resp.status() != StatusCode::OK {
        return None;
    }

    let body = axum::body::to_bytes(inspect_resp.into_body(), HOOK_BUFFER_LIMIT_BYTES)
        .await
        .ok()?;

    let bindings = proxy::parse_port_bindings(&body);
    if !bindings.is_empty() {
        let fwd_bindings: Vec<(String, u16, u16, String)> = bindings
            .iter()
            .map(|binding| {
                (
                    binding.host_ip.clone(),
                    binding.host_port,
                    binding.container_port,
                    binding.protocol.clone(),
                )
            })
            .collect();

        let machine_name = state.runtime.default_machine_name();
        if let Err(e) = state
            .runtime
            .start_port_forwarding_for(machine_name, id, &fwd_bindings)
            .await
        {
            tracing::warn!("Failed to start port forwarding: {}", e);
        }
    }

    Some(extract_metadata_from_inspect(&body, id))
}

fn extract_metadata_from_inspect(body: &[u8], fallback_id: &str) -> InspectMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return InspectMetadata::fallback(fallback_id);
    };

    let name = value
        .pointer("/Name")
        .and_then(|v| v.as_str())
        .unwrap_or(fallback_id)
        .trim_start_matches('/')
        .to_string();
    let image = value
        .pointer("/Config/Image")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let labels = value
        .pointer("/Config/Labels")
        .and_then(|v| serde_json::from_value::<HashMap<String, String>>(v.clone()).ok())
        .unwrap_or_default();

    InspectMetadata {
        name,
        image,
        labels,
    }
}

/// Extract container ID from a guest create-container JSON response.
fn extract_container_id(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get("Id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
