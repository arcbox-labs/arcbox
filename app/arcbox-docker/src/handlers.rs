//! Request handlers for Docker API endpoints.
//!
//! Most handlers forward requests to guest dockerd via the smart proxy.
//! Host-only handlers (ping, version, info, events) respond from host state.
//! Lifecycle handlers (start, stop, kill, remove) add post-hooks for port
//! forwarding and event publishing.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::proxy;
use crate::types::*;
use arcbox_core::event::Event;
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio_stream::wrappers::ReceiverStream;

const HOOK_BUFFER_LIMIT_BYTES: usize = 10 * 1024 * 1024;

// ============================================================================
// Proxy helpers
// ============================================================================

/// Forward a request to guest dockerd, ensuring the VM is running first.
async fn proxy(state: &AppState, uri: &Uri, req: Request<Body>) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;
    proxy::proxy_to_guest_stream(&state.runtime, uri, req).await
}

/// Fetch container name, image, and labels from guest dockerd.
async fn fetch_container_metadata(
    state: &AppState,
    container_id: &str,
) -> (String, String, HashMap<String, String>) {
    let path = format!("/v1.43/containers/{}/json", container_id);
    let resp = proxy::proxy_to_guest(
        &state.runtime,
        Method::GET,
        &path,
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await;
    let Ok(resp) = resp else {
        return (container_id.to_string(), String::new(), HashMap::new());
    };
    if resp.status() != StatusCode::OK {
        return (container_id.to_string(), String::new(), HashMap::new());
    }
    let Ok(body) = axum::body::to_bytes(resp.into_body(), HOOK_BUFFER_LIMIT_BYTES).await else {
        return (container_id.to_string(), String::new(), HashMap::new());
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (container_id.to_string(), String::new(), HashMap::new());
    };
    let name = value
        .pointer("/Name")
        .and_then(|v| v.as_str())
        .unwrap_or(container_id)
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
    (name, image, labels)
}

/// Extract container ID from a guest create-container JSON response.
fn extract_container_id(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value
        .get("Id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ============================================================================
// Container Handlers — pure proxy
// ============================================================================

/// List containers.
pub async fn list_containers(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Inspect container.
pub async fn inspect_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Get container logs.
pub async fn container_logs(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Wait for container to stop.
pub async fn wait_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Pause container.
pub async fn pause_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Unpause container.
pub async fn unpause_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Rename container.
pub async fn rename_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Get container processes (top).
pub async fn container_top(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Get container stats.
pub async fn container_stats(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Get container filesystem changes.
pub async fn container_changes(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Prune stopped containers.
pub async fn prune_containers(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

// ============================================================================
// Container Handlers — proxy + hooks
// ============================================================================

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

    // Post-hook: publish event if creation succeeded.
    if response.status() == StatusCode::CREATED {
        // Read the response body to get container ID, then re-wrap it.
        let (parts, resp_body) = response.into_parts();
        let resp_bytes = axum::body::to_bytes(resp_body, HOOK_BUFFER_LIMIT_BYTES)
            .await
            .map_err(|e| DockerError::Server(e.to_string()))?;

        if let Some(id) = extract_container_id(&resp_bytes) {
            let (meta_name, image, labels) = fetch_container_metadata(&state, &id).await;
            let fallback_name = uri
                .query()
                .and_then(|q| {
                    q.split('&')
                        .find_map(|p| p.strip_prefix("name=").map(String::from))
                })
                .unwrap_or_else(|| id.chars().take(12).collect());
            let name = if meta_name == id {
                fallback_name
            } else {
                meta_name
            };

            state.runtime.event_bus().publish(Event::ContainerCreated {
                id: id.clone(),
                name,
                image,
                labels,
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
    let response = proxy(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        // Inspect guest container for port bindings and metadata.
        let inspect_path = format!("/v1.43/containers/{}/json", id);
        if let Ok(inspect_resp) = proxy::proxy_to_guest(
            &state.runtime,
            Method::GET,
            &inspect_path,
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await
        {
            if inspect_resp.status() == StatusCode::OK {
                if let Ok(body) =
                    axum::body::to_bytes(inspect_resp.into_body(), HOOK_BUFFER_LIMIT_BYTES).await
                {
                    // Set up port forwarding.
                    let bindings = proxy::parse_port_bindings(&body);
                    if !bindings.is_empty() {
                        let fwd_bindings: Vec<(String, u16, u16, String)> = bindings
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
                            .start_port_forwarding_for(machine_name, &id, &fwd_bindings)
                            .await
                        {
                            tracing::warn!("Failed to start port forwarding: {}", e);
                        }
                    }

                    // Publish event.
                    let value: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
                    if let Some(ref v) = value {
                        let name = v
                            .pointer("/Name")
                            .and_then(|n| n.as_str())
                            .unwrap_or(&id)
                            .trim_start_matches('/')
                            .to_string();
                        let image = v
                            .pointer("/Config/Image")
                            .and_then(|i| i.as_str())
                            .unwrap_or("")
                            .to_string();
                        let labels = v
                            .pointer("/Config/Labels")
                            .and_then(|l| {
                                serde_json::from_value::<HashMap<String, String>>(l.clone()).ok()
                            })
                            .unwrap_or_default();
                        state.runtime.event_bus().publish(Event::ContainerStarted {
                            id: id.clone(),
                            name,
                            image,
                            labels,
                        });
                    }
                }
            }
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
    // Fetch metadata before stopping (container still exists after stop).
    let (name, image, labels) = fetch_container_metadata(&state, &id).await;

    let response = proxy(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        state.runtime.stop_port_forwarding_by_id(&id).await;
        state.runtime.event_bus().publish(Event::ContainerStopped {
            id: id.clone(),
            name: name.clone(),
            image: image.clone(),
            labels: labels.clone(),
            exit_code: None,
        });
        state.runtime.event_bus().publish(Event::ContainerDied {
            id,
            name,
            image,
            labels,
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
    let (name, image, labels) = fetch_container_metadata(&state, &id).await;

    let response = proxy(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        state.runtime.stop_port_forwarding_by_id(&id).await;
        state.runtime.event_bus().publish(Event::ContainerKilled {
            id: id.clone(),
            name: name.clone(),
            image: image.clone(),
            labels: labels.clone(),
            signal,
            exit_code: None,
        });
        state.runtime.event_bus().publish(Event::ContainerDied {
            id,
            name,
            image,
            labels,
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
    let response = proxy(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        // Teardown old port forwarding.
        state.runtime.stop_port_forwarding_by_id(&id).await;

        // Inspect and re-setup port forwarding.
        let inspect_path = format!("/v1.43/containers/{}/json", id);
        if let Ok(inspect_resp) = proxy::proxy_to_guest(
            &state.runtime,
            Method::GET,
            &inspect_path,
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await
        {
            if inspect_resp.status() == StatusCode::OK {
                if let Ok(body) =
                    axum::body::to_bytes(inspect_resp.into_body(), HOOK_BUFFER_LIMIT_BYTES).await
                {
                    let bindings = proxy::parse_port_bindings(&body);
                    if !bindings.is_empty() {
                        let fwd_bindings: Vec<(String, u16, u16, String)> = bindings
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
                            .start_port_forwarding_for(machine_name, &id, &fwd_bindings)
                            .await
                        {
                            tracing::warn!("Failed to start port forwarding: {}", e);
                        }
                    }

                    // Publish events.
                    let value: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
                    if let Some(ref v) = value {
                        let name = v
                            .pointer("/Name")
                            .and_then(|n| n.as_str())
                            .unwrap_or(&id)
                            .trim_start_matches('/')
                            .to_string();
                        let image = v
                            .pointer("/Config/Image")
                            .and_then(|i| i.as_str())
                            .unwrap_or("")
                            .to_string();
                        let labels = v
                            .pointer("/Config/Labels")
                            .and_then(|l| {
                                serde_json::from_value::<HashMap<String, String>>(l.clone()).ok()
                            })
                            .unwrap_or_default();
                        state.runtime.event_bus().publish(Event::ContainerStarted {
                            id: id.clone(),
                            name,
                            image,
                            labels,
                        });
                    }
                }
            }
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
    // Fetch metadata BEFORE removal (container won't exist after).
    let (name, image, labels) = fetch_container_metadata(&state, &id).await;

    let response = proxy(&state, &uri, req).await?;

    if response.status() == StatusCode::NO_CONTENT {
        state.runtime.stop_port_forwarding_by_id(&id).await;
        state.runtime.event_bus().publish(Event::ContainerRemoved {
            id,
            name,
            image,
            labels,
        });
    }

    Ok(response)
}

// ============================================================================
// Attach Handler — proxy + HTTP upgrade
// ============================================================================

/// Attach to a container.
pub async fn attach_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;
    proxy::proxy_with_upgrade(&state.runtime, req, &uri).await
}

// ============================================================================
// Exec Handlers
// ============================================================================

/// Create exec instance (pure proxy).
pub async fn exec_create(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Start exec instance (proxy + upgrade for interactive mode).
pub async fn exec_start(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;

    // Check if client wants upgrade (interactive mode).
    let wants_upgrade = req.headers().get(header::UPGRADE).is_some()
        || req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map_or(false, |v| v.to_ascii_lowercase().contains("upgrade"));

    if wants_upgrade {
        proxy::proxy_with_upgrade(&state.runtime, req, &uri).await
    } else {
        proxy::proxy_to_guest_stream(&state.runtime, &uri, req).await
    }
}

/// Resize exec TTY (pure proxy).
pub async fn exec_resize(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Inspect exec instance (pure proxy).
pub async fn exec_inspect(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

// ============================================================================
// Image Handlers — pure proxy
// ============================================================================

/// List images.
pub async fn list_images(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Pull image.
pub async fn pull_image(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Inspect image.
pub async fn inspect_image(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Remove image.
pub async fn remove_image(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Tag image.
pub async fn tag_image(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

// ============================================================================
// Network Handlers — pure proxy
// ============================================================================

/// List networks.
pub async fn list_networks(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Create network.
pub async fn create_network(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Inspect network.
pub async fn inspect_network(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Remove network.
pub async fn remove_network(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

// ============================================================================
// Volume Handlers — pure proxy
// ============================================================================

/// List volumes.
pub async fn list_volumes(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Create volume.
pub async fn create_volume(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Prune unused volumes.
pub async fn prune_volumes(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Inspect volume.
pub async fn inspect_volume(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

/// Remove volume.
pub async fn remove_volume(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    proxy(&state, &uri, req).await
}

// ============================================================================
// System Handlers — host-only (no proxy)
// ============================================================================

/// Get version.
pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: crate::API_VERSION.to_string(),
        min_api_version: crate::MIN_API_VERSION.to_string(),
        git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
        go_version: "N/A (Rust)".to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        kernel_version: None,
        build_time: None,
    })
}

/// Get system info.
pub async fn get_info(State(state): State<AppState>) -> Json<SystemInfoResponse> {
    Json(SystemInfoResponse {
        containers: 0,
        containers_running: 0,
        containers_paused: 0,
        containers_stopped: 0,
        images: 0,
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        operating_system: std::env::consts::OS.to_string(),
        os_type: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        ncpu: num_cpus(),
        mem_total: total_memory(),
        name: hostname(),
        id: uuid::Uuid::new_v4().to_string(),
        docker_root_dir: state.runtime.config().data_dir.display().to_string(),
        debug: cfg!(debug_assertions),
        kernel_version: String::new(),
    })
}

/// Ping handler.
pub async fn ping() -> &'static str {
    "OK"
}

fn num_cpus() -> i64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i64)
        .unwrap_or(1)
}

fn total_memory() -> i64 {
    use sysinfo::System;
    let sys = System::new_all();
    sys.total_memory() as i64
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "arcbox".to_string())
}

// ============================================================================
// Events Handler — host-only (streams from EventBus)
// ============================================================================

/// Events query parameters.
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    /// Show events since this timestamp (Unix seconds or RFC3339).
    pub since: Option<String>,
    /// Show events until this timestamp (Unix seconds or RFC3339).
    pub until: Option<String>,
    /// Filters (JSON encoded).
    pub filters: Option<String>,
}

#[derive(Default, Debug, Clone)]
struct EventFilters {
    fields: HashMap<String, HashSet<String>>,
}

impl EventFilters {
    fn add(&mut self, key: &str, value: String) {
        self.fields
            .entry(key.to_string())
            .or_default()
            .insert(value);
    }

    fn get(&self, key: &str) -> Vec<String> {
        self.fields
            .get(key)
            .map(|values| values.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn exact_match(&self, key: &str, source: &str) -> bool {
        let Some(values) = self.fields.get(key) else {
            return true;
        };
        if values.is_empty() {
            return true;
        }
        values.contains(source)
    }

    fn fuzzy_match(&self, key: &str, source: &str) -> bool {
        if self.exact_match(key, source) {
            return true;
        }
        let Some(values) = self.fields.get(key) else {
            return true;
        };
        for prefix in values {
            if source.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    fn match_kv_list(&self, key: &str, attributes: &HashMap<String, String>) -> bool {
        let Some(values) = self.fields.get(key) else {
            return true;
        };
        if values.is_empty() {
            return true;
        }
        if attributes.is_empty() {
            return false;
        }
        for value in values {
            let (attr_key, attr_value) = match value.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (value.as_str(), None),
            };
            let Some(found) = attributes.get(attr_key) else {
                return false;
            };
            if let Some(expected) = attr_value {
                if found != expected {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Serialize)]
struct EventMessage {
    #[serde(rename = "Type")]
    event_type: String,
    #[serde(rename = "Action")]
    action: String,
    #[serde(rename = "Actor")]
    actor: EventActor,
    #[serde(rename = "scope")]
    scope: String,
    #[serde(rename = "time")]
    time: i64,
    #[serde(rename = "timeNano")]
    time_nano: i64,
}

#[derive(Serialize)]
struct EventActor {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Attributes")]
    attributes: HashMap<String, String>,
}

struct EventMapping {
    event_type: &'static str,
    action: &'static str,
    actor_id: String,
    attributes: HashMap<String, String>,
    legacy_from: Option<String>,
}

/// Stream Docker-style events.
pub async fn events(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<EventsQuery>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Result<Response> {
    let filters = parse_event_filters(params.filters)?;
    let since = parse_event_timestamp(params.since.as_deref())?;
    let until = parse_event_timestamp(params.until.as_deref())?;
    let api_version = api_version_from_uri(&uri).unwrap_or_else(|| crate::API_VERSION.to_string());
    let include_legacy_fields = version_lt(&api_version, "1.52");
    let skip_image_create = version_lt(&api_version, "1.46");
    let content_type = negotiate_event_content_type(&headers);

    if let Some(until) = until {
        let now = chrono::Utc::now().timestamp();
        if until < now {
            let (tx, rx) =
                tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
            drop(tx);
            let body = Body::from_stream(ReceiverStream::new(rx));
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .body(body)
                .unwrap());
        }
    }

    let mut event_rx = state.runtime.event_bus().subscribe();
    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(64);

    let scope = "local";
    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    let now = chrono::Utc::now();
                    let time = now.timestamp();
                    if let Some(since) = since {
                        if time < since {
                            continue;
                        }
                    }
                    if let Some(until) = until {
                        if time > until {
                            break;
                        }
                    }

                    let mapping = match map_event(&event) {
                        Some(mapping) => mapping,
                        None => continue,
                    };

                    if skip_image_create
                        && mapping.event_type == "image"
                        && mapping.action == "create"
                    {
                        continue;
                    }

                    if !event_matches_filters(
                        &filters,
                        mapping.event_type,
                        mapping.action,
                        &mapping.actor_id,
                        &mapping.attributes,
                        scope,
                    ) {
                        continue;
                    }

                    let event_message = EventMessage {
                        event_type: mapping.event_type.to_string(),
                        action: mapping.action.to_string(),
                        actor: EventActor {
                            id: mapping.actor_id.clone(),
                            attributes: mapping.attributes.clone(),
                        },
                        scope: scope.to_string(),
                        time,
                        time_nano: now.timestamp_nanos_opt().unwrap_or(time * 1_000_000_000),
                    };
                    let mut event_value = match serde_json::to_value(event_message) {
                        Ok(value) => value,
                        Err(e) => {
                            tracing::warn!("Failed to serialize event: {}", e);
                            continue;
                        }
                    };

                    if include_legacy_fields {
                        if let serde_json::Value::Object(ref mut map) = event_value {
                            if mapping.event_type == "container" {
                                map.insert(
                                    "id".to_string(),
                                    serde_json::Value::String(mapping.actor_id.clone()),
                                );
                                map.insert(
                                    "status".to_string(),
                                    serde_json::Value::String(mapping.action.to_string()),
                                );
                                if let Some(from) = &mapping.legacy_from {
                                    map.insert(
                                        "from".to_string(),
                                        serde_json::Value::String(from.clone()),
                                    );
                                }
                            } else if mapping.event_type == "image" {
                                map.insert(
                                    "id".to_string(),
                                    serde_json::Value::String(mapping.actor_id.clone()),
                                );
                                map.insert(
                                    "status".to_string(),
                                    serde_json::Value::String(mapping.action.to_string()),
                                );
                            }
                        }
                    }

                    let line = match encode_event_line(&event_value, content_type) {
                        Ok(line) => line,
                        Err(e) => {
                            tracing::warn!("Failed to encode event: {}", e);
                            continue;
                        }
                    };

                    if tx.send(Ok(line)).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    let body = Body::from_stream(ReceiverStream::new(rx));

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(body)
        .unwrap())
}

// ============================================================================
// Event helpers (unchanged)
// ============================================================================

fn parse_event_timestamp(value: Option<&str>) -> Result<Option<i64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if let Ok(ts) = trimmed.parse::<i64>() {
        return Ok(Some(ts));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Ok(Some(dt.timestamp()));
    }

    Err(DockerError::BadRequest(format!(
        "invalid timestamp: {trimmed}"
    )))
}

fn parse_event_filters(filters: Option<String>) -> Result<EventFilters> {
    let raw = match filters {
        Some(raw) if !raw.trim().is_empty() => raw,
        _ => return Ok(EventFilters::default()),
    };

    if let Ok(parsed) = serde_json::from_str::<HashMap<String, HashMap<String, bool>>>(&raw) {
        let mut filters = EventFilters::default();
        for (key, values) in parsed {
            for value in values.keys() {
                filters.add(&key, value.to_string());
            }
        }
        return Ok(filters);
    }

    if let Ok(parsed) = serde_json::from_str::<HashMap<String, Vec<String>>>(&raw) {
        let mut filters = EventFilters::default();
        for (key, values) in parsed {
            for value in values {
                filters.add(&key, value);
            }
        }
        return Ok(filters);
    }

    Err(DockerError::BadRequest(
        "invalid filters parameter".to_string(),
    ))
}

fn event_matches_filters(
    filters: &EventFilters,
    event_type: &str,
    action: &str,
    actor_id: &str,
    attributes: &HashMap<String, String>,
    scope: &str,
) -> bool {
    if !match_event_action(filters, action) {
        return false;
    }
    if !filters.exact_match("type", event_type) {
        return false;
    }
    if !filters.exact_match("scope", scope) {
        return false;
    }
    if !fuzzy_match_name(filters, "daemon", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "container", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "plugin", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "volume", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "network", actor_id, attributes.get("name")) {
        return false;
    }
    if !match_image(filters, event_type, actor_id, attributes) {
        return false;
    }
    if !fuzzy_match_name(filters, "node", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "service", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "secret", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "config", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "machine", actor_id, attributes.get("name")) {
        return false;
    }
    if !fuzzy_match_name(filters, "vm", actor_id, attributes.get("id")) {
        return false;
    }
    if !filters.match_kv_list("label", attributes) {
        return false;
    }

    true
}

fn match_event_action(filters: &EventFilters, action: &str) -> bool {
    if filter_contains(
        filters,
        "event",
        &["health_status", "exec_create", "exec_start"],
    ) {
        return filters.fuzzy_match("event", action);
    }
    filters.exact_match("event", action)
}

fn filter_contains(filters: &EventFilters, key: &str, values: &[&str]) -> bool {
    for value in filters.get(key) {
        if values.iter().any(|candidate| candidate == &value) {
            return true;
        }
    }
    false
}

fn fuzzy_match_name(
    filters: &EventFilters,
    key: &str,
    actor_id: &str,
    name: Option<&String>,
) -> bool {
    if filters.fuzzy_match(key, actor_id) {
        return true;
    }
    name.map(|value| filters.fuzzy_match(key, value))
        .unwrap_or(false)
}

fn match_image(
    filters: &EventFilters,
    event_type: &str,
    actor_id: &str,
    attributes: &HashMap<String, String>,
) -> bool {
    let name_attr = if event_type == "image" {
        "name"
    } else {
        "image"
    };
    let image_name = attributes
        .get(name_attr)
        .map(|value| value.as_str())
        .unwrap_or("");
    let stripped_id = strip_tag(actor_id);
    let stripped_name = strip_tag(image_name);

    filters.exact_match("image", actor_id)
        || filters.exact_match("image", image_name)
        || filters.exact_match("image", stripped_id.as_str())
        || filters.exact_match("image", stripped_name.as_str())
}

fn strip_tag(image: &str) -> String {
    let mut name = match image.split_once('@') {
        Some((prefix, _)) => prefix.to_string(),
        None => image.to_string(),
    };

    let last_slash = name.rfind('/');
    if let Some(colon) = name.rfind(':') {
        if last_slash.map_or(true, |slash| colon > slash) {
            name.truncate(colon);
        }
    }

    if let Some(stripped) = name.strip_prefix("docker.io/") {
        name = stripped.to_string();
        if let Some(stripped) = name.strip_prefix("library/") {
            name = stripped.to_string();
        }
    }

    name
}

fn normalize_container_name(name: &str) -> String {
    name.trim_start_matches('/').to_string()
}

fn normalize_signal(signal: &str) -> String {
    if !signal.is_empty() && signal.chars().all(|c| c.is_ascii_digit()) {
        return signal.to_string();
    }

    let upper = signal.trim().trim_start_matches("SIG").to_uppercase();
    let number = match upper.as_str() {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" => 29,
        "SYS" => 31,
        _ => return signal.to_string(),
    };
    number.to_string()
}

const MEDIA_TYPE_JSON: &str = "application/json";
const MEDIA_TYPE_JSON_LINES: &str = "application/jsonl";
const MEDIA_TYPE_NDJSON: &str = "application/x-ndjson";
const MEDIA_TYPE_JSON_SEQ: &str = "application/json-seq";
const JSON_SEQ_RS: u8 = 0x1e;

fn negotiate_event_content_type(headers: &HeaderMap) -> &'static str {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    for part in accept.split(',') {
        let media = part.trim().split(';').next().unwrap_or("").trim();
        match media {
            MEDIA_TYPE_JSON_SEQ => return MEDIA_TYPE_JSON_SEQ,
            MEDIA_TYPE_JSON_LINES => return MEDIA_TYPE_JSON_LINES,
            MEDIA_TYPE_NDJSON => return MEDIA_TYPE_NDJSON,
            MEDIA_TYPE_JSON => return MEDIA_TYPE_JSON,
            _ => {}
        }
    }

    MEDIA_TYPE_JSON
}

fn encode_event_line(event: &serde_json::Value, content_type: &str) -> std::io::Result<Bytes> {
    let mut payload = serde_json::to_vec(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    if content_type == MEDIA_TYPE_JSON_SEQ {
        let mut buf = Vec::with_capacity(payload.len() + 2);
        buf.push(JSON_SEQ_RS);
        buf.append(&mut payload);
        buf.push(b'\n');
        return Ok(Bytes::from(buf));
    }

    payload.push(b'\n');
    Ok(Bytes::from(payload))
}

fn api_version_from_uri(uri: &Uri) -> Option<String> {
    let path = uri.path().trim_start_matches('/');
    let mut segments = path.split('/');
    let first = segments.next()?;
    if let Some(version) = first.strip_prefix('v') {
        if !version.is_empty() {
            return Some(version.to_string());
        }
    }
    None
}

fn version_lt(version: &str, other: &str) -> bool {
    let Some(left) = parse_version(version) else {
        return true;
    };
    let Some(right) = parse_version(other) else {
        return false;
    };
    left < right
}

fn parse_version(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn merge_labels(
    mut attributes: HashMap<String, String>,
    labels: &HashMap<String, String>,
) -> HashMap<String, String> {
    for (key, value) in labels {
        attributes
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
    attributes
}

fn map_event(event: &Event) -> Option<EventMapping> {
    match event {
        Event::ContainerCreated {
            id,
            name,
            image,
            labels,
        } => {
            let mut attributes = HashMap::new();
            if !image.is_empty() {
                attributes.insert("image".to_string(), image.clone());
            }
            attributes.insert("name".to_string(), normalize_container_name(name));
            Some(EventMapping {
                event_type: "container",
                action: "create",
                actor_id: id.clone(),
                attributes: merge_labels(attributes, labels),
                legacy_from: if image.is_empty() {
                    None
                } else {
                    Some(image.clone())
                },
            })
        }
        Event::ContainerStarted {
            id,
            name,
            image,
            labels,
        } => {
            let mut attributes = HashMap::new();
            if !image.is_empty() {
                attributes.insert("image".to_string(), image.clone());
            }
            attributes.insert("name".to_string(), normalize_container_name(name));
            Some(EventMapping {
                event_type: "container",
                action: "start",
                actor_id: id.clone(),
                attributes: merge_labels(attributes, labels),
                legacy_from: if image.is_empty() {
                    None
                } else {
                    Some(image.clone())
                },
            })
        }
        Event::ContainerStopped {
            id,
            name,
            image,
            labels,
            exit_code: _,
        } => {
            let mut attributes = HashMap::new();
            if !image.is_empty() {
                attributes.insert("image".to_string(), image.clone());
            }
            attributes.insert("name".to_string(), normalize_container_name(name));
            Some(EventMapping {
                event_type: "container",
                action: "stop",
                actor_id: id.clone(),
                attributes: merge_labels(attributes, labels),
                legacy_from: if image.is_empty() {
                    None
                } else {
                    Some(image.clone())
                },
            })
        }
        Event::ContainerKilled {
            id,
            name,
            image,
            labels,
            signal,
            exit_code: _,
        } => {
            let mut attributes = HashMap::new();
            if !image.is_empty() {
                attributes.insert("image".to_string(), image.clone());
            }
            attributes.insert("name".to_string(), normalize_container_name(name));
            attributes.insert("signal".to_string(), normalize_signal(signal));
            Some(EventMapping {
                event_type: "container",
                action: "kill",
                actor_id: id.clone(),
                attributes: merge_labels(attributes, labels),
                legacy_from: if image.is_empty() {
                    None
                } else {
                    Some(image.clone())
                },
            })
        }
        Event::ContainerDied {
            id,
            name,
            image,
            labels,
            exit_code,
        } => {
            let mut attributes = HashMap::new();
            if !image.is_empty() {
                attributes.insert("image".to_string(), image.clone());
            }
            attributes.insert("name".to_string(), normalize_container_name(name));
            if let Some(code) = exit_code {
                attributes.insert("exitCode".to_string(), code.to_string());
            }
            Some(EventMapping {
                event_type: "container",
                action: "die",
                actor_id: id.clone(),
                attributes: merge_labels(attributes, labels),
                legacy_from: if image.is_empty() {
                    None
                } else {
                    Some(image.clone())
                },
            })
        }
        Event::ContainerRemoved {
            id,
            name,
            image,
            labels,
        } => {
            let mut attributes = HashMap::new();
            if !image.is_empty() {
                attributes.insert("image".to_string(), image.clone());
            }
            attributes.insert("name".to_string(), normalize_container_name(name));
            Some(EventMapping {
                event_type: "container",
                action: "destroy",
                actor_id: id.clone(),
                attributes: merge_labels(attributes, labels),
                legacy_from: if image.is_empty() {
                    None
                } else {
                    Some(image.clone())
                },
            })
        }
        Event::ImagePulled { id, reference } => Some(EventMapping {
            event_type: "image",
            action: "pull",
            actor_id: id.clone(),
            attributes: HashMap::from([("name".to_string(), reference.clone())]),
            legacy_from: None,
        }),
        Event::ImageRemoved { id, reference } => Some(EventMapping {
            event_type: "image",
            action: "delete",
            actor_id: id.clone(),
            attributes: HashMap::from([("name".to_string(), reference.clone())]),
            legacy_from: None,
        }),
        Event::NetworkCreated {
            id,
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "network",
            action: "create",
            actor_id: id.clone(),
            attributes: HashMap::from([
                ("name".to_string(), name.clone()),
                ("type".to_string(), driver.clone()),
            ]),
            legacy_from: None,
        }),
        Event::NetworkRemoved {
            id,
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "network",
            action: "destroy",
            actor_id: id.clone(),
            attributes: HashMap::from([
                ("name".to_string(), name.clone()),
                ("type".to_string(), driver.clone()),
            ]),
            legacy_from: None,
        }),
        Event::VolumeCreated {
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "volume",
            action: "create",
            actor_id: name.clone(),
            attributes: HashMap::from([("driver".to_string(), driver.clone())]),
            legacy_from: None,
        }),
        Event::VolumeRemoved {
            name,
            driver,
            labels: _,
        } => Some(EventMapping {
            event_type: "volume",
            action: "destroy",
            actor_id: name.clone(),
            attributes: HashMap::from([("driver".to_string(), driver.clone())]),
            legacy_from: None,
        }),
        Event::MachineCreated { name } => Some(EventMapping {
            event_type: "machine",
            action: "create",
            actor_id: name.clone(),
            attributes: HashMap::from([("name".to_string(), name.clone())]),
            legacy_from: None,
        }),
        Event::MachineStarted { name } => Some(EventMapping {
            event_type: "machine",
            action: "start",
            actor_id: name.clone(),
            attributes: HashMap::from([("name".to_string(), name.clone())]),
            legacy_from: None,
        }),
        Event::MachineStopped { name } => Some(EventMapping {
            event_type: "machine",
            action: "stop",
            actor_id: name.clone(),
            attributes: HashMap::from([("name".to_string(), name.clone())]),
            legacy_from: None,
        }),
        Event::VmStarted { id } => Some(EventMapping {
            event_type: "vm",
            action: "start",
            actor_id: id.clone(),
            attributes: HashMap::from([("id".to_string(), id.clone())]),
            legacy_from: None,
        }),
        Event::VmStopped { id } => Some(EventMapping {
            event_type: "vm",
            action: "stop",
            actor_id: id.clone(),
            attributes: HashMap::from([("id".to_string(), id.clone())]),
            legacy_from: None,
        }),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod events_tests {
    use super::{EventFilters, event_matches_filters, map_event, parse_event_filters};
    use arcbox_core::event::Event;
    use std::collections::HashMap;

    #[test]
    fn parse_filters_with_type_and_container() {
        let raw =
            r#"{"type":{"container":true},"container":{"abc123":true},"event":{"start":true}}"#;
        let filters = parse_event_filters(Some(raw.to_string())).unwrap();

        assert!(filters.get("type").contains(&"container".to_string()));
        assert!(filters.get("container").contains(&"abc123".to_string()));
        assert!(filters.get("event").contains(&"start".to_string()));
    }

    #[test]
    fn parse_filters_with_list_values() {
        let raw = r#"{"type":["container"],"container":["abc123"],"event":["start"]}"#;
        let filters = parse_event_filters(Some(raw.to_string())).unwrap();

        assert!(filters.get("type").contains(&"container".to_string()));
        assert!(filters.get("container").contains(&"abc123".to_string()));
        assert!(filters.get("event").contains(&"start".to_string()));
    }

    #[test]
    fn event_matches_respects_type_and_event_filters() {
        let mut filters = EventFilters::default();
        filters.add("type", "container".to_string());
        filters.add("container", "abc123".to_string());
        filters.add("event", "start".to_string());

        let attributes = HashMap::from([("name".to_string(), "abc123".to_string())]);
        assert!(event_matches_filters(
            &filters,
            "container",
            "start",
            "abc123",
            &attributes,
            "local"
        ));
        assert!(!event_matches_filters(
            &filters,
            "container",
            "stop",
            "abc123",
            &attributes,
            "local"
        ));
        assert!(!event_matches_filters(
            &filters,
            "image",
            "pull",
            "abc123",
            &attributes,
            "local"
        ));
    }

    #[test]
    fn event_filter_exec_start_uses_fuzzy_match() {
        let mut filters = EventFilters::default();
        filters.add("event", "exec_start".to_string());

        let attributes = HashMap::new();
        assert!(event_matches_filters(
            &filters,
            "container",
            "exec_start: /bin/sh -c echo hello",
            "abc123",
            &attributes,
            "local"
        ));
    }

    #[test]
    fn map_event_container_die_has_exit_code() {
        let event = Event::ContainerDied {
            id: "abc123".to_string(),
            name: "/demo".to_string(),
            image: "alpine:latest".to_string(),
            labels: HashMap::new(),
            exit_code: Some(42),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "container");
        assert_eq!(mapping.action, "die");
        assert_eq!(mapping.actor_id, "abc123");
        assert_eq!(mapping.attributes.get("name"), Some(&"demo".to_string()));
        assert_eq!(
            mapping.attributes.get("image"),
            Some(&"alpine:latest".to_string())
        );
        assert_eq!(mapping.attributes.get("exitCode"), Some(&"42".to_string()));
        assert_eq!(mapping.legacy_from.as_deref(), Some("alpine:latest"));
    }

    #[test]
    fn map_event_container_kill_has_signal_only() {
        let event = Event::ContainerKilled {
            id: "abc123".to_string(),
            name: "demo".to_string(),
            image: "alpine:latest".to_string(),
            labels: HashMap::new(),
            signal: "SIGKILL".to_string(),
            exit_code: Some(137),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "container");
        assert_eq!(mapping.action, "kill");
        assert_eq!(mapping.attributes.get("signal"), Some(&"9".to_string()));
        assert!(mapping.attributes.get("exitCode").is_none());
    }

    #[test]
    fn map_event_network_attributes_match_moby() {
        let event = Event::NetworkCreated {
            id: "net123".to_string(),
            name: "demo".to_string(),
            driver: "bridge".to_string(),
            labels: HashMap::from([("env".to_string(), "dev".to_string())]),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "network");
        assert_eq!(mapping.action, "create");
        assert_eq!(mapping.attributes.get("name"), Some(&"demo".to_string()));
        assert_eq!(mapping.attributes.get("type"), Some(&"bridge".to_string()));
        assert!(mapping.attributes.get("driver").is_none());
        assert!(mapping.attributes.get("env").is_none());
    }

    #[test]
    fn map_event_volume_attributes_match_moby() {
        let event = Event::VolumeCreated {
            name: "vol1".to_string(),
            driver: "local".to_string(),
            labels: HashMap::from([("env".to_string(), "dev".to_string())]),
        };

        let mapping = map_event(&event).unwrap();
        assert_eq!(mapping.event_type, "volume");
        assert_eq!(mapping.action, "create");
        assert_eq!(mapping.attributes.get("driver"), Some(&"local".to_string()));
        assert!(mapping.attributes.get("name").is_none());
        assert!(mapping.attributes.get("env").is_none());
    }
}
