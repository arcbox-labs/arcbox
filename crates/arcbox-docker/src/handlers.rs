//! Request handlers for Docker API endpoints.
//!
//! Each handler corresponds to a Docker API endpoint and will eventually
//! forward requests to arcbox-core services.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::types::*;
use arcbox_container::config::ContainerConfig as CoreContainerConfig;
use arcbox_core::event::Event;
use arcbox_protocol::agent::LogEntry;
use axum::Json;
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use futures::StreamExt;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde::de::Deserializer;
use std::collections::{HashMap, HashSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant, sleep};
use tokio_stream::wrappers::ReceiverStream;

// ============================================================================
// Container Handlers
// ============================================================================

/// List containers query parameters.
#[derive(Debug, Deserialize)]
pub struct ListContainersQuery {
    /// Show all containers.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub all: bool,
    /// Limit results.
    pub limit: Option<i32>,
    /// Show sizes.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub size: bool,
    /// Filters (JSON encoded).
    pub filters: Option<String>,
}

/// List containers.
pub async fn list_containers(
    State(state): State<AppState>,
    Query(query): Query<ListContainersQuery>,
) -> Result<Json<Vec<ContainerSummary>>> {
    let containers = state.runtime.container_manager().list();
    let show_all = query.all;

    let summaries: Vec<ContainerSummary> = containers
        .iter()
        .filter(|c| show_all || c.state == arcbox_container::state::ContainerState::Running)
        .map(|c| {
            // Extract ports from container config.
            let ports = c.config.as_ref().map_or(vec![], |cfg| {
                cfg.port_bindings
                    .iter()
                    .map(|pb| Port {
                        private_port: pb.container_port,
                        public_port: Some(pb.host_port),
                        port_type: pb.protocol.clone(),
                        ip: if pb.host_ip.is_empty() {
                            Some("0.0.0.0".to_string())
                        } else {
                            Some(pb.host_ip.clone())
                        },
                    })
                    .collect()
            });

            ContainerSummary {
                id: c.id.to_string(),
                names: vec![format!("/{}", c.name)],
                image: c.image.clone(),
                image_id: String::new(),
                command: String::new(),
                created: c.created.timestamp(),
                ports,
                size_rw: None,
                size_root_fs: None,
                labels: HashMap::new(),
                state: docker_state_string(c.state),
                status: format_container_status(c),
                network_settings: None,
                mounts: None,
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// Formats container status string.
fn format_container_status(c: &arcbox_container::state::Container) -> String {
    match c.state {
        arcbox_container::state::ContainerState::Created => "Created".to_string(),
        arcbox_container::state::ContainerState::Starting => "Created".to_string(),
        arcbox_container::state::ContainerState::Running => {
            if let Some(started) = c.started_at {
                let duration = chrono::Utc::now() - started;
                format!("Up {} seconds", duration.num_seconds())
            } else {
                "Up".to_string()
            }
        }
        arcbox_container::state::ContainerState::Paused => "Paused".to_string(),
        _ => {
            if let Some(code) = c.exit_code {
                format!("Exited ({})", code)
            } else {
                "Exited".to_string()
            }
        }
    }
}

fn docker_state_string(state: arcbox_container::state::ContainerState) -> String {
    match state {
        arcbox_container::state::ContainerState::Starting => "created".to_string(),
        _ => state.to_string(),
    }
}

/// Create container query parameters.
#[derive(Debug, Deserialize)]
pub struct CreateContainerQuery {
    /// Container name.
    pub name: Option<String>,
    /// Platform.
    pub platform: Option<String>,
}

/// Create container.
pub async fn create_container(
    State(state): State<AppState>,
    Query(params): Query<CreateContainerQuery>,
    Json(body): Json<ContainerCreateRequest>,
) -> Result<(StatusCode, Json<ContainerCreateResponse>)> {
    // Ensure VM is ready before creating container.
    // This transparently starts the VM if needed (OrbStack-like UX).
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;

    // Convert env from Vec<String> ("KEY=VALUE") to HashMap
    let env: HashMap<String, String> = body
        .env
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| {
            let mut parts = s.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((key.to_string(), value.to_string()))
        })
        .collect();

    // Parse volume binds from host_config into VolumeMount structs.
    // Format: /host/path:/container/path[:ro|rw]
    let volumes = body
        .host_config
        .as_ref()
        .and_then(|hc| hc.binds.as_ref())
        .map(|binds| {
            binds
                .iter()
                .filter_map(|bind| {
                    let parts: Vec<&str> = bind.split(':').collect();
                    if parts.len() >= 2 {
                        let read_only = parts.get(2).is_some_and(|&opt| opt == "ro");
                        Some(arcbox_container::config::VolumeMount {
                            source: parts[0].to_string(),
                            target: parts[1].to_string(),
                            read_only,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse port bindings from host_config.
    // Docker format: {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}
    let port_bindings = body
        .host_config
        .as_ref()
        .and_then(|hc| hc.port_bindings.as_ref())
        .map(|bindings| {
            bindings
                .iter()
                .flat_map(|(container_port_proto, host_bindings)| {
                    // Parse container port and protocol (e.g., "80/tcp" or "53/udp")
                    let (container_port, protocol) = {
                        let parts: Vec<&str> = container_port_proto.split('/').collect();
                        let port: u16 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
                        let proto = parts.get(1).unwrap_or(&"tcp").to_string();
                        (port, proto)
                    };

                    host_bindings.iter().filter_map(move |hb| {
                        let host_port: u16 = hb
                            .host_port
                            .as_ref()
                            .and_then(|p| p.parse().ok())
                            .unwrap_or(0);
                        if container_port > 0 && host_port > 0 {
                            Some(arcbox_container::config::PortBinding {
                                host_ip: hb.host_ip.clone().unwrap_or_default(),
                                host_port,
                                container_port,
                                protocol: protocol.clone(),
                            })
                        } else {
                            None
                        }
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let config = CoreContainerConfig {
        name: params.name,
        image: body.image,
        cmd: body.cmd.unwrap_or_default(),
        entrypoint: body.entrypoint.unwrap_or_default(),
        env,
        working_dir: body.working_dir,
        user: body.user,
        volumes,
        port_bindings,
        ..Default::default()
    };
    let config_image = config.image.clone();

    // Create container using the default machine.
    let machine_name = state.runtime.default_machine_name();
    let container_id = state
        .runtime
        .create_container(machine_name, config)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    let (container_name, container_image, container_labels) = state
        .runtime
        .container_manager()
        .get(&container_id)
        .map(|c| {
            let labels = c
                .config
                .as_ref()
                .map(|cfg| cfg.labels.clone())
                .unwrap_or_default();
            (c.name.clone(), c.image.clone(), labels)
        })
        .unwrap_or_else(|| (container_id.to_string(), config_image, HashMap::new()));

    state.runtime.event_bus().publish(Event::ContainerCreated {
        id: container_id.to_string(),
        name: container_name,
        image: container_image,
        labels: container_labels,
    });

    Ok((
        StatusCode::CREATED,
        Json(ContainerCreateResponse {
            id: container_id.to_string(),
            warnings: vec![],
        }),
    ))
}

/// Inspect container.
pub async fn inspect_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<ContainerInspectResponse>> {
    // Use resolve() to support both ID and name lookups.
    let container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Extract configuration from container
    let container_config = container.config.as_ref();

    // Build state response with all available fields
    let state_response = ContainerState {
        status: docker_state_string(container.state),
        running: container.state == arcbox_container::state::ContainerState::Running,
        paused: container.state == arcbox_container::state::ContainerState::Paused,
        restarting: container.state == arcbox_container::state::ContainerState::Restarting,
        oom_killed: false,
        dead: container.state == arcbox_container::state::ContainerState::Dead,
        pid: 0, // PID not tracked in container state currently
        exit_code: container.exit_code.unwrap_or(0),
        error: String::new(),
        started_at: container
            .started_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        finished_at: container
            .finished_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
    };

    // Extract command path and args from config
    let (path, args) = if let Some(cfg) = container_config {
        if !cfg.entrypoint.is_empty() {
            // Use entrypoint as path, cmd as args
            (
                cfg.entrypoint.first().cloned().unwrap_or_default(),
                cfg.entrypoint
                    .iter()
                    .skip(1)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .chain(cfg.cmd.iter().cloned())
                    .collect(),
            )
        } else if !cfg.cmd.is_empty() {
            // Use first cmd element as path, rest as args
            (
                cfg.cmd.first().cloned().unwrap_or_default(),
                cfg.cmd.iter().skip(1).cloned().collect(),
            )
        } else {
            (String::new(), vec![])
        }
    } else {
        (String::new(), vec![])
    };

    // Build container config response
    let config_response = if let Some(cfg) = container_config {
        // Convert env HashMap to Docker's KEY=VALUE format
        let env: Vec<String> = cfg
            .env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        ContainerConfig {
            hostname: cfg.name.clone().unwrap_or_else(|| container.name.clone()),
            user: cfg.user.clone().unwrap_or_default(),
            env,
            cmd: cfg.cmd.clone(),
            image: cfg.image.clone(),
            working_dir: cfg.working_dir.clone().unwrap_or_default(),
            entrypoint: if cfg.entrypoint.is_empty() {
                None
            } else {
                Some(cfg.entrypoint.clone())
            },
            labels: cfg.labels.clone(),
            tty: cfg.tty.unwrap_or(false),
            open_stdin: cfg.open_stdin.unwrap_or(false),
        }
    } else {
        // Fallback to minimal config
        ContainerConfig {
            hostname: container.name.clone(),
            user: String::new(),
            env: vec![],
            cmd: vec![],
            image: container.image.clone(),
            working_dir: String::new(),
            entrypoint: None,
            labels: HashMap::new(),
            tty: false,
            open_stdin: false,
        }
    };

    // Build mounts from volume configuration
    let mounts = if let Some(cfg) = container_config {
        cfg.volumes
            .iter()
            .map(|v| MountPoint {
                mount_type: if v.source.starts_with('/') {
                    "bind".to_string()
                } else {
                    "volume".to_string()
                },
                source: v.source.clone(),
                destination: v.target.clone(),
                mode: if v.read_only { "ro" } else { "rw" }.to_string(),
                rw: !v.read_only,
                propagation: "rprivate".to_string(),
            })
            .collect()
    } else {
        vec![]
    };

    Ok(Json(ContainerInspectResponse {
        id: container.id.to_string(),
        created: container.created.to_rfc3339(),
        path,
        args,
        state: state_response,
        image: container.image.clone(),
        name: format!("/{}", container.name),
        restart_count: 0,
        config: config_response,
        host_config: HostConfig::default(),
        network_settings: NetworkSettings::default(),
        mounts,
    }))
}

/// Start container.
pub async fn start_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    // Ensure VM is ready before starting container.
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;

    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    // Get container to find its machine, or use default.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Start through Runtime -> Agent.
    let started = state
        .runtime
        .start_container(&machine_name, &container_id)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    if started {
        let labels = container
            .config
            .as_ref()
            .map(|cfg| cfg.labels.clone())
            .unwrap_or_default();
        state.runtime.event_bus().publish(Event::ContainerStarted {
            id: container_id.to_string(),
            name: container.name.clone(),
            image: container.image.clone(),
            labels,
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Stop container query parameters.
#[derive(Debug, Deserialize)]
pub struct StopContainerQuery {
    /// Timeout in seconds.
    pub t: Option<u32>,
    /// Signal to send.
    pub signal: Option<String>,
}

/// Stop container.
pub async fn stop_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<StopContainerQuery>,
) -> Result<StatusCode> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);
    let timeout = params.t.unwrap_or(10); // Default 10 seconds timeout

    // Get container to find its machine.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Stop through Runtime -> Agent.
    state
        .runtime
        .stop_container(&machine_name, &container_id, timeout)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    let (labels, image, exit_code) = state
        .runtime
        .container_manager()
        .get(&container_id)
        .map(|c| {
            let labels = c
                .config
                .as_ref()
                .map(|cfg| cfg.labels.clone())
                .unwrap_or_default();
            (labels, c.image.clone(), c.exit_code)
        })
        .unwrap_or_else(|| {
            (
                container
                    .config
                    .as_ref()
                    .map(|cfg| cfg.labels.clone())
                    .unwrap_or_default(),
                container.image.clone(),
                None,
            )
        });

    state.runtime.event_bus().publish(Event::ContainerStopped {
        id: container_id.to_string(),
        name: container.name.clone(),
        image: image.clone(),
        labels: labels.clone(),
        exit_code,
    });
    state.runtime.event_bus().publish(Event::ContainerDied {
        id: container_id.to_string(),
        name: container.name.clone(),
        image,
        labels,
        exit_code,
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Kill container.
pub async fn kill_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let signal = params
        .get("signal")
        .cloned()
        .unwrap_or_else(|| "SIGKILL".to_string());
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    // Get container to find its machine.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Kill through Runtime -> Agent.
    state
        .runtime
        .kill_container(&machine_name, &container_id, &signal)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    let (labels, image, exit_code) = state
        .runtime
        .container_manager()
        .get(&container_id)
        .map(|c| {
            let labels = c
                .config
                .as_ref()
                .map(|cfg| cfg.labels.clone())
                .unwrap_or_default();
            (labels, c.image.clone(), c.exit_code)
        })
        .unwrap_or_else(|| {
            (
                container
                    .config
                    .as_ref()
                    .map(|cfg| cfg.labels.clone())
                    .unwrap_or_default(),
                container.image.clone(),
                None,
            )
        });

    state.runtime.event_bus().publish(Event::ContainerKilled {
        id: container_id.to_string(),
        name: container.name.clone(),
        image: image.clone(),
        labels: labels.clone(),
        signal,
        exit_code,
    });
    state.runtime.event_bus().publish(Event::ContainerDied {
        id: container_id.to_string(),
        name: container.name.clone(),
        image,
        labels,
        exit_code,
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Restart container query parameters.
#[derive(Debug, Deserialize)]
pub struct RestartContainerQuery {
    /// Timeout in seconds.
    pub t: Option<u32>,
}

/// Restart container.
pub async fn restart_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<RestartContainerQuery>,
) -> Result<StatusCode> {
    // Ensure VM is ready before restarting container.
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;

    let container_id = arcbox_container::state::ContainerId::from_string(&id);
    let timeout = params.t.unwrap_or(10);

    // Get container to find its machine.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Restart = stop + start through Runtime -> Agent.
    state
        .runtime
        .stop_container(&machine_name, &container_id, timeout)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    let (labels, image, exit_code) = state
        .runtime
        .container_manager()
        .get(&container_id)
        .map(|c| {
            let labels = c
                .config
                .as_ref()
                .map(|cfg| cfg.labels.clone())
                .unwrap_or_default();
            (labels, c.image.clone(), c.exit_code)
        })
        .unwrap_or_else(|| {
            (
                container
                    .config
                    .as_ref()
                    .map(|cfg| cfg.labels.clone())
                    .unwrap_or_default(),
                container.image.clone(),
                None,
            )
        });

    state.runtime.event_bus().publish(Event::ContainerStopped {
        id: container_id.to_string(),
        name: container.name.clone(),
        image: image.clone(),
        labels: labels.clone(),
        exit_code,
    });
    state.runtime.event_bus().publish(Event::ContainerDied {
        id: container_id.to_string(),
        name: container.name.clone(),
        image: image.clone(),
        labels: labels.clone(),
        exit_code,
    });

    let started = state
        .runtime
        .start_container(&machine_name, &container_id)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    if started {
        state.runtime.event_bus().publish(Event::ContainerStarted {
            id: container_id.to_string(),
            name: container.name.clone(),
            image,
            labels,
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Remove container query parameters.
#[derive(Debug, Deserialize)]
pub struct RemoveContainerQuery {
    /// Force remove.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub force: bool,
    /// Remove volumes.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub v: bool,
    /// Remove link.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub link: bool,
}

/// Remove container.
pub async fn remove_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<RemoveContainerQuery>,
) -> Result<StatusCode> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    // Get container to find its machine.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Remove through Runtime -> Agent (if VM is running).
    // If VM is not running, just remove from local state.
    if state.runtime.vm_lifecycle().is_running().await {
        state
            .runtime
            .remove_container(&machine_name, &container_id, params.force)
            .await
            .map_err(|e| DockerError::Server(e.to_string()))?;
    } else {
        // VM not running, just remove from local state.
        state
            .runtime
            .container_manager()
            .remove(&container_id)
            .map_err(|e| match e {
                arcbox_container::ContainerError::NotFound(_) => DockerError::ContainerNotFound(id),
                _ => DockerError::Server(e.to_string()),
            })?;
    }

    let labels = container
        .config
        .as_ref()
        .map(|cfg| cfg.labels.clone())
        .unwrap_or_default();
    state.runtime.event_bus().publish(Event::ContainerRemoved {
        id: container_id.to_string(),
        name: container.name.clone(),
        image: container.image.clone(),
        labels,
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Wait for container.
///
/// Blocks until the container exits and returns the exit code.
pub async fn wait_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<WaitResponse>> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    // Check if container exists and get its machine name.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let machine_name = container
        .machine_name
        .clone()
        .ok_or_else(|| DockerError::Server("container has no machine assigned".to_string()))?;

    let should_emit_die = matches!(
        container.state,
        arcbox_container::state::ContainerState::Running
            | arcbox_container::state::ContainerState::Starting
    );

    // Connect to agent and wait for container to exit.
    #[cfg(target_os = "macos")]
    let exit_code = {
        let mut agent = state
            .runtime
            .machine_manager()
            .connect_agent(&machine_name)
            .map_err(|e| DockerError::Server(format!("failed to connect to agent: {}", e)))?;
        agent
            .wait_container(&id)
            .await
            .map_err(|e| DockerError::Server(format!("wait failed: {}", e)))?
    };

    #[cfg(target_os = "linux")]
    let exit_code = {
        let cid = state
            .runtime
            .machine_manager()
            .get_cid(&machine_name)
            .ok_or_else(|| DockerError::Server("machine has no CID".to_string()))?;
        let agent = state.runtime.agent_pool().get(cid).await;
        let mut agent = agent.write().await;
        agent
            .wait_container(&id)
            .await
            .map_err(|e| DockerError::Server(format!("wait failed: {}", e)))?
    };

    // Update container state.
    state
        .runtime
        .container_manager()
        .notify_exit(&container_id, exit_code);

    if should_emit_die {
        let labels = container
            .config
            .as_ref()
            .map(|cfg| cfg.labels.clone())
            .unwrap_or_default();
        state.runtime.event_bus().publish(Event::ContainerDied {
            id: container_id.to_string(),
            name: container.name.clone(),
            image: container.image.clone(),
            labels,
            exit_code: Some(exit_code),
        });
    }

    Ok(Json(WaitResponse {
        status_code: i64::from(exit_code),
        error: None,
    }))
}

/// Container logs query parameters.
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// Follow log output.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub follow: bool,
    /// Show stdout.
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub stdout: bool,
    /// Show stderr.
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub stderr: bool,
    /// Since timestamp.
    pub since: Option<i64>,
    /// Until timestamp.
    pub until: Option<i64>,
    /// Show timestamps.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub timestamps: bool,
    /// Tail lines.
    pub tail: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Deserialize a boolean from query string.
///
/// Docker CLI sends booleans as "true", "false", "1", "0", or empty string.
/// We need to be lenient and handle all these cases.
fn deserialize_bool<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" | "" => Ok(false),
        _ => {
            // Be lenient: treat unknown values as false instead of erroring
            tracing::warn!("Unknown boolean value '{}', treating as false", value);
            Ok(false)
        }
    }
}

/// Deserialize an optional boolean from query string.
///
/// Returns None if the value is empty or not provided.
fn deserialize_option_bool<'de, D>(deserializer: D) -> std::result::Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Option<String> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(s) => match s.to_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(Some(true)),
            "false" | "0" | "no" => Ok(Some(false)),
            "" => Ok(None),
            _ => {
                tracing::warn!("Unknown boolean value '{}', treating as None", s);
                Ok(None)
            }
        },
    }
}

/// Encodes data in Docker multiplexed stream format.
///
/// Format: [stream_type, 0, 0, 0, size (4 bytes BE), data]
/// stream_type: 1=stdout, 2=stderr
fn encode_docker_stream(stream_type: u8, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut output = Vec::with_capacity(8 + data.len());
    output.push(stream_type);
    output.extend_from_slice(&[0, 0, 0]);
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(data);
    output
}

/// Get container logs.
///
/// Returns logs in Docker raw-stream format:
/// - For TTY containers: plain text
/// - For non-TTY containers: 8-byte header + data
///   Header: [stream_type (1 byte), 0, 0, 0, size (4 bytes big-endian)]
///   stream_type: 0=stdin, 1=stdout, 2=stderr
///
/// When `follow=true`, returns a streaming response.
pub async fn container_logs(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<LogsQuery>,
) -> Result<Response> {
    // Verify container exists and get machine name.
    // Use resolve() to support both ID and name lookups.
    let container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Log query parameters for debugging.
    tracing::debug!(
        container = %id,
        follow = params.follow,
        stdout = params.stdout,
        stderr = params.stderr,
        tail = ?params.tail,
        "container logs request"
    );

    // Parse tail parameter.
    let tail: i64 = params
        .tail
        .as_ref()
        .and_then(|t| if t == "all" { Some(0) } else { t.parse().ok() })
        .unwrap_or(0);

    // Get machine name from container.
    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Use resolved container ID for agent communication.
    let container_id = container.id.to_string();

    // Check if we should stream (follow mode).
    if params.follow {
        // Streaming mode: return a streaming response.
        return container_logs_stream(
            state,
            container_id,
            machine_name,
            params.stdout,
            params.stderr,
            params.since.unwrap_or(0),
            params.until.unwrap_or(0),
            params.timestamps,
            tail,
        )
        .await;
    }

    // Non-streaming mode: get all logs at once.
    let mut log_entries = Vec::new();

    if params.stdout && params.stderr {
        let stdout_entry = state
            .runtime
            .container_logs(
                &machine_name,
                &container_id,
                false,
                true,
                false,
                params.since.unwrap_or(0),
                params.until.unwrap_or(0),
                params.timestamps,
                tail,
            )
            .await;
        let stderr_entry = state
            .runtime
            .container_logs(
                &machine_name,
                &container_id,
                false,
                false,
                true,
                params.since.unwrap_or(0),
                params.until.unwrap_or(0),
                params.timestamps,
                tail,
            )
            .await;

        if let Ok(entry) = stdout_entry {
            log_entries.push(entry);
        }
        if let Ok(entry) = stderr_entry {
            log_entries.push(entry);
        }
    } else {
        let log_entry = state
            .runtime
            .container_logs(
                &machine_name,
                &container_id,
                false,
                params.stdout,
                params.stderr,
                params.since.unwrap_or(0),
                params.until.unwrap_or(0),
                params.timestamps,
                tail,
            )
            .await;

        if let Ok(entry) = log_entry {
            log_entries.push(entry);
        }
    }

    if log_entries.is_empty() {
        tracing::warn!(container_id = %container_id, "Failed to get logs from agent");
        log_entries.push(LogEntry::default());
    }

    // Encode in Docker multiplexed stream format.
    let mut output = Vec::new();
    for entry in log_entries {
        let stream_type: u8 = if entry.stream == "stderr" { 2 } else { 1 };
        output.extend_from_slice(&encode_docker_stream(stream_type, &entry.data));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.docker.raw-stream",
        )
        .body(Body::from(output))
        .unwrap())
}

/// Streaming container logs handler.
async fn container_logs_stream(
    state: AppState,
    container_id: String,
    machine_name: String,
    stdout: bool,
    stderr: bool,
    since: i64,
    until: i64,
    timestamps: bool,
    tail: i64,
) -> Result<Response> {
    // Try to get log stream from agent.
    let log_stream = match state
        .runtime
        .container_logs_stream(
            &machine_name,
            &container_id,
            stdout,
            stderr,
            since,
            until,
            timestamps,
            tail,
        )
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!("Failed to get log stream from agent: {}", e);
            // Return empty streaming response.
            let (tx, rx) =
                tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
            drop(tx); // Close immediately.
            let body = Body::from_stream(ReceiverStream::new(rx));

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "application/vnd.docker.raw-stream",
                )
                .body(body)
                .unwrap());
        }
    };

    // Transform log entries to Docker stream format.
    let body_stream = log_stream.map(move |result| {
        match result {
            Ok(entry) => {
                let stream_type: u8 = if entry.stream == "stderr" { 2 } else { 1 };
                let encoded = encode_docker_stream(stream_type, &entry.data);
                Ok::<_, std::io::Error>(Bytes::from(encoded))
            }
            Err(e) => {
                tracing::warn!("Log stream error: {}", e);
                // Return empty bytes on error to keep stream alive.
                Ok(Bytes::new())
            }
        }
    });

    let body = Body::from_stream(body_stream);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.docker.raw-stream",
        )
        .body(body)
        .unwrap())
}

// ============================================================================
// Events Handler
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

    fn contains(&self, key: &str) -> bool {
        self.fields.contains_key(key)
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
    Query(params): Query<EventsQuery>,
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
    let (tx, rx) =
        tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(64);

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
                                map.insert("id".to_string(), serde_json::Value::String(mapping.actor_id.clone()));
                                map.insert(
                                    "status".to_string(),
                                    serde_json::Value::String(mapping.action.to_string()),
                                );
                                if let Some(from) = &mapping.legacy_from {
                                    map.insert("from".to_string(), serde_json::Value::String(from.clone()));
                                }
                            } else if mapping.event_type == "image" {
                                map.insert("id".to_string(), serde_json::Value::String(mapping.actor_id.clone()));
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
    if filter_contains(filters, "event", &["health_status", "exec_create", "exec_start"]) {
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
    let name_attr = if event_type == "image" { "name" } else { "image" };
    let image_name = attributes.get(name_attr).map(|value| value.as_str()).unwrap_or("");
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

fn encode_event_line(
    event: &serde_json::Value,
    content_type: &str,
) -> std::io::Result<Bytes> {
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
        attributes.entry(key.clone()).or_insert_with(|| value.clone());
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
                legacy_from: if image.is_empty() { None } else { Some(image.clone()) },
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
                legacy_from: if image.is_empty() { None } else { Some(image.clone()) },
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
                legacy_from: if image.is_empty() { None } else { Some(image.clone()) },
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
                legacy_from: if image.is_empty() { None } else { Some(image.clone()) },
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
                legacy_from: if image.is_empty() { None } else { Some(image.clone()) },
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
                legacy_from: if image.is_empty() { None } else { Some(image.clone()) },
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
// Attach Handler
// ============================================================================

/// Attach to container query parameters.
#[derive(Debug, Deserialize)]
pub struct AttachContainerQuery {
    /// Attach to stdin.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub stdin: bool,
    /// Attach to stdout.
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub stdout: bool,
    /// Attach to stderr.
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub stderr: bool,
    /// Stream output.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub stream: bool,
    /// Return logs.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub logs: bool,
}

/// Attach to a container.
///
/// This endpoint streams container output. The agent waits for the process to
/// appear and replays backlog so fast commands are not missed.
/// For non-TTY containers, output is encoded in Docker multiplexed stream format.
///
/// Docker CLI expects either:
/// - 101 Switching Protocols (for interactive/TTY)
/// - 200 OK with Content-Type: application/vnd.docker.raw-stream (for non-interactive)
pub async fn attach_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<AttachContainerQuery>,
    mut req: Request<Body>,
) -> Result<Response> {
    tracing::debug!(
        "attach_container: id={}, stdout={}, stderr={}, stream={}, logs={}",
        id,
        params.stdout,
        params.stderr,
        params.stream,
        params.logs
    );
    let upgrade_hdr = req
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let connection_hdr = req
        .headers()
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    tracing::debug!(
        "attach_container: request headers upgrade='{}' connection='{}'",
        upgrade_hdr,
        connection_hdr
    );
    tracing::debug!("attach_container: http version={:?}", req.version());

    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    // Check if container exists.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());
    let is_tty = container
        .config
        .as_ref()
        .and_then(|c| c.tty)
        .unwrap_or(false);
    let open_stdin = container
        .config
        .as_ref()
        .and_then(|c| c.open_stdin)
        .unwrap_or(false);
    let attach_stdin = params.stdin && open_stdin;

    // Ensure VM is ready.
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;

    let container_state = container.state;
    tracing::debug!("attach_container: container state = {:?}", container_state);

    // Only reject if container is being removed or dead - these are terminal states.
    // For Created/Starting, we'll wait inside the spawned task after returning 101.
    // This allows Docker CLI to send the /start request concurrently.
    if matches!(
        container_state,
        arcbox_container::state::ContainerState::Removing
            | arcbox_container::state::ContainerState::Dead
    ) {
        return Err(DockerError::Server(format!(
            "container {} is not running",
            id
        )));
    }

    // Optional: prepend existing logs when `logs=true`.
    let initial_chunk = if params.logs {
        match state
            .runtime
            .container_logs(
                &machine_name,
                &id,
                false, // follow
                params.stdout,
                params.stderr,
                0,
                0,
                false,
                -1,
            )
            .await
        {
            Ok(entry) => {
                let stream_type: u8 = if entry.stream == "stderr" { 2 } else { 1 };
                let encoded = if is_tty {
                    entry.data
                } else {
                    encode_docker_stream(stream_type, &entry.data)
                };
                if encoded.is_empty() {
                    None
                } else {
                    Some(Bytes::from(encoded))
                }
            }
            Err(e) => {
                tracing::warn!("attach_container: failed to read initial logs: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Prepare upgrade response and spawn bidirectional bridge.
    // Content-Type is required by Docker CLI to recognize the hijacked connection.
    let content_type = if is_tty {
        "application/vnd.docker.raw-stream"
    } else {
        "application/vnd.docker.multiplexed-stream"
    };

    let upgraded = hyper::upgrade::on(&mut req);
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .header(axum::http::header::CONNECTION, "Upgrade")
        .header(axum::http::header::UPGRADE, "tcp")
        .body(Body::empty())
        .unwrap();

    let state = state.clone();
    let container_id = container_id.clone();
    let id = id.clone();
    let machine_name = machine_name.clone();
    let attach_stdout = params.stdout;
    let attach_stderr = params.stderr;
    tokio::spawn(async move {
        match upgraded.await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let (mut reader, mut writer) = tokio::io::split(io);

                // Wait for container to be ready (Running or Exited) if it's still starting.
                // This is done inside the spawned task so the 101 response is sent first,
                // allowing Docker CLI to send the /start request concurrently.
                let container_state = match state
                    .runtime
                    .container_manager()
                    .wait_for_running_or_exited(&container_id, std::time::Duration::from_secs(30))
                    .await
                {
                    Ok(state) => {
                        tracing::debug!("attach_container: container now in state {:?}", state);
                        state
                    }
                    Err(e) => {
                        tracing::warn!("attach_container: timeout waiting for container: {}", e);
                        return;
                    }
                };

                // For exited containers, we still proceed to attach to get any buffered output
                // from the backlog. This is important for fast-exiting containers like `echo`.
                if matches!(
                    container_state,
                    arcbox_container::state::ContainerState::Exited
                        | arcbox_container::state::ContainerState::Dead
                ) {
                    tracing::debug!(
                        "attach_container: container already exited, will try to get buffered output"
                    );
                }

                let (mut output_stream, input_tx) = match state
                    .runtime
                    .container_attach(
                        &machine_name,
                        &id,
                        None,
                        attach_stdin,
                        attach_stdout,
                        attach_stderr,
                        0,
                        0,
                    )
                    .await
                {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::warn!("attach_container: failed to attach: {}", e);
                        return;
                    }
                };

                // Writer: send container output to client.
                let write_task = tokio::spawn(async move {
                    if let Some(chunk) = initial_chunk {
                        if writer.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }

                    while let Some(item) = output_stream.next().await {
                        match item {
                            Ok(out) => {
                                let stream_type: u8 = if out.stream == "stderr" { 2 } else { 1 };
                                let data = if is_tty {
                                    out.data
                                } else {
                                    encode_docker_stream(stream_type, &out.data)
                                };
                                if let Err(e) = writer.write_all(&data).await {
                                    tracing::debug!("attach write error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("attach output stream error: {}", e);
                                break;
                            }
                        }
                    }
                    let _ = writer.shutdown().await;
                });

                // Reader: forward client input to agent.
                let read_task = tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) => {
                                // Signal stdin close to agent so exec can terminate.
                                tracing::debug!("exec attach reader: client EOF, sending stdin close");
                                let _ = input_tx
                                    .send(arcbox_protocol::agent::AttachInput {
                                        data: Vec::new(),
                                        resize: false,
                                        width: 0,
                                        height: 0,
                                    })
                                    .await;
                                break;
                            }
                            Ok(n) => {
                                tracing::debug!("exec attach reader: received {} bytes", n);
                                let msg = arcbox_protocol::agent::AttachInput {
                                    data: buf[..n].to_vec(),
                                    resize: false,
                                    width: 0,
                                    height: 0,
                                };
                                if input_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::debug!("attach read error: {}", e);
                                break;
                            }
                        }
                    }
                });

                let _ = tokio::join!(write_task, read_task);
            }
            Err(e) => {
                tracing::warn!("upgrade to attach failed: {}", e);
            }
        }
    });

    Ok(response)
}

/// Concatenate a list of Bytes into one buffer.
fn concat_bytes(chunks: &[Bytes]) -> Bytes {
    if chunks.is_empty() {
        return Bytes::new();
    }
    let total: usize = chunks.iter().map(|b| b.len()).sum();
    let mut buf = Vec::with_capacity(total);
    for chunk in chunks {
        buf.extend_from_slice(chunk);
    }
    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_docker_stream_formats_header() {
        let data = b"abc";
        let frame = encode_docker_stream(1, data);
        assert_eq!(frame[0], 1);
        assert_eq!(&frame[4..8], &(data.len() as u32).to_be_bytes());
        assert_eq!(&frame[8..], data);
    }

    #[test]
    fn concat_bytes_preserves_order() {
        let chunks = vec![Bytes::from_static(b"foo"), Bytes::from_static(b"bar")];
        let out = concat_bytes(&chunks);
        assert_eq!(out, Bytes::from_static(b"foobar"));
    }
}
// ============================================================================
// Exec Handlers
// ============================================================================

/// Create exec instance.
pub async fn exec_create(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ExecCreateRequest>,
) -> Result<(StatusCode, Json<ExecCreateResponse>)> {
    use arcbox_container::{ContainerId, ExecConfig};

    // Verify container exists.
    let container_id = ContainerId::from_string(&id);
    if state
        .runtime
        .container_manager()
        .get(&container_id)
        .is_none()
    {
        return Err(DockerError::ContainerNotFound(id));
    }

    // Build exec config.
    let config = ExecConfig {
        container_id,
        cmd: body.cmd,
        env: body.env.unwrap_or_default(),
        working_dir: body.working_dir,
        attach_stdin: body.attach_stdin.unwrap_or(false),
        attach_stdout: body.attach_stdout.unwrap_or(true),
        attach_stderr: body.attach_stderr.unwrap_or(true),
        tty: body.tty.unwrap_or(false),
        user: body.user,
        privileged: body.privileged.unwrap_or(false),
    };

    // Create exec instance.
    let exec_id = state
        .runtime
        .exec_manager()
        .create(config)
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(ExecCreateResponse {
            id: exec_id.to_string(),
        }),
    ))
}

/// Start exec instance.
pub async fn exec_start(
    State(state): State<AppState>,
    Path(id): Path<String>,
    mut req: Request<Body>,
) -> Result<Response> {
    use arcbox_container::ExecId;

    let exec_id = ExecId::from_string(&id);
    let upgrade_hdr = req
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let connection_hdr = req
        .headers()
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    tracing::debug!(
        "exec_start: request headers upgrade='{}' connection='{}'",
        upgrade_hdr,
        connection_hdr
    );
    tracing::debug!("exec_start: http version={:?}", req.version());

    // Parse body manually to keep request for upgrade.
    let body_bytes = to_bytes(std::mem::take(req.body_mut()), 1024 * 1024)
        .await
        .map_err(|e| DockerError::BadRequest(format!("invalid exec start body: {}", e)))?;
    let body: ExecStartRequest = if body_bytes.is_empty() {
        ExecStartRequest::default()
    } else {
        serde_json::from_slice(&body_bytes).map_err(|e| {
            DockerError::BadRequest(format!("failed to decode exec start body: {}", e))
        })?
    };

    // Get exec instance.
    let exec = state
        .runtime
        .exec_manager()
        .get(&exec_id)
        .ok_or_else(|| DockerError::NotImplemented(format!("exec {id} not found")))?;

    // Get container to find its machine.
    let container = state
        .runtime
        .container_manager()
        .get(&exec.config.container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(exec.config.container_id.to_string()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    let detach = body.detach.unwrap_or(false);
    let tty = body.tty.unwrap_or(exec.config.tty);
    let (tty_width, tty_height) = body
        .console_size
        .clone()
        .and_then(|v| {
            if v.len() >= 2 {
                Some((v[0], v[1]))
            } else {
                None
            }
        })
        .unwrap_or((80, 24));

    // Ensure VM is ready before executing.
    state
        .runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure VM is ready: {}", e)))?;

    // Convert env from Vec<String> to HashMap.
    let env: std::collections::HashMap<String, String> = exec
        .config
        .env
        .iter()
        .filter_map(|e| {
            let parts: Vec<&str> = e.splitn(2, '=').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect();

    // Start exec process in guest (streaming ready).
    state
        .runtime
        .exec_start_streaming(
            &machine_name,
            &exec_id.to_string(),
            &exec.config.container_id.to_string(),
            exec.config.cmd.clone(),
            env,
            exec.config.working_dir.clone(),
            exec.config.user.clone(),
            tty,
            detach,
            tty_width,
            tty_height,
        )
        .await
        .map_err(|e| DockerError::Server(format!("failed to start exec: {}", e)))?;

    if detach {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    // Attach to exec stream.
    let (mut output_stream, input_tx) = state
        .runtime
        .exec_attach(
            &machine_name,
            &exec_id.to_string(),
            exec.config.attach_stdin,
            exec.config.attach_stdout,
            exec.config.attach_stderr,
            tty_width,
            tty_height,
        )
        .await
        .map_err(|e| DockerError::Server(format!("failed to attach exec: {}", e)))?;

    let upgraded = hyper::upgrade::on(&mut req);
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(axum::http::header::CONNECTION, "Upgrade")
        .header(axum::http::header::UPGRADE, "tcp")
        .body(Body::empty())
        .unwrap();

    tokio::spawn(async move {
        match upgraded.await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let (mut reader, mut writer) = tokio::io::split(io);
                let input_tx = input_tx;

                // Writer task: exec output to client.
                let write_task = tokio::spawn(async move {
                    while let Some(item) = output_stream.next().await {
                        match item {
                            Ok(out) => {
                                let stream_type: u8 = if out.stream == "stderr" { 2 } else { 1 };
                                let data = if tty {
                                    out.data
                                } else {
                                    encode_docker_stream(stream_type, &out.data)
                                };
                                if let Err(e) = writer.write_all(&data).await {
                                    tracing::debug!("exec attach write error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("exec output stream error: {}", e);
                                break;
                            }
                        }
                    }
                    let _ = writer.shutdown().await;
                });

                // Reader task: stdin to exec.
                let read_task = tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let msg = arcbox_protocol::agent::AttachInput {
                                    data: buf[..n].to_vec(),
                                    resize: false,
                                    width: 0,
                                    height: 0,
                                };
                                if input_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::debug!("exec attach read error: {}", e);
                                break;
                            }
                        }
                    }
                });

                let _ = tokio::join!(write_task, read_task);
            }
            Err(e) => {
                tracing::warn!("upgrade to exec attach failed: {}", e);
            }
        }
    });

    Ok(response)
}

/// Resize exec TTY.
pub async fn exec_resize(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    use arcbox_container::ExecId;

    let h: u32 = params.get("h").and_then(|v| v.parse().ok()).unwrap_or(24);
    let w: u32 = params.get("w").and_then(|v| v.parse().ok()).unwrap_or(80);

    let exec_id = ExecId::from_string(&id);

    let exec = state
        .runtime
        .exec_manager()
        .get(&exec_id)
        .ok_or_else(|| DockerError::NotImplemented(format!("exec {id} not found")))?;

    let container = state
        .runtime
        .container_manager()
        .get(&exec.config.container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(exec.config.container_id.to_string()))?;

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Resize via agent.
    state
        .runtime
        .exec_resize(&machine_name, &exec_id.to_string(), w, h)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(StatusCode::OK)
}

/// Inspect exec instance.
pub async fn exec_inspect(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ExecInspectResponse>> {
    use arcbox_container::ExecId;

    let exec_id = ExecId::from_string(&id);

    let exec = state
        .runtime
        .exec_manager()
        .get(&exec_id)
        .ok_or_else(|| DockerError::NotImplemented(format!("exec {id} not found")))?;

    Ok(Json(ExecInspectResponse {
        can_remove: !exec.running,
        container_id: exec.config.container_id.to_string(),
        detach_keys: String::new(),
        exit_code: exec.exit_code.unwrap_or(0),
        id: exec.id.to_string(),
        open_stderr: exec.config.attach_stderr,
        open_stdin: exec.config.attach_stdin,
        open_stdout: exec.config.attach_stdout,
        running: exec.running,
        pid: exec.pid.map_or(0, |p| p as i32),
    }))
}

// ============================================================================
// Image Handlers
// ============================================================================

/// List images query parameters.
#[derive(Debug, Deserialize)]
pub struct ListImagesQuery {
    /// Show all images.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub all: bool,
    /// Show digests.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub digests: bool,
    /// Filters (JSON encoded).
    pub filters: Option<String>,
}

/// List images.
pub async fn list_images(
    State(state): State<AppState>,
    Query(_query): Query<ListImagesQuery>,
) -> Result<Json<Vec<ImageSummary>>> {
    let images = state.runtime.image_store().list();

    let summaries: Vec<ImageSummary> = images
        .iter()
        .map(|img| ImageSummary {
            id: format!("sha256:{}", &img.id),
            parent_id: String::new(),
            repo_tags: vec![img.reference.to_string()],
            repo_digests: vec![],
            created: img.created.timestamp(),
            size: img.size as i64,
            virtual_size: img.size as i64,
            shared_size: Some(-1),
            labels: HashMap::new(),
            containers: Some(-1),
        })
        .collect();

    Ok(Json(summaries))
}

/// Inspect image.
pub async fn inspect_image(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ImageInspectResponse>> {
    use arcbox_image::ImageRef;

    // Try to parse as image reference.
    let reference = ImageRef::parse(&id).ok_or_else(|| DockerError::ImageNotFound(id.clone()))?;

    let image = state
        .runtime
        .image_store()
        .get(&reference)
        .ok_or_else(|| DockerError::ImageNotFound(id.clone()))?;

    Ok(Json(ImageInspectResponse {
        id: format!("sha256:{}", image.id),
        repo_tags: vec![image.reference.to_string()],
        repo_digests: vec![],
        parent: String::new(),
        comment: String::new(),
        created: image.created.to_rfc3339(),
        author: String::new(),
        architecture: std::env::consts::ARCH.to_string(),
        os: "linux".to_string(),
        size: image.size as i64,
        virtual_size: image.size as i64,
        config: ContainerConfig::default(),
        root_fs: RootFS {
            root_type: "layers".to_string(),
            layers: vec![],
        },
    }))
}

/// Pull image query parameters.
#[derive(Debug, Deserialize)]
pub struct PullImageQuery {
    /// Image to pull.
    #[serde(rename = "fromImage")]
    pub from_image: Option<String>,
    /// Image source.
    #[serde(rename = "fromSrc")]
    pub from_src: Option<String>,
    /// Repository name.
    pub repo: Option<String>,
    /// Tag.
    pub tag: Option<String>,
    /// Platform.
    pub platform: Option<String>,
}

/// Pull image.
pub async fn pull_image(
    State(state): State<AppState>,
    Query(params): Query<PullImageQuery>,
) -> Result<impl IntoResponse> {
    use arcbox_image::pull::ImagePuller;
    use arcbox_image::{ImageRef, RegistryClient};

    let image = params.from_image.unwrap_or_default();
    let tag = params.tag.unwrap_or_else(|| "latest".to_string());

    // Parse image reference.
    let reference = ImageRef::parse(&format!("{image}:{tag}")).ok_or_else(|| {
        DockerError::BadRequest(format!("invalid image reference: {image}:{tag}"))
    })?;

    // Build NDJSON output.
    let mut output = String::new();

    // Initial status.
    output.push_str(&format!(
        "{}\n",
        serde_json::json!({"status": format!("Pulling from {}", reference.repository)})
    ));

    // Pull the image.
    let store = state.runtime.image_store().clone();
    let client = RegistryClient::new(&reference.registry);
    let puller = ImagePuller::new(store, client);

    match puller.pull(&reference).await {
        Ok(image_id) => {
            let image_id_full = if image_id.starts_with("sha256:") {
                image_id.clone()
            } else {
                format!("sha256:{}", image_id)
            };
            // Short ID for display.
            let short_id = image_id_full.strip_prefix("sha256:").unwrap_or(&image_id_full);
            let short_id = &short_id[..12.min(short_id.len())];

            output.push_str(&format!(
                "{}\n",
                serde_json::json!({"status": "Pull complete", "id": short_id})
            ));

            output.push_str(&format!(
                "{}\n",
                serde_json::json!({"status": format!("Digest: {}", image_id)})
            ));

            output.push_str(&format!(
                "{}\n",
                serde_json::json!({"status": format!("Status: Downloaded newer image for {}:{}", image, tag)})
            ));

            state.runtime.event_bus().publish(Event::ImagePulled {
                id: image_id_full,
                reference: reference.to_string(),
            });
        }
        Err(e) => {
            output.push_str(&format!(
                "{}\n",
                serde_json::json!({"error": e.to_string()})
            ));
        }
    }

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        output,
    ))
}

/// Remove image query parameters.
#[derive(Debug, Deserialize)]
pub struct RemoveImageQuery {
    /// Force removal.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub force: bool,
    /// Do not delete untagged parents.
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub noprune: bool,
}

/// Remove image.
pub async fn remove_image(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_params): Query<RemoveImageQuery>,
) -> Result<Json<Vec<ImageDeleteResponse>>> {
    use arcbox_image::ImageRef;

    let reference = ImageRef::parse(&id).ok_or_else(|| DockerError::ImageNotFound(id.clone()))?;

    // Get image info before removing for response.
    let image = state
        .runtime
        .image_store()
        .get(&reference)
        .ok_or_else(|| DockerError::ImageNotFound(id.clone()))?;

    let image_id = image.id.clone();
    let image_id_full = format!("sha256:{}", image_id);
    let image_ref = image.reference.to_string();

    // Remove the image.
    state
        .runtime
        .image_store()
        .remove(&reference)
        .map_err(|e| DockerError::Server(e.to_string()))?;

    state.runtime.event_bus().publish(Event::ImageRemoved {
        id: image_id_full.clone(),
        reference: image_ref.clone(),
    });

    Ok(Json(vec![
        ImageDeleteResponse {
            untagged: Some(image_ref),
            deleted: None,
        },
        ImageDeleteResponse {
            untagged: None,
            deleted: Some(image_id_full),
        },
    ]))
}

/// Tag image.
pub async fn tag_image(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    use arcbox_image::ImageRef;

    let repo = params
        .get("repo")
        .ok_or_else(|| DockerError::BadRequest("missing 'repo' parameter".to_string()))?;
    let tag = params.get("tag").map_or("latest", |s| s.as_str());

    // Parse source reference.
    let source = ImageRef::parse(&id).ok_or_else(|| DockerError::ImageNotFound(id.clone()))?;

    // Build target reference.
    let target = ImageRef::parse(&format!("{repo}:{tag}")).ok_or_else(|| {
        DockerError::BadRequest(format!("invalid target reference: {repo}:{tag}"))
    })?;

    // Tag the image.
    state
        .runtime
        .image_store()
        .tag(&source, &target)
        .map_err(|e| match e {
            arcbox_image::ImageError::NotFound(_) => DockerError::ImageNotFound(id),
            e => DockerError::Server(e.to_string()),
        })?;

    Ok(StatusCode::CREATED)
}

// ============================================================================
// Network Handlers
// ============================================================================

/// List networks.
pub async fn list_networks(
    State(state): State<AppState>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<NetworkSummary>>> {
    let networks = state.runtime.network_manager().list_networks();

    // Start with default bridge network.
    let mut result = vec![NetworkSummary {
        name: "bridge".to_string(),
        id: "bridge".to_string(),
        created: chrono::Utc::now().to_rfc3339(),
        scope: "local".to_string(),
        driver: "bridge".to_string(),
        enable_ipv6: false,
        internal: false,
        attachable: false,
        ingress: false,
        labels: HashMap::new(),
    }];

    // Add user-created networks.
    result.extend(networks.into_iter().map(|n| NetworkSummary {
        name: n.name,
        id: n.id,
        created: n.created.to_rfc3339(),
        scope: n.scope,
        driver: n.driver,
        enable_ipv6: false,
        internal: n.internal,
        attachable: n.attachable,
        ingress: false,
        labels: n.labels,
    }));

    Ok(Json(result))
}

/// Create network.
pub async fn create_network(
    State(state): State<AppState>,
    Json(body): Json<NetworkCreateRequest>,
) -> Result<(StatusCode, Json<NetworkCreateResponse>)> {
    let id = state
        .runtime
        .network_manager()
        .create_network(
            &body.name,
            body.driver.as_deref(),
            body.labels.unwrap_or_default(),
        )
        .map_err(|e| DockerError::Server(e.to_string()))?;

    let (driver, labels) = state
        .runtime
        .network_manager()
        .get_network(&id)
        .map(|network| (network.driver, network.labels))
        .unwrap_or_else(|| (body.driver.unwrap_or_default(), HashMap::new()));

    state.runtime.event_bus().publish(Event::NetworkCreated {
        id: id.clone(),
        name: body.name.clone(),
        driver,
        labels,
    });

    Ok((
        StatusCode::CREATED,
        Json(NetworkCreateResponse { id, warning: None }),
    ))
}

/// Inspect network.
pub async fn inspect_network(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<NetworkSummary>> {
    // Check for default bridge network.
    if id == "bridge" {
        return Ok(Json(NetworkSummary {
            name: "bridge".to_string(),
            id: "bridge".to_string(),
            created: chrono::Utc::now().to_rfc3339(),
            scope: "local".to_string(),
            driver: "bridge".to_string(),
            enable_ipv6: false,
            internal: false,
            attachable: false,
            ingress: false,
            labels: HashMap::new(),
        }));
    }

    let network = state
        .runtime
        .network_manager()
        .get_network(&id)
        .ok_or_else(|| DockerError::NetworkNotFound(id))?;

    Ok(Json(NetworkSummary {
        name: network.name,
        id: network.id,
        created: network.created.to_rfc3339(),
        scope: network.scope,
        driver: network.driver,
        enable_ipv6: false,
        internal: network.internal,
        attachable: network.attachable,
        ingress: false,
        labels: network.labels,
    }))
}

/// Remove network.
pub async fn remove_network(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    // Cannot remove default bridge network.
    if id == "bridge" {
        return Err(DockerError::Conflict(
            "cannot remove default bridge network".to_string(),
        ));
    }

    let network = state
        .runtime
        .network_manager()
        .get_network(&id)
        .ok_or_else(|| DockerError::NetworkNotFound(id.clone()))?;
    let network_id = network.id.clone();
    let network_name = network.name.clone();

    state
        .runtime
        .network_manager()
        .remove_network(&id)
        .map_err(|_| DockerError::NetworkNotFound(id))?;

    state.runtime.event_bus().publish(Event::NetworkRemoved {
        id: network_id,
        name: network_name,
        driver: network.driver,
        labels: network.labels,
    });

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Volume Handlers
// ============================================================================

/// List volumes.
pub async fn list_volumes(
    State(state): State<AppState>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<VolumeListResponse>> {
    let vm = state
        .runtime
        .volume_manager()
        .read()
        .map_err(|_| DockerError::Server("lock poisoned".to_string()))?;

    let volumes = vm
        .list()
        .iter()
        .map(|v| VolumeSummary {
            name: v.name.clone(),
            driver: v.driver.clone(),
            mountpoint: v.mountpoint.display().to_string(),
            created_at: v.created_at.to_rfc3339(),
            labels: v.labels.clone(),
            scope: v.scope.clone(),
            options: HashMap::new(),
        })
        .collect();

    Ok(Json(VolumeListResponse {
        volumes,
        warnings: vec![],
    }))
}

/// Create volume.
pub async fn create_volume(
    State(state): State<AppState>,
    Json(body): Json<VolumeCreateRequest>,
) -> Result<(StatusCode, Json<VolumeSummary>)> {
    use arcbox_container::VolumeCreateOptions;

    let options = VolumeCreateOptions {
        name: body.name,
        driver: body.driver,
        labels: body.labels.unwrap_or_default(),
    };

    let mut vm = state
        .runtime
        .volume_manager()
        .write()
        .map_err(|_| DockerError::Server("lock poisoned".to_string()))?;

    let volume = vm
        .create(options)
        .map_err(|e| DockerError::Server(e.to_string()))?;

    state.runtime.event_bus().publish(Event::VolumeCreated {
        name: volume.name.clone(),
        driver: volume.driver.clone(),
        labels: volume.labels.clone(),
    });

    Ok((
        StatusCode::CREATED,
        Json(VolumeSummary {
            name: volume.name.clone(),
            driver: volume.driver.clone(),
            mountpoint: volume.mountpoint.display().to_string(),
            created_at: volume.created_at.to_rfc3339(),
            labels: volume.labels.clone(),
            scope: volume.scope.clone(),
            options: body.driver_opts.unwrap_or_default(),
        }),
    ))
}

/// Inspect volume.
pub async fn inspect_volume(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<VolumeSummary>> {
    let vm = state
        .runtime
        .volume_manager()
        .read()
        .map_err(|_| DockerError::Server("lock poisoned".to_string()))?;

    let volume = vm
        .inspect(&name)
        .ok_or_else(|| DockerError::VolumeNotFound(name.clone()))?;

    Ok(Json(VolumeSummary {
        name: volume.name.clone(),
        driver: volume.driver.clone(),
        mountpoint: volume.mountpoint.display().to_string(),
        created_at: volume.created_at.to_rfc3339(),
        labels: volume.labels.clone(),
        scope: volume.scope.clone(),
        options: HashMap::new(),
    }))
}

/// Remove volume.
pub async fn remove_volume(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let mut vm = state
        .runtime
        .volume_manager()
        .write()
        .map_err(|_| DockerError::Server("lock poisoned".to_string()))?;

    let volume = vm
        .get(&name)
        .ok_or_else(|| DockerError::VolumeNotFound(name.clone()))?;
    let volume_name = volume.name.clone();
    let volume_driver = volume.driver.clone();
    let volume_labels = volume.labels.clone();

    vm.remove(&name)
        .map_err(|e| DockerError::Server(e.to_string()))?;

    state.runtime.event_bus().publish(Event::VolumeRemoved {
        name: volume_name,
        driver: volume_driver,
        labels: volume_labels,
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Prune unused volumes.
pub async fn prune_volumes(
    State(state): State<AppState>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<VolumePruneResponse>> {
    let mut vm = state
        .runtime
        .volume_manager()
        .write()
        .map_err(|_| DockerError::Server("lock poisoned".to_string()))?;

    let result = vm.prune().map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(Json(VolumePruneResponse {
        volumes_deleted: result.volumes_deleted,
        space_reclaimed: result.space_reclaimed,
    }))
}

#[cfg(test)]
mod events_tests {
    use super::{EventFilters, event_matches_filters, map_event, parse_event_filters};
    use arcbox_core::event::Event;
    use std::collections::HashMap;

    #[test]
    fn parse_filters_with_type_and_container() {
        let raw = r#"{"type":{"container":true},"container":{"abc123":true},"event":{"start":true}}"#;
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
        assert_eq!(
            mapping.attributes.get("name"),
            Some(&"demo".to_string())
        );
        assert_eq!(
            mapping.attributes.get("image"),
            Some(&"alpine:latest".to_string())
        );
        assert_eq!(
            mapping.attributes.get("exitCode"),
            Some(&"42".to_string())
        );
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
        assert_eq!(
            mapping.attributes.get("signal"),
            Some(&"9".to_string())
        );
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
        assert_eq!(
            mapping.attributes.get("driver"),
            Some(&"local".to_string())
        );
        assert!(mapping.attributes.get("name").is_none());
        assert!(mapping.attributes.get("env").is_none());
    }
}

// ============================================================================
// System Handlers
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
    let containers = state.runtime.container_manager().list();
    let images = state.runtime.image_store().list();

    let running = containers
        .iter()
        .filter(|c| c.state == arcbox_container::state::ContainerState::Running)
        .count();
    let paused = containers
        .iter()
        .filter(|c| c.state == arcbox_container::state::ContainerState::Paused)
        .count();
    let stopped = containers.len() - running - paused;

    Json(SystemInfoResponse {
        containers: containers.len() as i64,
        containers_running: running as i64,
        containers_paused: paused as i64,
        containers_stopped: stopped as i64,
        images: images.len() as i64,
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

/// Calculates the total size of a directory recursively.
///
/// Returns 0 if the directory doesn't exist or on any I/O error.
async fn calculate_dir_size(path: &std::path::Path) -> u64 {
    let mut total_size = 0u64;

    let mut stack = vec![path.to_path_buf()];

    while let Some(current_path) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&current_path).await {
            Ok(e) => e,
            Err(_) => continue,
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let metadata = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_file() {
                total_size += metadata.len();
            } else if metadata.is_dir() {
                stack.push(entry.path());
            }
        }
    }

    total_size
}

// ============================================================================
// Additional Container Handlers
// ============================================================================

/// Pause container.
///
/// Pauses all processes within a container.
pub async fn pause_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Check if container is running.
    if container.state != arcbox_container::state::ContainerState::Running {
        return Err(DockerError::Conflict(format!(
            "container {} is not running",
            id
        )));
    }

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Pause through Runtime -> Agent.
    state
        .runtime
        .pause_container(&machine_name, &container.id)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Unpause container.
///
/// Resumes a paused container.
pub async fn unpause_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Check if container is paused.
    if container.state != arcbox_container::state::ContainerState::Paused {
        return Err(DockerError::Conflict(format!(
            "container {} is not paused",
            id
        )));
    }

    let machine_name = container
        .machine_name
        .clone()
        .unwrap_or_else(|| state.runtime.default_machine_name().to_string());

    // Unpause through Runtime -> Agent.
    state
        .runtime
        .unpause_container(&machine_name, &container.id)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Rename container query.
#[derive(Debug, Deserialize)]
pub struct RenameContainerQuery {
    /// New name for the container.
    pub name: String,
}

/// Rename container.
pub async fn rename_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<RenameContainerQuery>,
) -> Result<StatusCode> {
    let container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Update container name.
    state
        .runtime
        .container_manager()
        .update(&container.id, |c| {
            c.name = query.name.clone();
        })
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Container top response.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerTopResponse {
    /// Column titles.
    pub titles: Vec<String>,
    /// Process list.
    pub processes: Vec<Vec<String>>,
}

/// Get container processes (top).
///
/// Lists processes running inside a container.
pub async fn container_top(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<ContainerTopResponse>> {
    let container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Check if container is running.
    if container.state != arcbox_container::state::ContainerState::Running {
        return Err(DockerError::Conflict(format!(
            "container {} is not running",
            id
        )));
    }

    let machine_name = container
        .machine_name
        .as_ref()
        .ok_or_else(|| DockerError::Server("container has no machine".to_string()))?;

    let ps_args = _params.get("ps_args").map_or("", String::as_str);

    // Get process list from agent.
    let top_response = state
        .runtime
        .container_top(machine_name, &container.id.to_string(), ps_args)
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(Json(ContainerTopResponse {
        titles: top_response.titles,
        processes: top_response
            .processes
            .into_iter()
            .map(|p| p.values)
            .collect(),
    }))
}

/// Container stats response (single snapshot).
#[derive(Debug, serde::Serialize)]
pub struct ContainerStatsResponse {
    /// Container ID.
    pub id: String,
    /// Container name.
    pub name: String,
    /// Read time.
    pub read: String,
    /// CPU stats.
    pub cpu_stats: CpuStats,
    /// Previous CPU stats.
    pub precpu_stats: CpuStats,
    /// Memory stats.
    pub memory_stats: MemoryStats,
    /// Network stats.
    pub networks: HashMap<String, NetworkStats>,
}

/// CPU statistics.
#[derive(Debug, Default, serde::Serialize)]
pub struct CpuStats {
    /// CPU usage.
    pub cpu_usage: CpuUsage,
    /// System CPU usage.
    pub system_cpu_usage: u64,
    /// Number of online CPUs.
    pub online_cpus: u32,
}

/// CPU usage details.
#[derive(Debug, Default, serde::Serialize)]
pub struct CpuUsage {
    /// Total CPU usage.
    pub total_usage: u64,
    /// Per-CPU usage.
    pub percpu_usage: Vec<u64>,
    /// Usage in kernel mode.
    pub usage_in_kernelmode: u64,
    /// Usage in user mode.
    pub usage_in_usermode: u64,
}

/// Memory statistics.
#[derive(Debug, Default, serde::Serialize)]
pub struct MemoryStats {
    /// Current memory usage.
    pub usage: u64,
    /// Maximum memory usage.
    pub max_usage: u64,
    /// Memory limit.
    pub limit: u64,
}

/// Network statistics.
#[derive(Debug, Default, serde::Serialize)]
pub struct NetworkStats {
    /// Bytes received.
    pub rx_bytes: u64,
    /// Packets received.
    pub rx_packets: u64,
    /// Receive errors.
    pub rx_errors: u64,
    /// Receive drops.
    pub rx_dropped: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Transmit errors.
    pub tx_errors: u64,
    /// Transmit drops.
    pub tx_dropped: u64,
}

/// Container stats query.
#[derive(Debug, Deserialize)]
pub struct ContainerStatsQuery {
    /// Stream stats (default true).
    #[serde(default = "default_true", deserialize_with = "deserialize_bool")]
    pub stream: bool,
    /// Return one-shot stats (default false).
    #[serde(default, deserialize_with = "deserialize_bool")]
    pub one_shot: bool,
}

/// Get container stats.
///
/// Returns resource usage statistics for a container.
pub async fn container_stats(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_query): Query<ContainerStatsQuery>,
) -> Result<Json<ContainerStatsResponse>> {
    let container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Check if container is running (stats only available for running containers).
    if container.state != arcbox_container::state::ContainerState::Running {
        return Err(DockerError::Conflict(format!(
            "container {} is not running",
            id
        )));
    }

    let machine_name = container
        .machine_name
        .as_ref()
        .ok_or_else(|| DockerError::Server("container has no machine".to_string()))?;

    let now = chrono::Utc::now().to_rfc3339();

    // Get actual stats from agent.
    let agent_stats = state
        .runtime
        .container_stats(machine_name, &container.id.to_string())
        .await
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(Json(ContainerStatsResponse {
        id: container.id.to_string(),
        name: format!("/{}", container.name),
        read: now,
        cpu_stats: CpuStats {
            cpu_usage: CpuUsage {
                total_usage: agent_stats.cpu_usage,
                percpu_usage: vec![],
                usage_in_kernelmode: 0,
                usage_in_usermode: 0,
            },
            system_cpu_usage: agent_stats.system_cpu_usage,
            online_cpus: agent_stats.online_cpus,
        },
        precpu_stats: CpuStats::default(),
        memory_stats: MemoryStats {
            usage: agent_stats.memory_usage,
            max_usage: 0,
            limit: agent_stats.memory_limit,
        },
        networks: HashMap::new(),
    }))
}

/// Prune containers response.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerPruneResponse {
    /// Deleted container IDs.
    pub containers_deleted: Vec<String>,
    /// Space reclaimed in bytes.
    pub space_reclaimed: u64,
}

/// Prune stopped containers.
pub async fn prune_containers(
    State(state): State<AppState>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<ContainerPruneResponse>> {
    let containers = state.runtime.container_manager().list();

    // Find stopped containers.
    let stopped: Vec<_> = containers
        .iter()
        .filter(|c| {
            matches!(
                c.state,
                arcbox_container::state::ContainerState::Exited
                    | arcbox_container::state::ContainerState::Dead
            )
        })
        .collect();

    let mut deleted = Vec::new();
    let mut space_reclaimed = 0u64;

    // Get containers directory from config.
    let containers_dir = state.runtime.config().containers_dir();

    for container in stopped {
        let container_id = container.id.to_string();

        // Calculate container directory size before removal.
        let container_path = containers_dir.join(&container_id);
        let container_size = calculate_dir_size(&container_path).await;

        if state
            .runtime
            .container_manager()
            .remove(&container.id)
            .is_ok()
        {
            deleted.push(container_id);
            space_reclaimed += container_size;
        }
    }

    Ok(Json(ContainerPruneResponse {
        containers_deleted: deleted,
        space_reclaimed,
    }))
}

/// Container changes response.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerChangeItem {
    /// Path to the changed file.
    pub path: String,
    /// Kind of change (0=Modified, 1=Added, 2=Deleted).
    pub kind: i32,
}

/// Get container filesystem changes.
///
/// Returns a list of filesystem changes in the container relative to its base image.
/// This endpoint compares the container's writable layer against the read-only image layers.
///
/// Note: This feature requires tracking overlay filesystem diffs in the guest VM agent.
/// Currently returns an empty list, which is consistent with Docker's behavior when
/// the storage driver doesn't support diff operations.
pub async fn container_changes(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<ContainerChangeItem>>> {
    // Validate that the container exists.
    let _container = state
        .runtime
        .container_manager()
        .resolve(&id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // Filesystem diff tracking requires overlay fs support in the guest agent.
    // The agent would need to compare the container's upper directory against
    // the merged view to identify changes. For now, return empty list.
    Ok(Json(vec![]))
}
