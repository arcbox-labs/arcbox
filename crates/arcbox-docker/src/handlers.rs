//! Request handlers for Docker API endpoints.
//!
//! Each handler corresponds to a Docker API endpoint and will eventually
//! forward requests to arcbox-core services.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::types::*;
use arcbox_container::config::ContainerConfig as CoreContainerConfig;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use futures::StreamExt;
use serde::Deserialize;
use std::collections::HashMap;
use tokio_stream::wrappers::ReceiverStream;

// ============================================================================
// Container Handlers
// ============================================================================

/// List containers query parameters.
#[derive(Debug, Deserialize)]
pub struct ListContainersQuery {
    /// Show all containers.
    #[serde(default)]
    pub all: bool,
    /// Limit results.
    pub limit: Option<i32>,
    /// Show sizes.
    #[serde(default)]
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
        .filter(|c| {
            show_all
                || c.state == arcbox_container::state::ContainerState::Running
        })
        .map(|c| ContainerSummary {
            id: c.id.to_string(),
            names: vec![format!("/{}", c.name)],
            image: c.image.clone(),
            image_id: String::new(),
            command: String::new(),
            created: c.created.timestamp(),
            ports: vec![],
            size_rw: None,
            size_root_fs: None,
            labels: HashMap::new(),
            state: c.state.to_string(),
            status: format_container_status(c),
            network_settings: None,
            mounts: None,
        })
        .collect();

    Ok(Json(summaries))
}

/// Formats container status string.
fn format_container_status(c: &arcbox_container::state::Container) -> String {
    match c.state {
        arcbox_container::state::ContainerState::Created => "Created".to_string(),
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

    let config = CoreContainerConfig {
        name: params.name,
        image: body.image,
        cmd: body.cmd.unwrap_or_default(),
        entrypoint: body.entrypoint.unwrap_or_default(),
        env,
        working_dir: body.working_dir,
        user: body.user,
        ..Default::default()
    };

    let container_id = state
        .runtime
        .container_manager()
        .create(config)
        .map_err(|e| DockerError::Server(e.to_string()))?;

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
    let container_id = arcbox_container::state::ContainerId::from_string(&id);
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    let state_response = ContainerState {
        status: container.state.to_string().to_lowercase(),
        running: container.state == arcbox_container::state::ContainerState::Running,
        paused: container.state == arcbox_container::state::ContainerState::Paused,
        restarting: container.state == arcbox_container::state::ContainerState::Restarting,
        oom_killed: false,
        dead: container.state == arcbox_container::state::ContainerState::Dead,
        pid: 0,
        exit_code: container.exit_code.unwrap_or(0),
        error: String::new(),
        started_at: container
            .started_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_default(),
        finished_at: String::new(),
    };

    Ok(Json(ContainerInspectResponse {
        id: container.id.to_string(),
        created: container.created.to_rfc3339(),
        path: String::new(),
        args: vec![],
        state: state_response,
        image: container.image.clone(),
        name: format!("/{}", container.name),
        restart_count: 0,
        config: ContainerConfig {
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
        },
        host_config: HostConfig::default(),
        network_settings: NetworkSettings::default(),
        mounts: vec![],
    }))
}

/// Start container.
pub async fn start_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    state
        .runtime
        .container_manager()
        .start(&container_id)
        .map_err(|e| match e {
            arcbox_container::ContainerError::NotFound(_) => DockerError::ContainerNotFound(id),
            _ => DockerError::Server(e.to_string()),
        })?;

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
    Query(_params): Query<StopContainerQuery>,
) -> Result<StatusCode> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    state
        .runtime
        .container_manager()
        .stop(&container_id)
        .map_err(|e| match e {
            arcbox_container::ContainerError::NotFound(_) => DockerError::ContainerNotFound(id),
            _ => DockerError::Server(e.to_string()),
        })?;

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

    state
        .runtime
        .container_manager()
        .kill(&container_id, &signal)
        .map_err(|e| match e {
            arcbox_container::ContainerError::NotFound(_) => DockerError::ContainerNotFound(id),
            arcbox_container::ContainerError::InvalidState(msg) => DockerError::Conflict(msg),
            _ => DockerError::Server(e.to_string()),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Restart container.
pub async fn restart_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    state
        .runtime
        .container_manager()
        .restart(&container_id)
        .map_err(|e| match e {
            arcbox_container::ContainerError::NotFound(_) => DockerError::ContainerNotFound(id),
            _ => DockerError::Server(e.to_string()),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Remove container query parameters.
#[derive(Debug, Deserialize)]
pub struct RemoveContainerQuery {
    /// Force remove.
    #[serde(default)]
    pub force: bool,
    /// Remove volumes.
    #[serde(default)]
    pub v: bool,
    /// Remove link.
    #[serde(default)]
    pub link: bool,
}

/// Remove container.
pub async fn remove_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_params): Query<RemoveContainerQuery>,
) -> Result<StatusCode> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    state
        .runtime
        .container_manager()
        .remove(&container_id)
        .map_err(|e| match e {
            arcbox_container::ContainerError::NotFound(_) => DockerError::ContainerNotFound(id),
            _ => DockerError::Server(e.to_string()),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Wait for container.
pub async fn wait_container(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<WaitResponse>> {
    let container_id = arcbox_container::state::ContainerId::from_string(&id);

    // Check if container exists.
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
        .ok_or_else(|| DockerError::ContainerNotFound(id.clone()))?;

    // If already exited, return immediately.
    if let Some(exit_code) = state.runtime.container_manager().wait(&container_id) {
        return Ok(Json(WaitResponse {
            status_code: i64::from(exit_code),
            error: None,
        }));
    }

    // If still running, return current state.
    // Note: A full implementation would use async channels to wait for exit.
    if container.state == arcbox_container::state::ContainerState::Running {
        // For now, just return 0 as a placeholder.
        // In a real implementation, we'd wait for the container to exit.
        Ok(Json(WaitResponse {
            status_code: 0,
            error: None,
        }))
    } else {
        Ok(Json(WaitResponse {
            status_code: i64::from(container.exit_code.unwrap_or(0)),
            error: None,
        }))
    }
}

/// Container logs query parameters.
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// Follow log output.
    #[serde(default)]
    pub follow: bool,
    /// Show stdout.
    #[serde(default = "default_true")]
    pub stdout: bool,
    /// Show stderr.
    #[serde(default = "default_true")]
    pub stderr: bool,
    /// Since timestamp.
    pub since: Option<i64>,
    /// Until timestamp.
    pub until: Option<i64>,
    /// Show timestamps.
    #[serde(default)]
    pub timestamps: bool,
    /// Tail lines.
    pub tail: Option<String>,
}

fn default_true() -> bool {
    true
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
    let container_id = arcbox_container::state::ContainerId::from_string(&id);
    let container = state
        .runtime
        .container_manager()
        .get(&container_id)
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
        .and_then(|t| {
            if t == "all" {
                Some(0)
            } else {
                t.parse().ok()
            }
        })
        .unwrap_or(0);

    // Get machine name from container.
    let machine_name = container.machine_name.clone().unwrap_or_else(|| "default".to_string());

    // Check if we should stream (follow mode).
    if params.follow {
        // Streaming mode: return a streaming response.
        return container_logs_stream(
            state,
            id,
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
    let log_data = match state
        .runtime
        .container_logs(
            &machine_name,
            &id,
            false,
            params.stdout,
            params.stderr,
            params.since.unwrap_or(0),
            params.until.unwrap_or(0),
            params.timestamps,
            tail,
        )
        .await
    {
        Ok(entry) => entry.data,
        Err(e) => {
            tracing::warn!("Failed to get logs from agent: {}", e);
            // Return empty response if agent is not available.
            Vec::new()
        }
    };

    // Encode in Docker multiplexed stream format.
    let stream_type: u8 = if params.stdout { 1 } else { 2 };
    let output = encode_docker_stream(stream_type, &log_data);

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
            let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
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
    let stream_type: u8 = if stdout { 1 } else { 2 };
    let body_stream = log_stream.map(move |result| {
        match result {
            Ok(entry) => {
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
// Exec Handlers
// ============================================================================

/// Create exec instance.
pub async fn exec_create(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ExecCreateRequest>,
) -> Result<(StatusCode, Json<ExecCreateResponse>)> {
    use arcbox_container::{ExecConfig, ContainerId};

    // Verify container exists.
    let container_id = ContainerId::from_string(&id);
    if state.runtime.container_manager().get(&container_id).is_none() {
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
    let exec_id = state.runtime.exec_manager().create(config);

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
    Json(_body): Json<ExecStartRequest>,
) -> Result<impl IntoResponse> {
    use arcbox_container::ExecId;

    let exec_id = ExecId::from_string(&id);

    // Start the exec.
    state
        .runtime
        .exec_manager()
        .start(&exec_id)
        .map_err(|e| match e {
            arcbox_container::ContainerError::NotFound(_) => {
                DockerError::NotImplemented(format!("exec {id} not found"))
            }
            e => DockerError::Server(e.to_string()),
        })?;

    // Return raw stream format (empty for now since exec completes immediately).
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.docker.raw-stream",
        )],
        "",
    ))
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

    state
        .runtime
        .exec_manager()
        .resize(&exec_id, h, w)
        .map_err(|e| match e {
            arcbox_container::ContainerError::NotFound(_) => {
                DockerError::NotImplemented(format!("exec {id} not found"))
            }
            e => DockerError::Server(e.to_string()),
        })?;

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
    #[serde(default)]
    pub all: bool,
    /// Show digests.
    #[serde(default)]
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
    use arcbox_image::{ImageRef, RegistryClient};
    use arcbox_image::pull::ImagePuller;

    let image = params.from_image.unwrap_or_default();
    let tag = params.tag.unwrap_or_else(|| "latest".to_string());

    // Parse image reference.
    let reference = ImageRef::parse(&format!("{image}:{tag}"))
        .ok_or_else(|| DockerError::BadRequest(format!("invalid image reference: {image}:{tag}")))?;

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
            // Short ID for display.
            let short_id = image_id.strip_prefix("sha256:").unwrap_or(&image_id);
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
    #[serde(default)]
    pub force: bool,
    /// Do not delete untagged parents.
    #[serde(default)]
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
    let image_ref = image.reference.to_string();

    // Remove the image.
    state
        .runtime
        .image_store()
        .remove(&reference)
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(Json(vec![
        ImageDeleteResponse {
            untagged: Some(image_ref),
            deleted: None,
        },
        ImageDeleteResponse {
            untagged: None,
            deleted: Some(format!("sha256:{}", image_id)),
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
    let target = ImageRef::parse(&format!("{repo}:{tag}"))
        .ok_or_else(|| DockerError::BadRequest(format!("invalid target reference: {repo}:{tag}")))?;

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

    state
        .runtime
        .network_manager()
        .remove_network(&id)
        .map_err(|_| DockerError::NetworkNotFound(id))?;

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
            created_at: chrono::Utc::now().to_rfc3339(),
            labels: v.labels.clone(),
            scope: "local".to_string(),
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
    let name = body
        .name
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().replace('-', ""));

    let mut vm = state
        .runtime
        .volume_manager()
        .write()
        .map_err(|_| DockerError::Server("lock poisoned".to_string()))?;

    let volume = vm
        .create(&name)
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(VolumeSummary {
            name: volume.name.clone(),
            driver: volume.driver.clone(),
            mountpoint: volume.mountpoint.display().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            labels: volume.labels.clone(),
            scope: "local".to_string(),
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
        .get(&name)
        .ok_or_else(|| DockerError::VolumeNotFound(name.clone()))?;

    Ok(Json(VolumeSummary {
        name: volume.name.clone(),
        driver: volume.driver.clone(),
        mountpoint: volume.mountpoint.display().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        labels: volume.labels.clone(),
        scope: "local".to_string(),
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

    // Check if volume exists first.
    if vm.get(&name).is_none() {
        return Err(DockerError::VolumeNotFound(name));
    }

    vm.remove(&name)
        .map_err(|e| DockerError::Server(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
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
