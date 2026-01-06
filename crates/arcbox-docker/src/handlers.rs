//! Request handlers for Docker API endpoints.
//!
//! Each handler corresponds to a Docker API endpoint and will eventually
//! forward requests to arcbox-core services.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::types::*;
use arcbox_container::config::ContainerConfig as CoreContainerConfig;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use std::collections::HashMap;

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
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<ContainerInspectResponse>> {
    let _size = params.get("size").map(|v| v == "true").unwrap_or(false);

    // TODO: Get container from arcbox-core
    Err(DockerError::ContainerNotFound(id))
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
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let _signal = params.get("signal").cloned().unwrap_or_else(|| "SIGKILL".to_string());
    let _ = id;

    // TODO: Kill container via arcbox-core
    Ok(StatusCode::NO_CONTENT)
}

/// Restart container.
pub async fn restart_container(
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let _timeout = params
        .get("t")
        .and_then(|t| t.parse().ok())
        .unwrap_or(10u32);
    let _ = id;

    // TODO: Restart container via arcbox-core
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
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<WaitResponse>> {
    let _condition = params.get("condition").cloned();
    let _ = id;

    // TODO: Wait for container via arcbox-core
    Ok(Json(WaitResponse {
        status_code: 0,
        error: None,
    }))
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

/// Get container logs.
pub async fn container_logs(
    Path(id): Path<String>,
    Query(params): Query<LogsQuery>,
) -> Result<impl IntoResponse> {
    let _ = (id, params);

    // TODO: Stream logs from arcbox-core
    // For now, return empty response with proper content type
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.docker.raw-stream",
        )],
        "",
    ))
}

// ============================================================================
// Exec Handlers
// ============================================================================

/// Create exec instance.
pub async fn exec_create(
    Path(id): Path<String>,
    Json(body): Json<ExecCreateRequest>,
) -> Result<(StatusCode, Json<ExecCreateResponse>)> {
    let _ = (id, body);

    // TODO: Create exec via arcbox-core
    Ok((
        StatusCode::CREATED,
        Json(ExecCreateResponse {
            id: uuid::Uuid::new_v4().to_string().replace('-', ""),
        }),
    ))
}

/// Start exec instance.
pub async fn exec_start(
    Path(id): Path<String>,
    Json(body): Json<ExecStartRequest>,
) -> Result<impl IntoResponse> {
    let _ = (id, body);

    // TODO: Start exec via arcbox-core
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
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let _h: Option<u32> = params.get("h").and_then(|v| v.parse().ok());
    let _w: Option<u32> = params.get("w").and_then(|v| v.parse().ok());
    let _ = id;

    // TODO: Resize exec via arcbox-core
    Ok(StatusCode::OK)
}

/// Inspect exec instance.
pub async fn exec_inspect(Path(id): Path<String>) -> Result<Json<ExecInspectResponse>> {
    // TODO: Inspect exec via arcbox-core
    Err(DockerError::NotImplemented(format!("exec inspect {id}")))
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
pub async fn inspect_image(Path(id): Path<String>) -> Result<Json<ImageInspectResponse>> {
    // TODO: Get image from arcbox-core
    Err(DockerError::ImageNotFound(id))
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
pub async fn pull_image(Query(params): Query<PullImageQuery>) -> Result<impl IntoResponse> {
    let image = params.from_image.unwrap_or_default();
    let tag = params.tag.unwrap_or_else(|| "latest".to_string());
    let _ = (image, tag);

    // TODO: Pull image via arcbox-core
    // Returns newline-delimited JSON progress
    let progress = serde_json::json!({
        "status": "Pulling from library/nginx",
        "id": "latest"
    });

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        format!("{}\n", progress),
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
    Path(id): Path<String>,
    Query(_params): Query<RemoveImageQuery>,
) -> Result<Json<Vec<ImageDeleteResponse>>> {
    // TODO: Remove image via arcbox-core
    Err(DockerError::ImageNotFound(id))
}

/// Tag image.
pub async fn tag_image(
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let _repo = params.get("repo").cloned();
    let _tag = params.get("tag").cloned();
    let _ = id;

    // TODO: Tag image via arcbox-core
    Ok(StatusCode::CREATED)
}

// ============================================================================
// Network Handlers
// ============================================================================

/// List networks.
pub async fn list_networks(
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<NetworkSummary>>> {
    // TODO: Get networks from arcbox-core
    // Return default bridge network
    Ok(Json(vec![NetworkSummary {
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
    }]))
}

/// Create network.
pub async fn create_network(
    Json(body): Json<NetworkCreateRequest>,
) -> Result<(StatusCode, Json<NetworkCreateResponse>)> {
    let _ = body;

    // TODO: Create network via arcbox-core
    Ok((
        StatusCode::CREATED,
        Json(NetworkCreateResponse {
            id: uuid::Uuid::new_v4().to_string().replace('-', ""),
            warning: None,
        }),
    ))
}

/// Inspect network.
pub async fn inspect_network(Path(id): Path<String>) -> Result<Json<NetworkSummary>> {
    // TODO: Get network from arcbox-core
    Err(DockerError::NetworkNotFound(id))
}

/// Remove network.
pub async fn remove_network(Path(id): Path<String>) -> Result<StatusCode> {
    let _ = id;

    // TODO: Remove network via arcbox-core
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Volume Handlers
// ============================================================================

/// List volumes.
pub async fn list_volumes(
    Query(_params): Query<HashMap<String, String>>,
) -> Result<Json<VolumeListResponse>> {
    // TODO: Get volumes from arcbox-core
    Ok(Json(VolumeListResponse {
        volumes: vec![],
        warnings: vec![],
    }))
}

/// Create volume.
pub async fn create_volume(
    Json(body): Json<VolumeCreateRequest>,
) -> Result<(StatusCode, Json<VolumeSummary>)> {
    let name = body
        .name
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().replace('-', ""));

    // TODO: Create volume via arcbox-core
    Ok((
        StatusCode::CREATED,
        Json(VolumeSummary {
            name,
            driver: body.driver.unwrap_or_else(|| "local".to_string()),
            mountpoint: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            labels: body.labels.unwrap_or_default(),
            scope: "local".to_string(),
            options: body.driver_opts.unwrap_or_default(),
        }),
    ))
}

/// Inspect volume.
pub async fn inspect_volume(Path(name): Path<String>) -> Result<Json<VolumeSummary>> {
    // TODO: Get volume from arcbox-core
    Err(DockerError::VolumeNotFound(name))
}

/// Remove volume.
pub async fn remove_volume(
    Path(name): Path<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Result<StatusCode> {
    let _ = name;

    // TODO: Remove volume via arcbox-core
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
    // TODO: Get actual memory using sysinfo or similar
    8 * 1024 * 1024 * 1024 // 8GB default
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "arcbox".to_string())
}
