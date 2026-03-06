//! REST API route handlers.

use crate::rest::sse;
use crate::rest::types::{ApiError, ApiResult};
use arcbox_core::Runtime;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(not(target_os = "linux"))]
use arcbox_protocol::sandbox_v1 as proto;

/// Builds all v1 routes.
pub fn v1_routes(runtime: Arc<Runtime>) -> Router {
    Router::new()
        // System
        .route("/system/info", get(system_info))
        .route("/system/version", get(system_version))
        // Machines
        .route("/machines", get(list_machines))
        .route("/machines", post(create_machine))
        .route("/machines/{id}", get(inspect_machine))
        .route("/machines/{id}/start", post(start_machine))
        .route("/machines/{id}/stop", post(stop_machine))
        .route("/machines/{id}", delete(remove_machine))
        // Sandboxes
        .route("/sandboxes", get(list_sandboxes))
        .route("/sandboxes", post(create_sandbox))
        .route("/sandboxes/{id}", get(inspect_sandbox))
        .route("/sandboxes/{id}/stop", post(stop_sandbox))
        .route("/sandboxes/{id}", delete(remove_sandbox))
        .route("/sandboxes/{id}/run", post(run_sandbox))
        // Containers (proxy to guest docker)
        .route("/containers", get(list_containers))
        .with_state(runtime)
}

// =============================================================================
// System
// =============================================================================

#[derive(Serialize)]
struct SystemInfo {
    version: String,
    platform: String,
    arch: String,
    data_dir: String,
    vm_running: bool,
}

async fn system_info(State(runtime): State<Arc<Runtime>>) -> ApiResult<SystemInfo> {
    let config = runtime.config();
    Ok(Json(SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        data_dir: config.data_dir.display().to_string(),
        vm_running: runtime.vm_lifecycle().is_running().await,
    }))
}

#[derive(Serialize)]
struct VersionInfo {
    version: String,
    api_version: String,
    git_commit: String,
}

async fn system_version() -> Json<VersionInfo> {
    Json(VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: "v1".to_string(),
        git_commit: option_env!("ARCBOX_GIT_COMMIT")
            .unwrap_or("unknown")
            .to_string(),
    })
}

// =============================================================================
// Machines
// =============================================================================

#[derive(Serialize)]
struct MachineSummaryJson {
    id: String,
    name: String,
    state: String,
    cpus: u32,
    memory_mb: u64,
    disk_gb: u64,
    ip_address: Option<String>,
}

#[derive(Serialize)]
struct ListMachinesResponse {
    machines: Vec<MachineSummaryJson>,
}

async fn list_machines(State(runtime): State<Arc<Runtime>>) -> ApiResult<ListMachinesResponse> {
    let machines = runtime.machine_manager().list();
    let items = machines
        .into_iter()
        .map(|m| MachineSummaryJson {
            id: m.name.clone(),
            name: m.name,
            state: format!("{:?}", m.state).to_lowercase(),
            cpus: m.cpus,
            memory_mb: m.memory_mb,
            disk_gb: m.disk_gb,
            ip_address: m.ip_address,
        })
        .collect();
    Ok(Json(ListMachinesResponse { machines: items }))
}

#[derive(Deserialize)]
struct CreateMachineRequest {
    name: String,
    #[serde(default = "default_cpus")]
    cpus: u32,
    #[serde(default = "default_memory_mb")]
    memory_mb: u64,
    #[serde(default = "default_disk_gb")]
    disk_gb: u64,
    #[serde(default)]
    distro: Option<String>,
    #[serde(default)]
    distro_version: Option<String>,
}

fn default_cpus() -> u32 {
    4
}
fn default_memory_mb() -> u64 {
    4096
}
fn default_disk_gb() -> u64 {
    50
}

#[derive(Serialize)]
struct CreateMachineResponse {
    id: String,
}

async fn create_machine(
    State(runtime): State<Arc<Runtime>>,
    Json(req): Json<CreateMachineRequest>,
) -> Result<Json<CreateMachineResponse>, ApiError> {
    let config = arcbox_core::machine::MachineConfig {
        name: req.name.clone(),
        cpus: req.cpus,
        memory_mb: req.memory_mb,
        disk_gb: req.disk_gb,
        kernel: None,
        cmdline: None,
        distro: req.distro,
        distro_version: req.distro_version,
        block_devices: Vec::new(),
    };

    runtime
        .machine_manager()
        .create(config)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(CreateMachineResponse { id: req.name }))
}

async fn inspect_machine(
    State(runtime): State<Arc<Runtime>>,
    Path(id): Path<String>,
) -> Result<Json<MachineSummaryJson>, ApiError> {
    let machine = runtime
        .machine_manager()
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("machine '{id}' not found")))?;

    Ok(Json(MachineSummaryJson {
        id: machine.name.clone(),
        name: machine.name,
        state: format!("{:?}", machine.state).to_lowercase(),
        cpus: machine.cpus,
        memory_mb: machine.memory_mb,
        disk_gb: machine.disk_gb,
        ip_address: machine.ip_address,
    }))
}

async fn start_machine(
    State(runtime): State<Arc<Runtime>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    runtime
        .machine_manager()
        .start(&id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "started"})))
}

async fn stop_machine(
    State(runtime): State<Arc<Runtime>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    runtime
        .machine_manager()
        .stop(&id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "stopped"})))
}

async fn remove_machine(
    State(runtime): State<Arc<Runtime>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    runtime
        .machine_manager()
        .remove(&id, false)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({"status": "removed"})))
}

// =============================================================================
// Sandboxes
// =============================================================================

/// Query parameters for sandbox endpoints.
#[derive(Deserialize)]
struct MachineQuery {
    /// Target VM name (defaults to "default").
    #[serde(default)]
    machine: Option<String>,
}

/// Returns a non-empty machine name, falling back to the runtime default.
///
/// Handles both `None` and `Some("")` (which can come from `?machine=` or
/// `"machine": ""` in JSON) by treating empty strings as absent.
#[cfg(not(target_os = "linux"))]
fn resolve_machine<'a>(name: Option<&'a str>, runtime: &'a Runtime) -> &'a str {
    match name {
        Some(s) if !s.is_empty() => s,
        _ => runtime.default_machine_name(),
    }
}

/// Formats a Unix timestamp (seconds) as RFC 3339.
#[cfg(not(target_os = "linux"))]
fn unix_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

#[derive(Serialize)]
struct SandboxSummaryJson {
    id: String,
    state: String,
    ip_address: String,
    labels: HashMap<String, String>,
    created_at: String,
}

#[derive(Serialize)]
struct ListSandboxesResponse {
    sandboxes: Vec<SandboxSummaryJson>,
}

async fn list_sandboxes(
    State(_runtime): State<Arc<Runtime>>,
    Query(_query): Query<MachineQuery>,
) -> ApiResult<ListSandboxesResponse> {
    #[cfg(target_os = "linux")]
    {
        if let Some(mgr) = _runtime.sandbox_manager() {
            let sandboxes: Vec<SandboxSummaryJson> = mgr
                .list_sandboxes(None, &HashMap::new())
                .into_iter()
                .map(|s| SandboxSummaryJson {
                    id: s.id,
                    state: s.state.to_string(),
                    ip_address: s.ip_address,
                    labels: s.labels,
                    created_at: s.created_at.to_rfc3339(),
                })
                .collect();
            return Ok(Json(ListSandboxesResponse { sandboxes }));
        }
        return Ok(Json(ListSandboxesResponse {
            sandboxes: Vec::new(),
        }));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let machine = resolve_machine(_query.machine.as_deref(), &_runtime);
        let mut agent = _runtime
            .get_agent(machine)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let resp = agent
            .sandbox_list(proto::ListSandboxesRequest::default())
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let sandboxes = resp
            .sandboxes
            .into_iter()
            .map(|s| SandboxSummaryJson {
                id: s.id,
                state: s.state,
                ip_address: s.ip_address,
                labels: s.labels,
                created_at: unix_to_rfc3339(s.created_at),
            })
            .collect();
        Ok(Json(ListSandboxesResponse { sandboxes }))
    }
}

#[derive(Deserialize)]
struct CreateSandboxRequest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    kernel: Option<String>,
    #[serde(default)]
    rootfs: Option<String>,
    #[serde(default)]
    vcpus: Option<u32>,
    #[serde(default)]
    memory_mib: Option<u64>,
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    ttl_seconds: Option<u32>,
    #[serde(default)]
    machine: Option<String>,
}

#[derive(Serialize)]
struct CreateSandboxResponse {
    id: String,
    ip_address: String,
    state: String,
}

async fn create_sandbox(
    State(_runtime): State<Arc<Runtime>>,
    Query(_query): Query<MachineQuery>,
    Json(_req): Json<CreateSandboxRequest>,
) -> Result<Json<CreateSandboxResponse>, ApiError> {
    #[cfg(target_os = "linux")]
    {
        use arcbox_vm::{SandboxNetworkSpec, SandboxSpec};

        let mgr = _runtime
            .sandbox_manager()
            .ok_or_else(|| ApiError::unavailable("sandbox subsystem is not enabled"))?;

        let spec = SandboxSpec {
            id: _req.id,
            labels: _req.labels,
            kernel: _req.kernel.unwrap_or_default(),
            rootfs: _req.rootfs.unwrap_or_default(),
            vcpus: _req.vcpus.unwrap_or(0),
            memory_mib: _req.memory_mib.unwrap_or(0),
            cmd: _req.cmd,
            env: _req.env,
            ttl_seconds: _req.ttl_seconds.unwrap_or(0),
            network: SandboxNetworkSpec::default(),
            ..SandboxSpec::default()
        };

        let (id, ip) = mgr
            .create_sandbox(spec)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;

        return Ok(Json(CreateSandboxResponse {
            id,
            ip_address: ip,
            state: "starting".to_string(),
        }));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let machine = resolve_machine(
            _req.machine.as_deref().or(_query.machine.as_deref()),
            &_runtime,
        );
        let mut agent = _runtime
            .get_agent(machine)
            .map_err(|e| ApiError::internal(e.to_string()))?;

        let proto_req = proto::CreateSandboxRequest {
            id: _req.id.unwrap_or_default(),
            labels: _req.labels,
            kernel: _req.kernel.unwrap_or_default(),
            rootfs: _req.rootfs.unwrap_or_default(),
            limits: Some(proto::ResourceLimits {
                vcpus: _req.vcpus.unwrap_or(0),
                memory_mib: _req.memory_mib.unwrap_or(0),
            }),
            cmd: _req.cmd,
            env: _req.env,
            ttl_seconds: _req.ttl_seconds.unwrap_or(0),
            ..proto::CreateSandboxRequest::default()
        };

        let resp = agent
            .sandbox_create(proto_req)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;

        Ok(Json(CreateSandboxResponse {
            id: resp.id,
            ip_address: resp.ip_address,
            state: resp.state,
        }))
    }
}

async fn inspect_sandbox(
    State(_runtime): State<Arc<Runtime>>,
    Path(_id): Path<String>,
    Query(_query): Query<MachineQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    #[cfg(target_os = "linux")]
    {
        let mgr = _runtime
            .sandbox_manager()
            .ok_or_else(|| ApiError::unavailable("sandbox subsystem is not enabled"))?;
        let info = mgr
            .inspect_sandbox(&_id)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        return Ok(Json(serde_json::json!({
            "id": info.id,
            "state": info.state.to_string(),
            "vcpus": info.vcpus,
            "memory_mib": info.memory_mib,
            "created_at": info.created_at.to_rfc3339(),
        })));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let machine = resolve_machine(_query.machine.as_deref(), &_runtime);
        let mut agent = _runtime
            .get_agent(machine)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let info = agent
            .sandbox_inspect(proto::InspectSandboxRequest { id: _id })
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let limits = info.limits.unwrap_or_default();
        Ok(Json(serde_json::json!({
            "id": info.id,
            "state": info.state,
            "vcpus": limits.vcpus,
            "memory_mib": limits.memory_mib,
            "created_at": unix_to_rfc3339(info.created_at),
        })))
    }
}

async fn stop_sandbox(
    State(_runtime): State<Arc<Runtime>>,
    Path(_id): Path<String>,
    Query(_query): Query<MachineQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    #[cfg(target_os = "linux")]
    {
        let mgr = _runtime
            .sandbox_manager()
            .ok_or_else(|| ApiError::unavailable("sandbox subsystem is not enabled"))?;
        mgr.stop_sandbox(&_id, 30)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        return Ok(Json(serde_json::json!({"status": "stopped"})));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let machine = resolve_machine(_query.machine.as_deref(), &_runtime);
        let mut agent = _runtime
            .get_agent(machine)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        agent
            .sandbox_stop(proto::StopSandboxRequest {
                id: _id,
                timeout_seconds: 30,
            })
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        Ok(Json(serde_json::json!({"status": "stopped"})))
    }
}

async fn remove_sandbox(
    State(_runtime): State<Arc<Runtime>>,
    Path(_id): Path<String>,
    Query(_query): Query<MachineQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    #[cfg(target_os = "linux")]
    {
        let mgr = _runtime
            .sandbox_manager()
            .ok_or_else(|| ApiError::unavailable("sandbox subsystem is not enabled"))?;
        mgr.remove_sandbox(&_id, true)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        return Ok(Json(serde_json::json!({"status": "removed"})));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let machine = resolve_machine(_query.machine.as_deref(), &_runtime);
        let mut agent = _runtime
            .get_agent(machine)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        agent
            .sandbox_remove(proto::RemoveSandboxRequest {
                id: _id,
                force: true,
            })
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
        Ok(Json(serde_json::json!({"status": "removed"})))
    }
}

#[derive(Deserialize)]
struct RunSandboxRequest {
    cmd: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    tty: bool,
    #[serde(default)]
    timeout_seconds: Option<u32>,
}

async fn run_sandbox(
    State(_runtime): State<Arc<Runtime>>,
    Path(_id): Path<String>,
    Query(_query): Query<MachineQuery>,
    Json(_req): Json<RunSandboxRequest>,
) -> Result<Response, ApiError> {
    #[cfg(target_os = "linux")]
    {
        let mgr = _runtime
            .sandbox_manager()
            .ok_or_else(|| ApiError::unavailable("sandbox subsystem is not enabled"))?;

        let rx = mgr
            .run_in_sandbox(
                &_id,
                arcbox_vm::StartCommand {
                    cmd: _req.cmd,
                    env: _req.env,
                    working_dir: _req.working_dir.unwrap_or_default(),
                    user: _req.user.unwrap_or_default(),
                    tty: _req.tty,
                    timeout_seconds: _req.timeout_seconds.unwrap_or(0),
                },
            )
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;

        use axum::response::sse::Event;
        use std::convert::Infallible;
        use tokio_stream::StreamExt as _;

        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(|chunk| {
            let data = serde_json::json!({
                "stream": chunk.stream,
                "data": String::from_utf8_lossy(&chunk.data),
                "exit_code": chunk.exit_code,
                "done": chunk.done,
            });
            Ok::<_, Infallible>(Event::default().data(data.to_string()))
        });

        return Ok(sse::sse_response(stream));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let machine = resolve_machine(_query.machine.as_deref(), &_runtime);
        let agent = _runtime
            .get_agent(machine)
            .map_err(|e| ApiError::internal(e.to_string()))?;

        let proto_req = proto::RunRequest {
            id: _id,
            cmd: _req.cmd,
            env: _req.env,
            working_dir: _req.working_dir.unwrap_or_default(),
            user: _req.user.unwrap_or_default(),
            tty: _req.tty,
            timeout_seconds: _req.timeout_seconds.unwrap_or(0),
        };

        let rx = agent
            .sandbox_run(proto_req)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;

        use axum::response::sse::Event;
        use std::convert::Infallible;
        use tokio_stream::StreamExt as _;

        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(|result| {
            let chunk = result.unwrap_or_else(|e| proto::RunOutput {
                stream: "stderr".to_string(),
                data: e.to_string().into_bytes(),
                exit_code: -1,
                done: true,
            });
            let data = serde_json::json!({
                "stream": chunk.stream,
                "data": String::from_utf8_lossy(&chunk.data),
                "exit_code": chunk.exit_code,
                "done": chunk.done,
            });
            Ok::<_, Infallible>(Event::default().data(data.to_string()))
        });

        Ok(sse::sse_response(stream))
    }
}

// =============================================================================
// Containers (proxy to guest docker)
// =============================================================================

#[derive(Serialize)]
struct ListContainersResponse {
    containers: Vec<serde_json::Value>,
}

async fn list_containers(
    State(_runtime): State<Arc<Runtime>>,
) -> ApiResult<ListContainersResponse> {
    // Container listing is handled by the Docker-compatible API.
    // This endpoint returns an empty list as a placeholder; clients
    // should use the Docker socket for full container management.
    Ok(Json(ListContainersResponse {
        containers: Vec::new(),
    }))
}
