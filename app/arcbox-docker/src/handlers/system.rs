use crate::api::AppState;
use crate::proxy;
use crate::types::{SystemInfoResponse, VersionResponse};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Method};
use bytes::Bytes;
use http_body_util::BodyExt;
use serde_json::Value;
use sha2::{Digest, Sha256};

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
///
/// # Errors
///
/// Returns an error only if response serialization fails.
pub async fn get_info(
    State(state): State<AppState>,
) -> crate::error::Result<Json<SystemInfoResponse>> {
    let docker_root_dir = state.runtime.config().data_dir.display().to_string();
    let mut info = SystemInfoResponse {
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
        id: deterministic_id(&docker_root_dir),
        docker_root_dir,
        debug: cfg!(debug_assertions),
        kernel_version: String::new(),
    };

    if state.runtime.ensure_vm_ready().await.is_ok() {
        if let Ok(response) = proxy::proxy_to_guest(
            &state.runtime,
            Method::GET,
            "/info",
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await
        {
            if let Ok(collected) = response.into_body().collect().await {
                if let Ok(guest_info) = serde_json::from_slice::<Value>(&collected.to_bytes()) {
                    merge_guest_info(&guest_info, &mut info);
                }
            }
        }
    }

    Ok(Json(info))
}

/// Ping handler.
pub async fn ping() -> &'static str {
    "OK"
}

fn num_cpus() -> i64 {
    std::thread::available_parallelism()
        .map(|n| i64::try_from(n.get()).unwrap_or(i64::MAX))
        .unwrap_or(1)
}

fn total_memory() -> i64 {
    use sysinfo::System;
    let sys = System::new_all();
    i64::try_from(sys.total_memory()).unwrap_or(i64::MAX)
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "arcbox".to_string())
}

fn deterministic_id(data_dir: &str) -> String {
    let digest = Sha256::digest(data_dir.as_bytes());
    hex::encode(&digest[..12])
}

fn merge_guest_info(guest_info: &Value, info: &mut SystemInfoResponse) {
    info.containers = guest_i64(guest_info, "/Containers").unwrap_or(info.containers);
    info.containers_running =
        guest_i64(guest_info, "/ContainersRunning").unwrap_or(info.containers_running);
    info.containers_paused =
        guest_i64(guest_info, "/ContainersPaused").unwrap_or(info.containers_paused);
    info.containers_stopped =
        guest_i64(guest_info, "/ContainersStopped").unwrap_or(info.containers_stopped);
    info.images = guest_i64(guest_info, "/Images").unwrap_or(info.images);

    if let Some(kernel_version) = guest_string(guest_info, "/KernelVersion") {
        info.kernel_version = kernel_version;
    }
    if let Some(operating_system) = guest_string(guest_info, "/OperatingSystem") {
        info.operating_system = operating_system;
    }
    if let Some(os_type) = guest_string(guest_info, "/OSType") {
        info.os_type = os_type;
    }
    if let Some(architecture) = guest_string(guest_info, "/Architecture") {
        info.architecture = architecture;
    }
}

fn guest_i64(guest_info: &Value, path: &str) -> Option<i64> {
    guest_info.pointer(path).and_then(Value::as_i64)
}

fn guest_string(guest_info: &Value, path: &str) -> Option<String> {
    guest_info
        .pointer(path)
        .and_then(Value::as_str)
        .map(str::to_owned)
}
