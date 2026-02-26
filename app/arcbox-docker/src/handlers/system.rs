use crate::api::AppState;
use crate::types::{SystemInfoResponse, VersionResponse};
use axum::Json;
use axum::extract::State;

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
