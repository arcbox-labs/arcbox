use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use vmm_core::VmmManager;

use crate::proto::arcbox::{
    system_service_server::SystemService, Event, EventsRequest, GetInfoRequest, GetInfoResponse,
    GetVersionRequest, GetVersionResponse, PruneRequest, PruneResponse, SystemPingRequest,
    SystemPingResponse,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Implementation of `arcbox.v1.SystemService`.
pub struct SystemServiceImpl {
    manager: Arc<VmmManager>,
}

impl SystemServiceImpl {
    pub fn new(manager: Arc<VmmManager>) -> Self {
        Self { manager }
    }
}

#[tonic::async_trait]
impl SystemService for SystemServiceImpl {
    /// Return daemon statistics.
    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        let all_vms = self
            .manager
            .list_vms(true)
            .map_err(|e| Status::internal(e.to_string()))?;

        let running = all_vms
            .iter()
            .filter(|v| v.state == vmm_core::VmState::Running)
            .count() as i64;

        Ok(Response::new(GetInfoResponse {
            containers: 0,
            containers_running: 0,
            containers_paused: 0,
            containers_stopped: 0,
            images: 0,
            machines: all_vms.len() as i64,
            machines_running: running,
            server_version: VERSION.into(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            mem_total: total_memory_bytes(),
            ncpu: num_cpus(),
            data_dir: String::new(),
            kernel_version: kernel_version(),
            os_type: "linux".into(),
            logging_driver: "tracing".into(),
            storage_driver: "ext4".into(),
        }))
    }

    /// Return daemon version.
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse {
            version: VERSION.into(),
            api_version: "1.0".into(),
            min_api_version: "1.0".into(),
            git_commit: option_env!("GIT_COMMIT").unwrap_or("unknown").into(),
            build_time: option_env!("BUILD_TIME").unwrap_or("unknown").into(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            go_version: String::new(),
        }))
    }

    /// Liveness probe.
    async fn ping(
        &self,
        _request: Request<SystemPingRequest>,
    ) -> Result<Response<SystemPingResponse>, Status> {
        Ok(Response::new(SystemPingResponse {
            api_version: "1.0".into(),
            build_version: VERSION.into(),
        }))
    }

    type EventsStream = Pin<Box<dyn Stream<Item = Result<Event, Status>> + Send + 'static>>;

    /// VM lifecycle event stream (placeholder — will be backed by a broadcast channel).
    async fn events(
        &self,
        _request: Request<EventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        // Return an empty stream for now; real implementation would subscribe
        // to a tokio::sync::broadcast channel on VmmManager.
        let stream = tokio_stream::empty();
        Ok(Response::new(Box::pin(stream)))
    }

    /// Prune unused resources (not implemented in VMM context).
    async fn prune(
        &self,
        _request: Request<PruneRequest>,
    ) -> Result<Response<PruneResponse>, Status> {
        Ok(Response::new(PruneResponse {
            space_reclaimed: 0,
            containers_deleted: vec![],
            images_deleted: vec![],
            networks_deleted: vec![],
            volumes_deleted: vec![],
        }))
    }
}

// =============================================================================
// Host introspection helpers
// =============================================================================

fn total_memory_bytes() -> i64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<i64>() {
                            return kb * 1024;
                        }
                    }
                }
            }
        }
    }
    0
}

fn num_cpus() -> i32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/cpuinfo") {
            return s.lines().filter(|l| l.starts_with("processor")).count() as i32;
        }
    }
    1
}

fn kernel_version() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(uname) = std::fs::read_to_string("/proc/version") {
            return uname.split_whitespace().nth(2).unwrap_or("unknown").into();
        }
    }
    "unknown".into()
}
