//! macOS guest service gRPC implementation (Apple Silicon only).
//!
//! Disposable macOS VMs and their base images. The whole surface delegates to
//! [`arcbox_core::MacMachineManager`]; lifecycle operations hold `!Send`
//! Virtualization.framework handles across await, so they run through
//! [`super::run_macos_blocking`].

use std::sync::Arc;

use arcbox_grpc::v1::macos_service_server;
use arcbox_protocol::v1::{
    CreateMacosMachineRequest, Empty, InspectMacosMachineRequest, MacosImageListResponse,
    MacosImagePullRequest, MacosImageRemoveRequest, MacosImageSummary, MacosMachineInfo,
    MacosMachineListResponse, MacosMachineSummary, RemoveMacosMachineRequest,
    StartMacosMachineRequest, StopMacosMachineRequest,
};
use tonic::{Request, Response, Status};

use super::{SharedRuntime, SharedRuntimeExt, run_macos_blocking};

/// Minimum system disk size for a base image, in GiB.
const MIN_IMAGE_DISK_GB: u64 = 64;

/// macOS guest service implementation.
pub struct MacosServiceImpl {
    runtime: SharedRuntime,
}

impl MacosServiceImpl {
    /// Creates a new macOS guest service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl macos_service_server::MacosService for MacosServiceImpl {
    async fn create(
        &self,
        request: Request<CreateMacosMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.runtime
            .ready()?
            .mac_machine_manager()
            .create(arcbox_core::MacMachineConfig {
                name: req.name,
                image: req.image,
                cpus: req.cpus,
                memory_mib: req.memory_mib,
            })
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    async fn start(
        &self,
        request: Request<StartMacosMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let name = request.into_inner().name;
        let mgr = Arc::clone(self.runtime.ready()?.mac_machine_manager());
        run_macos_blocking(move || async move { mgr.start(&name).await }).await?;
        Ok(Response::new(Empty {}))
    }

    async fn stop(
        &self,
        request: Request<StopMacosMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let name = request.into_inner().name;
        let mgr = Arc::clone(self.runtime.ready()?.mac_machine_manager());
        run_macos_blocking(move || async move { mgr.stop(&name).await }).await?;
        Ok(Response::new(Empty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveMacosMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let mgr = Arc::clone(self.runtime.ready()?.mac_machine_manager());
        let name = req.name;
        let force = req.force;
        run_macos_blocking(move || async move { mgr.remove(&name, force).await }).await?;
        Ok(Response::new(Empty {}))
    }

    async fn list(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<MacosMachineListResponse>, Status> {
        let machines = self
            .runtime
            .ready()?
            .mac_machine_manager()
            .list()
            .into_iter()
            .map(|m| MacosMachineSummary {
                name: m.name,
                state: format!("{:?}", m.state).to_lowercase(),
                cpus: m.cpus,
                memory_mib: m.memory_mib,
                image: m.image,
                created: m.created_at.timestamp(),
            })
            .collect();
        Ok(Response::new(MacosMachineListResponse { machines }))
    }

    async fn inspect(
        &self,
        request: Request<InspectMacosMachineRequest>,
    ) -> Result<Response<MacosMachineInfo>, Status> {
        let name = request.into_inner().name;
        let machine = self
            .runtime
            .ready()?
            .mac_machine_manager()
            .get(&name)
            .ok_or_else(|| Status::not_found("macOS guest not found"))?;
        Ok(Response::new(MacosMachineInfo {
            name: machine.name,
            state: format!("{:?}", machine.state).to_lowercase(),
            cpus: machine.cpus,
            memory_mib: machine.memory_mib,
            image: machine.image,
            created: machine.created_at.timestamp(),
        }))
    }

    async fn image_pull(
        &self,
        request: Request<MacosImagePullRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let mgr = Arc::clone(self.runtime.ready()?.mac_machine_manager());
        let name = req.name;
        let ipsw = req.ipsw_path;
        let disk_gb = req.disk_gb.max(MIN_IMAGE_DISK_GB);
        // An empty ipsw_path means "download the latest from Apple".
        let source = if ipsw.is_empty() {
            arcbox_core::PullSource::Latest
        } else {
            arcbox_core::PullSource::LocalIpsw(std::path::PathBuf::from(ipsw))
        };
        run_macos_blocking(move || async move {
            let mut last = String::new();
            mgr.images()
                .pull(source, &name, disk_gb, |phase, frac| {
                    let label = match phase {
                        arcbox_core::PullPhase::Download => "download",
                        arcbox_core::PullPhase::Install => "install",
                    };
                    let msg = format!("macOS image {label}: {:.0}%", frac * 100.0);
                    if msg != last {
                        tracing::info!("{msg}");
                        last = msg;
                    }
                })
                .await
        })
        .await?;
        Ok(Response::new(Empty {}))
    }

    async fn image_list(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<MacosImageListResponse>, Status> {
        let images = self
            .runtime
            .ready()?
            .mac_machine_manager()
            .images()
            .list()
            .into_iter()
            .map(|i| MacosImageSummary {
                name: i.meta.name,
                minimum_cpu_count: i.meta.minimum_cpu_count,
                minimum_memory_mib: i.meta.minimum_memory_mib,
                disk_gb: i.meta.disk_gb,
                created: i.meta.created_at.timestamp(),
                source: i.meta.source.unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(MacosImageListResponse { images }))
    }

    async fn image_remove(
        &self,
        request: Request<MacosImageRemoveRequest>,
    ) -> Result<Response<Empty>, Status> {
        let name = request.into_inner().name;
        self.runtime
            .ready()?
            .mac_machine_manager()
            .images()
            .remove(&name)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }
}
