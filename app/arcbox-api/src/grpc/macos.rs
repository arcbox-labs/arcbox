//! macOS guest service gRPC implementation (Apple Silicon only).
//!
//! Disposable macOS VMs and their base images. The whole surface delegates to
//! [`arcbox_core::MacMachineManager`]; lifecycle operations hold `!Send`
//! Virtualization.framework handles across await, so they run through
//! [`super::run_macos_blocking`]. Image pulls are plain `Send` futures and
//! stream progress from an ordinary spawned task.

use std::pin::Pin;
use std::sync::Arc;

use arcbox_core::{PullStage, RemoteLocation, RemoteSource};
use arcbox_grpc::v1::macos_service_server;
use arcbox_protocol::v1::{
    CreateMacosMachineRequest, Empty, InspectMacosMachineRequest, MacosImageListResponse,
    MacosImagePullEvent, MacosImagePullRequest, MacosImageRemoveRequest, MacosImageSummary,
    MacosMachineInfo, MacosMachineListResponse, MacosMachineSummary, RemoveMacosMachineRequest,
    StartMacosMachineRequest, StopMacosMachineRequest,
};
use tokio_stream::Stream;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{Request, Response, Status};

use super::{SharedRuntime, SharedRuntimeExt, run_macos_blocking};

/// Wire name of a pull stage.
const fn stage_name(stage: PullStage) -> &'static str {
    match stage {
        PullStage::Resolve => "resolving",
        PullStage::Validate => "validating",
        PullStage::Disk => "disk",
        PullStage::Aux => "aux",
        PullStage::Verify => "verifying",
    }
}

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

    type ImagePullStream = Pin<Box<dyn Stream<Item = Result<MacosImagePullEvent, Status>> + Send>>;

    async fn image_pull(
        &self,
        request: Request<MacosImagePullRequest>,
    ) -> Result<Response<Self::ImagePullStream>, Status> {
        let req = request.into_inner();
        let source =
            match (req.reference.is_empty(), req.manifest_url.is_empty()) {
                (false, true) => RemoteSource::Reference(req.reference.parse().map_err(
                    |e: arcbox_core::CoreError| Status::invalid_argument(e.to_string()),
                )?),
                (true, false) => RemoteSource::Manifest(RemoteLocation::parse(&req.manifest_url)),
                _ => {
                    return Err(Status::invalid_argument(
                        "exactly one of reference / manifest_url must be set",
                    ));
                }
            };

        let mgr = Arc::clone(self.runtime.ready()?.mac_machine_manager());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            // Throttle to whole-percent changes so a multi-gigabyte download
            // doesn't emit an event per network chunk.
            let progress = tx.clone();
            let mut last = (PullStage::Resolve, u32::MAX);
            let result = mgr
                .images()
                .pull_remote(source, move |stage, fraction| {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "fraction is clamped to 0.0..=1.0 by the producer"
                    )]
                    let percent = (fraction * 100.0) as u32;
                    if last != (stage, percent) {
                        last = (stage, percent);
                        let _ = progress.send(Ok(MacosImagePullEvent {
                            stage: stage_name(stage).to_string(),
                            fraction,
                        }));
                    }
                })
                .await;
            if let Err(e) = result {
                let _ = tx.send(Err(Status::internal(e.to_string())));
            }
        });
        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(rx))))
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
                version: i.meta.version.unwrap_or_default(),
                os_version: i.meta.os_version.unwrap_or_default(),
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
