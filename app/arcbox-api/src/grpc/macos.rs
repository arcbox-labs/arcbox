//! macOS guest service gRPC implementation (Apple Silicon only).
//!
//! Disposable macOS VMs and their base images. The whole surface delegates to
//! [`arcbox_core::MacMachineManager`]; lifecycle operations hold `!Send`
//! Virtualization.framework handles across await, so they run through
//! [`super::run_macos_blocking`]. Image pulls are plain `Send` futures and
//! stream progress from an ordinary spawned task.

use std::pin::Pin;
use std::sync::Arc;

use arcbox_core::{MacImage, PullStage, RemoteLocation, RemoteSource};
use arcbox_grpc::v1::macos_service_server;
use arcbox_protocol::v1::{
    CreateMacosMachineRequest, Empty, InspectMacosMachineRequest, MacosImageListResponse,
    MacosImagePullEvent, MacosImagePullRequest, MacosImageRemoveRequest, MacosImageResolveRequest,
    MacosImageResolveResponse, MacosImageSummary, MacosMachineInfo, MacosMachineListResponse,
    MacosMachineSummary, RemoveMacosMachineRequest, StartMacosMachineRequest,
    StopMacosMachineRequest,
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

/// Parses an image source: exactly one of `reference` / `manifest_url`.
/// Shared by `ImagePull` and `ImageResolve`, which take the same source.
fn parse_source(reference: &str, manifest_url: &str) -> Result<RemoteSource, Status> {
    match (reference.is_empty(), manifest_url.is_empty()) {
        (false, true) => Ok(RemoteSource::Reference(reference.parse().map_err(
            |e: arcbox_core::CoreError| Status::invalid_argument(e.to_string()),
        )?)),
        (true, false) => Ok(RemoteSource::Manifest(RemoteLocation::parse(manifest_url))),
        _ => Err(Status::invalid_argument(
            "exactly one of reference / manifest_url must be set",
        )),
    }
}

/// Wire summary of a registered image. Shared by `ImageList` and
/// `ImagePull`'s terminal event.
fn image_summary(image: MacImage) -> MacosImageSummary {
    MacosImageSummary {
        name: image.meta.name,
        minimum_cpu_count: image.meta.minimum_cpu_count,
        minimum_memory_mib: image.meta.minimum_memory_mib,
        disk_gb: image.meta.disk_gb,
        created: image.meta.created_at.timestamp(),
        source: image.meta.source.unwrap_or_default(),
        version: image.meta.version.unwrap_or_default(),
        os_version: image.meta.os_version.unwrap_or_default(),
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
            mac_address: machine.mac_address.unwrap_or_default(),
            ip_address: machine.ip_address.unwrap_or_default(),
        }))
    }

    type ImagePullStream = Pin<Box<dyn Stream<Item = Result<MacosImagePullEvent, Status>> + Send>>;

    async fn image_pull(
        &self,
        request: Request<MacosImagePullRequest>,
    ) -> Result<Response<Self::ImagePullStream>, Status> {
        let req = request.into_inner();
        let source = parse_source(&req.reference, &req.manifest_url)?;

        let mgr = Arc::clone(self.runtime.ready()?.mac_machine_manager());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            // Throttle to whole-percent changes so a multi-gigabyte download
            // doesn't emit an event per network chunk.
            let progress = tx.clone();
            let mut last = (PullStage::Resolve, u32::MAX);
            let pull = mgr.images().pull_remote(source, move |stage, fraction| {
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
                        image: None,
                    }));
                }
            });
            // A dropped client stream closes the channel; cancel the pull by
            // dropping its future (its staging guard cleans up the partials).
            tokio::select! {
                result = pull => match result {
                    // Terminal event: what actually landed (or was already
                    // present), so the caller learns the concrete version a
                    // floating reference resolved to.
                    Ok(image) => {
                        let _ = tx.send(Ok(MacosImagePullEvent {
                            stage: "done".to_string(),
                            fraction: 1.0,
                            image: Some(image_summary(image)),
                        }));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string())));
                    }
                },
                () = tx.closed() => {
                    tracing::info!("macOS image pull canceled: client disconnected");
                }
            }
        });
        Ok(Response::new(Box::pin(UnboundedReceiverStream::new(rx))))
    }

    async fn image_resolve(
        &self,
        request: Request<MacosImageResolveRequest>,
    ) -> Result<Response<MacosImageResolveResponse>, Status> {
        let req = request.into_inner();
        let source = parse_source(&req.reference, &req.manifest_url)?;
        let mgr = Arc::clone(self.runtime.ready()?.mac_machine_manager());
        let resolved = mgr
            .images()
            .resolve_remote(&source)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(MacosImageResolveResponse {
            name: resolved.name,
            version: resolved.version,
            os_version: resolved.os_version,
            minimum_cpu_count: resolved.minimum_cpu_count,
            minimum_memory_mib: resolved.minimum_memory_mib,
            disk_gb: resolved.disk_gb,
            installed_version: resolved.installed_version.unwrap_or_default(),
        }))
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
            .map(image_summary)
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
