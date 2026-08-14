//! Test-only mock of the arcbox-daemon's `MacosService`, served on a
//! scratch Unix socket, so `VmRunner` probes, pulls, and activations can be
//! exercised without a real daemon (or a macOS host). Only the methods the
//! agent actually calls are implemented; the rest answer `UNIMPLEMENTED`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arcbox_grpc::{MacosService, MacosServiceServer};
use arcbox_protocol::v1::{
    CreateMacosMachineRequest, Empty, InspectMacosMachineRequest, MacosImageListResponse,
    MacosImagePullEvent, MacosImagePullRequest, MacosImageRemoveRequest, MacosImageResolveRequest,
    MacosImageResolveResponse, MacosImageSummary, MacosMachineInfo, MacosMachineListResponse,
    RemoveMacosMachineRequest, StartMacosMachineRequest, StopMacosMachineRequest,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request, Response, Status};

/// A running mock daemon: the socket path `VmRunner` should dial, plus the
/// guards that keep it alive (drop the handle to tear it down).
pub struct MockDaemon {
    pub socket: PathBuf,
    /// Stream names the daemon reports installed; `ImagePull` appends.
    installed: Arc<Mutex<Vec<String>>>,
    _dir: tempfile::TempDir,
    server: tokio::task::JoinHandle<()>,
}

impl MockDaemon {
    /// Serve a mock daemon whose registry starts with `images` installed.
    pub async fn spawn(images: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("scratch dir for mock daemon");
        let socket = dir.path().join("arcbox.sock");
        let installed = Arc::new(Mutex::new(
            images.iter().map(|&s| s.to_owned()).collect::<Vec<_>>(),
        ));
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind mock daemon socket");
        let service = Service {
            installed: Arc::clone(&installed),
        };
        let server = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(MacosServiceServer::new(service))
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await;
        });
        Self {
            socket,
            installed,
            _dir: dir,
            server,
        }
    }

    /// Register `name` as installed, as if pulled out-of-band (e.g. by
    /// `abctl macos image pull`) — the next `ImageList` reports it.
    pub fn install(&self, name: &str) {
        self.installed
            .lock()
            .expect("mock registry lock")
            .push(name.to_owned());
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct Service {
    installed: Arc<Mutex<Vec<String>>>,
}

fn summary(name: &str) -> MacosImageSummary {
    MacosImageSummary {
        name: name.to_owned(),
        minimum_cpu_count: 2,
        minimum_memory_mib: 4096,
        ..Default::default()
    }
}

#[tonic::async_trait]
impl MacosService for Service {
    async fn create(
        &self,
        _: Request<CreateMacosMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented("mock daemon runs no guests"))
    }

    async fn start(&self, _: Request<StartMacosMachineRequest>) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented("mock daemon runs no guests"))
    }

    async fn stop(&self, _: Request<StopMacosMachineRequest>) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented("mock daemon runs no guests"))
    }

    async fn remove(
        &self,
        _: Request<RemoveMacosMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented("mock daemon runs no guests"))
    }

    /// Always empty: the leftover sweep sees nothing to remove.
    async fn list(&self, _: Request<Empty>) -> Result<Response<MacosMachineListResponse>, Status> {
        Ok(Response::new(MacosMachineListResponse {
            machines: Vec::new(),
        }))
    }

    async fn inspect(
        &self,
        _: Request<InspectMacosMachineRequest>,
    ) -> Result<Response<MacosMachineInfo>, Status> {
        Err(Status::unimplemented("mock daemon runs no guests"))
    }

    type ImagePullStream = ReceiverStream<Result<MacosImagePullEvent, Status>>;

    /// Registers the reference's stream name as installed and emits the
    /// terminal "done" event, mirroring the real daemon's contract.
    async fn image_pull(
        &self,
        request: Request<MacosImagePullRequest>,
    ) -> Result<Response<Self::ImagePullStream>, Status> {
        let reference = request.into_inner().reference;
        let stream_name = reference
            .split_once('@')
            .map_or(reference.as_str(), |(s, _)| s)
            .to_owned();
        {
            let mut installed = self.installed.lock().expect("mock registry lock");
            if !installed.contains(&stream_name) {
                installed.push(stream_name.clone());
            }
        }
        let (tx, rx) = mpsc::channel(2);
        let _ = tx
            .send(Ok(MacosImagePullEvent {
                stage: "done".to_owned(),
                fraction: 1.0,
                image: Some(summary(&stream_name)),
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn image_resolve(
        &self,
        _: Request<MacosImageResolveRequest>,
    ) -> Result<Response<MacosImageResolveResponse>, Status> {
        Err(Status::unimplemented("mock daemon resolves nothing"))
    }

    async fn image_list(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<MacosImageListResponse>, Status> {
        let images = self
            .installed
            .lock()
            .expect("mock registry lock")
            .iter()
            .map(|name| summary(name))
            .collect();
        Ok(Response::new(MacosImageListResponse { images }))
    }

    async fn image_remove(
        &self,
        _: Request<MacosImageRemoveRequest>,
    ) -> Result<Response<Empty>, Status> {
        Err(Status::unimplemented("mock daemon removes nothing"))
    }
}
