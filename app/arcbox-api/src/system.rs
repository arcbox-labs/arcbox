//! SystemService gRPC implementation.
//!
//! Provides setup status queries so the desktop app (or any gRPC client)
//! can observe daemon readiness without managing its lifecycle.

use std::pin::Pin;
use std::sync::Arc;

use arcbox_grpc::SystemService;
use arcbox_protocol::v1::{Empty, SetupStatus, setup_status};
use tokio::sync::watch;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

/// Shared state tracking daemon startup progress.
///
/// Updated by the daemon as it progresses through startup phases.
/// Observed by `SystemServiceImpl` to serve gRPC queries.
#[derive(Debug, Clone)]
pub struct SetupState {
    tx: Arc<watch::Sender<SetupStatus>>,
}

impl SetupState {
    /// Creates a new setup state starting in the INITIALIZING phase.
    pub fn new() -> Self {
        let initial = SetupStatus {
            phase: setup_status::Phase::Initializing.into(),
            dns_resolver_installed: false,
            docker_socket_linked: false,
            route_installed: false,
            vm_running: false,
            message: "Daemon starting...".to_string(),
            docker_tools_installed: false,
        };
        let (tx, _) = watch::channel(initial);
        Self { tx: Arc::new(tx) }
    }

    /// Updates the current setup phase.
    pub fn set_phase(&self, phase: setup_status::Phase, message: &str) {
        self.tx.send_modify(|s| {
            s.phase = phase.into();
            message.clone_into(&mut s.message);
        });
    }

    /// Updates a specific infrastructure flag.
    pub fn set_dns_installed(&self, installed: bool) {
        self.tx
            .send_modify(|s| s.dns_resolver_installed = installed);
    }

    pub fn set_docker_socket_linked(&self, linked: bool) {
        self.tx.send_modify(|s| s.docker_socket_linked = linked);
    }

    pub fn set_route_installed(&self, installed: bool) {
        self.tx.send_modify(|s| s.route_installed = installed);
    }

    pub fn set_vm_running(&self, running: bool) {
        self.tx.send_modify(|s| s.vm_running = running);
    }

    pub fn set_docker_tools_installed(&self, installed: bool) {
        self.tx
            .send_modify(|s| s.docker_tools_installed = installed);
    }

    /// Returns a watch receiver for streaming updates.
    fn subscribe(&self) -> watch::Receiver<SetupStatus> {
        self.tx.subscribe()
    }

    /// Returns the current status snapshot.
    pub fn current(&self) -> SetupStatus {
        self.tx.borrow().clone()
    }
}

impl Default for SetupState {
    fn default() -> Self {
        Self::new()
    }
}

/// SystemService gRPC implementation.
pub struct SystemServiceImpl {
    setup_state: Arc<SetupState>,
}

impl SystemServiceImpl {
    /// Creates a new system service.
    pub fn new(setup_state: Arc<SetupState>) -> Self {
        Self { setup_state }
    }
}

#[tonic::async_trait]
impl SystemService for SystemServiceImpl {
    async fn get_info(
        &self,
        _request: Request<arcbox_protocol::v1::GetInfoRequest>,
    ) -> Result<Response<arcbox_protocol::v1::GetInfoResponse>, Status> {
        // TODO: Populate from runtime.
        Err(Status::unimplemented("get_info not yet implemented"))
    }

    async fn get_version(
        &self,
        _request: Request<arcbox_protocol::v1::GetVersionRequest>,
    ) -> Result<Response<arcbox_protocol::v1::GetVersionResponse>, Status> {
        Ok(Response::new(arcbox_protocol::v1::GetVersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: "1.0".to_string(),
            min_api_version: "1.0".to_string(),
            ..Default::default()
        }))
    }

    async fn ping(
        &self,
        _request: Request<arcbox_protocol::v1::SystemPingRequest>,
    ) -> Result<Response<arcbox_protocol::v1::SystemPingResponse>, Status> {
        Ok(Response::new(arcbox_protocol::v1::SystemPingResponse {
            api_version: "1.0".to_string(),
            build_version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    type EventsStream =
        Pin<Box<dyn Stream<Item = Result<arcbox_protocol::v1::Event, Status>> + Send + 'static>>;

    async fn events(
        &self,
        _request: Request<arcbox_protocol::v1::EventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        // TODO: Implement event streaming.
        Err(Status::unimplemented("events not yet implemented"))
    }

    async fn prune(
        &self,
        _request: Request<arcbox_protocol::v1::PruneRequest>,
    ) -> Result<Response<arcbox_protocol::v1::PruneResponse>, Status> {
        // TODO: Implement resource pruning.
        Err(Status::unimplemented("prune not yet implemented"))
    }

    async fn get_setup_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<SetupStatus>, Status> {
        Ok(Response::new(self.setup_state.current()))
    }

    type WatchSetupStatusStream =
        Pin<Box<dyn Stream<Item = Result<SetupStatus, Status>> + Send + 'static>>;

    async fn watch_setup_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::WatchSetupStatusStream>, Status> {
        let mut rx = self.setup_state.subscribe();
        let stream = async_stream::stream! {
            // Send current state immediately.
            let initial = rx.borrow_and_update().clone();
            yield Ok(initial);
            // Then stream changes.
            while rx.changed().await.is_ok() {
                let status = rx.borrow_and_update().clone();
                yield Ok(status);
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}
