//! Sandbox service gRPC implementation.

use std::pin::Pin;

use arcbox_grpc::SandboxService;
use arcbox_protocol::sandbox_v1::Empty as SandboxEmpty;
use arcbox_protocol::sandbox_v1::{
    CreateSandboxRequest, CreateSandboxResponse, ExecInput, ExecOutput, InspectSandboxRequest,
    ListSandboxesRequest, ListSandboxesResponse, RemoveSandboxRequest, RunOutput, RunRequest,
    SandboxEvent, SandboxEventsRequest, SandboxInfo, StopSandboxRequest, exec_input,
};
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::codec::Streaming;
use tonic::{Request, Response, Status};

use crate::ApiError;

use super::{RequestExt, SharedRuntime, SharedRuntimeExt};

/// Sandbox service implementation.
///
/// Routes each RPC to the `arcbox-agent` running in the target guest VM
/// via the port-1024 vsock binary-frame protocol. The target machine is
/// identified by the `x-machine` gRPC metadata header attached by the CLI.
pub struct SandboxServiceImpl {
    runtime: SharedRuntime,
}

impl SandboxServiceImpl {
    /// Creates a new sandbox service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl SandboxService for SandboxServiceImpl {
    async fn create(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_create(request.into_inner())
            .await
            .map_err(ApiError::from)?;

        // Register sandbox DNS so the host can resolve sandbox-id.arcbox.local.
        if let Ok(ip) = resp.ip_address.parse() {
            self.runtime
                .ready()?
                .register_dns(&resp.id, std::slice::from_ref(&resp.id), ip)
                .await;
        }

        Ok(Response::new(resp))
    }

    type RunStream = Pin<Box<dyn Stream<Item = Result<RunOutput, Status>> + Send + 'static>>;

    async fn run(&self, request: Request<RunRequest>) -> Result<Response<Self::RunStream>, Status> {
        let machine = request.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_run(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        let stream = UnboundedReceiverStream::new(rx)
            .map(|r| r.map_err(|e| Status::internal(e.to_string())));
        Ok(Response::new(Box::pin(stream)))
    }

    type ExecStream = Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    async fn exec(
        &self,
        request: Request<Streaming<ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let machine = request.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;

        let mut stream = request.into_inner();

        // The first message in the stream must carry the Init payload.
        let first = stream
            .next()
            .await
            .ok_or_else(|| Status::invalid_argument("exec: stream closed before Init message"))??;

        let exec_req = match first.payload {
            Some(exec_input::Payload::Init(req)) => req,
            _ => return Err(Status::invalid_argument("exec: first message must be Init")),
        };

        // Feed remaining gRPC input into a channel for the core layer.
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(Ok(input)) = stream.next().await {
                if let Some(exec_input::Payload::Stdin(data)) = input.payload {
                    if in_tx.send(data).await.is_err() {
                        return;
                    }
                }
            }
            let _ = in_tx.send(Vec::new()).await;
        });

        let out_rx = agent
            .sandbox_exec(exec_req, in_rx)
            .await
            .map_err(ApiError::from)?;

        let out_stream = UnboundedReceiverStream::new(out_rx)
            .map(|r| r.map_err(|e| Status::internal(e.to_string())));
        Ok(Response::new(Box::pin(out_stream)))
    }

    async fn stop(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<SandboxEmpty>, Status> {
        let machine = request.machine_id()?;
        let sandbox_id = request.get_ref().id.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_stop(request.into_inner())
            .await
            .map_err(ApiError::from)?;

        self.runtime
            .ready()?
            .deregister_dns_by_id(&sandbox_id)
            .await;

        Ok(Response::new(SandboxEmpty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveSandboxRequest>,
    ) -> Result<Response<SandboxEmpty>, Status> {
        let machine = request.machine_id()?;
        let sandbox_id = request.get_ref().id.clone();
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_remove(request.into_inner())
            .await
            .map_err(ApiError::from)?;

        self.runtime
            .ready()?
            .deregister_dns_by_id(&sandbox_id)
            .await;

        Ok(Response::new(SandboxEmpty {}))
    }

    async fn inspect(
        &self,
        request: Request<InspectSandboxRequest>,
    ) -> Result<Response<SandboxInfo>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let info = agent
            .sandbox_inspect(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(info))
    }

    async fn list(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_list(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(resp))
    }

    type EventsStream = Pin<Box<dyn Stream<Item = Result<SandboxEvent, Status>> + Send + 'static>>;

    async fn events(
        &self,
        request: Request<SandboxEventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        let machine = request.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_events(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        let stream = UnboundedReceiverStream::new(rx)
            .map(|r| r.map_err(|e| Status::internal(e.to_string())));
        Ok(Response::new(Box::pin(stream)))
    }
}
