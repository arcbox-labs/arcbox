//! Sandbox process (execution) service — data plane.

use std::pin::Pin;

use arcbox_grpc::SandboxProcessService;
use arcbox_protocol::pbjson_types::Empty;
use arcbox_protocol::sandbox_v1::{
    AttachExecutionRequest, Execution, ExecutionEvent, GetStdinStatusRequest, KeepAlive,
    ResizeExecutionTtyRequest, SignalExecutionRequest, StartExecutionRequest, StdinStatus,
    WaitExecutionRequest, WriteStdinRequest, execution_event,
};
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codec::Streaming;
use tonic::{Request, Response, Status};

use crate::ApiError;

use super::super::{RequestExt, SharedRuntime, SharedRuntimeExt};
use super::with_keepalive;

/// Execution service implementation.
///
/// Every call addresses one execution inside one sandbox and carries its
/// stdio, so this is the half a cloud deployment serves from whatever is
/// co-located with the sandbox rather than from the control-plane front
/// door.
pub struct SandboxProcessServiceImpl {
    runtime: SharedRuntime,
}

impl SandboxProcessServiceImpl {
    /// Creates a new execution service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl SandboxProcessService for SandboxProcessServiceImpl {
    async fn start_execution(
        &self,
        request: Request<StartExecutionRequest>,
    ) -> Result<Response<Execution>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let execution = agent
            .sandbox_exec_start(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(execution))
    }

    type AttachExecutionStream =
        Pin<Box<dyn Stream<Item = Result<ExecutionEvent, Status>> + Send + 'static>>;

    async fn attach_execution(
        &self,
        request: Request<AttachExecutionRequest>,
    ) -> Result<Response<Self::AttachExecutionStream>, Status> {
        let machine = request.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_exec_attach(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        let stream =
            ReceiverStream::new(rx).map(|r| r.map_err(|e| Status::from(ApiError::from(e))));
        let stream = with_keepalive(stream, || ExecutionEvent {
            event: Some(execution_event::Event::KeepAlive(KeepAlive {})),
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn write_stdin(
        &self,
        request: Request<WriteStdinRequest>,
    ) -> Result<Response<StdinStatus>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let status = agent
            .sandbox_stdin_write(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(status))
    }

    async fn stream_stdin(
        &self,
        request: Request<Streaming<WriteStdinRequest>>,
    ) -> Result<Response<StdinStatus>, Status> {
        let machine = request.machine_id()?;
        let mut stream = request.into_inner();

        let mut last = None;
        while let Some(req) = stream.message().await? {
            let mut agent = self
                .runtime
                .ready()?
                .get_agent(&machine)
                .map_err(ApiError::from)?;
            last = Some(
                agent
                    .sandbox_stdin_write(req)
                    .await
                    .map_err(ApiError::from)?,
            );
        }
        last.map(Response::new)
            .ok_or_else(|| Status::invalid_argument("stream_stdin: empty request stream"))
    }

    async fn get_stdin_status(
        &self,
        request: Request<GetStdinStatusRequest>,
    ) -> Result<Response<StdinStatus>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let status = agent
            .sandbox_stdin_status(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(status))
    }

    async fn signal_execution(
        &self,
        request: Request<SignalExecutionRequest>,
    ) -> Result<Response<Empty>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_exec_signal(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(Empty {}))
    }

    async fn resize_execution_tty(
        &self,
        request: Request<ResizeExecutionTtyRequest>,
    ) -> Result<Response<Empty>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_exec_resize(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(Empty {}))
    }

    async fn wait_execution(
        &self,
        request: Request<WaitExecutionRequest>,
    ) -> Result<Response<Execution>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let execution = agent
            .sandbox_exec_wait(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(execution))
    }
}
