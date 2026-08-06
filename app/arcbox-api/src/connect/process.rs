//! Sandbox process (execution) service — data plane.

use std::sync::Arc;

use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{ExecutionEvent, KeepAlive, execution_event};
use buffa_types::google::protobuf::Empty;
use connectrpc::{
    ConnectError, InboundStream, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;

use super::SharedRuntime;
use crate::ApiError;

use super::sandbox_locks::SandboxOperationLocks;
use super::sandbox_resume;
use super::{ConnectRuntimeExt as _, ContextExt as _, with_keepalive};

/// Execution service implementation.
///
/// Every call addresses one execution inside one sandbox and carries its
/// stdio, so this is the half a cloud deployment serves from whatever is
/// co-located with the sandbox rather than from the control-plane front
/// door.
///
/// Data-plane calls transparently resume a paused sandbox (CORE-21): a
/// guest answer of SANDBOX_PAUSED triggers one shared resume and one retry,
/// unless the caller opted out via `x-arcbox-no-auto-resume`. Calls that
/// address execution *history* (attach, wait, stdin status, signal, resize)
/// are served from the guest's registry without waking the sandbox.
pub struct SandboxProcessServiceImpl {
    runtime: SharedRuntime,
    operations: Arc<SandboxOperationLocks>,
}

impl SandboxProcessServiceImpl {
    /// Creates a new execution service with a deferred runtime.
    #[must_use]
    pub(super) fn new(runtime: SharedRuntime, operations: Arc<SandboxOperationLocks>) -> Self {
        Self {
            runtime,
            operations,
        }
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxProcessService for SandboxProcessServiceImpl {
    async fn start_execution(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::StartExecutionRequest>,
    ) -> ServiceResult<pb::Execution> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        let execution = sandbox_resume::with_auto_resume(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &req.sandbox_id,
            || {
                let req = req.clone();
                async {
                    let mut agent = runtime.get_agent(&machine)?;
                    agent.sandbox_exec_start(req).await
                }
            },
        )
        .await?;
        Response::ok(execution)
    }

    async fn attach_execution(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::AttachExecutionRequest>,
    ) -> ServiceResult<ServiceStream<ExecutionEvent>> {
        let machine = ctx.sandbox_machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_exec_attach(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        let stream =
            ReceiverStream::new(rx).map(|r| r.map_err(|e| ConnectError::from(ApiError::from(e))));
        let stream = with_keepalive(stream, || ExecutionEvent {
            event: Some(execution_event::Event::from(KeepAlive::default())),
            ..Default::default()
        });
        Response::ok(Box::pin(stream))
    }

    async fn write_stdin(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::WriteStdinRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        let status = sandbox_resume::with_auto_resume(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &req.sandbox_id,
            || {
                let req = req.clone();
                async {
                    let mut agent = runtime.get_agent(&machine)?;
                    agent.sandbox_stdin_write(req).await
                }
            },
        )
        .await?;
        Response::ok(status)
    }

    async fn stream_stdin(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<pb::WriteStdinRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        let machine = ctx.sandbox_machine_id()?;

        let mut last = None;
        while let Some(item) = requests.next().await {
            // `Some(Err(..))` is an abnormal end (decode failure or a
            // truncated body), so it must fail the RPC rather than be read
            // as a clean finish — only `None` means the client is done.
            let req = item?.to_owned_message();
            let runtime = self.runtime.ready()?;
            let status = sandbox_resume::with_auto_resume(
                runtime,
                &self.operations,
                &ctx,
                &machine,
                &req.sandbox_id,
                || {
                    let req = req.clone();
                    async {
                        let mut agent = runtime.get_agent(&machine)?;
                        agent.sandbox_stdin_write(req).await
                    }
                },
            )
            .await?;
            last = Some(status);
        }
        let last = last
            .ok_or_else(|| ConnectError::invalid_argument("stream_stdin: empty request stream"))?;
        Response::ok(last)
    }

    async fn get_stdin_status(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::GetStdinStatusRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        let machine = ctx.sandbox_machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let status = agent
            .sandbox_stdin_status(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(status)
    }

    async fn signal_execution(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::SignalExecutionRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_exec_signal(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(Empty::default())
    }

    async fn resize_execution_tty(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ResizeExecutionTtyRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_exec_resize(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(Empty::default())
    }

    async fn wait_execution(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::WaitExecutionRequest>,
    ) -> ServiceResult<pb::Execution> {
        let machine = ctx.sandbox_machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let execution = agent
            .sandbox_exec_wait(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(execution)
    }

    /// Contract-only stub (CORE-58 phase 1): execution discovery lands
    /// with CORE-58 phase 2 (guest-agent enumeration).
    async fn list_executions(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListExecutionsRequest>,
    ) -> ServiceResult<pb::ListExecutionsResponse> {
        Err(ConnectError::unimplemented(
            "execution listing is not implemented yet (CORE-58 phase 2)",
        ))
    }

    /// Contract-only stub (CORE-58 phase 1): the guest-agent listen-table
    /// watch lands with CORE-58 phase 2.
    async fn wait_for_port(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WaitForPortRequest>,
    ) -> ServiceResult<Empty> {
        Err(ConnectError::unimplemented(
            "port readiness waits are not implemented yet (CORE-58 phase 2)",
        ))
    }
}
