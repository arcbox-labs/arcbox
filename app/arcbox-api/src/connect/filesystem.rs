//! Sandbox filesystem service — data plane.

use std::sync::Arc;

use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{FileChunk, write_file_request};
use buffa_types::google::protobuf::Empty;
use connectrpc::{
    ConnectError, InboundStream, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;

use arcbox_core::WriteFileChunk;

use super::SharedRuntime;
use crate::ApiError;

use super::sandbox_resume;
use super::{ConnectRuntimeExt as _, ContextExt as _, with_keepalive};
use arcbox_computer::locks::SandboxOperationLocks;

/// Filesystem service implementation.
///
/// Carries file bytes for one sandbox, so it belongs with the data plane
/// rather than the control-plane front door — and, like the rest of the
/// data plane, it transparently resumes a paused sandbox (CORE-21) unless
/// the caller set `x-arcbox-no-auto-resume`.
pub struct SandboxFilesystemServiceImpl {
    runtime: SharedRuntime,
    operations: Arc<SandboxOperationLocks>,
}

impl SandboxFilesystemServiceImpl {
    /// Creates a new filesystem service with a deferred runtime.
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
impl pb::SandboxFilesystemService for SandboxFilesystemServiceImpl {
    async fn read_file(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ReadFileRequest>,
    ) -> ServiceResult<ServiceStream<FileChunk>> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;

        // Optimistic first attempt. The guest's verdict arrives as the first
        // stream frame, so peek it: a SANDBOX_PAUSED answer becomes one
        // resume + one fresh read instead of an in-stream error.
        let agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        let mut rx = agent
            .sandbox_read_file(req.clone())
            .await
            .map_err(ApiError::from)?;
        let first = match rx.recv().await {
            Some(Err(error)) if sandbox_resume::is_sandbox_paused(&error) => {
                if sandbox_resume::auto_resume_opted_out(&ctx) {
                    return Err(ConnectError::from(ApiError::from(error)));
                }
                sandbox_resume::resume(
                    runtime,
                    &self.operations,
                    &machine,
                    &req.id,
                    sandbox_resume::REASON_AUTO_RESUME,
                )
                .await?;
                let agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
                rx = agent.sandbox_read_file(req).await.map_err(ApiError::from)?;
                rx.recv().await
            }
            other => other,
        };

        let stream = tokio_stream::iter(first)
            .chain(ReceiverStream::new(rx))
            .map(|r| r.map_err(|e| ConnectError::from(ApiError::from(e))));
        // Keepalives are empty non-final chunks, as documented in the proto.
        let stream = with_keepalive(stream, FileChunk::default);
        Response::ok(Box::pin(stream))
    }

    async fn write_file(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<pb::WriteFileRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let runtime = self.runtime.ready()?;

        // The first message in the stream must carry the Open payload.
        let first = requests.next().await.ok_or_else(|| {
            ConnectError::invalid_argument("write_file: stream closed before Open message")
        })??;
        let open = match first.to_owned_message().payload {
            Some(write_file_request::Payload::Open(open)) => *open,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "write_file: first message must be Open",
                ));
            }
        };

        // A paused sandbox must be handled before any chunk is consumed —
        // the input stream cannot be replayed for a retry.
        sandbox_resume::ensure_resumed_for_write(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &open.id,
        )
        .await?;
        let agent = runtime.get_agent(&machine).map_err(ApiError::from)?;

        // Bridge Connect chunks into the agent write stream. A clean end (the
        // client's `done` chunk) closes the channel, which triggers the
        // terminating frame; a client error or a stream that ends *before*
        // `done` sends `Abort` so the partial upload is never finalized.
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                match requests.next().await {
                    Some(Ok(item)) => {
                        if let Some(write_file_request::Payload::Chunk(chunk)) =
                            item.to_owned_message().payload
                        {
                            let done = chunk.done;
                            if !chunk.data.is_empty()
                                && tx.send(WriteFileChunk::Data(chunk.data)).await.is_err()
                            {
                                return;
                            }
                            if done {
                                return; // clean completion: drop tx → done frame
                            }
                        }
                    }
                    // Client RST/cancel, or the stream closed without `done`.
                    Some(Err(_)) | None => {
                        let _ = tx.send(WriteFileChunk::Abort).await;
                        return;
                    }
                }
            }
        });

        agent
            .sandbox_write_file(open, rx)
            .await
            .map_err(ApiError::from)?;
        Response::ok(Empty::default())
    }

    async fn stat(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::StatFileRequest>,
    ) -> ServiceResult<pb::FileStat> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        let stat = sandbox_resume::with_auto_resume(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &req.id,
            || {
                let req = req.clone();
                async {
                    let mut agent = sandbox_resume::engine_agent(runtime, &machine)?;
                    agent.sandbox_stat(req).await
                }
            },
        )
        .await?;
        Response::ok(stat)
    }

    async fn list_dir(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListDirRequest>,
    ) -> ServiceResult<pb::ListDirResponse> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        let listing = sandbox_resume::with_auto_resume(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &req.id,
            || {
                let req = req.clone();
                async {
                    let mut agent = sandbox_resume::engine_agent(runtime, &machine)?;
                    agent.sandbox_list_dir(req).await
                }
            },
        )
        .await?;
        Response::ok(listing)
    }

    async fn make_dir(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::MakeDirRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        sandbox_resume::with_auto_resume(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &req.id,
            || {
                let req = req.clone();
                async {
                    let mut agent = sandbox_resume::engine_agent(runtime, &machine)?;
                    agent.sandbox_make_dir(req).await
                }
            },
        )
        .await?;
        Response::ok(Empty::default())
    }

    async fn remove(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveEntryRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        sandbox_resume::with_auto_resume(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &req.id,
            || {
                let req = req.clone();
                async {
                    let mut agent = sandbox_resume::engine_agent(runtime, &machine)?;
                    agent.sandbox_remove_entry(req).await
                }
            },
        )
        .await?;
        Response::ok(Empty::default())
    }

    async fn r#move(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::MoveEntryRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;
        sandbox_resume::with_auto_resume(
            runtime,
            &self.operations,
            &ctx,
            &machine,
            &req.id,
            || {
                let req = req.clone();
                async {
                    let mut agent = sandbox_resume::engine_agent(runtime, &machine)?;
                    agent.sandbox_move_entry(req).await
                }
            },
        )
        .await?;
        Response::ok(Empty::default())
    }

    async fn watch_dir(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::WatchDirRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchDirResponse>> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let runtime = self.runtime.ready()?;

        // Optimistic first attempt, mirroring read_file: the guest confirms
        // an established watch with an immediate keepalive frame, so peeking
        // the first item is fast — a SANDBOX_PAUSED answer becomes one
        // resume + one fresh watch instead of an in-stream error.
        let agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        let mut rx = agent
            .sandbox_watch_dir(req.clone())
            .await
            .map_err(ApiError::from)?;
        let first = match rx.recv().await {
            Some(Err(error)) if sandbox_resume::is_sandbox_paused(&error) => {
                if sandbox_resume::auto_resume_opted_out(&ctx) {
                    return Err(ConnectError::from(ApiError::from(error)));
                }
                sandbox_resume::resume(
                    runtime,
                    &self.operations,
                    &machine,
                    &req.id,
                    sandbox_resume::REASON_AUTO_RESUME,
                )
                .await?;
                let agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
                rx = agent.sandbox_watch_dir(req).await.map_err(ApiError::from)?;
                rx.recv().await
            }
            other => other,
        };

        let stream = tokio_stream::iter(first)
            .chain(ReceiverStream::new(rx))
            .map(|r| r.map_err(|e| ConnectError::from(ApiError::from(e))));
        // The guest already interleaves its own keepalives; this adds the
        // daemon-side ones the proto promises even if that hop stalls.
        let stream = with_keepalive(stream, || pb::WatchDirResponse {
            payload: pb::KeepAlive::default().into(),
            ..Default::default()
        });
        Response::ok(Box::pin(stream))
    }
}
