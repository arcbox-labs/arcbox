//! Sandbox filesystem service — data plane.

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

use super::{ConnectRuntimeExt as _, ContextExt as _, with_keepalive};

/// Filesystem service implementation.
///
/// Carries file bytes for one sandbox, so it belongs with the data plane
/// rather than the control-plane front door.
pub struct SandboxFilesystemServiceImpl {
    runtime: SharedRuntime,
}

impl SandboxFilesystemServiceImpl {
    /// Creates a new filesystem service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
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
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_read_file(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        let stream =
            ReceiverStream::new(rx).map(|r| r.map_err(|e| ConnectError::from(ApiError::from(e))));
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
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;

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

    /// Contract-only stub (CORE-58 phase 1): the path verbs land with
    /// CORE-62 (guest-agent implementation).
    async fn stat(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::StatFileRequest>,
    ) -> ServiceResult<pb::FileStat> {
        Err(ConnectError::unimplemented(
            "stat is not implemented yet (CORE-62)",
        ))
    }

    /// Contract-only stub (CORE-58 phase 1): the path verbs land with
    /// CORE-62 (guest-agent implementation).
    async fn list_dir(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListDirRequest>,
    ) -> ServiceResult<pb::ListDirResponse> {
        Err(ConnectError::unimplemented(
            "list_dir is not implemented yet (CORE-62)",
        ))
    }

    /// Contract-only stub (CORE-58 phase 1): the path verbs land with
    /// CORE-62 (guest-agent implementation).
    async fn make_dir(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::MakeDirRequest>,
    ) -> ServiceResult<Empty> {
        Err(ConnectError::unimplemented(
            "make_dir is not implemented yet (CORE-62)",
        ))
    }

    /// Contract-only stub (CORE-58 phase 1): the path verbs land with
    /// CORE-62 (guest-agent implementation).
    async fn remove(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::RemoveEntryRequest>,
    ) -> ServiceResult<Empty> {
        Err(ConnectError::unimplemented(
            "remove is not implemented yet (CORE-62)",
        ))
    }

    /// Contract-only stub (CORE-58 phase 1): the path verbs land with
    /// CORE-62 (guest-agent implementation).
    async fn r#move(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::MoveEntryRequest>,
    ) -> ServiceResult<Empty> {
        Err(ConnectError::unimplemented(
            "move is not implemented yet (CORE-62)",
        ))
    }

    /// Contract-only stub (CORE-58 phase 1): the path verbs land with
    /// CORE-62 (guest-agent implementation).
    async fn watch_dir(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WatchDirRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchDirResponse>> {
        Err(ConnectError::unimplemented(
            "watch_dir is not implemented yet (CORE-62)",
        ))
    }
}
