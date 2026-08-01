//! Sandbox filesystem service — data plane.

use arcbox_connect::sandbox_v1 as pb;
use arcbox_protocol::sandbox_v1::{FileChunk, write_file_request};
use buffa_types::google::protobuf::Empty;
use connectrpc::{
    ConnectError, InboundStream, PreEncoded, RequestContext, Response, ServiceRequest,
    ServiceResult, ServiceStream,
};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;

use arcbox_core::WriteFileChunk;

use crate::ApiError;
use crate::grpc::SharedRuntime;

use super::bridge::{wire_request, wire_response, wire_stream_item};
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
    ) -> ServiceResult<ServiceStream<PreEncoded<pb::FileChunk>>> {
        let machine = ctx.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_read_file(wire_request(&request)?)
            .await
            .map_err(ApiError::from)?;
        let stream =
            ReceiverStream::new(rx).map(|r| r.map_err(|e| ConnectError::from(ApiError::from(e))));
        // Keepalives are empty non-final chunks, as documented in the proto.
        let stream = with_keepalive(stream, || FileChunk {
            data: Vec::new(),
            done: false,
        });
        let stream = stream.map(|item| item.map(|chunk| wire_response::<pb::FileChunk, _>(&chunk)));
        Response::ok(Box::pin(stream))
    }

    async fn write_file(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<pb::WriteFileRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;

        // The first message in the stream must carry the Open payload.
        let first = requests.next().await.ok_or_else(|| {
            ConnectError::invalid_argument("write_file: stream closed before Open message")
        })??;
        let first: arcbox_protocol::sandbox_v1::WriteFileRequest = wire_stream_item(&first)?;
        let open = match first.payload {
            Some(write_file_request::Payload::Open(open)) => open,
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
                        let Ok(msg) = wire_stream_item::<
                            arcbox_protocol::sandbox_v1::WriteFileRequest,
                            _,
                        >(&item) else {
                            let _ = tx.send(WriteFileChunk::Abort).await;
                            return;
                        };
                        if let Some(write_file_request::Payload::Chunk(chunk)) = msg.payload {
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
}
