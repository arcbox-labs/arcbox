//! Sandbox filesystem service — data plane.

use std::pin::Pin;

use arcbox_grpc::SandboxFilesystemService;
use arcbox_protocol::pbjson_types::Empty;
use arcbox_protocol::sandbox_v1::{
    FileChunk, ReadFileRequest, WriteFileRequest, write_file_request,
};
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codec::Streaming;
use tonic::{Request, Response, Status};

use arcbox_core::WriteFileChunk;

use crate::ApiError;

use super::super::{RequestExt, SharedRuntime, SharedRuntimeExt};
use super::with_keepalive;

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

#[tonic::async_trait]
impl SandboxFilesystemService for SandboxFilesystemServiceImpl {
    type ReadFileStream = Pin<Box<dyn Stream<Item = Result<FileChunk, Status>> + Send + 'static>>;

    async fn read_file(
        &self,
        request: Request<ReadFileRequest>,
    ) -> Result<Response<Self::ReadFileStream>, Status> {
        let machine = request.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let rx = agent
            .sandbox_read_file(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        let stream =
            ReceiverStream::new(rx).map(|r| r.map_err(|e| Status::from(ApiError::from(e))));
        // Keepalives are empty non-final chunks, as documented in the proto.
        let stream = with_keepalive(stream, || FileChunk {
            data: Vec::new(),
            done: false,
        });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn write_file(
        &self,
        request: Request<Streaming<WriteFileRequest>>,
    ) -> Result<Response<Empty>, Status> {
        let machine = request.machine_id()?;
        let agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;

        let mut stream = request.into_inner();

        // The first message in the stream must carry the Open payload.
        let first = stream.next().await.ok_or_else(|| {
            Status::invalid_argument("write_file: stream closed before Open message")
        })??;
        let open = match first.payload {
            Some(write_file_request::Payload::Open(open)) => open,
            _ => {
                return Err(Status::invalid_argument(
                    "write_file: first message must be Open",
                ));
            }
        };

        // Bridge gRPC chunks into the agent write stream. A clean end (the
        // client's `done` chunk) closes the channel, which triggers the
        // terminating frame; a client error or a stream that ends *before*
        // `done` sends `Abort` so the partial upload is never finalized.
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                match stream.next().await {
                    Some(Ok(msg)) => {
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
        Ok(Response::new(Empty {}))
    }
}
