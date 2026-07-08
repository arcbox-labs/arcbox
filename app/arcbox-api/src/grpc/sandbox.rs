//! Sandbox service gRPC implementation.

use std::pin::Pin;

use arcbox_grpc::SandboxService;
use arcbox_protocol::sandbox_v1::Empty as SandboxEmpty;
use arcbox_protocol::sandbox_v1::{
    CreateSandboxRequest, CreateSandboxResponse, ExecInput, ExecOutput, ExposePortRequest,
    ExposePortResponse, FileChunk, InspectSandboxRequest, ListSandboxesRequest,
    ListSandboxesResponse, ReadFileRequest, RemoveSandboxRequest, RunOutput, RunRequest,
    SandboxEvent, SandboxEventsRequest, SandboxInfo, SandboxPortForwardRemoveRequest,
    SandboxPortForwardRequest, StopSandboxRequest, UnexposePortRequest, WriteFileRequest,
    exec_input, write_file_request,
};
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::codec::Streaming;
use tonic::{Request, Response, Status};

use arcbox_core::{ExecSessionInput, SandboxPortExposure, WriteFileChunk};

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
            .map(|r| r.map_err(|e| Status::from(ApiError::from(e))));
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

        // Feed remaining gRPC input (stdin + TTY resizes) into a channel for
        // the core layer. Stream end sends the empty-stdin EOF sentinel.
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(Ok(input)) = stream.next().await {
                let msg = match input.payload {
                    Some(exec_input::Payload::Stdin(data)) => ExecSessionInput::Stdin(data),
                    Some(exec_input::Payload::Resize(size)) => ExecSessionInput::Resize {
                        width: u16::try_from(size.width).unwrap_or(u16::MAX),
                        height: u16::try_from(size.height).unwrap_or(u16::MAX),
                    },
                    _ => continue,
                };
                if in_tx.send(msg).await.is_err() {
                    return;
                }
            }
            let _ = in_tx.send(ExecSessionInput::Stdin(Vec::new())).await;
        });

        let out_rx = agent
            .sandbox_exec(exec_req, in_rx)
            .await
            .map_err(ApiError::from)?;

        let out_stream = UnboundedReceiverStream::new(out_rx)
            .map(|r| r.map_err(|e| Status::from(ApiError::from(e))));
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

        let runtime = self.runtime.ready()?;
        runtime.deregister_dns_by_id(&sandbox_id).await;
        runtime.remove_sandbox_ports(&sandbox_id).await;

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

        let runtime = self.runtime.ready()?;
        runtime.deregister_dns_by_id(&sandbox_id).await;
        runtime.remove_sandbox_ports(&sandbox_id).await;

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
        let stream = UnboundedReceiverStream::new(rx)
            .map(|r| r.map_err(|e| Status::from(ApiError::from(e))));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn write_file(
        &self,
        request: Request<Streaming<WriteFileRequest>>,
    ) -> Result<Response<SandboxEmpty>, Status> {
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
        Ok(Response::new(SandboxEmpty {}))
    }

    async fn expose_port(
        &self,
        request: Request<ExposePortRequest>,
    ) -> Result<Response<ExposePortResponse>, Status> {
        let machine = request.machine_id()?;
        let req = request.into_inner();
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| Status::invalid_argument("sandbox_port must be 1-65535"))?;
        let host_port = u16::try_from(req.host_port)
            .map_err(|_| Status::invalid_argument("host_port must be 0-65535"))?;
        let protocol = if req.protocol.is_empty() {
            "tcp".to_owned()
        } else {
            req.protocol.to_ascii_lowercase()
        };

        // Guest half: allocate the reserved relay port and install the DNAT.
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let forwarded = agent
            .sandbox_port_forward(SandboxPortForwardRequest {
                id: req.id.clone(),
                sandbox_port: u32::from(sandbox_port),
                protocol: protocol.clone(),
            })
            .await
            .map_err(ApiError::from)?;
        let guest_port = u16::try_from(forwarded.guest_port)
            .map_err(|_| Status::internal("agent returned an invalid guest port"))?;

        // Host half: bind the listener; default the host port to the relay
        // port for a stable, collision-free mapping.
        let host_port = if host_port == 0 {
            guest_port
        } else {
            host_port
        };
        let exposure = SandboxPortExposure {
            sandbox_id: req.id.clone(),
            sandbox_port,
            protocol: protocol.clone(),
            host_port,
            guest_port,
        };
        if let Err(e) = self
            .runtime
            .ready()?
            .expose_sandbox_port(&machine, &exposure)
            .await
        {
            // Roll back the guest DNAT so a failed bind leaves no half rule.
            let mut agent = self
                .runtime
                .ready()?
                .get_agent(&machine)
                .map_err(ApiError::from)?;
            let _ = agent
                .sandbox_port_forward_remove(SandboxPortForwardRemoveRequest {
                    id: req.id,
                    sandbox_port: u32::from(sandbox_port),
                    protocol,
                })
                .await;
            return Err(ApiError::from(e).into());
        }

        Ok(Response::new(ExposePortResponse {
            host_port: u32::from(host_port),
            guest_port: u32::from(guest_port),
        }))
    }

    async fn unexpose_port(
        &self,
        request: Request<UnexposePortRequest>,
    ) -> Result<Response<SandboxEmpty>, Status> {
        let machine = request.machine_id()?;
        let req = request.into_inner();
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| Status::invalid_argument("sandbox_port must be 1-65535"))?;
        let protocol = if req.protocol.is_empty() {
            "tcp".to_owned()
        } else {
            req.protocol.to_ascii_lowercase()
        };

        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_port_forward_remove(SandboxPortForwardRemoveRequest {
                id: req.id.clone(),
                sandbox_port: u32::from(sandbox_port),
                protocol: protocol.clone(),
            })
            .await
            .map_err(ApiError::from)?;

        self.runtime
            .ready()?
            .unexpose_sandbox_port(&req.id, sandbox_port, &protocol)
            .await;

        Ok(Response::new(SandboxEmpty {}))
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
            .map(|r| r.map_err(|e| Status::from(ApiError::from(e))));
        Ok(Response::new(Box::pin(stream)))
    }
}
