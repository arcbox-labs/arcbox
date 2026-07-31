//! Sandbox service gRPC implementation.

use std::pin::Pin;
use std::time::Duration;

use arcbox_grpc::SandboxService;
use arcbox_protocol::pbjson_types::Empty;
use arcbox_protocol::sandbox_v1::{
    AttachExecutionRequest, CreateSandboxRequest, CreateSandboxResponse, Execution, ExecutionEvent,
    ExposePortRequest, ExposePortResponse, FileChunk, GetStdinStatusRequest, InspectSandboxRequest,
    KeepAlive, ListSandboxesRequest, ListSandboxesResponse, PortProtocol, ReadFileRequest,
    RemoveSandboxRequest, ResizeExecutionTtyRequest, SandboxEventsRequest, SandboxInfo,
    SandboxPortForwardRemoveRequest, SandboxPortForwardRequest, SignalExecutionRequest,
    StartExecutionRequest, StdinStatus, StopSandboxRequest, UnexposePortRequest,
    WaitExecutionRequest, WatchEventsResponse, WriteFileRequest, WriteStdinRequest,
    execution_event, watch_events_response, write_file_request,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt as _};
use tonic::codec::Streaming;
use tonic::{Request, Response, Status};

use arcbox_core::{SandboxPortExposure, WriteFileChunk};

use crate::ApiError;

use super::{RequestExt, SharedRuntime, SharedRuntimeExt};

/// Idle interval after which a server stream emits a keepalive frame, so
/// proxies and load balancers never see a silent connection (CORE-55).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Interleave keepalive items whenever `stream` stays idle for
/// [`KEEPALIVE_INTERVAL`].
fn with_keepalive<S, T>(stream: S, keepalive: fn() -> T) -> impl Stream<Item = Result<T, Status>>
where
    S: Stream<Item = Result<T, Status>>,
{
    stream
        .timeout(KEEPALIVE_INTERVAL)
        .map(move |item| item.unwrap_or_else(|_elapsed| Ok(keepalive())))
}

/// Map the wire port protocol onto the host-side exposure key
/// (`UNSPECIFIED` defaults to TCP).
fn protocol_key(protocol: PortProtocol) -> &'static str {
    match protocol {
        PortProtocol::Udp => "udp",
        _ => "tcp",
    }
}

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

    async fn stop(&self, request: Request<StopSandboxRequest>) -> Result<Response<Empty>, Status> {
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

        Ok(Response::new(Empty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveSandboxRequest>,
    ) -> Result<Response<Empty>, Status> {
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

        Ok(Response::new(Empty {}))
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
        let protocol = protocol_key(req.protocol()).to_owned();

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
                protocol: req.protocol,
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
                    protocol: req.protocol,
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
    ) -> Result<Response<Empty>, Status> {
        let machine = request.machine_id()?;
        let req = request.into_inner();
        let sandbox_port = u16::try_from(req.sandbox_port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| Status::invalid_argument("sandbox_port must be 1-65535"))?;
        let protocol = protocol_key(req.protocol());

        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_port_forward_remove(SandboxPortForwardRemoveRequest {
                id: req.id.clone(),
                sandbox_port: u32::from(sandbox_port),
                protocol: req.protocol,
            })
            .await
            .map_err(ApiError::from)?;

        self.runtime
            .ready()?
            .unexpose_sandbox_port(&req.id, sandbox_port, protocol)
            .await;

        Ok(Response::new(Empty {}))
    }

    type EventsStream =
        Pin<Box<dyn Stream<Item = Result<WatchEventsResponse, Status>> + Send + 'static>>;

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
        let stream = ReceiverStream::new(rx).map(|r| {
            r.map(|event| WatchEventsResponse {
                payload: Some(watch_events_response::Payload::Event(event)),
            })
            .map_err(|e| Status::from(ApiError::from(e)))
        });
        let stream = with_keepalive(stream, || WatchEventsResponse {
            payload: Some(watch_events_response::Payload::KeepAlive(KeepAlive {})),
        });
        Ok(Response::new(Box::pin(stream)))
    }
}
