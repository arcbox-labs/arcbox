use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::warn;

use vmm_core::{
    ExecInputMsg, RestoreSandboxSpec, SandboxEvent as CoreEvent, SandboxManager, SandboxMountSpec,
    SandboxNetworkSpec, SandboxSpec,
};

use crate::proto::sandbox::{
    CheckpointRequest, CheckpointResponse, CreateSandboxRequest, CreateSandboxResponse,
    DeleteSnapshotRequest, Empty, ExecInput, ExecOutput, InspectSandboxRequest,
    ListSandboxesRequest, ListSandboxesResponse, ListSnapshotsRequest, ListSnapshotsResponse,
    RemoveSandboxRequest, ResourceLimits, RestoreRequest, RestoreResponse, RunOutput, RunRequest,
    SandboxEvent as ProtoEvent, SandboxEventsRequest, SandboxInfo as ProtoSandboxInfo,
    SandboxNetwork, SandboxSummary as ProtoSandboxSummary, SnapshotSummary, StopSandboxRequest,
    exec_input,
    sandbox_service_server::SandboxService,
    sandbox_snapshot_service_server::SandboxSnapshotService,
};

// =============================================================================
// SandboxServiceImpl
// =============================================================================

/// Implementation of `sandbox.v1.SandboxService` backed by [`SandboxManager`].
pub struct SandboxServiceImpl {
    manager: Arc<SandboxManager>,
}

impl SandboxServiceImpl {
    pub fn new(manager: Arc<SandboxManager>) -> Self {
        Self { manager }
    }
}

#[tonic::async_trait]
impl SandboxService for SandboxServiceImpl {
    /// Create a sandbox and return immediately with state `"starting"`.
    async fn create(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let req = request.into_inner();

        let limits = req.limits.unwrap_or_default();
        let net = req.network.unwrap_or_default();

        let spec = SandboxSpec {
            id: if req.id.is_empty() {
                None
            } else {
                Some(req.id)
            },
            labels: req.labels,
            kernel: req.kernel,
            rootfs: req.rootfs,
            boot_args: req.boot_args,
            vcpus: limits.vcpus,
            memory_mib: limits.memory_mib,
            image: req.image,
            cmd: req.cmd,
            env: req.env,
            working_dir: req.working_dir,
            user: req.user,
            mounts: req
                .mounts
                .into_iter()
                .map(|m| SandboxMountSpec {
                    source: m.source,
                    target: m.target,
                    readonly: m.readonly,
                })
                .collect(),
            network: SandboxNetworkSpec {
                mode: net.mode,
                ip: net.ip,
                egress_bps: net.egress_bps,
                ingress_bps: net.ingress_bps,
            },
            ttl_seconds: req.ttl_seconds,
            ssh_public_key: req.ssh_public_key,
        };

        let (id, ip_address) = self
            .manager
            .create_sandbox(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateSandboxResponse {
            id,
            ip_address,
            state: "starting".into(),
        }))
    }

    type RunStream = Pin<Box<dyn Stream<Item = Result<RunOutput, Status>> + Send + 'static>>;

    /// Run a command inside a sandbox and stream its output.
    async fn run(
        &self,
        request: Request<RunRequest>,
    ) -> Result<Response<Self::RunStream>, Status> {
        let req = request.into_inner();
        let tty_size = if req.tty { Some((80u16, 24u16)) } else { None };

        let rx = self
            .manager
            .run_in_sandbox(
                &req.id,
                req.cmd,
                req.env,
                req.working_dir,
                req.user,
                req.tty,
                tty_size,
                req.timeout_seconds,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let stream = ReceiverStream::new(rx).map(|result| {
            result
                .map(|chunk| {
                    let done = chunk.stream == "exit";
                    RunOutput {
                        stream: chunk.stream,
                        data: chunk.data,
                        exit_code: chunk.exit_code,
                        done,
                    }
                })
                .map_err(|e| Status::internal(e.to_string()))
        });

        Ok(Response::new(Box::pin(stream)))
    }

    type ExecStream = Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    /// Execute an interactive command inside a sandbox (bidirectional streaming).
    async fn exec(
        &self,
        request: Request<Streaming<ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let mut input_stream = request.into_inner();

        // First message must be ExecInput { init: ExecRequest }.
        let first = input_stream
            .message()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::invalid_argument("exec stream closed before init message"))?;

        let exec_req = match first.payload {
            Some(exec_input::Payload::Init(r)) => r,
            _ => {
                return Err(Status::invalid_argument(
                    "first exec message must be ExecInput { init: ... }",
                ))
            }
        };

        let tty_size = if exec_req.tty {
            exec_req
                .tty_size
                .as_ref()
                .map(|s| (s.width as u16, s.height as u16))
                .or(Some((80, 24)))
        } else {
            None
        };

        let (in_tx, out_rx) = self
            .manager
            .exec_in_sandbox(
                &exec_req.id,
                exec_req.cmd,
                exec_req.env,
                exec_req.working_dir,
                exec_req.user,
                exec_req.tty,
                tty_size,
                exec_req.timeout_seconds,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Forward subsequent input messages to the vsock writer.
        tokio::spawn(async move {
            let mut stream = input_stream;
            while let Ok(Some(msg)) = stream.message().await {
                let client_msg = match msg.payload {
                    Some(exec_input::Payload::Stdin(data)) => ExecInputMsg::Stdin(data),
                    Some(exec_input::Payload::Resize(sz)) => ExecInputMsg::Resize {
                        width: sz.width as u16,
                        height: sz.height as u16,
                    },
                    _ => ExecInputMsg::Eof,
                };
                if in_tx.send(client_msg).await.is_err() {
                    break;
                }
            }
            // Signal EOF when the gRPC client closes the send side.
            let _ = in_tx.send(ExecInputMsg::Eof).await;
        });

        // Stream output back to the gRPC client.
        let stream = ReceiverStream::new(out_rx).map(|result| {
            result
                .map(|chunk| {
                    let done = chunk.stream == "exit";
                    ExecOutput {
                        stream: chunk.stream,
                        data: chunk.data,
                        exit_code: chunk.exit_code,
                        done,
                    }
                })
                .map_err(|e| Status::internal(e.to_string()))
        });

        Ok(Response::new(Box::pin(stream)))
    }

    /// Stop a sandbox gracefully.
    async fn stop(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .stop_sandbox(&req.id, req.timeout_seconds)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Forcibly destroy a sandbox and release all resources.
    async fn remove(
        &self,
        request: Request<RemoveSandboxRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .remove_sandbox(&req.id, req.force)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Return the current state and metadata of a sandbox.
    async fn inspect(
        &self,
        request: Request<InspectSandboxRequest>,
    ) -> Result<Response<ProtoSandboxInfo>, Status> {
        let req = request.into_inner();
        let info = self
            .manager
            .inspect_sandbox(&req.id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let net = info.network.as_ref();
        Ok(Response::new(ProtoSandboxInfo {
            id: info.id,
            state: info.state.to_string(),
            labels: info.labels,
            limits: Some(ResourceLimits {
                vcpus: info.vcpus,
                memory_mib: info.memory_mib,
            }),
            network: net.map(|n| SandboxNetwork {
                ip_address: n.ip_address.clone(),
                gateway: n.gateway.clone(),
                tap_name: n.tap_name.clone(),
            }),
            created_at: info.created_at.timestamp(),
            ready_at: info.ready_at.map(|t| t.timestamp()).unwrap_or(0),
            last_exited_at: info.last_exited_at.map(|t| t.timestamp()).unwrap_or(0),
            last_exit_code: info.last_exit_code.unwrap_or(0),
            error: info.error.unwrap_or_default(),
        }))
    }

    /// List sandboxes, optionally filtered by state or labels.
    async fn list(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let req = request.into_inner();
        let summaries = self
            .manager
            .list_sandboxes(Some(&req.state), &req.labels);

        let sandboxes = summaries
            .into_iter()
            .map(|s| ProtoSandboxSummary {
                id: s.id,
                state: s.state.to_string(),
                labels: s.labels,
                ip_address: s.ip_address,
                created_at: s.created_at.timestamp(),
            })
            .collect();

        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    type EventsStream =
        Pin<Box<dyn Stream<Item = Result<ProtoEvent, Status>> + Send + 'static>>;

    /// Subscribe to sandbox lifecycle events.
    async fn events(
        &self,
        request: Request<SandboxEventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        let req = request.into_inner();
        let filter_id = req.id;
        let filter_action = req.action;

        let (tx, rx) = mpsc::channel(128);
        let mut broadcast_rx = self.manager.subscribe_events();

        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(event) => {
                        if !filter_id.is_empty() && event.sandbox_id != filter_id {
                            continue;
                        }
                        if !filter_action.is_empty() && event.action != filter_action {
                            continue;
                        }
                        let proto_event = core_event_to_proto(event);
                        if tx.send(Ok(proto_event)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "sandbox events subscriber lagged");
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

// =============================================================================
// SandboxSnapshotServiceImpl
// =============================================================================

/// Implementation of `sandbox.v1.SandboxSnapshotService`.
pub struct SandboxSnapshotServiceImpl {
    manager: Arc<SandboxManager>,
}

impl SandboxSnapshotServiceImpl {
    pub fn new(manager: Arc<SandboxManager>) -> Self {
        Self { manager }
    }
}

#[tonic::async_trait]
impl SandboxSnapshotService for SandboxSnapshotServiceImpl {
    /// Checkpoint a sandbox into a reusable snapshot.
    async fn checkpoint(
        &self,
        request: Request<CheckpointRequest>,
    ) -> Result<Response<CheckpointResponse>, Status> {
        let req = request.into_inner();
        let info = self
            .manager
            .checkpoint_sandbox(&req.sandbox_id, req.name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CheckpointResponse {
            snapshot_id: info.snapshot_id,
            snapshot_dir: info.snapshot_dir,
            created_at: info.created_at,
        }))
    }

    /// Restore a new sandbox from a previously created snapshot.
    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        let req = request.into_inner();
        let spec = RestoreSandboxSpec {
            id: if req.id.is_empty() {
                None
            } else {
                Some(req.id)
            },
            snapshot_id: req.snapshot_id,
            labels: req.labels,
            network_override: req.network_override,
            ttl_seconds: req.ttl_seconds,
        };

        let (id, ip_address) = self
            .manager
            .restore_sandbox(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RestoreResponse { id, ip_address }))
    }

    /// List all snapshots, optionally filtered by origin sandbox or label.
    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let req = request.into_inner();
        let sandbox_id_filter = if req.sandbox_id.is_empty() {
            None
        } else {
            Some(req.sandbox_id.as_str())
        };

        let summaries = self
            .manager
            .list_checkpoints(sandbox_id_filter)
            .map_err(|e| Status::internal(e.to_string()))?;

        let snapshots = summaries
            .into_iter()
            .map(|s| SnapshotSummary {
                id: s.id,
                sandbox_id: s.sandbox_id,
                name: s.name,
                labels: HashMap::new(),
                snapshot_dir: s.snapshot_dir,
                created_at: s.created_at,
            })
            .collect();

        Ok(Response::new(ListSnapshotsResponse { snapshots }))
    }

    /// Delete a snapshot and its on-disk data.
    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .delete_checkpoint(&req.snapshot_id)
            .map_err(|e| Status::not_found(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn core_event_to_proto(event: CoreEvent) -> ProtoEvent {
    ProtoEvent {
        sandbox_id: event.sandbox_id,
        action: event.action,
        timestamp: event.timestamp_ns,
        attributes: event.attributes,
    }
}
