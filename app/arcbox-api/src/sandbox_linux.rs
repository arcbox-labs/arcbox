//! Sandbox gRPC service implementation — Linux direct path.
//!
//! On Linux the `SandboxServiceImpl` calls `arcbox_vm::SandboxManager` directly
//! instead of proxying through the guest agent. This avoids an extra VM hop and
//! enables bare-metal Firecracker sandbox management.

use crate::sandbox_conv;
use arcbox_core::Runtime;
use arcbox_grpc::{SandboxService, SandboxSnapshotService};
use arcbox_protocol::sandbox_v1::{
    CheckpointRequest, CheckpointResponse, CreateSandboxRequest, CreateSandboxResponse,
    DeleteSnapshotRequest, Empty as SandboxEmpty, ExecInput, ExecOutput, InspectSandboxRequest,
    ListSandboxesRequest, ListSandboxesResponse, ListSnapshotsRequest, ListSnapshotsResponse,
    RemoveSandboxRequest, RestoreRequest, RestoreResponse, RunOutput, RunRequest, SandboxEvent,
    SandboxEventsRequest, SandboxInfo, StopSandboxRequest,
};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tonic::codec::Streaming;
use tonic::{Request, Response, Status};

/// Returns a reference to the sandbox manager or a gRPC error.
fn get_sandbox_manager(runtime: &Runtime) -> Result<&Arc<arcbox_vm::SandboxManager>, Status> {
    runtime
        .sandbox_manager()
        .ok_or_else(|| Status::unavailable("sandbox subsystem is not enabled"))
}

/// Sandbox service implementation (Linux — direct Firecracker path).
pub struct SandboxServiceImpl {
    runtime: Arc<Runtime>,
}

impl SandboxServiceImpl {
    /// Creates a new sandbox service.
    #[must_use]
    pub const fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl SandboxService for SandboxServiceImpl {
    async fn create(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let spec = sandbox_conv::proto_to_sandbox_spec(request.into_inner());
        let (id, ip) = mgr
            .create_sandbox(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreateSandboxResponse {
            id,
            ip_address: ip,
            state: "starting".to_string(),
        }))
    }

    type RunStream = Pin<Box<dyn Stream<Item = Result<RunOutput, Status>> + Send + 'static>>;

    async fn run(&self, request: Request<RunRequest>) -> Result<Response<Self::RunStream>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let req = request.into_inner();
        let rx = mgr
            .run_in_sandbox(
                &req.id,
                arcbox_vm::StartCommand {
                    cmd: req.cmd,
                    env: req.env,
                    working_dir: req.working_dir,
                    user: req.user,
                    tty: req.tty,
                    timeout_seconds: req.timeout_seconds,
                },
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(|chunk| {
            Ok(RunOutput {
                stream: chunk.stream,
                data: chunk.data,
                exit_code: chunk.exit_code,
                done: chunk.done,
            })
        });

        Ok(Response::new(Box::pin(stream)))
    }

    type ExecStream = Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    async fn exec(
        &self,
        _request: Request<Streaming<ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        Err(Status::unimplemented(
            "sandbox exec bidirectional stream not yet implemented",
        ))
    }

    async fn stop(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<SandboxEmpty>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let req = request.into_inner();
        mgr.stop_sandbox(&req.id, req.timeout_seconds)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SandboxEmpty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveSandboxRequest>,
    ) -> Result<Response<SandboxEmpty>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let req = request.into_inner();
        mgr.remove_sandbox(&req.id, req.force)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SandboxEmpty {}))
    }

    async fn inspect(
        &self,
        request: Request<InspectSandboxRequest>,
    ) -> Result<Response<SandboxInfo>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let info = mgr
            .inspect_sandbox(&request.into_inner().id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(sandbox_conv::sandbox_info_to_proto(info)))
    }

    async fn list(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let req = request.into_inner();
        let state_filter = if req.state.is_empty() {
            None
        } else {
            Some(req.state.as_str())
        };
        let sandboxes = mgr.list_sandboxes(state_filter, &req.labels);
        Ok(Response::new(sandbox_conv::sandbox_list_to_proto(
            sandboxes,
        )))
    }

    type EventsStream = Pin<Box<dyn Stream<Item = Result<SandboxEvent, Status>> + Send + 'static>>;

    async fn events(
        &self,
        request: Request<SandboxEventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let req = request.into_inner();
        let rx = mgr.subscribe_events();

        let filter_id = if req.id.is_empty() {
            None
        } else {
            Some(req.id)
        };
        let filter_action = if req.action.is_empty() {
            None
        } else {
            Some(req.action)
        };

        let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(move |result| {
            match result {
                Ok(event) => {
                    // Apply filters.
                    if let Some(ref id) = filter_id {
                        if event.sandbox_id != *id {
                            return None;
                        }
                    }
                    if let Some(ref action) = filter_action {
                        if event.action != *action {
                            return None;
                        }
                    }
                    Some(Ok(SandboxEvent {
                        sandbox_id: event.sandbox_id,
                        action: event.action,
                        timestamp: event.timestamp_ns,
                        attributes: event.attributes,
                    }))
                }
                Err(_) => None,
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }
}

/// Sandbox snapshot service implementation (Linux — direct Firecracker path).
pub struct SandboxSnapshotServiceImpl {
    runtime: Arc<Runtime>,
}

impl SandboxSnapshotServiceImpl {
    /// Creates a new sandbox snapshot service.
    #[must_use]
    pub const fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl SandboxSnapshotService for SandboxSnapshotServiceImpl {
    async fn checkpoint(
        &self,
        request: Request<CheckpointRequest>,
    ) -> Result<Response<CheckpointResponse>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let req = request.into_inner();
        let info = mgr
            .checkpoint_sandbox(&req.sandbox_id, &req.name, req.labels)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(sandbox_conv::checkpoint_to_proto(info)))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let spec = sandbox_conv::proto_to_restore_spec(request.into_inner());
        let (id, ip) = mgr
            .restore_sandbox(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(RestoreResponse { id, ip_address: ip }))
    }

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        let req = request.into_inner();
        let sandbox_filter = if req.sandbox_id.is_empty() {
            None
        } else {
            Some(req.sandbox_id.as_str())
        };
        let snapshots = mgr
            .list_checkpoints(sandbox_filter)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ListSnapshotsResponse {
            snapshots: snapshots
                .into_iter()
                .map(sandbox_conv::checkpoint_summary_to_proto)
                .collect(),
        }))
    }

    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<SandboxEmpty>, Status> {
        let mgr = get_sandbox_manager(&self.runtime)?;
        mgr.delete_checkpoint(&request.into_inner().snapshot_id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SandboxEmpty {}))
    }
}
