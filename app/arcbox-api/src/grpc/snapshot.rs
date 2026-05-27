//! Sandbox snapshot service gRPC implementation.

use arcbox_grpc::SandboxSnapshotService;
use arcbox_protocol::sandbox_v1::Empty as SandboxEmpty;
use arcbox_protocol::sandbox_v1::{
    CheckpointRequest, CheckpointResponse, DeleteSnapshotRequest, ListSnapshotsRequest,
    ListSnapshotsResponse, RestoreRequest, RestoreResponse,
};
use tonic::{Request, Response, Status};

use crate::ApiError;

use super::{RequestExt, SharedRuntime, SharedRuntimeExt};

/// Sandbox snapshot service implementation.
pub struct SandboxSnapshotServiceImpl {
    runtime: SharedRuntime,
}

impl SandboxSnapshotServiceImpl {
    /// Creates a new sandbox snapshot service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl SandboxSnapshotService for SandboxSnapshotServiceImpl {
    async fn checkpoint(
        &self,
        request: Request<CheckpointRequest>,
    ) -> Result<Response<CheckpointResponse>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_checkpoint(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(resp))
    }

    async fn restore(
        &self,
        request: Request<RestoreRequest>,
    ) -> Result<Response<RestoreResponse>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_restore(request.into_inner())
            .await
            .map_err(ApiError::from)?;

        // Register restored sandbox DNS.
        if let Ok(ip) = resp.ip_address.parse() {
            self.runtime
                .ready()?
                .register_dns(&resp.id, std::slice::from_ref(&resp.id), ip)
                .await;
        }

        Ok(Response::new(resp))
    }

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_list_snapshots(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(resp))
    }

    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<SandboxEmpty>, Status> {
        let machine = request.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_delete_snapshot(request.into_inner())
            .await
            .map_err(ApiError::from)?;
        Ok(Response::new(SandboxEmpty {}))
    }
}
