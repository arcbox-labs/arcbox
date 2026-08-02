//! Sandbox snapshot service — checkpoint and restore.

use arcbox_connect::sandbox_v1 as pb;
use buffa_types::google::protobuf::Empty;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};

use super::SharedRuntime;
use crate::ApiError;

use super::{ConnectRuntimeExt as _, ContextExt as _};

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

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and these impls are registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxSnapshotService for SandboxSnapshotServiceImpl {
    async fn checkpoint(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::CheckpointRequest>,
    ) -> ServiceResult<pb::CheckpointResponse> {
        let machine = ctx.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_checkpoint(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(resp)
    }

    async fn restore(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::RestoreRequest>,
    ) -> ServiceResult<pb::RestoreResponse> {
        let machine = ctx.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_restore(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;

        // Register restored sandbox DNS.
        if let Ok(ip) = resp.ip_address.parse() {
            self.runtime
                .ready()?
                .register_dns(&resp.id, std::slice::from_ref(&resp.id), ip)
                .await;
        }

        Response::ok(resp)
    }

    async fn list_snapshots(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListSnapshotsRequest>,
    ) -> ServiceResult<pb::ListSnapshotsResponse> {
        let machine = ctx.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        let resp = agent
            .sandbox_list_snapshots(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(resp)
    }

    async fn delete_snapshot(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::DeleteSnapshotRequest>,
    ) -> ServiceResult<Empty> {
        let machine = ctx.machine_id()?;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        agent
            .sandbox_delete_snapshot(request.to_owned_message())
            .await
            .map_err(ApiError::from)?;
        Response::ok(Empty::default())
    }
}
