//! Sandbox snapshot service — checkpoint and restore.

use arcbox_connect::sandbox_v1 as pb;
use buffa_types::google::protobuf::Empty;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};

use std::sync::Arc;

use super::SharedRuntime;
use crate::ApiError;

use super::{ConnectRuntimeExt as _, ContextExt as _};
use arcbox_computer::cleanup as sandbox_cleanup;
use arcbox_computer::locks::SandboxOperationLocks;

/// Sandbox snapshot service implementation.
pub struct SandboxSnapshotServiceImpl {
    runtime: SharedRuntime,
    operations: Arc<SandboxOperationLocks>,
}

impl SandboxSnapshotServiceImpl {
    /// Creates a new sandbox snapshot service with a deferred runtime.
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
impl pb::SandboxSnapshotService for SandboxSnapshotServiceImpl {
    async fn checkpoint(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::CheckpointRequest>,
    ) -> ServiceResult<pb::CheckpointResponse> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.sandbox_id.clone();
        let _operation = self.operations.lock(&machine, &sandbox_id).await;
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&machine)
            .map_err(ApiError::from)?;
        // The RPC error otherwise reaches only the caller; the daemon log
        // must record a failed lifecycle mutation on its own (CORE-82).
        let resp = agent
            .sandbox_checkpoint(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, sandbox_id = %sandbox_id, %error, "sandbox checkpoint failed");
            })
            .map_err(ApiError::from)?;
        Response::ok(resp)
    }

    async fn restore(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::RestoreRequest>,
    ) -> ServiceResult<pb::RestoreResponse> {
        let machine = ctx.sandbox_machine_id()?;
        let req = request.to_owned_message();
        let sandbox_id = req.id.clone();
        let _operation = self.operations.lock(&machine, &sandbox_id).await;
        let runtime = self.runtime.ready()?;
        let mut agent = runtime.get_agent(&machine).map_err(ApiError::from)?;
        let resp = agent
            .sandbox_restore(req)
            .await
            .inspect_err(|error| {
                tracing::warn!(machine = %machine, sandbox_id = %sandbox_id, %error, "sandbox restore failed");
            })
            .map_err(ApiError::from)?;
        let _host_state = runtime.lock_sandbox_host_state().await;

        // Register restored sandbox DNS.
        // Replays retain the original result even after Stop, so always
        // confirm that the exact sandbox and IP are still live.
        if let Ok(ip) = resp.ip_address.parse()
            && sandbox_cleanup::live_sandbox_matches(runtime, &machine, &resp.id, ip).await
        {
            runtime.register_sandbox_dns(&resp.id, ip).await;
        }

        Response::ok(resp)
    }

    async fn list_snapshots(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListSnapshotsRequest>,
    ) -> ServiceResult<pb::ListSnapshotsResponse> {
        let machine = ctx.sandbox_machine_id()?;
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
        let machine = ctx.sandbox_machine_id()?;
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
