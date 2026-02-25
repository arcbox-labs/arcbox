use std::sync::Arc;

use tonic::{Request, Response, Status};

use vmm_core::config::{RestoreSpec, SnapshotRequest, SnapshotType};
use vmm_core::VmmManager;

use crate::proto::vmm::{
    vmm_service_server::VmmService, CreateSnapshotRequest, CreateSnapshotResponse,
    DeleteSnapshotRequest, Empty, GetMetricsRequest, ListSnapshotsRequest, ListSnapshotsResponse,
    PauseVmRequest, RestoreSnapshotRequest, RestoreSnapshotResponse, ResumeVmRequest,
    SnapshotSummary, UpdateBalloonRequest, UpdateMemoryRequest, VmMetrics,
};

/// Implementation of `vmm.v1.VmmService`.
pub struct VmmServiceImpl {
    manager: Arc<VmmManager>,
}

impl VmmServiceImpl {
    pub fn new(manager: Arc<VmmManager>) -> Self {
        Self { manager }
    }
}

#[tonic::async_trait]
impl VmmService for VmmServiceImpl {
    /// Pause a running VM.
    async fn pause(&self, request: Request<PauseVmRequest>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .pause_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Resume a paused VM.
    async fn resume(&self, request: Request<ResumeVmRequest>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .resume_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Create a snapshot.
    async fn create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        let req = request.into_inner();
        let snapshot_type = match req.snapshot_type.as_str() {
            "diff" => SnapshotType::Diff,
            _ => SnapshotType::Full,
        };
        let snap_req = SnapshotRequest {
            name: if req.name.is_empty() {
                None
            } else {
                Some(req.name)
            },
            snapshot_type,
        };

        let info = self
            .manager
            .snapshot_vm(&req.id, snap_req)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateSnapshotResponse {
            snapshot_id: info.id,
            snapshot_dir: info
                .vmstate_path
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            created_at: info.created_at.to_rfc3339(),
        }))
    }

    /// List snapshots for a VM.
    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let req = request.into_inner();
        let snaps = self
            .manager
            .list_snapshots(&req.id)
            .map_err(|e| Status::internal(e.to_string()))?;

        let snapshots = snaps
            .into_iter()
            .map(|s| SnapshotSummary {
                id: s.id,
                vm_id: s.vm_id,
                name: s.name.unwrap_or_default(),
                snapshot_type: format!("{:?}", s.snapshot_type).to_lowercase(),
                vmstate_path: s.vmstate_path.to_string_lossy().into_owned(),
                mem_path: s
                    .mem_path
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                created_at: s.created_at.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(ListSnapshotsResponse { snapshots }))
    }

    /// Restore a VM from a snapshot.
    async fn restore_snapshot(
        &self,
        request: Request<RestoreSnapshotRequest>,
    ) -> Result<Response<RestoreSnapshotResponse>, Status> {
        let req = request.into_inner();
        let spec = RestoreSpec {
            name: req.name,
            snapshot_dir: req.snapshot_dir,
            network_override: req.network_override,
        };

        let id = self
            .manager
            .restore_vm(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RestoreSnapshotResponse { id }))
    }

    /// Delete a snapshot.
    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .delete_snapshot(&req.vm_id, &req.snapshot_id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Get VM metrics.
    async fn get_metrics(
        &self,
        request: Request<GetMetricsRequest>,
    ) -> Result<Response<VmMetrics>, Status> {
        let req = request.into_inner();
        let m = self
            .manager
            .get_metrics(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(VmMetrics {
            vm_id: m.vm_id,
            balloon_target_mib: m.balloon_target_mib.unwrap_or(-1),
            balloon_actual_mib: m.balloon_actual_mib.unwrap_or(-1),
        }))
    }

    /// Update balloon target.
    async fn update_balloon(
        &self,
        request: Request<UpdateBalloonRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .update_balloon(&req.id, req.amount_mib)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Update hotplug memory size.
    async fn update_memory(
        &self,
        request: Request<UpdateMemoryRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .update_memory(&req.id, req.size_mib)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }
}
