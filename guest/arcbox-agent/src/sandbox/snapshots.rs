//! Sandbox checkpoint / restore handlers.

use arcbox_computer_runtime::{ComputerState, RestoreComputerSpec};
use arcbox_connect::sandbox_v1;
use buffa::Message;

use super::{SandboxService, convert, register_sandbox_dns};
use crate::error::SandboxError;

impl SandboxService {
    /// Checkpoint a sandbox.
    pub async fn checkpoint(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::CheckpointResponse, SandboxError> {
        let req = sandbox_v1::CheckpointRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let _operation = self.operations.lock(&req.sandbox_id).await;
        let info = self
            .manager
            .checkpoint_sandbox(&req.sandbox_id, req.name, req.labels.into_iter().collect())
            .await
            .map_err(SandboxError::from)?;
        Ok(convert::checkpoint_to_proto(info))
    }

    /// Restore a sandbox from a snapshot.
    pub async fn restore(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::RestoreResponse, SandboxError> {
        let req = sandbox_v1::RestoreRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager.wait_startup_cleanup_complete().await;
        let _operation = self.operations.lock(&req.id).await;
        let restore_key = crate::create_key::restore_key(&req);
        if !req.id.is_empty() {
            self.clear_stale_completed_create(&req.id);
        }
        let spec = RestoreComputerSpec {
            id: if req.id.is_empty() {
                None
            } else {
                Some(req.id)
            },
            snapshot_id: req.snapshot_id,
            labels: req.labels.into_iter().collect(),
            network_override: req.network_override,
            ttl_seconds: req.ttl_seconds,
        };
        let (id, ip_address) = self
            .manager
            .restore_sandbox_keyed(spec, &restore_key)
            .await
            .map_err(SandboxError::from)?;
        let live = self.manager.inspect_sandbox(&id).is_ok_and(|info| {
            matches!(
                info.state,
                ComputerState::Starting | ComputerState::Ready | ComputerState::Running
            ) && info
                .network
                .is_some_and(|network| network.ip_address == ip_address)
        });
        if live {
            register_sandbox_dns(&id, &ip_address);
        }
        Ok(sandbox_v1::RestoreResponse {
            id,
            ip_address,
            ..Default::default()
        })
    }

    /// List snapshots (id-ordered, paginated).
    pub fn list_snapshots(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::ListSnapshotsResponse, SandboxError> {
        let req = sandbox_v1::ListSnapshotsRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let filter = if req.sandbox_id.is_empty() {
            None
        } else {
            Some(req.sandbox_id.as_str())
        };
        let mut summaries = self
            .manager
            .list_checkpoints(filter)
            .map_err(SandboxError::from)?;
        // Label filter: every requested pair must match, mirroring List.
        // The manager only filters by origin sandbox, so apply it here
        // rather than silently returning unrelated snapshots.
        if !req.labels.is_empty() {
            summaries.retain(|s| {
                req.labels
                    .iter()
                    .all(|(key, value)| s.labels.get(key) == Some(value))
            });
        }
        let (page, next_page_token) =
            convert::paginate(summaries, |s| &s.id, req.page_size, &req.page_token);
        Ok(sandbox_v1::ListSnapshotsResponse {
            snapshots: page
                .into_iter()
                .map(convert::checkpoint_summary_to_proto)
                .collect(),
            next_page_token,
            ..Default::default()
        })
    }

    /// Delete a snapshot.
    pub async fn delete_snapshot(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::DeleteSnapshotRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager
            .delete_checkpoint(&req.snapshot_id)
            .await
            .map_err(SandboxError::from)
    }
}
