//! Sandbox service for the guest agent.
//!
//! Wraps [`SandboxManager`] from `arcbox-vm` and translates between the
//! `sandbox_v1` protobuf types (from `arcbox-protocol`) and the native Rust
//! types used by `arcbox-vm`.

use std::collections::HashMap;
use std::sync::Arc;

use arcbox_protocol::sandbox_v1;
use arcbox_vm::{
    CheckpointInfo, CheckpointSummary, RestoreSandboxSpec, SandboxEvent as VmSandboxEvent,
    SandboxInfo, SandboxManager, SandboxMountSpec, SandboxNetworkSpec, SandboxSpec, SandboxSummary,
    VmmConfig,
};
use prost::Message;
use tokio::sync::mpsc;

// =============================================================================
// SandboxService
// =============================================================================

/// Thin wrapper around [`SandboxManager`] for use in the agent's RPC layer.
pub struct SandboxService {
    manager: Arc<SandboxManager>,
}

impl SandboxService {
    /// Create a new [`SandboxService`] from the given config.
    pub fn new(config: VmmConfig) -> anyhow::Result<Self> {
        let manager = SandboxManager::new(config).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Self {
            manager: Arc::new(manager),
        })
    }

    // =========================================================================
    // CRUD
    // =========================================================================

    /// Create a sandbox.
    pub async fn create(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::CreateSandboxResponse, String> {
        let req = sandbox_v1::CreateSandboxRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        let spec = proto_to_spec(req);
        let (id, ip_address) = self
            .manager
            .create_sandbox(spec)
            .await
            .map_err(|e| e.to_string())?;
        Ok(sandbox_v1::CreateSandboxResponse {
            id,
            ip_address,
            state: "starting".into(),
        })
    }

    /// Stop a sandbox.
    pub async fn stop(&self, payload: &[u8]) -> Result<(), String> {
        let req = sandbox_v1::StopSandboxRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        self.manager
            .stop_sandbox(&req.id, req.timeout_seconds)
            .await
            .map_err(|e| e.to_string())
    }

    /// Remove a sandbox.
    pub async fn remove(&self, payload: &[u8]) -> Result<(), String> {
        let req = sandbox_v1::RemoveSandboxRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        self.manager
            .remove_sandbox(&req.id, req.force)
            .await
            .map_err(|e| e.to_string())
    }

    /// Inspect a sandbox.
    pub fn inspect(&self, payload: &[u8]) -> Result<sandbox_v1::SandboxInfo, String> {
        let req = sandbox_v1::InspectSandboxRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        let info = self
            .manager
            .inspect_sandbox(&req.id)
            .map_err(|e| e.to_string())?;
        Ok(vm_info_to_proto(info))
    }

    /// List sandboxes.
    pub fn list(&self, payload: &[u8]) -> Result<sandbox_v1::ListSandboxesResponse, String> {
        let req = sandbox_v1::ListSandboxesRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        let state_filter = if req.state.is_empty() {
            None
        } else {
            Some(req.state.as_str())
        };
        let summaries = self.manager.list_sandboxes(state_filter, &req.labels);
        Ok(sandbox_v1::ListSandboxesResponse {
            sandboxes: summaries.into_iter().map(vm_summary_to_proto).collect(),
        })
    }

    // =========================================================================
    // Workload
    // =========================================================================

    /// Run a command in a sandbox.  Returns a channel of encoded [`RunOutput`] payloads.
    pub async fn run(&self, payload: &[u8]) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, String> {
        let req =
            sandbox_v1::RunRequest::decode(payload).map_err(|e| format!("decode error: {e}"))?;

        let tty_size = None; // RunRequest has no tty_size field; use default.

        let mut rx = self
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
            .map_err(|e| e.to_string())?;

        let (tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(result) = rx.recv().await {
                let chunk = match result {
                    Ok(c) => c,
                    Err(e) => {
                        // Encode an exit chunk carrying the error.
                        let done_msg = sandbox_v1::RunOutput {
                            stream: "exit".into(),
                            data: Vec::new().into(),
                            exit_code: 1,
                            done: true,
                        };
                        tracing::warn!(error = %e, "run_in_sandbox stream error");
                        let _ = tx.send(done_msg.encode_to_vec());
                        break;
                    }
                };
                let is_done = chunk.stream == "exit";
                let msg = sandbox_v1::RunOutput {
                    stream: chunk.stream,
                    data: chunk.data.into(),
                    exit_code: chunk.exit_code,
                    done: is_done,
                };
                if tx.send(msg.encode_to_vec()).is_err() {
                    break;
                }
                if is_done {
                    break;
                }
            }
        });

        Ok(out_rx)
    }

    /// Subscribe to sandbox lifecycle events.  Returns a channel of encoded
    /// [`SandboxEvent`] payloads.
    pub fn subscribe_events(
        &self,
        payload: &[u8],
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, String> {
        let req = sandbox_v1::SandboxEventsRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        let filter_id = req.id.clone();
        let filter_action = req.action.clone();

        let mut bcast_rx = self.manager.subscribe_events();
        let (tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            loop {
                match bcast_rx.recv().await {
                    Ok(event) => {
                        // Apply filters.
                        if !filter_id.is_empty() && event.sandbox_id != filter_id {
                            continue;
                        }
                        if !filter_action.is_empty() && event.action != filter_action {
                            continue;
                        }
                        let msg = vm_event_to_proto(event);
                        if tx.send(msg.encode_to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "sandbox events receiver lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        Ok(out_rx)
    }

    // =========================================================================
    // Snapshots
    // =========================================================================

    /// Checkpoint a sandbox.
    pub async fn checkpoint(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::CheckpointResponse, String> {
        let req = sandbox_v1::CheckpointRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        let info = self
            .manager
            .checkpoint_sandbox(&req.sandbox_id, req.name)
            .await
            .map_err(|e| e.to_string())?;
        Ok(checkpoint_to_proto(info))
    }

    /// Restore a sandbox from a snapshot.
    pub async fn restore(&self, payload: &[u8]) -> Result<sandbox_v1::RestoreResponse, String> {
        let req = sandbox_v1::RestoreRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
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
            .map_err(|e| e.to_string())?;
        Ok(sandbox_v1::RestoreResponse { id, ip_address })
    }

    /// List snapshots.
    pub fn list_snapshots(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::ListSnapshotsResponse, String> {
        let req = sandbox_v1::ListSnapshotsRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        let filter = if req.sandbox_id.is_empty() {
            None
        } else {
            Some(req.sandbox_id.as_str())
        };
        let summaries = self
            .manager
            .list_checkpoints(filter)
            .map_err(|e| e.to_string())?;
        Ok(sandbox_v1::ListSnapshotsResponse {
            snapshots: summaries
                .into_iter()
                .map(checkpoint_summary_to_proto)
                .collect(),
        })
    }

    /// Delete a snapshot.
    pub fn delete_snapshot(&self, payload: &[u8]) -> Result<(), String> {
        let req = sandbox_v1::DeleteSnapshotRequest::decode(payload)
            .map_err(|e| format!("decode error: {e}"))?;
        self.manager
            .delete_checkpoint(&req.snapshot_id)
            .map_err(|e| e.to_string())
    }
}

// =============================================================================
// Conversion helpers
// =============================================================================

/// Convert a `CreateSandboxRequest` proto to a [`SandboxSpec`].
fn proto_to_spec(req: sandbox_v1::CreateSandboxRequest) -> SandboxSpec {
    let limits = req.limits.unwrap_or_default();
    let network = req.network.unwrap_or_default();
    SandboxSpec {
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
        network: SandboxNetworkSpec { mode: network.mode },
        ttl_seconds: req.ttl_seconds,
        ssh_public_key: req.ssh_public_key,
    }
}

/// Convert a [`SandboxInfo`] to `sandbox_v1::SandboxInfo`.
fn vm_info_to_proto(info: SandboxInfo) -> sandbox_v1::SandboxInfo {
    let network = info.network.map(|n| sandbox_v1::SandboxNetwork {
        ip_address: n.ip_address,
        gateway: n.gateway,
        tap_name: n.tap_name,
    });
    let limits = sandbox_v1::ResourceLimits {
        vcpus: info.vcpus,
        memory_mib: info.memory_mib,
    };
    sandbox_v1::SandboxInfo {
        id: info.id,
        state: info.state.to_string(),
        labels: info.labels,
        limits: Some(limits),
        network,
        created_at: info.created_at.timestamp(),
        ready_at: info.ready_at.map(|t| t.timestamp()).unwrap_or(0),
        last_exited_at: info.last_exited_at.map(|t| t.timestamp()).unwrap_or(0),
        last_exit_code: info.last_exit_code.unwrap_or(0),
        error: info.error.unwrap_or_default(),
    }
}

/// Convert a [`SandboxSummary`] to `sandbox_v1::SandboxSummary`.
fn vm_summary_to_proto(s: SandboxSummary) -> sandbox_v1::SandboxSummary {
    sandbox_v1::SandboxSummary {
        id: s.id,
        state: s.state.to_string(),
        labels: s.labels,
        ip_address: s.ip_address,
        created_at: s.created_at.timestamp(),
    }
}

/// Convert a [`VmSandboxEvent`] to `sandbox_v1::SandboxEvent`.
pub fn vm_event_to_proto(e: VmSandboxEvent) -> sandbox_v1::SandboxEvent {
    sandbox_v1::SandboxEvent {
        sandbox_id: e.sandbox_id,
        action: e.action,
        timestamp: e.timestamp_ns,
        attributes: e.attributes,
    }
}

/// Convert a [`CheckpointInfo`] to `sandbox_v1::CheckpointResponse`.
fn checkpoint_to_proto(info: CheckpointInfo) -> sandbox_v1::CheckpointResponse {
    sandbox_v1::CheckpointResponse {
        snapshot_id: info.snapshot_id,
        snapshot_dir: info.snapshot_dir,
        created_at: info.created_at,
    }
}

/// Convert a [`CheckpointSummary`] to `sandbox_v1::SnapshotSummary`.
fn checkpoint_summary_to_proto(s: CheckpointSummary) -> sandbox_v1::SnapshotSummary {
    sandbox_v1::SnapshotSummary {
        id: s.id,
        sandbox_id: s.sandbox_id,
        name: s.name,
        labels: s.labels,
        snapshot_dir: s.snapshot_dir,
        created_at: s.created_at,
    }
}
