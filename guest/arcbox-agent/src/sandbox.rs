//! Sandbox service for the guest agent.
//!
//! Wraps [`SandboxManager`] from `arcbox-vm` and translates between the
//! `sandbox_v1` protobuf types (from `arcbox-protocol`) and the native Rust
//! types used by `arcbox-vm`.

use std::sync::Arc;

use arcbox_constants::wire::MessageType;
use arcbox_protocol::sandbox_v1;
use arcbox_vm::{
    CheckpointInfo, CheckpointSummary, ExecInputMsg, RestoreSandboxSpec,
    SandboxEvent as VmSandboxEvent, SandboxInfo, SandboxManager, SandboxMountSpec,
    SandboxNetworkSpec, SandboxSpec, SandboxSummary, VmmConfig,
};
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::error::SandboxError;
use crate::rpc::{ErrorResponse, read_message, write_message};

/// Drain a single trailing `SandboxExecInput` frame after exec completes.
///
/// The client may send a final EOF frame after the command exits.  We read
/// it here using the framing protocol so we only discard complete frames.
/// Only `SandboxExecInput` frames are discarded; any other message type
/// causes an immediate return.
///
/// This is safe because exec sessions are one-shot: the host consumes its
/// `AgentClient` via `into_split()`, so the vsock connection is never
/// reused for subsequent requests.
async fn drain_trailing_input<S: AsyncRead + Unpin>(stream: &mut S) {
    use tokio::time::{Duration, timeout};
    let _ = timeout(Duration::from_millis(100), async {
        if let Ok((msg_type, _, _)) = read_message(stream).await {
            if msg_type != MessageType::SandboxExecInput {
                tracing::warn!(?msg_type, "unexpected trailing message after exec");
            }
        }
    })
    .await;
}

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
    ///
    /// When the rootfs path points to a directory (overlay2 layer), the agent
    /// converts it to ext4 via `oci2rootfs` and injects `vm-agent` before
    /// booting. Ext4 images are used directly.
    pub async fn create(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::CreateSandboxResponse, SandboxError> {
        let req = sandbox_v1::CreateSandboxRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let mut spec = proto_to_spec(req);

        // Auto-detect: directory → overlay2 layer needing conversion.
        if !spec.rootfs.is_empty() && std::path::Path::new(&spec.rootfs).is_dir() {
            let ext4_path = crate::rootfs_builder::convert_layer_to_rootfs(&spec.rootfs)
                .await
                .map_err(|e| SandboxError::Internal(format!("rootfs build failed: {e}")))?;
            spec.rootfs = ext4_path;
        }

        let (id, ip_address) = self
            .manager
            .create_sandbox(spec)
            .await
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        register_sandbox_dns(&id, &ip_address);
        Ok(sandbox_v1::CreateSandboxResponse {
            id,
            ip_address,
            state: "starting".into(),
        })
    }

    /// Stop a sandbox.
    pub async fn stop(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::StopSandboxRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager
            .stop_sandbox(&req.id, req.timeout_seconds)
            .await
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        deregister_sandbox_dns(&req.id);
        Ok(())
    }

    /// Remove a sandbox.
    pub async fn remove(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::RemoveSandboxRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager
            .remove_sandbox(&req.id, req.force)
            .await
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        deregister_sandbox_dns(&req.id);
        Ok(())
    }

    /// Inspect a sandbox.
    pub fn inspect(&self, payload: &[u8]) -> Result<sandbox_v1::SandboxInfo, SandboxError> {
        let req = sandbox_v1::InspectSandboxRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let info = self
            .manager
            .inspect_sandbox(&req.id)
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        Ok(vm_info_to_proto(info))
    }

    /// List sandboxes.
    pub fn list(&self, payload: &[u8]) -> Result<sandbox_v1::ListSandboxesResponse, SandboxError> {
        let req = sandbox_v1::ListSandboxesRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
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
    pub async fn run(
        &self,
        payload: &[u8],
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, SandboxError> {
        let req = sandbox_v1::RunRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
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
            .map_err(|e| SandboxError::Internal(e.to_string()))?;

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

    /// Start an interactive exec session.
    ///
    /// Returns `(input_sender, output_receiver)`:
    /// - Send [`ExecInputMsg`]s into `input_sender` to forward stdin / EOF to
    ///   the running process.
    /// - Read pre-encoded [`sandbox_v1::ExecOutput`] payloads from
    ///   `output_receiver`.  The final payload has `done == true`.
    pub async fn exec(
        &self,
        payload: &[u8],
    ) -> Result<(mpsc::Sender<ExecInputMsg>, mpsc::UnboundedReceiver<Vec<u8>>), SandboxError> {
        let req = sandbox_v1::ExecRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;

        let tty_size = req
            .tty_size
            .map(|s| {
                let width = u16::try_from(s.width)
                    .map_err(|_| SandboxError::Decode(format!("invalid tty width {}", s.width)))?;
                let height = u16::try_from(s.height).map_err(|_| {
                    SandboxError::Decode(format!("invalid tty height {}", s.height))
                })?;
                Ok::<_, SandboxError>((width, height))
            })
            .transpose()?;

        let (in_tx, mut out_rx) = self
            .manager
            .exec_in_sandbox(
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
            .map_err(|e| SandboxError::Internal(e.to_string()))?;

        let (tx, out_stream_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(result) = out_rx.recv().await {
                let chunk = match result {
                    Ok(c) => c,
                    Err(e) => {
                        let done_msg = sandbox_v1::ExecOutput {
                            stream: "exit".into(),
                            data: Vec::new(),
                            exit_code: 1,
                            done: true,
                        };
                        tracing::warn!(error = %e, "exec_in_sandbox stream error");
                        let _ = tx.send(done_msg.encode_to_vec());
                        break;
                    }
                };
                let is_done = chunk.stream == "exit";
                let msg = sandbox_v1::ExecOutput {
                    stream: chunk.stream,
                    data: chunk.data,
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

        Ok((in_tx, out_stream_rx))
    }

    /// Bridge a `SandboxExecRequest` between the host vsock stream and the
    /// vm-agent.
    ///
    /// The host sends [`MessageType::SandboxExecInput`] frames carrying raw
    /// stdin bytes; an empty payload signals EOF on stdin.  The agent forwards
    /// [`MessageType::SandboxExecOutput`] frames (stdout / stderr / exit) back
    /// to the host until the process terminates.
    pub async fn handle_exec<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (in_tx, mut out_rx) = match self.exec(payload).await {
            Ok(pair) => pair,
            Err(e) => {
                let err = ErrorResponse::new(e.status_code(), &e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        // Split the stream so reads and writes operate independently.
        // The input reader may be cancelled mid-frame by tokio::select!
        // when the output side finishes first; this is safe because this
        // connection is not reused for subsequent requests.
        {
            let (mut rh, mut wh) = tokio::io::split(&mut *stream);

            let input_fut = async {
                loop {
                    match read_message(&mut rh).await {
                        Err(_) => {
                            let _ = in_tx.send(ExecInputMsg::Eof).await;
                            break;
                        }
                        Ok((MessageType::SandboxExecInput, _, data)) => {
                            let msg = if data.is_empty() {
                                ExecInputMsg::Eof
                            } else {
                                ExecInputMsg::Stdin(data)
                            };
                            if in_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                        Ok(_) => break,
                    }
                }
            };

            let trace_id_owned = trace_id.to_owned();
            let output_fut = async {
                while let Some(encoded) = out_rx.recv().await {
                    let done = sandbox_v1::ExecOutput::decode(encoded.as_slice())
                        .map(|m| m.done)
                        .unwrap_or(false);
                    write_message(
                        &mut wh,
                        MessageType::SandboxExecOutput,
                        &trace_id_owned,
                        &encoded,
                    )
                    .await?;
                    if done {
                        break;
                    }
                }
                Ok::<_, anyhow::Error>(())
            };

            tokio::pin!(input_fut);
            tokio::pin!(output_fut);

            // Run both concurrently.  When output finishes (process exited),
            // the input reader is cancelled — this is safe because the host
            // consumes its AgentClient (via into_split) for exec sessions, so
            // this vsock connection is never reused for further requests.
            tokio::select! {
                () = &mut input_fut => {
                    // Host disconnected first; drain remaining output.
                    output_fut.await?;
                }
                result = &mut output_fut => {
                    result?;
                }
            }
        }
        // Split halves are dropped here; `stream` is usable again.
        drain_trailing_input(stream).await;

        Ok(())
    }

    /// Stream `SandboxRunOutput` frames from [`SandboxService::run`].
    pub async fn handle_run<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut rx = match self.run(payload).await {
            Ok(r) => r,
            Err(e) => {
                let err = ErrorResponse::new(e.status_code(), &e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        while let Some(encoded) = rx.recv().await {
            write_message(stream, MessageType::SandboxRunOutput, trace_id, &encoded).await?;
        }

        Ok(())
    }

    /// Stream `SandboxEvent` frames from [`SandboxService::subscribe_events`].
    pub async fn handle_events<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut rx = match self.subscribe_events(payload) {
            Ok(r) => r,
            Err(e) => {
                let err = ErrorResponse::new(e.status_code(), &e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        while let Some(encoded) = rx.recv().await {
            write_message(stream, MessageType::SandboxEvent, trace_id, &encoded).await?;
        }

        Ok(())
    }

    /// Subscribe to sandbox lifecycle events.  Returns a channel of encoded
    /// [`SandboxEvent`] payloads.
    pub fn subscribe_events(
        &self,
        payload: &[u8],
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, SandboxError> {
        let req = sandbox_v1::SandboxEventsRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
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
    ) -> Result<sandbox_v1::CheckpointResponse, SandboxError> {
        let req = sandbox_v1::CheckpointRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let info = self
            .manager
            .checkpoint_sandbox(&req.sandbox_id, req.name)
            .await
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        Ok(checkpoint_to_proto(info))
    }

    /// Restore a sandbox from a snapshot.
    pub async fn restore(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::RestoreResponse, SandboxError> {
        let req = sandbox_v1::RestoreRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
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
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        register_sandbox_dns(&id, &ip_address);
        Ok(sandbox_v1::RestoreResponse { id, ip_address })
    }

    /// List snapshots.
    pub fn list_snapshots(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::ListSnapshotsResponse, SandboxError> {
        let req = sandbox_v1::ListSnapshotsRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let filter = if req.sandbox_id.is_empty() {
            None
        } else {
            Some(req.sandbox_id.as_str())
        };
        let summaries = self
            .manager
            .list_checkpoints(filter)
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        Ok(sandbox_v1::ListSnapshotsResponse {
            snapshots: summaries
                .into_iter()
                .map(checkpoint_summary_to_proto)
                .collect(),
        })
    }

    /// Return the IP address of a sandbox, or an error if not found.
    pub fn sandbox_ip(&self, sandbox_id: &str) -> Result<std::net::Ipv4Addr, SandboxError> {
        let info = self
            .manager
            .inspect_sandbox(&sandbox_id.to_string())
            .map_err(|e| SandboxError::Internal(e.to_string()))?;
        info.network
            .and_then(|n| n.ip_address.parse().ok())
            .ok_or_else(|| {
                SandboxError::Internal(format!("sandbox '{sandbox_id}' has no network allocation"))
            })
    }

    /// Delete a snapshot.
    pub fn delete_snapshot(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::DeleteSnapshotRequest::decode(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        self.manager
            .delete_checkpoint(&req.snapshot_id)
            .map_err(|e| SandboxError::Internal(e.to_string()))
    }
}

// =============================================================================
// DNS registration helpers
// =============================================================================

/// Register a sandbox in the guest DNS server registry.
fn register_sandbox_dns(id: &str, ip: &str) {
    let Ok(ipv4) = ip.parse::<std::net::Ipv4Addr>() else {
        tracing::warn!(id, ip, "invalid sandbox IP for DNS registration");
        return;
    };
    let registry = crate::dns_server::sandbox_registry();
    if let Ok(mut map) = registry.write() {
        map.insert(id.to_lowercase(), ipv4);
    }
}

/// Deregister a sandbox from the guest DNS server registry.
fn deregister_sandbox_dns(id: &str) {
    let registry = crate::dns_server::sandbox_registry();
    if let Ok(mut map) = registry.write() {
        map.remove(&id.to_lowercase());
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
