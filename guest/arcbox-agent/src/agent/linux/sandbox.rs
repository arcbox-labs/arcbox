//! Sandbox RPC dispatcher.
//!
//! The sandbox service is initialised lazily as a process-wide singleton.
//! `handle_sandbox_message` routes vsock frames to the right `SandboxService`
//! method and writes either a single response frame or a stream of frames
//! for streaming requests (Run / Events / Exec).

use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::rpc::{ErrorResponse, MessageType, write_message};
use crate::sandbox::SandboxService;

/// Returns the global [`SandboxService`] singleton.
///
/// The service is initialised lazily on the first call. The nested-virt
/// prerequisite is probed first: without `/dev/kvm` every sandbox RPC is
/// rejected with 412 (mapped to `FAILED_PRECONDITION` on the host) and an
/// actionable reason. Initialisation failures store a 503 so sandbox
/// operations degrade instead of crashing the agent.
pub(super) fn sandbox_service() -> Result<&'static Arc<SandboxService>, &'static (i32, String)> {
    static SERVICE: OnceLock<Result<Arc<SandboxService>, (i32, String)>> = OnceLock::new();
    SERVICE
        .get_or_init(|| {
            if let Err(reason) = crate::sandbox::probe_kvm() {
                tracing::warn!(reason, "sandbox prerequisite missing");
                return Err((412, reason));
            }
            let config = crate::config::load();
            match SandboxService::new(config) {
                Ok(svc) => {
                    tracing::info!("sandbox service initialised");
                    Ok(Arc::new(svc))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "sandbox service unavailable");
                    Err((503, format!("sandbox service unavailable: {e}")))
                }
            }
        })
        .as_ref()
}

/// Dispatches a sandbox RPC request.
///
/// Non-streaming requests (CRUD, snapshots) write a single response frame
/// and return.  Streaming requests (Run, Events) write multiple frames
/// until the stream ends.
pub(super) async fn handle_sandbox_message<S>(
    stream: &mut S,
    msg_type: MessageType,
    trace_id: &str,
    payload: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let svc = match sandbox_service() {
        Ok(s) => Arc::clone(s),
        Err((code, reason)) => {
            let err = ErrorResponse::new(*code, reason.as_str());
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            return Ok(());
        }
    };

    match msg_type {
        // -----------------------------------------------------------------
        // CRUD
        // -----------------------------------------------------------------
        MessageType::SandboxCreateRequest => match svc.create(payload).await {
            Ok(resp) => {
                use prost::Message as _;
                write_message(
                    stream,
                    MessageType::SandboxCreateResponse,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxStopRequest => match svc.stop(payload).await {
            Ok(()) => {
                write_message(stream, MessageType::SandboxStopResponse, trace_id, &[]).await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxRemoveRequest => match svc.remove(payload).await {
            Ok(()) => {
                write_message(stream, MessageType::SandboxRemoveResponse, trace_id, &[]).await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxInspectRequest => match svc.inspect(payload) {
            Ok(resp) => {
                use prost::Message as _;
                write_message(
                    stream,
                    MessageType::SandboxInspectResponse,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxListRequest => match svc.list(payload) {
            Ok(resp) => {
                use prost::Message as _;
                write_message(
                    stream,
                    MessageType::SandboxListResponse,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        // -----------------------------------------------------------------
        // Streaming: Run
        // -----------------------------------------------------------------
        MessageType::SandboxRunRequest => {
            svc.handle_run(stream, trace_id, payload).await?;
        }
        // -----------------------------------------------------------------
        // Streaming: Events
        // -----------------------------------------------------------------
        MessageType::SandboxEventsRequest => {
            svc.handle_events(stream, trace_id, payload).await?;
        }
        // -----------------------------------------------------------------
        // Streaming: Exec
        // -----------------------------------------------------------------
        MessageType::SandboxExecRequest => {
            svc.handle_exec(stream, trace_id, payload).await?;
        }
        // -----------------------------------------------------------------
        // Snapshots
        // -----------------------------------------------------------------
        MessageType::SandboxCheckpointRequest => match svc.checkpoint(payload).await {
            Ok(resp) => {
                use prost::Message as _;
                write_message(
                    stream,
                    MessageType::SandboxCheckpointResponse,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxRestoreRequest => match svc.restore(payload).await {
            Ok(resp) => {
                use prost::Message as _;
                write_message(
                    stream,
                    MessageType::SandboxRestoreResponse,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxListSnapshotsRequest => match svc.list_snapshots(payload) {
            Ok(resp) => {
                use prost::Message as _;
                write_message(
                    stream,
                    MessageType::SandboxListSnapshotsResponse,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxDeleteSnapshotRequest => match svc.delete_snapshot(payload) {
            Ok(()) => {
                write_message(
                    stream,
                    MessageType::SandboxDeleteSnapshotResponse,
                    trace_id,
                    &[],
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        _ => {
            send_sandbox_error(stream, trace_id, 400, "unrecognised sandbox message type").await?;
        }
    }

    Ok(())
}

/// Write a single `Error` frame back to the caller.
async fn send_sandbox_error<S>(
    stream: &mut S,
    trace_id: &str,
    code: i32,
    message: &str,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let err = ErrorResponse::new(code, message);
    write_message(stream, MessageType::Error, trace_id, &err.encode()).await
}
