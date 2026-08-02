//! Sandbox RPC dispatcher.
//!
//! The sandbox service is initialised lazily as a process-wide singleton.
//! `handle_sandbox_message` routes vsock frames to the right `SandboxService`
//! method and writes either a single response frame or a stream of frames
//! for streaming requests (execution attach / Events / file reads).

use std::sync::{Arc, OnceLock};

use prost::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use super::port_forward::{PortForwardManager, Protocol};
use super::runtime_cache::ensure_local_runtime;
use crate::rpc::{ErrorResponse, MessageType, write_message};
use crate::sandbox::SandboxService;

/// Returns the global [`PortForwardManager`] singleton.
fn port_forwards() -> &'static Mutex<PortForwardManager> {
    static MANAGER: OnceLock<Mutex<PortForwardManager>> = OnceLock::new();
    MANAGER.get_or_init(|| Mutex::new(PortForwardManager::default()))
}

/// Map the host↔guest wire protocol enum onto the forwarder's protocol
/// (`UNSPECIFIED` defaults to TCP).
///
/// This is the vsock payload's own enum, not the published sandbox
/// contract's — the two are deliberately separate (CORE-57).
fn wire_protocol(protocol: arcbox_protocol::v1::SandboxPortProtocol) -> Protocol {
    match protocol {
        arcbox_protocol::v1::SandboxPortProtocol::Udp => Protocol::Udp,
        _ => Protocol::Tcp,
    }
}

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
                    let svc = Arc::new(svc);
                    spawn_port_forward_cleanup(&svc);
                    Ok(svc)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "sandbox service unavailable");
                    Err((503, format!("sandbox service unavailable: {e}")))
                }
            }
        })
        .as_ref()
}

/// Drop every DNAT mapping of a sandbox as soon as it stops.
///
/// Subscribing to lifecycle events covers all teardown paths — explicit
/// Stop/Remove, TTL expiry, and boot failures — without threading cleanup
/// hooks through each of them.
fn spawn_port_forward_cleanup(svc: &Arc<SandboxService>) {
    use arcbox_protocol::sandbox_v1::{SandboxEvent, SandboxEventKind, SandboxEventsRequest};

    let payload = SandboxEventsRequest::default().encode_to_vec();
    let mut rx = match svc.subscribe_events(&payload) {
        Ok(rx) => rx,
        Err(e) => {
            tracing::warn!(error = %e, "port-forward cleanup subscription failed");
            return;
        }
    };
    tokio::spawn(async move {
        while let Some(encoded) = rx.recv().await {
            let Ok(event) = SandboxEvent::decode(encoded.as_slice()) else {
                continue;
            };
            if matches!(
                event.kind(),
                SandboxEventKind::Stopped | SandboxEventKind::Removed | SandboxEventKind::Failed
            ) {
                port_forwards()
                    .lock()
                    .await
                    .remove_all_for(&event.sandbox_id)
                    .await;
            }
        }
    });
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
    if matches!(
        msg_type,
        MessageType::SandboxCreateRequest | MessageType::SandboxRestoreRequest
    ) {
        if let Err(reason) = ensure_local_runtime().await {
            send_sandbox_error(
                stream,
                trace_id,
                503,
                &format!("sandbox runtime unavailable: {reason}"),
            )
            .await?;
            return Ok(());
        }
    }

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
        // Executions (protocol v2)
        // -----------------------------------------------------------------
        MessageType::SandboxExecStartRequest => match svc.start_execution(payload).await {
            Ok(resp) => {
                write_message(
                    stream,
                    MessageType::SandboxExecStartResponse,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxExecAttachRequest => {
            svc.handle_attach(stream, trace_id, payload).await?;
        }
        MessageType::SandboxStdinWriteRequest => match svc.write_stdin(payload).await {
            Ok(resp) => {
                write_message(
                    stream,
                    MessageType::SandboxStdinStatus,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxStdinStatusRequest => match svc.stdin_status(payload) {
            Ok(resp) => {
                write_message(
                    stream,
                    MessageType::SandboxStdinStatus,
                    trace_id,
                    &resp.encode_to_vec(),
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxExecSignalRequest => match svc.signal_execution(payload).await {
            Ok(()) => {
                write_message(
                    stream,
                    MessageType::SandboxExecSignalResponse,
                    trace_id,
                    &[],
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxExecResizeRequest => match svc.resize_execution(payload).await {
            Ok(()) => {
                write_message(
                    stream,
                    MessageType::SandboxExecResizeResponse,
                    trace_id,
                    &[],
                )
                .await?;
            }
            Err(e) => {
                send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            }
        },
        MessageType::SandboxExecWaitRequest => match svc.wait_execution(payload).await {
            Ok(resp) => {
                write_message(
                    stream,
                    MessageType::SandboxExecWaitResponse,
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
        // Streaming: Events
        // -----------------------------------------------------------------
        MessageType::SandboxEventsRequest => {
            svc.handle_events(stream, trace_id, payload).await?;
        }
        // -----------------------------------------------------------------
        // File I/O
        // -----------------------------------------------------------------
        MessageType::SandboxFileReadRequest => {
            svc.handle_read_file(stream, trace_id, payload).await?;
        }
        MessageType::SandboxFileWriteRequest => {
            svc.handle_write_file(stream, trace_id, payload).await?;
        }
        // -----------------------------------------------------------------
        // Port forwarding
        // -----------------------------------------------------------------
        MessageType::SandboxPortForwardRequest => {
            handle_port_forward(stream, &svc, trace_id, payload).await?;
        }
        MessageType::SandboxPortForwardRemoveRequest => {
            handle_port_forward_remove(stream, trace_id, payload).await?;
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

/// Install a DNAT mapping and answer with the allocated guest port.
async fn handle_port_forward<S>(
    stream: &mut S,
    svc: &SandboxService,
    trace_id: &str,
    payload: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    use arcbox_protocol::v1::{SandboxPortForwardRequest, SandboxPortForwardResponse};

    let (req, sandbox_port, protocol) = match SandboxPortForwardRequest::decode(payload)
        .map_err(|e| format!("decode error: {e}"))
        .and_then(|req| {
            let port = u16::try_from(req.sandbox_port)
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("invalid sandbox port {}", req.sandbox_port))?;
            let proto = wire_protocol(req.protocol());
            Ok((req, port, proto))
        }) {
        Ok(parsed) => parsed,
        Err(msg) => {
            let err = ErrorResponse::new(400, msg);
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            return Ok(());
        }
    };

    let ip = match svc.sandbox_ip(&req.id) {
        Ok(ip) => ip,
        Err(e) => {
            let err = ErrorResponse::new(e.status_code(), e.to_string());
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            return Ok(());
        }
    };

    match port_forwards()
        .lock()
        .await
        .forward(&req.id, ip, sandbox_port, protocol)
        .await
    {
        Ok(guest_port) => {
            let resp = SandboxPortForwardResponse {
                guest_port: u32::from(guest_port),
            };
            write_message(
                stream,
                MessageType::SandboxPortForwardResponse,
                trace_id,
                &resp.encode_to_vec(),
            )
            .await?;
        }
        Err(e) => {
            let err = ErrorResponse::new(500, e.to_string());
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
        }
    }
    Ok(())
}

/// Remove a DNAT mapping (idempotent) and acknowledge.
async fn handle_port_forward_remove<S>(
    stream: &mut S,
    trace_id: &str,
    payload: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    use arcbox_protocol::v1::SandboxPortForwardRemoveRequest;

    let (req, sandbox_port, protocol) = match SandboxPortForwardRemoveRequest::decode(payload)
        .map_err(|e| format!("decode error: {e}"))
        .and_then(|req| {
            let port = u16::try_from(req.sandbox_port)
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("invalid sandbox port {}", req.sandbox_port))?;
            let proto = wire_protocol(req.protocol());
            Ok((req, port, proto))
        }) {
        Ok(parsed) => parsed,
        Err(msg) => {
            let err = ErrorResponse::new(400, msg);
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            return Ok(());
        }
    };

    match port_forwards()
        .lock()
        .await
        .remove(&req.id, sandbox_port, protocol)
        .await
    {
        Ok(()) => {
            write_message(
                stream,
                MessageType::SandboxPortForwardRemoveResponse,
                trace_id,
                &[],
            )
            .await?;
        }
        Err(e) => {
            let err = ErrorResponse::new(500, e.to_string());
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
        }
    }
    Ok(())
}
