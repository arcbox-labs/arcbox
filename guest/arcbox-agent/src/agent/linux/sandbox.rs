//! Sandbox RPC dispatcher.
//!
//! The sandbox service is initialised lazily as a process-wide singleton.
//! `handle_sandbox_message` routes vsock frames to the right `SandboxService`
//! method and writes either a single response frame or a stream of frames
//! for streaming requests (execution attach / Events / file reads).

use std::sync::{Arc, OnceLock};

use buffa::Message as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use super::btrfs::{ensure_data_mount, ensure_no_legacy_live_sandboxes};
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
fn wire_protocol(protocol: arcbox_connect::v1::SandboxPortProtocol) -> Protocol {
    match protocol {
        arcbox_connect::v1::SandboxPortProtocol::Udp => Protocol::Udp,
        _ => Protocol::Tcp,
    }
}

/// Returns the global [`SandboxService`] singleton.
///
/// The service is initialised lazily on the first call. The nested-virt
/// prerequisite is probed first, then the persistent Btrfs data volume is
/// mounted before the manager can create state. Without `/dev/kvm` every
/// sandbox RPC is rejected with 412 (mapped to `FAILED_PRECONDITION` on the
/// host) and an actionable reason. Initialisation failures store a 503 so
/// sandbox operations degrade instead of crashing the agent.
pub(super) fn sandbox_service() -> Result<&'static Arc<SandboxService>, &'static (i32, String)> {
    static SERVICE: OnceLock<Result<Arc<SandboxService>, (i32, String)>> = OnceLock::new();
    SERVICE
        .get_or_init(|| {
            if let Err(reason) = crate::sandbox::probe_kvm() {
                tracing::warn!(reason, "sandbox prerequisite missing");
                return Err((412, reason));
            }
            if let Err(reason) = ensure_data_mount() {
                tracing::warn!(reason, "sandbox data volume unavailable");
                return Err((503, format!("sandbox data volume unavailable: {reason}")));
            }
            if let Err(reason) = ensure_no_legacy_live_sandboxes() {
                tracing::warn!(reason, "legacy sandbox runtime requires guest restart");
                return Err((503, reason));
            }
            let config = crate::config::load();
            match SandboxService::new(config) {
                Ok(svc) => {
                    tracing::info!("sandbox service initialised");
                    let svc = Arc::new(svc);
                    spawn_create_registry_cleanup(&svc);
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

/// Release process-local Create responses after their sandbox becomes terminal.
fn spawn_create_registry_cleanup(svc: &Arc<SandboxService>) {
    use arcbox_connect::sandbox_v1::{SandboxEvent, SandboxEventKind, SandboxEventsRequest};

    let payload = SandboxEventsRequest::default().encode_to_vec();
    let mut rx = match svc.subscribe_events(&payload) {
        Ok(rx) => rx,
        Err(e) => {
            tracing::warn!(error = %e, "create-registry cleanup subscription failed");
            return;
        }
    };
    let svc = Arc::clone(svc);
    tokio::spawn(async move {
        while let Some(encoded) = rx.recv().await {
            let Ok(event) = SandboxEvent::decode_from_slice(&encoded) else {
                continue;
            };
            if matches!(
                event.kind.as_known(),
                Some(
                    SandboxEventKind::Stopped
                        | SandboxEventKind::Removed
                        | SandboxEventKind::Failed
                )
            ) {
                svc.clear_stale_completed_create(&event.sandbox_id);
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
            send_sandbox_error(stream, trace_id, *code, reason).await?;
            return Ok(());
        }
    };

    match msg_type {
        // -----------------------------------------------------------------
        // CRUD
        // -----------------------------------------------------------------
        MessageType::SandboxCreateRequest => match svc.create(payload).await {
            Ok(resp) => {
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
        MessageType::SandboxStopRequest => {
            use arcbox_connect::sandbox_v1::StopSandboxRequest;
            use arcbox_connect::v1::SandboxCleanupResponse;
            let req = match StopSandboxRequest::decode_from_slice(payload) {
                Ok(req) => req,
                Err(error) => {
                    send_sandbox_error(stream, trace_id, 400, &error.to_string()).await?;
                    return Ok(());
                }
            };
            let sandbox_id = req.id.clone();
            let _operation = svc.lock_operation(&req.id).await;
            match svc.stop_request(req).await {
                Ok(()) => match svc.pending_cleanup_ticket(&sandbox_id).await {
                    Ok(ticket) => {
                        let response = SandboxCleanupResponse {
                            ticket: ticket.into(),
                            ..Default::default()
                        };
                        write_message(
                            stream,
                            MessageType::SandboxStopResponse,
                            trace_id,
                            &response.encode_to_vec(),
                        )
                        .await?;
                    }
                    Err(error) => {
                        send_sandbox_error(
                            stream,
                            trace_id,
                            error.status_code(),
                            &error.to_string(),
                        )
                        .await?;
                    }
                },
                Err(e) => {
                    send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
                }
            }
        }
        MessageType::SandboxRemoveRequest => {
            use arcbox_connect::sandbox_v1::RemoveSandboxRequest;
            use arcbox_connect::v1::SandboxCleanupResponse;
            let req = match RemoveSandboxRequest::decode_from_slice(payload) {
                Ok(req) => req,
                Err(error) => {
                    send_sandbox_error(stream, trace_id, 400, &error.to_string()).await?;
                    return Ok(());
                }
            };
            let sandbox_id = req.id.clone();
            let _operation = svc.lock_operation(&req.id).await;
            match svc.remove_request(req).await {
                Ok(()) => match svc.pending_cleanup_ticket(&sandbox_id).await {
                    Ok(ticket) => {
                        let response = SandboxCleanupResponse {
                            ticket: ticket.into(),
                            ..Default::default()
                        };
                        write_message(
                            stream,
                            MessageType::SandboxRemoveResponse,
                            trace_id,
                            &response.encode_to_vec(),
                        )
                        .await?;
                    }
                    Err(error) => {
                        send_sandbox_error(
                            stream,
                            trace_id,
                            error.status_code(),
                            &error.to_string(),
                        )
                        .await?;
                    }
                },
                Err(e) => {
                    send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
                }
            }
        }
        MessageType::SandboxCleanupPrepareRequest => {
            use arcbox_connect::v1::SandboxCleanupTicket;

            let ticket = match SandboxCleanupTicket::decode_from_slice(payload) {
                Ok(ticket) => ticket,
                Err(error) => {
                    send_sandbox_error(stream, trace_id, 400, &error.to_string()).await?;
                    return Ok(());
                }
            };
            let _operation = svc.lock_operation(&ticket.id).await;
            match svc.prepare_cleanup(&ticket).await {
                Ok(_) => {
                    write_message(
                        stream,
                        MessageType::SandboxCleanupPrepareResponse,
                        trace_id,
                        &[],
                    )
                    .await?;
                }
                Err(error) => {
                    send_sandbox_error(stream, trace_id, error.status_code(), &error.to_string())
                        .await?;
                }
            }
        }
        MessageType::SandboxCleanupFinalizeRequest => {
            use arcbox_connect::v1::SandboxCleanupTicket;

            let ticket = match SandboxCleanupTicket::decode_from_slice(payload) {
                Ok(ticket) => ticket,
                Err(error) => {
                    send_sandbox_error(stream, trace_id, 400, &error.to_string()).await?;
                    return Ok(());
                }
            };
            let _operation = svc.lock_operation(&ticket.id).await;
            let result = async {
                let sandbox_ip = svc.prepare_cleanup(&ticket).await?;
                if ticket.startup {
                    super::port_forward::remove_legacy_orphan_rules()
                        .await
                        .map_err(|error| crate::error::SandboxError::Internal(error.to_string()))?;
                    return svc.finalize_cleanup(&ticket).await;
                }
                port_forwards()
                    .lock()
                    .await
                    .remove_all_for(&ticket.id, &ticket.token)
                    .await
                    .map_err(|error| crate::error::SandboxError::Internal(error.to_string()))?;
                super::port_forward::remove_orphan_rules_for(sandbox_ip, &ticket.token)
                    .await
                    .map_err(|error| crate::error::SandboxError::Internal(error.to_string()))?;
                svc.finalize_cleanup(&ticket).await
            }
            .await;
            match result {
                Ok(()) => {
                    write_message(
                        stream,
                        MessageType::SandboxCleanupFinalizeResponse,
                        trace_id,
                        &[],
                    )
                    .await?;
                }
                Err(error) => {
                    send_sandbox_error(stream, trace_id, error.status_code(), &error.to_string())
                        .await?;
                }
            }
        }
        MessageType::SandboxInspectRequest => match svc.inspect(payload) {
            Ok(resp) => {
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
        // Executions (execution redesign, CORE-55/56)
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
        MessageType::WatchSandboxCleanupRequest => {
            svc.handle_cleanup_events(stream, trace_id, payload).await?;
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
            handle_port_forward_remove(stream, &svc, trace_id, payload).await?;
        }
        // -----------------------------------------------------------------
        // Snapshots
        // -----------------------------------------------------------------
        MessageType::SandboxCheckpointRequest => match svc.checkpoint(payload).await {
            Ok(resp) => {
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
        MessageType::SandboxDeleteSnapshotRequest => match svc.delete_snapshot(payload).await {
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
///
/// Also logs the failure: the frame is the only copy of the error, and the
/// caller may have dropped the connection before reading it — without this
/// line a failed sandbox RPC leaves the guest log silent (CORE-82). The
/// request type is the `Received message type …` line just above on the same
/// connection.
async fn send_sandbox_error<S>(
    stream: &mut S,
    trace_id: &str,
    code: i32,
    message: &str,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    // `message` is tracing's reserved field for the event message itself:
    // passing it as a field renders the error text unlabelled, looking like
    // a second message spliced onto the first. `error` matches this file's
    // convention and renders quoted.
    tracing::warn!(trace_id, code, error = message, "sandbox RPC failed");
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
    use arcbox_connect::v1::{SandboxPortForwardRequest, SandboxPortForwardResponse};

    let (req, sandbox_port, protocol) = match SandboxPortForwardRequest::decode_from_slice(payload)
        .map_err(|e| format!("decode error: {e}"))
        .and_then(|req| {
            let port = u16::try_from(req.sandbox_port)
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("invalid sandbox port {}", req.sandbox_port))?;
            let proto = wire_protocol(req.protocol.as_known().unwrap_or_default());
            Ok((req, port, proto))
        }) {
        Ok(parsed) => parsed,
        Err(msg) => {
            send_sandbox_error(stream, trace_id, 400, &msg).await?;
            return Ok(());
        }
    };
    svc.wait_startup_cleanup_complete().await;
    let _operation = svc.lock_operation(&req.id).await;

    let identity = match svc.sandbox_network_identity(&req.id) {
        Ok(identity) => identity,
        Err(e) => {
            send_sandbox_error(stream, trace_id, e.status_code(), &e.to_string()).await?;
            return Ok(());
        }
    };

    match port_forwards()
        .lock()
        .await
        .forward(&req.id, &identity, sandbox_port, protocol)
        .await
    {
        Ok(guest_port) => {
            let resp = SandboxPortForwardResponse {
                guest_port: u32::from(guest_port),
                ..Default::default()
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
            send_sandbox_error(stream, trace_id, 500, &e.to_string()).await?;
        }
    }
    Ok(())
}

/// Remove a DNAT mapping (idempotent) and acknowledge.
async fn handle_port_forward_remove<S>(
    stream: &mut S,
    svc: &SandboxService,
    trace_id: &str,
    payload: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    use arcbox_connect::v1::SandboxPortForwardRemoveRequest;

    let (req, sandbox_port, protocol) =
        match SandboxPortForwardRemoveRequest::decode_from_slice(payload)
            .map_err(|e| format!("decode error: {e}"))
            .and_then(|req| {
                let port = u16::try_from(req.sandbox_port)
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or_else(|| format!("invalid sandbox port {}", req.sandbox_port))?;
                let proto = wire_protocol(req.protocol.as_known().unwrap_or_default());
                Ok((req, port, proto))
            }) {
            Ok(parsed) => parsed,
            Err(msg) => {
                send_sandbox_error(stream, trace_id, 400, &msg).await?;
                return Ok(());
            }
        };
    svc.wait_startup_cleanup_complete().await;
    let _operation = svc.lock_operation(&req.id).await;
    let identity = match svc.sandbox_network_identity(&req.id) {
        Ok(identity) => identity,
        Err(error) => {
            send_sandbox_error(stream, trace_id, error.status_code(), &error.to_string()).await?;
            return Ok(());
        }
    };

    match port_forwards()
        .lock()
        .await
        .remove(&req.id, &identity.cleanup_token, sandbox_port, protocol)
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
            send_sandbox_error(stream, trace_id, 500, &e.to_string()).await?;
        }
    }
    Ok(())
}
