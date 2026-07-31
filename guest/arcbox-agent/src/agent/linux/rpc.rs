//! Per-connection RPC dispatch and the small inline RPC handlers
//! (Ping / Shutdown / MmapReadFile).
//!
//! Sandbox / SystemInfo / EnsureRuntime / RuntimeStatus / Kubernetes* handlers
//! live in their respective modules; this file routes parsed `RpcRequest`s
//! to the right one.

use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use arcbox_protocol::agent::PingResponse;
use prost::Message as _;

use crate::rpc::{
    AGENT_VERSION, ErrorResponse, RpcRequest, RpcResponse, parse_request, read_message,
    write_message, write_response,
};

use super::disk::handle_disk_trim;
use super::kubernetes::{
    handle_delete_kubernetes, handle_kubernetes_kubeconfig, handle_kubernetes_status,
    handle_start_kubernetes, handle_stop_kubernetes,
};
use super::runtime::{handle_ensure_runtime, handle_runtime_status};
use super::sandbox::handle_sandbox_message;
use super::system_info::handle_get_system_info;
use super::vsock::is_peer_closed_error;

/// Result from handling a request.
enum RequestResult {
    /// Single response.
    Single(RpcResponse),
}

/// Handles a single vsock connection.
///
/// Reads RPC requests, processes them, and writes responses.
pub(super) async fn handle_connection<S>(mut stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        // Read the next request (V2 wire format with trace_id).
        let (msg_type, trace_id, payload) = match read_message(&mut stream).await {
            Ok(msg) => msg,
            Err(e) => {
                // Treat peer-closed errors as a clean disconnect; surface
                // anything else (parse failure, unexpected I/O) to the
                // caller so it's logged.
                if is_peer_closed_error(&e) {
                    tracing::debug!("Client disconnected");
                    return Ok(());
                }
                return Err(e);
            }
        };

        tracing::info!(
            trace_id = %trace_id,
            "Received message type {:?}, payload_len={}",
            msg_type,
            payload.len()
        );

        // Sandbox requests are handled separately — they bypass the normal
        // RPC request/response cycle because streaming operations hold the
        // connection open and write multiple frames.
        if msg_type.is_sandbox_request() {
            if let Err(e) = handle_sandbox_message(&mut stream, msg_type, &trace_id, &payload).await
            {
                tracing::warn!(trace_id = %trace_id, error = %e, "sandbox handler error");
            }
            continue;
        }

        // Machine-level exec also streams multiple frames on this connection.
        if matches!(msg_type, crate::rpc::MessageType::MachineExecRequest) {
            if let Err(e) =
                super::machine_exec::handle_machine_exec(&mut stream, &trace_id, &payload).await
            {
                tracing::warn!(trace_id = %trace_id, error = %e, "machine exec handler error");
            }
            continue;
        }

        // Parse and handle the request.
        let result = match parse_request(msg_type, &payload) {
            Ok(RpcRequest::WatchReadiness(req)) => {
                handle_watch_readiness(&mut stream, req, &trace_id).await?;
                continue;
            }
            Ok(RpcRequest::WatchMemoryPressure(req)) => {
                super::memory_pressure::handle_watch_memory_pressure(&mut stream, req, &trace_id)
                    .await?;
                continue;
            }
            Ok(RpcRequest::WatchStats(req)) => {
                super::stats::handle_watch_stats(&mut stream, req, &trace_id).await?;
                continue;
            }
            Ok(request) => handle_request(request).await,
            Err(e) => {
                tracing::warn!(trace_id = %trace_id, "Failed to parse request: {}", e);
                RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                    400,
                    format!("invalid request: {}", e),
                )))
            }
        };

        // Handle the result, echoing back the trace_id in responses.
        match result {
            RequestResult::Single(response) => {
                // Write single response
                write_response(&mut stream, &response, &trace_id).await?;
            }
        }
    }
}

/// Handles a single RPC request.
async fn handle_request(request: RpcRequest) -> RequestResult {
    match request {
        RpcRequest::Ping(req) => RequestResult::Single(handle_ping(req)),
        RpcRequest::GetSystemInfo => RequestResult::Single(handle_get_system_info().await),
        RpcRequest::EnsureRuntime(req) => RequestResult::Single(handle_ensure_runtime(req).await),
        RpcRequest::RuntimeStatus(req) => RequestResult::Single(handle_runtime_status(req).await),
        RpcRequest::StartKubernetes(req) => {
            RequestResult::Single(handle_start_kubernetes(req).await)
        }
        RpcRequest::StopKubernetes(req) => RequestResult::Single(handle_stop_kubernetes(req).await),
        RpcRequest::DeleteKubernetes(req) => {
            RequestResult::Single(handle_delete_kubernetes(req).await)
        }
        RpcRequest::KubernetesStatus(req) => {
            RequestResult::Single(handle_kubernetes_status(req).await)
        }
        RpcRequest::KubernetesKubeconfig(req) => {
            RequestResult::Single(handle_kubernetes_kubeconfig(req).await)
        }
        RpcRequest::Shutdown(req) => RequestResult::Single(handle_shutdown(req)),
        RpcRequest::MmapReadFile(req) => RequestResult::Single(handle_mmap_read_file(req)),
        RpcRequest::DiskTrim(_) => RequestResult::Single(handle_disk_trim().await),
        RpcRequest::ContainerFsPaths(req) => {
            RequestResult::Single(handle_container_fs_paths(req).await)
        }
        RpcRequest::ImageFsPaths(req) => RequestResult::Single(handle_image_fs_paths(req).await),
        RpcRequest::EnsureNfsExport(_) => RequestResult::Single(handle_ensure_nfs_export().await),
        RpcRequest::KillAgent => RequestResult::Single(handle_kill_agent()),
        RpcRequest::WatchReadiness(_) => unreachable!("watch readiness is streaming"),
        RpcRequest::WatchMemoryPressure(_) => {
            unreachable!("watch memory pressure is streaming")
        }
        RpcRequest::WatchStats(_) => unreachable!("watch stats is streaming"),
    }
}

async fn handle_watch_readiness<S>(
    stream: &mut S,
    req: arcbox_protocol::agent::WatchReadinessRequest,
    trace_id: &str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    use arcbox_protocol::agent::readiness_event::Kind;
    use arcbox_protocol::agent::{ReadinessEvent, RuntimeEnsureRequest};

    write_readiness_event(
        stream,
        trace_id,
        ReadinessEvent {
            kind: Kind::AgentReady as i32,
            endpoint: String::new(),
            detail: "agent ready".to_string(),
            services: Vec::new(),
        },
    )
    .await?;

    if !req.start_runtime_if_needed {
        return Ok(());
    }

    write_readiness_event(
        stream,
        trace_id,
        ReadinessEvent {
            kind: Kind::RuntimeStarting as i32,
            endpoint: String::new(),
            detail: "ensuring guest runtime".to_string(),
            services: Vec::new(),
        },
    )
    .await?;

    let timeout = Duration::from_millis(u64::from(req.timeout_ms).max(1));
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let response = match super::runtime::handle_ensure_runtime(RuntimeEnsureRequest {
            start_if_needed: true,
        })
        .await
        {
            RpcResponse::RuntimeEnsure(response) => response,
            other => {
                anyhow::bail!("unexpected ensure runtime response: {:?}", other);
            }
        };
        let response_message = response.message;

        let status = match super::runtime::handle_runtime_status(
            arcbox_protocol::agent::RuntimeStatusRequest {},
        )
        .await
        {
            RpcResponse::RuntimeStatus(status) => status,
            other => {
                anyhow::bail!("unexpected runtime status response: {:?}", other);
            }
        };

        // EnsureRuntime settles only after Docker and its post-start routing
        // setup are ready; RuntimeStatus independently confirms Docker is
        // still reachable at the point we publish the terminal event.
        if response.ready && status.docker_ready {
            return write_readiness_event(
                stream,
                trace_id,
                ReadinessEvent {
                    kind: Kind::RuntimeReady as i32,
                    endpoint: if response.endpoint.is_empty() {
                        status.endpoint
                    } else {
                        response.endpoint
                    },
                    detail: if response_message.is_empty() {
                        status.detail
                    } else {
                        response_message
                    },
                    services: status.services,
                },
            )
            .await;
        }

        if tokio::time::Instant::now() >= deadline {
            return write_readiness_event(
                stream,
                trace_id,
                ReadinessEvent {
                    kind: Kind::RuntimeFailed as i32,
                    endpoint: status.endpoint,
                    detail: if response_message.is_empty() {
                        status.detail
                    } else {
                        response_message
                    },
                    services: status.services,
                },
            )
            .await;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn write_readiness_event<S>(
    stream: &mut S,
    trace_id: &str,
    event: arcbox_protocol::agent::ReadinessEvent,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_message(
        stream,
        crate::rpc::MessageType::ReadinessEvent,
        trace_id,
        &event.encode_to_vec(),
    )
    .await
}

/// Handles a Shutdown request.
///
/// Responds immediately so the host receives the ack, then spawns the
/// shutdown sequence in a background OS thread (not a tokio task) because
/// [`crate::shutdown::poweroff`] calls blocking libc functions and never
/// returns.
fn handle_shutdown(req: arcbox_protocol::agent::ShutdownRequest) -> RpcResponse {
    let grace = if req.timeout_seconds == 0 {
        Duration::from_secs(u64::from(
            arcbox_constants::timeouts::GUEST_SHUTDOWN_GRACE_SECS,
        ))
    } else {
        Duration::from_secs(u64::from(req.timeout_seconds))
    };
    tracing::info!(grace_secs = grace.as_secs(), "Shutdown requested by host");
    std::thread::spawn(move || {
        // Brief delay so the response frame flushes over vsock.
        std::thread::sleep(Duration::from_millis(100));
        crate::shutdown::poweroff(grace);
    });
    RpcResponse::Shutdown(arcbox_protocol::agent::ShutdownResponse { accepted: true })
}

/// Handles a `KillAgent` request (test-only).
///
/// Exits the agent process so PID 1 (busybox init) respawns it — used by the
/// hv_e2e supervision harness to prove crash recovery without panicking the
/// kernel. Acks first, then exits after a brief delay so the response frame
/// flushes over vsock (mirrors [`handle_shutdown`]).
fn handle_kill_agent() -> RpcResponse {
    tracing::warn!("KillAgent requested by host (test-only); exiting for busybox-init respawn");
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        std::process::exit(1);
    });
    RpcResponse::KillAgent
}

/// Handles a `ContainerFsPaths` request.
///
/// Resolves the container's snapshot layer directories from containerd (the
/// snapshot key in the moby namespace is the container ID). The host reads
/// the returned guest paths through the read-only NFS export.
async fn handle_container_fs_paths(
    req: arcbox_protocol::agent::ContainerFsPathsRequest,
) -> RpcResponse {
    let id = req.container_id.as_str();
    // Container IDs are 64 hex chars; bound and charset-check the untrusted
    // input before handing it to containerd as a snapshot key.
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return RpcResponse::Error(crate::rpc::ErrorResponse::new(
            libc::EINVAL,
            format!("invalid container id {id:?}"),
        ));
    }

    match crate::containerd::container_snapshot_paths(id).await {
        Ok(paths) => {
            RpcResponse::ContainerFsPaths(arcbox_protocol::agent::ContainerFsPathsResponse {
                upper_dir: paths.upper_dir.unwrap_or_default(),
                lower_dirs: paths.lower_dirs,
            })
        }
        Err(e) => RpcResponse::Error(crate::rpc::ErrorResponse::new(
            libc::EIO,
            format!("container fs paths: {e}"),
        )),
    }
}

/// Handles an `ImageFsPaths` request.
///
/// Resolves an image's layer directories from its top layer chain ID via
/// an ephemeral containerd View snapshot. The host reads the returned
/// guest paths through the read-only NFS export.
async fn handle_image_fs_paths(req: arcbox_protocol::agent::ImageFsPathsRequest) -> RpcResponse {
    let chain_id = req.top_chain_id.as_str();
    // Chain IDs are `sha256:` + 64 hex chars; charset-check the untrusted
    // input before handing it to containerd as a snapshot key.
    let is_valid = chain_id
        .strip_prefix("sha256:")
        .is_some_and(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()));
    if !is_valid {
        return RpcResponse::Error(crate::rpc::ErrorResponse::new(
            libc::EINVAL,
            format!("invalid top chain id {chain_id:?}"),
        ));
    }

    match crate::containerd::image_snapshot_paths(chain_id).await {
        Ok(paths) => RpcResponse::ImageFsPaths(arcbox_protocol::agent::ImageFsPathsResponse {
            lower_dirs: paths.lower_dirs,
        }),
        Err(e) => RpcResponse::Error(crate::rpc::ErrorResponse::new(
            libc::EIO,
            format!("image fs paths: {e}"),
        )),
    }
}

/// Handles an `EnsureNfsExport` request.
///
/// Brings up the read-only NFS export of the docker data mount so the host
/// can browse it at `~/ArcBox`. The host daemon sends this only when the
/// mount is enabled, so the guest runs no nfsd unless asked. Runtime startup
/// no longer sets the export up itself, so this is the sole entry point.
async fn handle_ensure_nfs_export() -> RpcResponse {
    match super::runtime::ensure_nfs_export().await {
        Ok(notes) => {
            RpcResponse::EnsureNfsExport(arcbox_protocol::agent::EnsureNfsExportResponse { notes })
        }
        Err(e) => RpcResponse::Error(crate::rpc::ErrorResponse::new(
            libc::EIO,
            format!("ensure nfs export: {e}"),
        )),
    }
}

/// Sets CLOCK_REALTIME from the given timestamp (seconds since UNIX epoch).
///
/// Idempotent — safe to call more than once. Returns `true` if the clock
/// was set successfully.
pub(super) fn sync_clock_from_host(timestamp_secs: i64) -> bool {
    if timestamp_secs <= 0 {
        return false;
    }
    let ts = libc::timespec {
        tv_sec: timestamp_secs,
        tv_nsec: 0,
    };
    // SAFETY: `ts` points to a valid initialized timespec for this call,
    // and CLOCK_REALTIME is a valid clock ID on Linux guests.
    let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if ret != 0 {
        tracing::warn!(
            timestamp_secs,
            error = %std::io::Error::last_os_error(),
            "failed to set clock from host"
        );
        return false;
    }
    true
}

/// Handles a `MmapReadFile` request (test-only).
///
/// Opens the requested file `O_RDONLY`, calls `mmap(MAP_SHARED)`, reads
/// the mapped region into a heap buffer, then `munmap`s. When the path
/// is on a VirtioFS mount, the `mmap` call triggers `FUSE_SETUPMAPPING`
/// on the host, which exercises the DAX path end-to-end (ABX-362).
///
/// Page-alignment: `mmap` requires page-aligned offsets, so we round
/// `offset` down to the nearest page and slice the returned bytes to
/// compensate. This matches how real userspace code uses `mmap`.
fn handle_mmap_read_file(req: arcbox_protocol::agent::MmapReadFileRequest) -> RpcResponse {
    use std::os::unix::io::AsRawFd;

    const PAGE_SIZE: u64 = 4096;

    if req.length == 0 {
        return RpcResponse::MmapReadFile(arcbox_protocol::agent::MmapReadFileResponse {
            data: Vec::new(),
            bytes_read: 0,
        });
    }
    // Hard cap to keep the response message size bounded.
    if req.length > 64 * 1024 * 1024 {
        return RpcResponse::Error(crate::rpc::ErrorResponse::new(
            libc::EINVAL,
            "MmapReadFile length exceeds 64 MiB cap",
        ));
    }

    let file = match std::fs::OpenOptions::new().read(true).open(&req.path) {
        Ok(f) => f,
        Err(e) => {
            return RpcResponse::Error(crate::rpc::ErrorResponse::new(
                e.raw_os_error().unwrap_or(libc::EIO),
                format!("open {}: {e}", req.path),
            ));
        }
    };

    let page_base = req.offset & !(PAGE_SIZE - 1);
    let inner_off = (req.offset - page_base) as usize;
    let total_len = inner_off + req.length as usize;
    let mapped_len = total_len.div_ceil(PAGE_SIZE as usize) * PAGE_SIZE as usize;

    // SAFETY: mapped_len is > 0 and page-aligned. We pass PROT_READ and a
    // valid file fd; on success we own the mapping and must munmap it.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mapped_len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            #[allow(clippy::cast_possible_wrap)]
            {
                page_base as libc::off_t
            },
        )
    };
    if ptr == libc::MAP_FAILED {
        let e = std::io::Error::last_os_error();
        return RpcResponse::Error(crate::rpc::ErrorResponse::new(
            e.raw_os_error().unwrap_or(libc::EIO),
            format!("mmap {}: {e}", req.path),
        ));
    }

    // SAFETY: [ptr + inner_off .. ptr + inner_off + req.length] is within
    // the mapping we just obtained. Copy into a heap buffer so we can
    // unmap before returning.
    let data = unsafe {
        let slice =
            std::slice::from_raw_parts(ptr.cast::<u8>().add(inner_off), req.length as usize);
        slice.to_vec()
    };
    // SAFETY: ptr/mapped_len were returned by mmap above.
    unsafe {
        libc::munmap(ptr, mapped_len);
    }

    let bytes_read = data.len() as u64;
    RpcResponse::MmapReadFile(arcbox_protocol::agent::MmapReadFileResponse { data, bytes_read })
}

/// Handles a Ping request.
fn handle_ping(req: arcbox_protocol::agent::PingRequest) -> RpcResponse {
    tracing::debug!("Ping request: {:?}", req.message);
    sync_clock_from_host(req.timestamp_secs);
    RpcResponse::Ping(PingResponse {
        message: if req.message.is_empty() {
            "pong".to_string()
        } else {
            format!("pong: {}", req.message)
        },
        version: AGENT_VERSION.to_string(),
        protocol_version: arcbox_constants::wire::AGENT_PROTOCOL_VERSION,
    })
}
