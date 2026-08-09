//! Agent client for communicating with the guest VM.
//!
//! Provides RPC communication with the arcbox-agent running inside guest VMs.
//!
//! Message types are buffa-generated (`arcbox_connect`), the one Rust
//! representation of the ArcBox protos since CORE-73. buffa encodes the
//! same bytes prost did, so this daemon interoperates with both old
//! (prost) and new (buffa) guest agents: same length-prefixed
//! `MessageType` frames, same `AGENT_PROTOCOL_VERSION`, no wire change.

mod transport;
mod wire;

use self::transport::{AgentTransport, BLOCKING_RPC_TIMEOUT};
use crate::error::{CoreError, Result};
use arcbox_connect::sandbox_v1::{
    AttachExecutionRequest, CheckpointRequest, CheckpointResponse, CreateSandboxRequest,
    CreateSandboxResponse, DeleteSnapshotRequest, Execution, ExecutionEvent, FileChunk, FileStat,
    GetStdinStatusRequest, InspectSandboxRequest, ListDirRequest, ListDirResponse,
    ListExecutionsRequest, ListExecutionsResponse, ListSandboxesRequest, ListSandboxesResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, MakeDirRequest, MoveEntryRequest,
    PauseSandboxRequest, ReadFileRequest, RemoveEntryRequest, RemoveSandboxRequest,
    ResizeExecutionTtyRequest, RestoreRequest, RestoreResponse, SandboxEvent, SandboxEventsRequest,
    SandboxInfo, SetLifecycleRequest, SignalExecutionRequest, StartExecutionRequest,
    StatFileRequest, StdinStatus, StopSandboxRequest, WaitExecutionRequest, WaitForPortRequest,
    WatchDirRequest, WatchDirResponse, WriteFileOpen, WriteStdinRequest, execution_event,
};
use arcbox_connect::v1::{
    AgentPingRequest as PingRequest, AgentPingResponse as PingResponse, ContainerFsPathsRequest,
    ContainerFsPathsResponse, DiskTrimRequest, DiskTrimResponse, EnsureNfsExportRequest,
    EnsureNfsExportResponse, ImageFsPathsRequest, ImageFsPathsResponse, KubernetesDeleteRequest,
    KubernetesDeleteResponse, KubernetesKubeconfigRequest, KubernetesKubeconfigResponse,
    KubernetesStartRequest, KubernetesStartResponse, KubernetesStatusRequest,
    KubernetesStatusResponse, KubernetesStopRequest, KubernetesStopResponse, MachineExecOutput,
    MachineExecRequest, MachineStats, MemoryPressureEvent, MmapReadFileRequest,
    MmapReadFileResponse, ReadinessEvent, RuntimeEnsureRequest, RuntimeEnsureResponse,
    RuntimeStatusRequest, RuntimeStatusResponse, SandboxCleanupResponse, SandboxCleanupTicket,
    SandboxPortForwardRemoveRequest, SandboxPortForwardRequest, SandboxPortForwardResponse,
    SandboxResumeCommand, SandboxResumeResponse, SystemInfo, TerminalSize,
    WatchMemoryPressureRequest, WatchReadinessRequest, WatchSandboxCleanupRequest,
    WatchStatsRequest,
};
use arcbox_constants::ports::AGENT_PORT;
use arcbox_constants::wire::MessageType;
use arcbox_transport::Transport;
use arcbox_transport::vsock::{BlockingVsockTransport, VsockAddr, VsockTransport};
use buffa::Message;
use bytes::Bytes;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A single client→guest message during an interactive machine exec session.
#[derive(Debug)]
pub enum ExecSessionInput {
    /// Raw bytes for the process's stdin. An empty payload signals EOF and
    /// ends the input stream.
    Stdin(Vec<u8>),
    /// Resize the pseudo-TTY (only meaningful for `tty = true` sessions).
    Resize {
        /// Terminal width in columns.
        width: u16,
        /// Terminal height in rows.
        height: u16,
    },
}

/// Bound on frames buffered between the guest transport and a streaming RPC's
/// consumer. When the consumer stalls, the relay task blocks on a full channel,
/// which propagates backpressure to the guest (vsock flow control) instead of
/// letting an untrusted sandbox's output grow daemon memory without limit.
const STREAM_CHANNEL_CAPACITY: usize = 64;

/// A chunk in a sandbox file-write stream.
#[derive(Debug)]
pub enum WriteFileChunk {
    /// Payload bytes to append to the file.
    Data(Vec<u8>),
    /// The client stream ended without a terminating `done` chunk (a cancelled
    /// or reset upload). The write must be aborted rather than finalized, so a
    /// partially-received file is never committed as if it were complete.
    Abort,
}

/// Agent client for a single VM.
pub struct AgentClient {
    /// VM CID (Context ID).
    cid: u32,
    /// Transport backend.
    transport: AgentTransport,
    /// Whether connected.
    connected: bool,
}

impl AgentClient {
    /// Creates a new agent client for the given VM CID (async transport).
    #[must_use]
    pub const fn new(cid: u32) -> Self {
        let addr = VsockAddr::new(cid, AGENT_PORT);
        Self {
            cid,
            transport: AgentTransport::Async(VsockTransport::new(addr)),
            connected: false,
        }
    }

    /// Creates an agent client over an existing fd using the **blocking**
    /// transport.
    ///
    /// For the HV backend's AF_UNIX socketpair: the blocking path avoids the
    /// tokio/kqueue reactor stall on rapid connect/teardown cycles. Callers
    /// must route streaming RPCs elsewhere — the blocking transport rejects
    /// them.
    #[cfg(target_os = "macos")]
    pub fn from_fd_blocking(cid: u32, fd: std::os::unix::io::RawFd) -> Result<Self> {
        let transport = unsafe { BlockingVsockTransport::from_raw_fd(fd) }
            .map_err(|e| CoreError::Machine(format!("invalid vsock fd: {e}")))?;
        Ok(Self {
            cid,
            transport: AgentTransport::Blocking(transport),
            connected: true,
        })
    }

    /// Creates an agent client over an existing fd using the **async** tokio
    /// transport.
    ///
    /// For the VZ backend's bridged socket fd (and any true AF_VSOCK fd):
    /// supports the full RPC surface including streaming sandbox calls.
    ///
    /// The choice between this and [`Self::from_fd_blocking`] must come from
    /// the VM backend — both backends hand over unnamed AF_UNIX fds, so the
    /// socket domain cannot distinguish them.
    #[cfg(target_os = "macos")]
    pub fn from_fd_async(cid: u32, fd: std::os::unix::io::RawFd) -> Result<Self> {
        let addr = VsockAddr::new(cid, AGENT_PORT);
        let transport = VsockTransport::from_raw_fd(fd, addr)
            .map_err(|e| CoreError::Machine(format!("invalid vsock fd: {e}")))?;
        Ok(Self {
            cid,
            transport: AgentTransport::Async(transport),
            connected: true,
        })
    }

    /// Returns the VM CID.
    #[must_use]
    pub const fn cid(&self) -> u32 {
        self.cid
    }

    /// Builds a V2 wire message with an optional `trace_id`.
    pub(crate) fn build_message(msg_type: MessageType, trace_id: &str, payload: &[u8]) -> Bytes {
        wire::build_message(msg_type, trace_id, payload)
    }

    /// Connects to the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect(&mut self) -> Result<()> {
        if self.connected {
            return Ok(());
        }

        match &mut self.transport {
            AgentTransport::Async(t) => {
                t.connect()
                    .await
                    .map_err(|e| CoreError::Machine(format!("failed to connect to agent: {e}")))?;
            }
            AgentTransport::Blocking(_) => {
                // Blocking transport is connected at creation time (from_fd).
            }
        }

        self.connected = true;
        tracing::debug!(cid = self.cid, "connected to agent");
        Ok(())
    }

    /// Disconnects from the agent.
    pub async fn disconnect(&mut self) -> Result<()> {
        if self.connected {
            if let AgentTransport::Async(t) = &mut self.transport {
                t.disconnect()
                    .await
                    .map_err(|e| CoreError::Machine(format!("failed to disconnect: {e}")))?;
            }
            self.connected = false;
        }
        Ok(())
    }

    /// Sends an RPC request and receives a response.
    ///
    /// Automatically picks up the trace ID from task-local storage (set by
    /// the Docker API trace middleware) so callers don't need to thread it
    /// through manually.
    async fn rpc_call(&mut self, msg_type: MessageType, payload: &[u8]) -> Result<(u32, Vec<u8>)> {
        let trace_id = crate::trace::current_trace_id();
        self.rpc_call_traced(msg_type, &trace_id, payload).await
    }

    /// Sends an RPC request with a `trace_id` and receives a response.
    async fn rpc_call_traced(
        &mut self,
        msg_type: MessageType,
        trace_id: &str,
        payload: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        if !self.connected {
            self.connect().await?;
        }

        let buf = wire::build_message(msg_type, trace_id, payload);

        // Errors name the RPC: a per-call vsock connection failing surfaces
        // far from its caller (a warn in some supervisor loop), and without
        // the message type the log cannot say which RPC died (CORE-82).
        let response = match &mut self.transport {
            AgentTransport::Async(t) => {
                // Send request.
                t.send(buf)
                    .await
                    .map_err(|e| CoreError::Machine(format!("{msg_type:?} send failed: {e}")))?;
                // Receive response.
                t.recv().await.map_err(|e| {
                    CoreError::Machine(format!("{msg_type:?} response receive failed: {e}"))
                })?
            }
            AgentTransport::Blocking(t) => {
                // block_in_place tells the tokio multi-thread scheduler that
                // this worker is about to block, so it can spawn a replacement.
                // This prevents the 5s poll timeout from stalling other tasks.
                tokio::task::block_in_place(|| {
                    let deadline = Instant::now() + BLOCKING_RPC_TIMEOUT;
                    t.send(&buf, deadline).map_err(|e| {
                        CoreError::Machine(format!("{msg_type:?} send failed: {e}"))
                    })?;
                    t.recv(deadline).map_err(|e| {
                        CoreError::Machine(format!("{msg_type:?} response receive failed: {e}"))
                    })
                })?
            }
        };

        let (resp_type, _resp_trace, payload) = wire::parse_response(&response)?;

        // Check for error response.
        if resp_type == MessageType::Error as u32 {
            let (code, message) = wire::parse_error_response(&payload)?;
            return Err(CoreError::Agent { code, message });
        }

        Ok((resp_type, payload))
    }

    /// Synchronous RPC call for blocking transport. No async, no tokio.
    /// Only works with `AgentTransport::Blocking`.
    fn rpc_call_blocking(
        &mut self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        let trace_id = "";
        let buf = wire::build_message(msg_type, trace_id, payload);

        let response = match &mut self.transport {
            AgentTransport::Blocking(t) => {
                let deadline = Instant::now() + BLOCKING_RPC_TIMEOUT;
                t.send(&buf, deadline)
                    .map_err(|e| CoreError::Machine(format!("{msg_type:?} send failed: {e}")))?;
                t.recv(deadline).map_err(|e| {
                    CoreError::Machine(format!("{msg_type:?} response receive failed: {e}"))
                })?
            }
            AgentTransport::Async(_) => {
                return Err(CoreError::Machine(
                    "rpc_call_blocking called on async transport".into(),
                ));
            }
        };

        let (resp_type, _resp_trace, payload) = wire::parse_response(&response)?;
        if resp_type == MessageType::Error as u32 {
            let (code, message) = wire::parse_error_response(&payload)?;
            return Err(CoreError::Agent { code, message });
        }
        Ok((resp_type, payload))
    }

    fn decode_response<T: Message>(payload: &[u8]) -> Result<T> {
        T::decode_from_slice(payload)
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    fn expect_response_type(resp_type: u32, expected: MessageType) -> Result<()> {
        if resp_type == expected as u32 {
            Ok(())
        } else {
            Err(CoreError::Machine(format!(
                "unexpected response type: 0x{resp_type:04x}"
            )))
        }
    }

    fn expect_ack_response_type(resp_type: u32, expected: MessageType) -> Result<()> {
        if resp_type == expected as u32 || resp_type == MessageType::Empty as u32 {
            Ok(())
        } else {
            Err(CoreError::Machine(format!(
                "unexpected response type: 0x{resp_type:04x}"
            )))
        }
    }

    async fn unary_rpc<T: Message>(
        &mut self,
        request_type: MessageType,
        payload: &[u8],
        response_type: MessageType,
    ) -> Result<T> {
        let (resp_type, resp_payload) = self.rpc_call(request_type, payload).await?;
        Self::expect_response_type(resp_type, response_type)?;
        Self::decode_response(&resp_payload)
    }

    fn unary_rpc_blocking<T: Message>(
        &mut self,
        request_type: MessageType,
        payload: &[u8],
        response_type: MessageType,
    ) -> Result<T> {
        let (resp_type, resp_payload) = self.rpc_call_blocking(request_type, payload)?;
        Self::expect_response_type(resp_type, response_type)?;
        Self::decode_response(&resp_payload)
    }

    /// Verifies the agent's protocol version from a ping response.
    ///
    /// Rejects agents older than
    /// [`arcbox_constants::wire::MIN_AGENT_PROTOCOL_VERSION`]. Protocol `0`
    /// means no compatible handshake completed and may carry a boot-contract
    /// rejection from a current agent; positive older versions identify a
    /// stale staged agent.
    /// A *newer* agent than the host only warns: protocol evolution is
    /// additive, so newer agents understand older hosts.
    ///
    /// # Errors
    ///
    /// Returns an error when the agent's protocol version is below the
    /// host's minimum supported version.
    pub fn check_agent_protocol(resp: &PingResponse) -> Result<()> {
        use arcbox_constants::wire::{AGENT_PROTOCOL_VERSION, MIN_AGENT_PROTOCOL_VERSION};

        if resp.protocol_version == 0 {
            return Err(CoreError::Machine(format!(
                "guest agent did not complete a compatible handshake \
                 (agent version {}, response {:?}); fix the reported guest boot contract",
                resp.version, resp.message,
            )));
        }
        if resp.protocol_version < MIN_AGENT_PROTOCOL_VERSION {
            return Err(CoreError::Machine(format!(
                "guest agent is incompatible with this daemon: agent protocol {} \
                 (agent version {}, response {:?}), daemon requires >= {}. The staged agent \
                 binary is stale — reinstall or update ArcBox so the bundled \
                 agent is staged again",
                resp.protocol_version, resp.version, resp.message, MIN_AGENT_PROTOCOL_VERSION,
            )));
        }
        if resp.protocol_version > AGENT_PROTOCOL_VERSION {
            tracing::warn!(
                agent_protocol = resp.protocol_version,
                host_protocol = AGENT_PROTOCOL_VERSION,
                agent_version = %resp.version,
                "guest agent speaks a newer protocol than this daemon; \
                 continuing (protocol evolution is additive)"
            );
        }
        Ok(())
    }

    /// Synchronous ping — uses blocking transport's native deadline.
    /// Call from `spawn_blocking` or any non-async context.
    pub fn ping_blocking(&mut self) -> Result<PingResponse> {
        let req = PingRequest {
            message: "ping".to_string(),
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0)),
            ..Default::default()
        };
        let payload = req.encode_to_vec();
        self.unary_rpc_blocking(
            MessageType::PingRequest,
            &payload,
            MessageType::PingResponse,
        )
    }

    /// Returns true if this client uses the blocking transport (AF_UNIX / HV).
    pub fn is_blocking(&self) -> bool {
        matches!(self.transport, AgentTransport::Blocking(_))
    }

    /// Test-only: asks the guest agent to exit so PID 1 (busybox init) respawns
    /// it, exercising the supervision path. Returns once the agent acks; the
    /// agent then exits shortly after. Blocking transport only (hv_e2e harness).
    pub fn kill_agent_blocking(&mut self) -> Result<()> {
        let (resp_type, _payload) = self.rpc_call_blocking(MessageType::KillAgentRequest, &[])?;
        if resp_type != MessageType::KillAgentResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }
        Ok(())
    }

    /// Pings the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the ping fails.
    pub async fn ping(&mut self) -> Result<PingResponse> {
        let req = PingRequest {
            message: "ping".to_string(),
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0)),
            ..Default::default()
        };
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::PingRequest,
            &payload,
            MessageType::PingResponse,
        )
        .await
    }

    /// Gets system information from the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    /// Synchronous get_system_info for blocking transport.
    pub fn get_system_info_blocking(&mut self) -> Result<SystemInfo> {
        self.unary_rpc_blocking(
            MessageType::GetSystemInfoRequest,
            &[],
            MessageType::GetSystemInfoResponse,
        )
    }

    pub async fn get_system_info(&mut self) -> Result<SystemInfo> {
        self.unary_rpc(
            MessageType::GetSystemInfoRequest,
            &[],
            MessageType::GetSystemInfoResponse,
        )
        .await
    }

    /// Test-only: ask the guest to `mmap(MAP_SHARED)` a file and return its
    /// bytes. Used by the ABX-362 DAX E2E harness — on a VirtioFS mount the
    /// guest's `mmap` triggers `FUSE_SETUPMAPPING` and exercises the HV
    /// DAX path end-to-end. Not wired to any production CLI path.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the guest reports an
    /// `open`/`mmap` failure.
    pub fn mmap_read_file_blocking(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<MmapReadFileResponse> {
        let req = MmapReadFileRequest {
            path: path.to_string(),
            offset,
            length,
            ..Default::default()
        };
        let payload = req.encode_to_vec();
        self.unary_rpc_blocking(
            MessageType::MmapReadFileRequest,
            &payload,
            MessageType::MmapReadFileResponse,
        )
    }

    /// Ensures guest runtime services are ready.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn ensure_runtime(&mut self, start_if_needed: bool) -> Result<RuntimeEnsureResponse> {
        let req = RuntimeEnsureRequest {
            start_if_needed,
            ..Default::default()
        };
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::EnsureRuntimeRequest,
            &payload,
            MessageType::EnsureRuntimeResponse,
        )
        .await
    }

    /// Synchronous `ensure_runtime` for the blocking transport (HV backend).
    ///
    /// Mirrors [`Self::ensure_runtime`] but over the blocking vsock transport
    /// the HV backend hands out, so non-async harnesses (hv_e2e / cold-boot
    /// repro) can drive the "Starting Docker engine" stage. The caller bounds
    /// the wall-clock via `SO_RCVTIMEO`/`SO_SNDTIMEO` on the fd before the call.
    pub fn ensure_runtime_blocking(
        &mut self,
        start_if_needed: bool,
    ) -> Result<RuntimeEnsureResponse> {
        let req = RuntimeEnsureRequest {
            start_if_needed,
            ..Default::default()
        };
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) =
            self.rpc_call_blocking(MessageType::EnsureRuntimeRequest, &payload)?;
        if resp_type != MessageType::EnsureRuntimeResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }
        RuntimeEnsureResponse::decode_from_slice(&resp_payload)
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Gets guest runtime status.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn get_runtime_status(&mut self) -> Result<RuntimeStatusResponse> {
        let req = RuntimeStatusRequest::default();
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::RuntimeStatusRequest,
            &payload,
            MessageType::RuntimeStatusResponse,
        )
        .await
    }

    /// Watches guest readiness until the agent reports a terminal state.
    ///
    /// Unlike the older host-side poll loop, this is one request on one
    /// connection. The guest publishes readiness transitions as soon as it
    /// observes them, which removes host retry overshoot from warm boot.
    pub async fn watch_readiness(
        mut self,
        start_runtime_if_needed: bool,
        timeout: Duration,
        trace_id: &str,
    ) -> Result<ReadinessEvent> {
        if !self.connected {
            self.connect().await?;
        }

        let req = WatchReadinessRequest {
            start_runtime_if_needed,
            timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::WatchReadinessRequest, trace_id, &payload);

        match &mut self.transport {
            AgentTransport::Async(t) => {
                t.send(buf).await.map_err(|e| {
                    CoreError::Machine(format!("failed to send readiness watch request: {e}"))
                })?;

                let deadline = tokio::time::Instant::now() + timeout;
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(CoreError::Machine(
                            "timeout waiting for guest readiness event".to_string(),
                        ));
                    }

                    let raw = tokio::time::timeout(remaining, t.recv())
                        .await
                        .map_err(|_| {
                            CoreError::Machine(
                                "timeout waiting for guest readiness event".to_string(),
                            )
                        })?
                        .map_err(|e| {
                            CoreError::Machine(format!("failed to receive readiness event: {e}"))
                        })?;

                    let event = Self::decode_readiness_event(&raw)?;
                    if readiness_event_is_terminal(&event) || !start_runtime_if_needed {
                        return Ok(event);
                    }
                }
            }
            AgentTransport::Blocking(t) => tokio::task::block_in_place(|| {
                let deadline = Instant::now() + timeout;
                t.send(&buf, deadline).map_err(|e| {
                    CoreError::Machine(format!("failed to send readiness watch request: {e}"))
                })?;

                loop {
                    let raw = t.recv(deadline).map_err(|e| {
                        CoreError::Machine(format!("failed to receive readiness event: {e}"))
                    })?;
                    let event = Self::decode_readiness_event(&raw)?;
                    if readiness_event_is_terminal(&event) || !start_runtime_if_needed {
                        return Ok(event);
                    }
                }
            }),
        }
    }

    /// Blocking readiness watch for the macOS HV socketpair transport.
    ///
    /// This is used from startup's blocking probe thread so HV readiness does
    /// not touch tokio's kqueue reactor while the guest is still booting.
    pub fn watch_readiness_blocking(
        mut self,
        start_runtime_if_needed: bool,
        timeout: Duration,
        trace_id: &str,
    ) -> Result<ReadinessEvent> {
        let req = WatchReadinessRequest {
            start_runtime_if_needed,
            timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::WatchReadinessRequest, trace_id, &payload);

        let AgentTransport::Blocking(t) = &mut self.transport else {
            return Err(CoreError::Machine(
                "blocking readiness watch called on async transport".to_string(),
            ));
        };

        let deadline = Instant::now() + timeout;
        t.send(&buf, deadline).map_err(|e| {
            CoreError::Machine(format!("failed to send readiness watch request: {e}"))
        })?;

        loop {
            let raw = t.recv(deadline).map_err(|e| {
                CoreError::Machine(format!("failed to receive readiness event: {e}"))
            })?;
            let event = Self::decode_readiness_event(&raw)?;
            if readiness_event_is_terminal(&event) || !start_runtime_if_needed {
                return Ok(event);
            }
        }
    }

    /// Opens a guest memory pressure watch (`WatchMemoryPressure`).
    ///
    /// The agent answers with an immediate keepalive frame and then streams
    /// pressure events; consume them with
    /// [`Self::next_memory_pressure_event`]. The connection is dedicated to
    /// the watch until the agent closes the window.
    pub async fn watch_memory_pressure(&mut self, req: WatchMemoryPressureRequest) -> Result<()> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::WatchMemoryPressureRequest, "", &payload);

        match &mut self.transport {
            AgentTransport::Async(t) => t.send(buf).await.map_err(|e| {
                CoreError::Machine(format!("failed to send memory pressure watch request: {e}"))
            }),
            AgentTransport::Blocking(t) => tokio::task::block_in_place(|| {
                let deadline = Instant::now() + Duration::from_secs(5);
                t.send(&buf, deadline).map_err(|e| {
                    CoreError::Machine(format!("failed to send memory pressure watch request: {e}"))
                })
            }),
        }
    }

    /// Receives the next frame on an open memory pressure watch, waiting at
    /// most `max_wait`.
    ///
    /// A timeout means the agent went silent past its keepalive budget — the
    /// caller treats that exactly like a pressure event (fail open), because
    /// a guest too starved to answer is the incident signature.
    pub async fn next_memory_pressure_event(
        &mut self,
        max_wait: Duration,
    ) -> Result<MemoryPressureEvent> {
        match &mut self.transport {
            AgentTransport::Async(t) => {
                let raw = tokio::time::timeout(max_wait, t.recv())
                    .await
                    .map_err(|_| {
                        CoreError::Machine("timeout waiting for memory pressure event".to_string())
                    })?
                    .map_err(|e| {
                        CoreError::Machine(format!("failed to receive memory pressure event: {e}"))
                    })?;
                Self::decode_memory_pressure_event(&raw)
            }
            AgentTransport::Blocking(t) => tokio::task::block_in_place(|| {
                let raw = t.recv(Instant::now() + max_wait).map_err(|e| {
                    CoreError::Machine(format!("failed to receive memory pressure event: {e}"))
                })?;
                Self::decode_memory_pressure_event(&raw)
            }),
        }
    }

    /// Opens a guest machine stats watch (`WatchStats`).
    ///
    /// The agent streams one [`MachineStats`] frame per sample interval;
    /// consume them with [`Self::next_machine_stats`]. The connection is
    /// dedicated to the watch until the agent closes the window.
    pub async fn watch_stats(&mut self, req: WatchStatsRequest) -> Result<()> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::WatchStatsRequest, "", &payload);

        match &mut self.transport {
            AgentTransport::Async(t) => t.send(buf).await.map_err(|e| {
                CoreError::Machine(format!("failed to send stats watch request: {e}"))
            }),
            AgentTransport::Blocking(t) => tokio::task::block_in_place(|| {
                let deadline = Instant::now() + Duration::from_secs(5);
                t.send(&buf, deadline).map_err(|e| {
                    CoreError::Machine(format!("failed to send stats watch request: {e}"))
                })
            }),
        }
    }

    /// Receives the next frame on an open stats watch, waiting at most
    /// `max_wait`. Frames double as keepalives, so a timeout means the
    /// stream is stale (window elapsed or agent gone) and the caller
    /// should re-open the watch.
    pub async fn next_machine_stats(&mut self, max_wait: Duration) -> Result<MachineStats> {
        match &mut self.transport {
            AgentTransport::Async(t) => {
                let raw = tokio::time::timeout(max_wait, t.recv())
                    .await
                    .map_err(|_| CoreError::Machine("timeout waiting for stats frame".to_string()))?
                    .map_err(|e| {
                        CoreError::Machine(format!("failed to receive stats frame: {e}"))
                    })?;
                Self::decode_machine_stats(&raw)
            }
            AgentTransport::Blocking(t) => tokio::task::block_in_place(|| {
                let raw = t.recv(Instant::now() + max_wait).map_err(|e| {
                    CoreError::Machine(format!("failed to receive stats frame: {e}"))
                })?;
                Self::decode_machine_stats(&raw)
            }),
        }
    }

    fn decode_machine_stats(raw: &[u8]) -> Result<MachineStats> {
        let (resp_type, _, resp_payload) = wire::parse_response(raw)?;
        if resp_type == MessageType::Error as u32 {
            let (code, message) = wire::parse_error_response(&resp_payload)?;
            return Err(CoreError::Agent { code, message });
        }
        if resp_type != MessageType::MachineStats as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected stats response type: 0x{resp_type:04x}"
            )));
        }
        MachineStats::decode_from_slice(&resp_payload)
            .map_err(|e| CoreError::Machine(format!("failed to decode machine stats: {e}")))
    }

    fn decode_memory_pressure_event(raw: &[u8]) -> Result<MemoryPressureEvent> {
        let (resp_type, _, resp_payload) = wire::parse_response(raw)?;
        if resp_type == MessageType::Error as u32 {
            let (code, message) = wire::parse_error_response(&resp_payload)?;
            return Err(CoreError::Agent { code, message });
        }
        if resp_type != MessageType::MemoryPressureEvent as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected memory pressure response type: 0x{resp_type:04x}"
            )));
        }
        MemoryPressureEvent::decode_from_slice(&resp_payload)
            .map_err(|e| CoreError::Machine(format!("failed to decode memory pressure event: {e}")))
    }

    fn decode_readiness_event(raw: &[u8]) -> Result<ReadinessEvent> {
        let (resp_type, _, resp_payload) = wire::parse_response(raw)?;
        if resp_type == MessageType::Error as u32 {
            let (code, message) = wire::parse_error_response(&resp_payload)?;
            return Err(CoreError::Agent { code, message });
        }
        if resp_type != MessageType::ReadinessEvent as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected readiness response type: 0x{resp_type:04x}"
            )));
        }
        ReadinessEvent::decode_from_slice(&resp_payload)
            .map_err(|e| CoreError::Machine(format!("failed to decode readiness event: {e}")))
    }

    /// Starts the native Kubernetes cluster in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn start_kubernetes(&mut self) -> Result<KubernetesStartResponse> {
        let payload = KubernetesStartRequest::default().encode_to_vec();
        self.unary_rpc(
            MessageType::KubernetesStartRequest,
            &payload,
            MessageType::KubernetesStartResponse,
        )
        .await
    }

    /// Stops the native Kubernetes cluster in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn stop_kubernetes(&mut self) -> Result<KubernetesStopResponse> {
        let payload = KubernetesStopRequest::default().encode_to_vec();
        self.unary_rpc(
            MessageType::KubernetesStopRequest,
            &payload,
            MessageType::KubernetesStopResponse,
        )
        .await
    }

    /// Deletes the native Kubernetes cluster state in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn delete_kubernetes(&mut self) -> Result<KubernetesDeleteResponse> {
        let payload = KubernetesDeleteRequest::default().encode_to_vec();
        self.unary_rpc(
            MessageType::KubernetesDeleteRequest,
            &payload,
            MessageType::KubernetesDeleteResponse,
        )
        .await
    }

    /// Gets native Kubernetes cluster status from the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn get_kubernetes_status(&mut self) -> Result<KubernetesStatusResponse> {
        let payload = KubernetesStatusRequest::default().encode_to_vec();
        self.unary_rpc(
            MessageType::KubernetesStatusRequest,
            &payload,
            MessageType::KubernetesStatusResponse,
        )
        .await
    }

    /// Gets the guest-exported kubeconfig payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn get_kubeconfig(&mut self) -> Result<KubernetesKubeconfigResponse> {
        let payload = KubernetesKubeconfigRequest::default().encode_to_vec();
        self.unary_rpc(
            MessageType::KubernetesKubeconfigRequest,
            &payload,
            MessageType::KubernetesKubeconfigResponse,
        )
        .await
    }

    /// Resolves a container's filesystem layer directories (guest paths)
    /// from containerd snapshot metadata in the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the container has no
    /// snapshot (e.g. it was removed).
    pub async fn container_fs_paths(
        &mut self,
        container_id: &str,
    ) -> Result<ContainerFsPathsResponse> {
        let payload = ContainerFsPathsRequest {
            container_id: container_id.to_string(),
            ..Default::default()
        }
        .encode_to_vec();
        self.unary_rpc(
            MessageType::ContainerFsPathsRequest,
            &payload,
            MessageType::ContainerFsPathsResponse,
        )
        .await
    }

    /// Blocking variant of [`Self::container_fs_paths`] for the HV
    /// socketpair transport. Call from `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the container has no
    /// snapshot (e.g. it was removed).
    pub fn container_fs_paths_blocking(
        &mut self,
        container_id: &str,
    ) -> Result<ContainerFsPathsResponse> {
        let payload = ContainerFsPathsRequest {
            container_id: container_id.to_string(),
            ..Default::default()
        }
        .encode_to_vec();
        self.unary_rpc_blocking(
            MessageType::ContainerFsPathsRequest,
            &payload,
            MessageType::ContainerFsPathsResponse,
        )
    }

    /// Resolves an image's layer directories (guest paths) from its top
    /// layer chain ID via containerd snapshot metadata in the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the image's snapshot chain
    /// is absent (e.g. the image was removed).
    pub async fn image_fs_paths(&mut self, top_chain_id: &str) -> Result<ImageFsPathsResponse> {
        let payload = ImageFsPathsRequest {
            top_chain_id: top_chain_id.to_string(),
            ..Default::default()
        }
        .encode_to_vec();
        self.unary_rpc(
            MessageType::ImageFsPathsRequest,
            &payload,
            MessageType::ImageFsPathsResponse,
        )
        .await
    }

    /// Blocking variant of [`Self::image_fs_paths`] for the HV socketpair
    /// transport. Call from `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the image's snapshot chain
    /// is absent (e.g. the image was removed).
    pub fn image_fs_paths_blocking(&mut self, top_chain_id: &str) -> Result<ImageFsPathsResponse> {
        let payload = ImageFsPathsRequest {
            top_chain_id: top_chain_id.to_string(),
            ..Default::default()
        }
        .encode_to_vec();
        self.unary_rpc_blocking(
            MessageType::ImageFsPathsRequest,
            &payload,
            MessageType::ImageFsPathsResponse,
        )
    }

    /// Asks the guest to bring up the read-only NFS export of the docker data
    /// mount (browsable on the host at `~/ArcBox`). Idempotent: the agent
    /// ensures the data mount exists and converges an existing export.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the guest could not establish
    /// the export.
    pub async fn ensure_nfs_export(&mut self) -> Result<EnsureNfsExportResponse> {
        let payload = EnsureNfsExportRequest::default().encode_to_vec();
        self.unary_rpc(
            MessageType::EnsureNfsExportRequest,
            &payload,
            MessageType::EnsureNfsExportResponse,
        )
        .await
    }

    /// Blocking variant of [`Self::ensure_nfs_export`] for the HV socketpair
    /// transport. Call from `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the guest could not establish
    /// the export.
    pub fn ensure_nfs_export_blocking(&mut self) -> Result<EnsureNfsExportResponse> {
        let payload = EnsureNfsExportRequest::default().encode_to_vec();
        self.unary_rpc_blocking(
            MessageType::EnsureNfsExportRequest,
            &payload,
            MessageType::EnsureNfsExportResponse,
        )
    }

    /// Triggers an immediate fstrim on guest data mount points.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn disk_trim(&mut self) -> Result<DiskTrimResponse> {
        let payload = DiskTrimRequest::default().encode_to_vec();
        self.unary_rpc(
            MessageType::DiskTrimRequest,
            &payload,
            MessageType::DiskTrimResponse,
        )
        .await
    }

    /// Creates a new sandbox in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_create(
        &mut self,
        req: CreateSandboxRequest,
    ) -> Result<CreateSandboxResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxCreateRequest,
            &payload,
            MessageType::SandboxCreateResponse,
        )
        .await
    }

    /// Asks the guest agent to DNAT a reserved guest port to a sandbox port.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_port_forward(
        &mut self,
        req: SandboxPortForwardRequest,
    ) -> Result<SandboxPortForwardResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxPortForwardRequest,
            &payload,
            MessageType::SandboxPortForwardResponse,
        )
        .await
    }

    /// Asks the guest agent to remove a sandbox DNAT mapping.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_port_forward_remove(
        &mut self,
        req: SandboxPortForwardRemoveRequest,
    ) -> Result<()> {
        let payload = req.encode_to_vec();
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxPortForwardRemoveRequest, &payload)
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxPortForwardRemoveResponse)
    }

    /// Stops a sandbox in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_stop(
        &mut self,
        req: StopSandboxRequest,
    ) -> Result<SandboxCleanupResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxStopRequest,
            &payload,
            MessageType::SandboxStopResponse,
        )
        .await
    }

    /// Pauses a sandbox in the guest VM (checkpoint + release; CORE-21).
    ///
    /// Answers with the same durable network-cleanup ticket a Stop does —
    /// pause quarantines the sandbox's TAP + IP for host-side cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_pause(
        &mut self,
        req: PauseSandboxRequest,
    ) -> Result<SandboxCleanupResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxPauseRequest,
            &payload,
            MessageType::SandboxPauseResponse,
        )
        .await
    }

    /// Resumes a paused sandbox in place (CORE-21).
    ///
    /// `req.reason` distinguishes an explicit Resume from the daemon's
    /// transparent auto-resume; the guest surfaces it on the RESUMED event.
    /// The response carries the fresh IP for host DNS re-registration.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_resume(
        &mut self,
        req: SandboxResumeCommand,
    ) -> Result<SandboxResumeResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxResumeRequest,
            &payload,
            MessageType::SandboxResumeResponse,
        )
        .await
    }

    /// Replaces a sandbox's lifecycle deadlines in the guest VM (CORE-60):
    /// TTL re-armed from now, idle timeout/policy replaced. Absent fields
    /// are left unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_set_lifecycle(&mut self, req: SetLifecycleRequest) -> Result<()> {
        let (response_type, _) = self
            .rpc_call(
                MessageType::SandboxSetLifecycleRequest,
                &req.encode_to_vec(),
            )
            .await?;
        Self::expect_ack_response_type(response_type, MessageType::SandboxSetLifecycleResponse)
    }

    /// Removes a sandbox from the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_remove(
        &mut self,
        req: RemoveSandboxRequest,
    ) -> Result<SandboxCleanupResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxRemoveRequest,
            &payload,
            MessageType::SandboxRemoveResponse,
        )
        .await
    }

    /// Validate one exact cleanup generation before host listeners are removed.
    pub async fn sandbox_cleanup_prepare(&mut self, ticket: &SandboxCleanupTicket) -> Result<()> {
        let (response_type, _) = self
            .rpc_call(
                MessageType::SandboxCleanupPrepareRequest,
                &ticket.encode_to_vec(),
            )
            .await?;
        Self::expect_ack_response_type(response_type, MessageType::SandboxCleanupPrepareResponse)
    }

    /// Finalize one exact cleanup generation after host listeners are gone.
    pub async fn sandbox_cleanup_finalize(&mut self, ticket: &SandboxCleanupTicket) -> Result<()> {
        let (response_type, _) = self
            .rpc_call(
                MessageType::SandboxCleanupFinalizeRequest,
                &ticket.encode_to_vec(),
            )
            .await?;
        Self::expect_ack_response_type(response_type, MessageType::SandboxCleanupFinalizeResponse)
    }

    /// Inspects a sandbox in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_inspect(&mut self, req: InspectSandboxRequest) -> Result<SandboxInfo> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxInspectRequest,
            &payload,
            MessageType::SandboxInspectResponse,
        )
        .await
    }

    /// Lists sandboxes in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_list(
        &mut self,
        req: ListSandboxesRequest,
    ) -> Result<ListSandboxesResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxListRequest,
            &payload,
            MessageType::SandboxListResponse,
        )
        .await
    }

    /// Streams a file out of a sandbox as decoded [`FileChunk`]s.
    ///
    /// The final chunk carries `done == true`. Consumes the client because
    /// the stream task requires exclusive transport access.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails.
    pub async fn sandbox_read_file(
        mut self,
        req: ReadFileRequest,
    ) -> Result<mpsc::Receiver<Result<FileChunk>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = wire::build_message(MessageType::SandboxFileReadRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send read-file request: {e}")))?;

        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("recv error: {e}"))))
                            .await;
                        break;
                    }
                };
                let (resp_type, _, resp_payload) = match wire::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };
                if resp_type == MessageType::Error as u32 {
                    let (code, message) = wire::parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| (500, "unknown error".to_string()));
                    let _ = tx.send(Err(CoreError::Agent { code, message })).await;
                    break;
                }
                if resp_type != MessageType::SandboxFileData as u32 {
                    let _ = tx
                        .send(Err(CoreError::Machine(format!(
                            "unexpected response type: 0x{resp_type:04x}"
                        ))))
                        .await;
                    break;
                }
                match FileChunk::decode_from_slice(&resp_payload) {
                    Ok(chunk) => {
                        let done = chunk.done;
                        if tx.send(Ok(chunk)).await.is_err() || done {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("decode error: {e}"))))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Writes a file into a sandbox from a channel of data chunks.
    ///
    /// The channel closing marks end-of-data; the client then sends the
    /// terminating chunk and waits for the agent's acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an error if any send fails or the agent reports a failure.
    pub async fn sandbox_write_file(
        mut self,
        open: WriteFileOpen,
        mut data_rx: mpsc::Receiver<WriteFileChunk>,
    ) -> Result<()> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = open.encode_to_vec();
        let buf = wire::build_message(MessageType::SandboxFileWriteRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send write-file open: {e}")))?;

        while let Some(item) = data_rx.recv().await {
            let data = match item {
                WriteFileChunk::Data(data) => data,
                WriteFileChunk::Abort => {
                    // Do not send the terminating `done` frame. Returning drops
                    // the connection; the guest sees the stream end before
                    // `done` and discards the partial file instead of
                    // committing a truncated one.
                    return Err(CoreError::Machine(
                        "write_file aborted: client stream ended before completion".to_owned(),
                    ));
                }
            };
            let chunk = FileChunk {
                data,
                done: false,
                ..Default::default()
            };
            let frame =
                wire::build_message(MessageType::SandboxFileChunk, "", &chunk.encode_to_vec());
            self.transport
                .async_send(frame)
                .await
                .map_err(|e| CoreError::Machine(format!("failed to send file chunk: {e}")))?;
        }
        let done = FileChunk {
            data: Vec::new(),
            done: true,
            ..Default::default()
        };
        let frame = wire::build_message(MessageType::SandboxFileChunk, "", &done.encode_to_vec());
        self.transport
            .async_send(frame)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send final chunk: {e}")))?;

        let raw = self
            .transport
            .async_recv()
            .await
            .map_err(|e| CoreError::Machine(format!("recv error: {e}")))?;
        let (resp_type, _, resp_payload) = wire::parse_response(&raw)?;
        if resp_type == MessageType::Error as u32 {
            let (code, message) = wire::parse_error_response(&resp_payload)?;
            return Err(CoreError::Agent { code, message });
        }
        if resp_type != MessageType::SandboxFileWriteResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{resp_type:04x}"
            )));
        }
        Ok(())
    }

    /// Stats one path inside a sandbox (symlinks reported, not followed).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_stat(&mut self, req: StatFileRequest) -> Result<FileStat> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxFileStatRequest,
            &payload,
            MessageType::SandboxFileStatResponse,
        )
        .await
    }

    /// Lists a sandbox directory, non-recursively, with full per-entry
    /// metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_list_dir(&mut self, req: ListDirRequest) -> Result<ListDirResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxFileListDirRequest,
            &payload,
            MessageType::SandboxFileListDirResponse,
        )
        .await
    }

    /// Creates a directory inside a sandbox (`mkdir -p` semantics).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_make_dir(&mut self, req: MakeDirRequest) -> Result<()> {
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxFileMakeDirRequest, &req.encode_to_vec())
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxFileMakeDirResponse)
    }

    /// Removes a file, symlink, or directory inside a sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_remove_entry(&mut self, req: RemoveEntryRequest) -> Result<()> {
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxFileRemoveRequest, &req.encode_to_vec())
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxFileRemoveResponse)
    }

    /// Renames / moves an entry within a sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_move_entry(&mut self, req: MoveEntryRequest) -> Result<()> {
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxFileMoveRequest, &req.encode_to_vec())
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxFileMoveResponse)
    }

    /// Opens a directory watch stream inside a sandbox.
    ///
    /// The guest confirms establishment with an immediate keepalive frame
    /// and interleaves further keepalives while idle; the channel closes
    /// cleanly when the guest ends the stream (sandbox stop). Consumes the
    /// client because the stream task requires exclusive transport access.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails; in-stream failures
    /// arrive as `Err` items on the channel.
    pub async fn sandbox_watch_dir(
        mut self,
        req: WatchDirRequest,
    ) -> Result<mpsc::Receiver<Result<WatchDirResponse>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = wire::build_message(MessageType::SandboxFileWatchRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send watch-dir request: {e}")))?;

        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("recv error: {e}"))))
                            .await;
                        break;
                    }
                };
                let (resp_type, _, resp_payload) = match wire::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };
                if resp_type == MessageType::SandboxFileWatchEnd as u32 {
                    break; // clean end: the sandbox stopped
                }
                if resp_type == MessageType::Error as u32 {
                    let (code, message) = wire::parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| (500, "unknown error".to_string()));
                    let _ = tx.send(Err(CoreError::Agent { code, message })).await;
                    break;
                }
                if resp_type != MessageType::SandboxFileWatchEvent as u32 {
                    let _ = tx
                        .send(Err(CoreError::Machine(format!(
                            "unexpected response type: 0x{resp_type:04x}"
                        ))))
                        .await;
                    break;
                }
                match WatchDirResponse::decode_from_slice(&resp_payload) {
                    Ok(frame) => {
                        if tx.send(Ok(frame)).await.is_err() {
                            break; // consumer gone: dropping self cancels the watch
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("decode error: {e}"))))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Runs a command in the machine root (the agent's own mount namespace)
    /// and returns a channel of streaming output.
    ///
    /// Consumes the client because the stream task requires exclusive
    /// transport access. Non-interactive: the guest rejects `tty` requests
    /// until the bidi exec session lands.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails.
    pub async fn machine_exec(
        mut self,
        req: MachineExecRequest,
    ) -> Result<mpsc::Receiver<Result<MachineExecOutput>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = wire::build_message(MessageType::MachineExecRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send exec request: {}", e)))?;

        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("recv error: {}", e))))
                            .await;
                        break;
                    }
                };

                let (resp_type, _, resp_payload) = match wire::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };

                if resp_type == MessageType::Error as u32 {
                    let (code, message) = wire::parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| (500, "unknown error".to_string()));
                    let _ = tx.send(Err(CoreError::Agent { code, message })).await;
                    break;
                }

                if resp_type != MessageType::MachineExecOutput as u32 {
                    let _ = tx
                        .send(Err(CoreError::Machine(format!(
                            "unexpected response type: 0x{:04x}",
                            resp_type
                        ))))
                        .await;
                    break;
                }

                match MachineExecOutput::decode_from_slice(&resp_payload) {
                    Ok(output) => {
                        let done = output.done;
                        // Stop reading if the consumer dropped, so a spewing
                        // process isn't drained into the void indefinitely.
                        if tx.send(Ok(output)).await.is_err() || done {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("decode error: {}", e))))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Starts an interactive exec session in the machine root (PTY-backed).
    ///
    /// Consumes the client because the stream task requires exclusive
    /// transport access. The caller supplies a receiver of
    /// [`ExecSessionInput`]s (stdin bytes, TTY resizes, or EOF) and gets an
    /// output receiver of [`MachineExecOutput`] frames
    /// (stdout/stderr merged by the PTY; final frame carries the exit code).
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails.
    pub async fn machine_exec_session(
        mut self,
        req: MachineExecRequest,
        mut input_rx: mpsc::Receiver<ExecSessionInput>,
    ) -> Result<mpsc::Receiver<Result<MachineExecOutput>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = wire::build_message(MessageType::MachineExecRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send exec request: {}", e)))?;

        let (mut sender, mut receiver) = self
            .transport
            .into_split()
            .map_err(|e| CoreError::Machine(format!("failed to split transport: {e}")))?;

        let (out_tx, out_rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);

        // Input pump: channel → MachineExecInput / MachineExecResize frames.
        let stdin_handle = tokio::spawn(async move {
            loop {
                match input_rx.recv().await {
                    Some(ExecSessionInput::Stdin(data)) => {
                        let is_eof = data.is_empty();
                        let frame = wire::build_message(MessageType::MachineExecInput, "", &data);
                        if sender.send(frame).await.is_err() || is_eof {
                            break;
                        }
                    }
                    Some(ExecSessionInput::Resize { width, height }) => {
                        let size = TerminalSize {
                            width: u32::from(width),
                            height: u32::from(height),
                            ..Default::default()
                        };
                        let frame = wire::build_message(
                            MessageType::MachineExecResize,
                            "",
                            &size.encode_to_vec(),
                        );
                        if sender.send(frame).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        // Channel closed without explicit EOF; best-effort EOF
                        // frame so the guest session doesn't hang on stdin.
                        let eof = wire::build_message(MessageType::MachineExecInput, "", &[]);
                        let _ = sender.send(eof).await;
                        break;
                    }
                }
            }
        });

        // Output pump: MachineExecOutput frames → channel.
        tokio::spawn(async move {
            loop {
                let raw = match receiver.recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = out_tx
                            .send(Err(CoreError::Machine(format!("recv error: {}", e))))
                            .await;
                        break;
                    }
                };

                let (resp_type, _, resp_payload) = match wire::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = out_tx.send(Err(e)).await;
                        break;
                    }
                };

                if resp_type == MessageType::Error as u32 {
                    let (code, message) = wire::parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| (500, "unknown error".to_string()));
                    let _ = out_tx.send(Err(CoreError::Agent { code, message })).await;
                    break;
                }

                if resp_type != MessageType::MachineExecOutput as u32 {
                    let _ = out_tx
                        .send(Err(CoreError::Machine(format!(
                            "unexpected response type: 0x{:04x}",
                            resp_type
                        ))))
                        .await;
                    break;
                }

                match MachineExecOutput::decode_from_slice(&resp_payload) {
                    Ok(output) => {
                        let done = output.done;
                        if out_tx.send(Ok(output)).await.is_err() || done {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = out_tx
                            .send(Err(CoreError::Machine(format!("decode error: {}", e))))
                            .await;
                        break;
                    }
                }
            }
            stdin_handle.abort();
        });

        Ok(out_rx)
    }

    /// Starts an addressable execution inside a sandbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_exec_start(&mut self, req: StartExecutionRequest) -> Result<Execution> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxExecStartRequest,
            &payload,
            MessageType::SandboxExecStartResponse,
        )
        .await
    }

    /// Writes stdin bytes to an execution at an absolute offset
    /// (offset-idempotent; see the sandbox proto contract).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_stdin_write(&mut self, req: WriteStdinRequest) -> Result<StdinStatus> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxStdinWriteRequest,
            &payload,
            MessageType::SandboxStdinStatus,
        )
        .await
    }

    /// Reports how many stdin bytes the execution has accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_stdin_status(
        &mut self,
        req: GetStdinStatusRequest,
    ) -> Result<StdinStatus> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxStdinStatusRequest,
            &payload,
            MessageType::SandboxStdinStatus,
        )
        .await
    }

    /// Delivers a POSIX signal to an execution's process group.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_exec_signal(&mut self, req: SignalExecutionRequest) -> Result<()> {
        let payload = req.encode_to_vec();
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxExecSignalRequest, &payload)
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxExecSignalResponse)
    }

    /// Resizes a TTY execution's terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_exec_resize(&mut self, req: ResizeExecutionTtyRequest) -> Result<()> {
        let payload = req.encode_to_vec();
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxExecResizeRequest, &payload)
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxExecResizeResponse)
    }

    /// Waits for an execution to exit (zero timeout polls) and returns its
    /// state.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_exec_wait(&mut self, req: WaitExecutionRequest) -> Result<Execution> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxExecWaitRequest,
            &payload,
            MessageType::SandboxExecWaitResponse,
        )
        .await
    }

    /// Lists a sandbox's retained executions, running and exited.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_exec_list(
        &mut self,
        req: ListExecutionsRequest,
    ) -> Result<ListExecutionsResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxExecListRequest,
            &payload,
            MessageType::SandboxExecListResponse,
        )
        .await
    }

    /// Waits until something inside a sandbox listens on a TCP port.
    ///
    /// The guest enforces the wait budget from `req.timeout_seconds` (the
    /// caller resolves the default) and answers 504 when it elapses; the
    /// async transport applies no client-side deadline of its own.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the deadline elapses.
    pub async fn sandbox_wait_for_port(&mut self, req: WaitForPortRequest) -> Result<()> {
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxWaitForPortRequest, &req.encode_to_vec())
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxWaitForPortResponse)
    }

    /// Attaches to an execution's output and returns a channel of
    /// [`ExecutionEvent`]s. The stream ends after the `exited` event.
    ///
    /// Consumes the client because the stream task requires exclusive
    /// transport access.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails.
    pub async fn sandbox_exec_attach(
        mut self,
        req: AttachExecutionRequest,
    ) -> Result<mpsc::Receiver<Result<ExecutionEvent>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = wire::build_message(MessageType::SandboxExecAttachRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send attach request: {}", e)))?;

        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("recv error: {}", e))))
                            .await;
                        break;
                    }
                };

                let (resp_type, _, resp_payload) = match wire::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };

                if resp_type == MessageType::Error as u32 {
                    let (code, message) = wire::parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| (500, "unknown error".to_string()));
                    let _ = tx.send(Err(CoreError::Agent { code, message })).await;
                    break;
                }

                if resp_type != MessageType::SandboxExecEvent as u32 {
                    let _ = tx
                        .send(Err(CoreError::Machine(format!(
                            "unexpected response type: 0x{:04x}",
                            resp_type
                        ))))
                        .await;
                    break;
                }

                match ExecutionEvent::decode_from_slice(&resp_payload) {
                    Ok(event) => {
                        let done = matches!(event.event, Some(execution_event::Event::Exited(_)));
                        // Stop reading if the consumer dropped, so a spewing
                        // sandbox isn't drained into the void indefinitely.
                        if tx.send(Ok(event)).await.is_err() || done {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("decode error: {}", e))))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Subscribes to sandbox lifecycle events and returns a channel of streaming events.
    ///
    /// Consumes the client because the stream task requires exclusive transport access.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails.
    pub async fn sandbox_events(
        mut self,
        req: SandboxEventsRequest,
    ) -> Result<mpsc::Receiver<Result<SandboxEvent>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = wire::build_message(MessageType::SandboxEventsRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send events request: {}", e)))?;

        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("recv error: {}", e))))
                            .await;
                        break;
                    }
                };

                let (resp_type, _, resp_payload) = match wire::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                };

                if resp_type == MessageType::Error as u32 {
                    let (code, message) = wire::parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| (500, "unknown error".to_string()));
                    let _ = tx.send(Err(CoreError::Agent { code, message })).await;
                    break;
                }

                if resp_type != MessageType::SandboxEvent as u32 {
                    let _ = tx
                        .send(Err(CoreError::Machine(format!(
                            "unexpected response type: 0x{:04x}",
                            resp_type
                        ))))
                        .await;
                    break;
                }

                match SandboxEvent::decode_from_slice(&resp_payload) {
                    Ok(event) => {
                        // Stop when the subscriber drops instead of draining the
                        // event stream forever.
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!("decode error: {}", e))))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Stream durable sandbox cleanup tickets. Reconnecting replays every
    /// generation that has not finalized.
    pub async fn sandbox_cleanup_events(
        mut self,
    ) -> Result<mpsc::Receiver<Result<SandboxCleanupTicket>>> {
        if !self.connected {
            self.connect().await?;
        }

        let request = WatchSandboxCleanupRequest::default();
        let buffer = wire::build_message(
            MessageType::WatchSandboxCleanupRequest,
            "",
            &request.encode_to_vec(),
        );
        self.transport.async_send(buffer).await.map_err(|error| {
            CoreError::Machine(format!("failed to send sandbox cleanup watch: {error}"))
        })?;

        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(raw) => raw,
                    Err(error) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!(
                                "sandbox cleanup watch receive failed: {error}"
                            ))))
                            .await;
                        break;
                    }
                };
                let (response_type, _, payload) = match wire::parse_response(&raw) {
                    Ok(frame) => frame,
                    Err(error) => {
                        let _ = tx.send(Err(error)).await;
                        break;
                    }
                };
                if response_type == MessageType::Error as u32 {
                    let (code, message) = wire::parse_error_response(&payload)
                        .unwrap_or_else(|_| (500, "unknown error".to_owned()));
                    let _ = tx.send(Err(CoreError::Agent { code, message })).await;
                    break;
                }
                if response_type != MessageType::SandboxCleanupEvent as u32 {
                    let _ = tx
                        .send(Err(CoreError::Machine(format!(
                            "unexpected sandbox cleanup response: 0x{response_type:04x}"
                        ))))
                        .await;
                    break;
                }
                match SandboxCleanupTicket::decode_from_slice(&payload) {
                    Ok(ticket) => {
                        if tx.send(Ok(ticket)).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = tx
                            .send(Err(CoreError::Machine(format!(
                                "sandbox cleanup ticket decode failed: {error}"
                            ))))
                            .await;
                        break;
                    }
                }
            }
        });
        Ok(rx)
    }

    /// Checkpoints a sandbox (creates a snapshot).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_checkpoint(
        &mut self,
        req: CheckpointRequest,
    ) -> Result<CheckpointResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxCheckpointRequest,
            &payload,
            MessageType::SandboxCheckpointResponse,
        )
        .await
    }

    /// Restores a sandbox from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_restore(&mut self, req: RestoreRequest) -> Result<RestoreResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxRestoreRequest,
            &payload,
            MessageType::SandboxRestoreResponse,
        )
        .await
    }

    /// Lists snapshots for sandboxes in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_list_snapshots(
        &mut self,
        req: ListSnapshotsRequest,
    ) -> Result<ListSnapshotsResponse> {
        let payload = req.encode_to_vec();
        self.unary_rpc(
            MessageType::SandboxListSnapshotsRequest,
            &payload,
            MessageType::SandboxListSnapshotsResponse,
        )
        .await
    }

    /// Deletes a snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_delete_snapshot(&mut self, req: DeleteSnapshotRequest) -> Result<()> {
        let payload = req.encode_to_vec();
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxDeleteSnapshotRequest, &payload)
            .await?;
        Self::expect_ack_response_type(resp_type, MessageType::SandboxDeleteSnapshotResponse)
    }
}

fn readiness_event_is_terminal(event: &ReadinessEvent) -> bool {
    use arcbox_connect::v1::readiness_event::Kind;

    matches!(
        event.kind.as_known(),
        Some(Kind::RuntimeReady | Kind::RuntimeFailed)
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        assert_eq!(
            MessageType::from_u32(MessageType::PingRequest as u32),
            Some(MessageType::PingRequest)
        );
        assert_eq!(
            MessageType::from_u32(MessageType::PingResponse as u32),
            Some(MessageType::PingResponse)
        );
        assert_eq!(
            MessageType::from_u32(MessageType::PortBindingsChanged as u32),
            Some(MessageType::PortBindingsChanged)
        );
    }

    #[test]
    fn test_agent_client_new() {
        let client = AgentClient::new(3);
        assert_eq!(client.cid(), 3);
        assert!(!client.connected);
    }

    fn ping_response(protocol_version: u32) -> PingResponse {
        PingResponse {
            message: "pong".to_string(),
            version: "0.4.16".to_string(),
            protocol_version,
            ..Default::default()
        }
    }

    #[test]
    fn boot_contract_rejection_is_not_reported_as_a_stale_agent() {
        let mut response = ping_response(0);
        response.message =
            "incompatible host boot contract: missing arcbox.runtime_generation".to_string();
        let err =
            AgentClient::check_agent_protocol(&response).expect_err("protocol 0 must be rejected");
        assert!(err.to_string().contains("incompatible"));
        assert!(err.to_string().contains("arcbox.runtime_generation"));
        assert!(!err.to_string().contains("stale"));
    }

    #[test]
    fn previous_protocol_is_rejected() {
        let previous = arcbox_constants::wire::AGENT_PROTOCOL_VERSION - 1;
        let err = AgentClient::check_agent_protocol(&ping_response(previous))
            .expect_err("previous protocol must be rejected");
        assert!(err.to_string().contains("incompatible"));
        assert!(err.to_string().contains("stale"));
    }

    #[test]
    fn current_protocol_is_accepted() {
        let resp = ping_response(arcbox_constants::wire::AGENT_PROTOCOL_VERSION);
        AgentClient::check_agent_protocol(&resp).expect("current protocol must pass");
    }

    #[test]
    fn newer_agent_protocol_is_accepted_with_warning() {
        // Additive evolution: a newer agent understands an older host.
        let resp = ping_response(arcbox_constants::wire::AGENT_PROTOCOL_VERSION + 1);
        AgentClient::check_agent_protocol(&resp).expect("newer protocol must pass");
    }
}
