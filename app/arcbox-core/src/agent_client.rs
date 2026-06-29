//! Agent client for communicating with the guest VM.
//!
//! Provides RPC communication with the arcbox-agent running inside guest VMs.

use crate::error::{CoreError, Result};
use arcbox_constants::ports::AGENT_PORT;
use arcbox_constants::wire::{
    ERROR_HEADER_SIZE, FRAME_HEADER_SIZE, MessageType, TRACE_LEN_FIELD_SIZE, TYPE_FIELD_SIZE,
};
use arcbox_protocol::agent::{
    DiskTrimRequest, DiskTrimResponse, KubernetesDeleteRequest, KubernetesDeleteResponse,
    KubernetesKubeconfigRequest, KubernetesKubeconfigResponse, KubernetesStartRequest,
    KubernetesStartResponse, KubernetesStatusRequest, KubernetesStatusResponse,
    KubernetesStopRequest, KubernetesStopResponse, MmapReadFileRequest, MmapReadFileResponse,
    PingRequest, PingResponse, ReadinessEvent, RuntimeEnsureRequest, RuntimeEnsureResponse,
    RuntimeStatusRequest, RuntimeStatusResponse, SystemInfo, WatchReadinessRequest,
};
use arcbox_protocol::sandbox_v1::{
    CheckpointRequest, CheckpointResponse, CreateSandboxRequest, CreateSandboxResponse,
    DeleteSnapshotRequest, ExecOutput, ExecRequest, InspectSandboxRequest, ListSandboxesRequest,
    ListSandboxesResponse, ListSnapshotsRequest, ListSnapshotsResponse, RemoveSandboxRequest,
    RestoreRequest, RestoreResponse, RunOutput, RunRequest, SandboxEvent, SandboxEventsRequest,
    SandboxInfo, StopSandboxRequest,
};
use arcbox_transport::Transport;
use arcbox_transport::vsock::{BlockingVsockTransport, VsockAddr, VsockTransport};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Transport backend for agent RPC.
///
/// `Async` is the default for Linux AF_VSOCK and macOS VZ backend (real vsock
/// fds that tokio/kqueue handles correctly).
///
/// `Blocking` is used for macOS HV backend socketpair fds (AF_UNIX). These fds
/// trigger a tokio/kqueue reactor stall when rapidly created and torn down in a
/// retry loop, causing timer wakeups to stop firing. The blocking transport
/// uses `libc::poll` + `std::os::unix::net::UnixStream` and never touches the
/// tokio reactor.
enum AgentTransport {
    Async(VsockTransport),
    Blocking(BlockingVsockTransport),
}

/// Default RPC deadline for blocking transport operations.
const BLOCKING_RPC_TIMEOUT: Duration = Duration::from_secs(5);

impl AgentTransport {
    /// Async send — only valid for `Async` variant. Streaming RPCs that
    /// consume `self` and spawn async tasks must go through the async path.
    async fn async_send(
        &mut self,
        data: Bytes,
    ) -> std::result::Result<(), arcbox_transport::error::TransportError> {
        match self {
            Self::Async(t) => t.send(data).await,
            Self::Blocking(_) => Err(arcbox_transport::error::TransportError::Protocol(
                "streaming RPCs not supported on blocking transport".into(),
            )),
        }
    }

    /// Async recv — only valid for `Async` variant.
    async fn async_recv(
        &mut self,
    ) -> std::result::Result<Bytes, arcbox_transport::error::TransportError> {
        match self {
            Self::Async(t) => t.recv().await,
            Self::Blocking(_) => Err(arcbox_transport::error::TransportError::Protocol(
                "streaming RPCs not supported on blocking transport".into(),
            )),
        }
    }

    /// Split into send/recv halves — only valid for `Async` variant.
    fn into_split(
        self,
    ) -> std::result::Result<
        (
            arcbox_transport::vsock::VsockSender,
            arcbox_transport::vsock::VsockReceiver,
        ),
        arcbox_transport::error::TransportError,
    > {
        match self {
            Self::Async(t) => t.into_split(),
            Self::Blocking(_) => Err(arcbox_transport::error::TransportError::Protocol(
                "split not supported on blocking transport".into(),
            )),
        }
    }
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

    /// Creates an agent client from an existing vsock file descriptor.
    ///
    /// Detects the socket domain via `getsockname`:
    /// - `AF_UNIX` → blocking transport (HV backend socketpair)
    /// - anything else → async tokio transport (VZ / AF_VSOCK)
    #[cfg(target_os = "macos")]
    pub fn from_fd(cid: u32, fd: std::os::unix::io::RawFd) -> Result<Self> {
        let is_unix = {
            let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len: libc::socklen_t =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockname(fd, (&raw mut addr).cast::<libc::sockaddr>(), &raw mut len)
            };
            // Hard-fail on getsockname errors rather than silently falling
            // through to async transport. If the HV backend handed us an
            // AF_UNIX socketpair and getsockname fails, mis-routing to async
            // transport would re-enter the exact kqueue/tokio stall the
            // blocking path was designed to avoid.
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(CoreError::Machine(format!(
                    "getsockname failed on vsock fd {fd}: {err}"
                )));
            }
            addr.ss_family == libc::AF_UNIX as libc::sa_family_t
        };

        if is_unix {
            // HV backend socketpair — use blocking transport to avoid
            // tokio/kqueue reactor stall on rapid connect/teardown cycles.
            let transport = unsafe { BlockingVsockTransport::from_raw_fd(fd) }
                .map_err(|e| CoreError::Machine(format!("invalid vsock fd: {e}")))?;
            Ok(Self {
                cid,
                transport: AgentTransport::Blocking(transport),
                connected: true,
            })
        } else {
            // VZ backend or AF_VSOCK — use async tokio transport.
            let addr = VsockAddr::new(cid, AGENT_PORT);
            let transport = VsockTransport::from_raw_fd(fd, addr)
                .map_err(|e| CoreError::Machine(format!("invalid vsock fd: {e}")))?;
            Ok(Self {
                cid,
                transport: AgentTransport::Async(transport),
                connected: true,
            })
        }
    }

    /// Returns the VM CID.
    #[must_use]
    pub const fn cid(&self) -> u32 {
        self.cid
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

    /// Builds a V2 wire message with an optional `trace_id`.
    ///
    /// Wire format V2:
    /// ```text
    /// +----------------+----------------+------------------+----------------+
    /// | Length (4B BE) | Type (4B BE)   | TraceLen (2B BE) | TraceID bytes  | Payload
    /// +----------------+----------------+------------------+----------------+
    /// ```
    pub(crate) fn build_message(msg_type: MessageType, trace_id: &str, payload: &[u8]) -> Bytes {
        let trace_bytes = trace_id.as_bytes();
        let trace_len = trace_bytes.len().min(u16::MAX as usize);
        // Length = type(4) + trace_len_field(2) + trace_bytes + payload
        let length = TYPE_FIELD_SIZE + TRACE_LEN_FIELD_SIZE + trace_len + payload.len();
        let mut buf = BytesMut::with_capacity(
            FRAME_HEADER_SIZE + TRACE_LEN_FIELD_SIZE + trace_len + payload.len(),
        );
        buf.put_u32(length as u32);
        buf.put_u32(msg_type as u32);
        buf.put_u16(trace_len as u16);
        if trace_len > 0 {
            buf.extend_from_slice(&trace_bytes[..trace_len]);
        }
        buf.extend_from_slice(payload);
        buf.freeze()
    }

    /// Parses a V2 wire response. Returns (`resp_type`, `trace_id`, payload).
    fn parse_response(response: &[u8]) -> Result<(u32, String, Vec<u8>)> {
        if response.len() < FRAME_HEADER_SIZE {
            return Err(CoreError::Machine("response too short".to_string()));
        }
        let mut cursor = std::io::Cursor::new(response);
        let length = cursor.get_u32() as usize;
        let resp_type = cursor.get_u32();

        let remaining = length.saturating_sub(TYPE_FIELD_SIZE);
        let offset = FRAME_HEADER_SIZE;

        if remaining < TRACE_LEN_FIELD_SIZE || response.len() < offset + TRACE_LEN_FIELD_SIZE {
            // No trace_len field; treat the rest as payload.
            return Ok((resp_type, String::new(), response[offset..].to_vec()));
        }

        let trace_len = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        let trace_start = offset + TRACE_LEN_FIELD_SIZE;
        let trace_end = trace_start + trace_len;
        let payload_start = trace_end;

        if response.len() < trace_end {
            return Ok((resp_type, String::new(), response[trace_start..].to_vec()));
        }

        let trace_id =
            String::from_utf8(response[trace_start..trace_end].to_vec()).unwrap_or_default();
        let payload = if response.len() > payload_start {
            response[payload_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok((resp_type, trace_id, payload))
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

        let buf = Self::build_message(msg_type, trace_id, payload);

        let response = match &mut self.transport {
            AgentTransport::Async(t) => {
                // Send request.
                t.send(buf)
                    .await
                    .map_err(|e| CoreError::Machine(format!("failed to send request: {e}")))?;
                // Receive response.
                t.recv()
                    .await
                    .map_err(|e| CoreError::Machine(format!("failed to receive response: {e}")))?
            }
            AgentTransport::Blocking(t) => {
                // block_in_place tells the tokio multi-thread scheduler that
                // this worker is about to block, so it can spawn a replacement.
                // This prevents the 5s poll timeout from stalling other tasks.
                tokio::task::block_in_place(|| {
                    let deadline = Instant::now() + BLOCKING_RPC_TIMEOUT;
                    t.send(&buf, deadline)
                        .map_err(|e| CoreError::Machine(format!("failed to send request: {e}")))?;
                    t.recv(deadline)
                        .map_err(|e| CoreError::Machine(format!("failed to receive response: {e}")))
                })?
            }
        };

        let (resp_type, _resp_trace, payload) = Self::parse_response(&response)?;

        // Check for error response.
        if resp_type == MessageType::Error as u32 {
            let error_msg = parse_error_response(&payload)?;
            return Err(CoreError::Machine(error_msg));
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
        let buf = Self::build_message(msg_type, trace_id, payload);

        let response = match &mut self.transport {
            AgentTransport::Blocking(t) => {
                let deadline = Instant::now() + BLOCKING_RPC_TIMEOUT;
                t.send(&buf, deadline)
                    .map_err(|e| CoreError::Machine(format!("failed to send request: {e}")))?;
                t.recv(deadline)
                    .map_err(|e| CoreError::Machine(format!("failed to receive response: {e}")))?
            }
            AgentTransport::Async(_) => {
                return Err(CoreError::Machine(
                    "rpc_call_blocking called on async transport".into(),
                ));
            }
        };

        let (resp_type, _resp_trace, payload) = Self::parse_response(&response)?;
        if resp_type == MessageType::Error as u32 {
            let error_msg = parse_error_response(&payload)?;
            return Err(CoreError::Machine(error_msg));
        }
        Ok((resp_type, payload))
    }

    /// Synchronous ping — uses blocking transport's native deadline.
    /// Call from `spawn_blocking` or any non-async context.
    pub fn ping_blocking(&mut self) -> Result<PingResponse> {
        let req = PingRequest {
            message: "ping".to_string(),
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0)),
        };
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) =
            self.rpc_call_blocking(MessageType::PingRequest, &payload)?;
        if resp_type != MessageType::PingResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }
        PingResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
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
        };
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self.rpc_call(MessageType::PingRequest, &payload).await?;

        if resp_type != MessageType::PingResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        PingResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Gets system information from the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    /// Synchronous get_system_info for blocking transport.
    pub fn get_system_info_blocking(&mut self) -> Result<SystemInfo> {
        let (resp_type, resp_payload) =
            self.rpc_call_blocking(MessageType::GetSystemInfoRequest, &[])?;
        if resp_type != MessageType::GetSystemInfoResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }
        SystemInfo::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    pub async fn get_system_info(&mut self) -> Result<SystemInfo> {
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::GetSystemInfoRequest, &[])
            .await?;

        if resp_type != MessageType::GetSystemInfoResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        SystemInfo::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
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
        };
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) =
            self.rpc_call_blocking(MessageType::MmapReadFileRequest, &payload)?;
        if resp_type != MessageType::MmapReadFileResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }
        MmapReadFileResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Ensures guest runtime services are ready.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn ensure_runtime(&mut self, start_if_needed: bool) -> Result<RuntimeEnsureResponse> {
        let req = RuntimeEnsureRequest { start_if_needed };
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::EnsureRuntimeRequest, &payload)
            .await?;

        if resp_type != MessageType::EnsureRuntimeResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        RuntimeEnsureResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
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
        let req = RuntimeEnsureRequest { start_if_needed };
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) =
            self.rpc_call_blocking(MessageType::EnsureRuntimeRequest, &payload)?;
        if resp_type != MessageType::EnsureRuntimeResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }
        RuntimeEnsureResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Gets guest runtime status.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn get_runtime_status(&mut self) -> Result<RuntimeStatusResponse> {
        let req = RuntimeStatusRequest {};
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::RuntimeStatusRequest, &payload)
            .await?;

        if resp_type != MessageType::RuntimeStatusResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        RuntimeStatusResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
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
    ) -> Result<ReadinessEvent> {
        if !self.connected {
            self.connect().await?;
        }

        let req = WatchReadinessRequest {
            start_runtime_if_needed,
            timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        };
        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::WatchReadinessRequest, "", &payload);

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
    ) -> Result<ReadinessEvent> {
        let req = WatchReadinessRequest {
            start_runtime_if_needed,
            timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        };
        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::WatchReadinessRequest, "", &payload);

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

    fn decode_readiness_event(raw: &[u8]) -> Result<ReadinessEvent> {
        let (resp_type, _, resp_payload) = Self::parse_response(raw)?;
        if resp_type == MessageType::Error as u32 {
            let error_msg = parse_error_response(&resp_payload)?;
            return Err(CoreError::Machine(error_msg));
        }
        if resp_type != MessageType::ReadinessEvent as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected readiness response type: 0x{resp_type:04x}"
            )));
        }
        ReadinessEvent::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode readiness event: {e}")))
    }

    /// Starts the native Kubernetes cluster in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn start_kubernetes(&mut self) -> Result<KubernetesStartResponse> {
        let payload = KubernetesStartRequest {}.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::KubernetesStartRequest, &payload)
            .await?;

        if resp_type != MessageType::KubernetesStartResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        KubernetesStartResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Stops the native Kubernetes cluster in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn stop_kubernetes(&mut self) -> Result<KubernetesStopResponse> {
        let payload = KubernetesStopRequest {}.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::KubernetesStopRequest, &payload)
            .await?;

        if resp_type != MessageType::KubernetesStopResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        KubernetesStopResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Deletes the native Kubernetes cluster state in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn delete_kubernetes(&mut self) -> Result<KubernetesDeleteResponse> {
        let payload = KubernetesDeleteRequest {}.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::KubernetesDeleteRequest, &payload)
            .await?;

        if resp_type != MessageType::KubernetesDeleteResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        KubernetesDeleteResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Gets native Kubernetes cluster status from the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn get_kubernetes_status(&mut self) -> Result<KubernetesStatusResponse> {
        let payload = KubernetesStatusRequest {}.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::KubernetesStatusRequest, &payload)
            .await?;

        if resp_type != MessageType::KubernetesStatusResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        KubernetesStatusResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Gets the guest-exported kubeconfig payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn get_kubeconfig(&mut self) -> Result<KubernetesKubeconfigResponse> {
        let payload = KubernetesKubeconfigRequest {}.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::KubernetesKubeconfigRequest, &payload)
            .await?;

        if resp_type != MessageType::KubernetesKubeconfigResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        KubernetesKubeconfigResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
    }

    /// Triggers an immediate fstrim on guest data mount points.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn disk_trim(&mut self) -> Result<DiskTrimResponse> {
        let payload = DiskTrimRequest {}.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::DiskTrimRequest, &payload)
            .await?;

        if resp_type != MessageType::DiskTrimResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {resp_type}"
            )));
        }

        DiskTrimResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {e}")))
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
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::SandboxCreateRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxCreateResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        CreateSandboxResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Stops a sandbox in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_stop(&mut self, req: StopSandboxRequest) -> Result<()> {
        let payload = req.encode_to_vec();
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxStopRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxStopResponse as u32
            && resp_type != MessageType::Empty as u32
        {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Removes a sandbox from the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_remove(&mut self, req: RemoveSandboxRequest) -> Result<()> {
        let payload = req.encode_to_vec();
        let (resp_type, _) = self
            .rpc_call(MessageType::SandboxRemoveRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxRemoveResponse as u32
            && resp_type != MessageType::Empty as u32
        {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Inspects a sandbox in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_inspect(&mut self, req: InspectSandboxRequest) -> Result<SandboxInfo> {
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::SandboxInspectRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxInspectResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        SandboxInfo::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
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
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::SandboxListRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxListResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        ListSandboxesResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Runs a command inside a sandbox and returns a channel of streaming output.
    ///
    /// Consumes the client because the stream task requires exclusive transport access.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails.
    pub async fn sandbox_run(
        mut self,
        req: RunRequest,
    ) -> Result<mpsc::UnboundedReceiver<Result<RunOutput>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::SandboxRunRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send run request: {}", e)))?;

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Err(CoreError::Machine(format!("recv error: {}", e))));
                        break;
                    }
                };

                let (resp_type, _, resp_payload) = match Self::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                };

                if resp_type == MessageType::Error as u32 {
                    let msg = parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| "unknown error".to_string());
                    let _ = tx.send(Err(CoreError::Machine(msg)));
                    break;
                }

                if resp_type != MessageType::SandboxRunOutput as u32 {
                    let _ = tx.send(Err(CoreError::Machine(format!(
                        "unexpected response type: 0x{:04x}",
                        resp_type
                    ))));
                    break;
                }

                match RunOutput::decode(&resp_payload[..]) {
                    Ok(output) => {
                        let done = output.done;
                        let _ = tx.send(Ok(output));
                        if done {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(CoreError::Machine(format!("decode error: {}", e))));
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
    ) -> Result<mpsc::UnboundedReceiver<Result<SandboxEvent>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::SandboxEventsRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send events request: {}", e)))?;

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let raw = match self.transport.async_recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Err(CoreError::Machine(format!("recv error: {}", e))));
                        break;
                    }
                };

                let (resp_type, _, resp_payload) = match Self::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                };

                if resp_type == MessageType::Error as u32 {
                    let msg = parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| "unknown error".to_string());
                    let _ = tx.send(Err(CoreError::Machine(msg)));
                    break;
                }

                if resp_type != MessageType::SandboxEvent as u32 {
                    let _ = tx.send(Err(CoreError::Machine(format!(
                        "unexpected response type: 0x{:04x}",
                        resp_type
                    ))));
                    break;
                }

                match SandboxEvent::decode(&resp_payload[..]) {
                    Ok(event) => {
                        let _ = tx.send(Ok(event));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(CoreError::Machine(format!("decode error: {}", e))));
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Starts an interactive exec session inside a sandbox.
    ///
    /// Consumes the client because the stream task requires exclusive transport
    /// access.  The caller supplies a receiver of raw stdin bytes (empty `Vec`
    /// signals EOF).  Returns an output receiver of [`ExecOutput`] frames.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial send fails.
    pub async fn sandbox_exec(
        mut self,
        req: ExecRequest,
        mut stdin_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Result<mpsc::UnboundedReceiver<Result<ExecOutput>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        let buf = Self::build_message(MessageType::SandboxExecRequest, "", &payload);
        self.transport
            .async_send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send exec request: {}", e)))?;

        let (mut sender, mut receiver) = self
            .transport
            .into_split()
            .map_err(|e| CoreError::Machine(format!("failed to split transport: {e}")))?;

        let (out_tx, out_rx) = mpsc::unbounded_channel();

        // Stdin pump: channel → SandboxExecInput frames.
        let stdin_handle = tokio::spawn(async move {
            loop {
                match stdin_rx.recv().await {
                    Some(data) => {
                        let frame = Self::build_message(MessageType::SandboxExecInput, "", &data);
                        if sender.send(frame).await.is_err() {
                            break;
                        }
                        if data.is_empty() {
                            break;
                        }
                    }
                    None => {
                        // Channel closed without explicit EOF; send best-effort EOF frame
                        // so the guest-side exec session doesn't hang waiting on stdin.
                        let eof = Self::build_message(MessageType::SandboxExecInput, "", &[]);
                        let _ = sender.send(eof).await;
                        break;
                    }
                }
            }
        });

        // Output pump: SandboxExecOutput frames → channel.
        // When the loop exits (process done / error / receiver dropped), the
        // stdin pump is aborted so the transport write half is released promptly.
        tokio::spawn(async move {
            loop {
                let raw = match receiver.recv().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = out_tx.send(Err(CoreError::Machine(format!("recv error: {}", e))));
                        break;
                    }
                };

                let (resp_type, _, resp_payload) = match Self::parse_response(&raw) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = out_tx.send(Err(e));
                        break;
                    }
                };

                if resp_type == MessageType::Error as u32 {
                    let msg = parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| "unknown error".to_string());
                    let _ = out_tx.send(Err(CoreError::Machine(msg)));
                    break;
                }

                if resp_type != MessageType::SandboxExecOutput as u32 {
                    let _ = out_tx.send(Err(CoreError::Machine(format!(
                        "unexpected response type: 0x{:04x}",
                        resp_type
                    ))));
                    break;
                }

                match ExecOutput::decode(&resp_payload[..]) {
                    Ok(output) => {
                        let done = output.done;
                        if out_tx.send(Ok(output)).is_err() {
                            break;
                        }
                        if done {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ =
                            out_tx.send(Err(CoreError::Machine(format!("decode error: {}", e))));
                        break;
                    }
                }
            }
            stdin_handle.abort();
        });

        Ok(out_rx)
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
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::SandboxCheckpointRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxCheckpointResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        CheckpointResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Restores a sandbox from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn sandbox_restore(&mut self, req: RestoreRequest) -> Result<RestoreResponse> {
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::SandboxRestoreRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxRestoreResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        RestoreResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
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
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::SandboxListSnapshotsRequest, &payload)
            .await?;

        if resp_type != MessageType::SandboxListSnapshotsResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        ListSnapshotsResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
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

        if resp_type != MessageType::SandboxDeleteSnapshotResponse as u32
            && resp_type != MessageType::Empty as u32
        {
            return Err(CoreError::Machine(format!(
                "unexpected response type: 0x{:04x}",
                resp_type
            )));
        }

        Ok(())
    }
}

/// Parses an error response from the agent.
fn parse_error_response(payload: &[u8]) -> Result<String> {
    if payload.len() < ERROR_HEADER_SIZE {
        return Ok("unknown error".to_string());
    }

    let mut cursor = std::io::Cursor::new(payload);
    let _code = cursor.get_i32();
    let msg_len = cursor.get_u32() as usize;

    if payload.len() < ERROR_HEADER_SIZE + msg_len {
        return Ok("truncated error message".to_string());
    }

    String::from_utf8(payload[ERROR_HEADER_SIZE..ERROR_HEADER_SIZE + msg_len].to_vec())
        .map_err(|_| CoreError::Machine("invalid error message encoding".to_string()))
}

fn readiness_event_is_terminal(event: &ReadinessEvent) -> bool {
    use arcbox_protocol::agent::readiness_event::Kind;

    matches!(
        Kind::try_from(event.kind),
        Ok(Kind::RuntimeReady | Kind::RuntimeFailed)
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
}
