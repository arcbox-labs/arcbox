//! Agent main loop and request handling.
//!
//! The Agent listens on vsock port 1024 and handles RPC requests from the host.
//! It manages container lifecycle and executes commands in the guest VM.

use anyhow::Result;

/// Vsock port for agent communication.
pub const AGENT_PORT: u32 = 1024;

// =============================================================================
// EnsureRuntime State Machine (platform-independent, testable)
// =============================================================================

pub(crate) mod ensure_runtime {
    use std::sync::OnceLock;

    use arcbox_protocol::agent::RuntimeEnsureResponse;
    use tokio::sync::{Mutex, Notify};

    /// Outcome status constants for `RuntimeEnsureResponse.status`.
    pub const STATUS_STARTED: &str = "started";
    pub const STATUS_REUSED: &str = "reused";
    pub const STATUS_FAILED: &str = "failed";

    /// Runtime lifecycle state.
    #[derive(Debug, Clone)]
    pub enum RuntimeState {
        /// No ensure has been attempted yet.
        NotStarted,
        /// An ensure operation is in progress (first caller drives it).
        Starting,
        /// Runtime is confirmed ready.
        Ready { endpoint: String, message: String },
        /// Last ensure attempt failed; may retry on next start_if_needed=true.
        Failed { message: String },
    }

    /// Global singleton guard that serializes EnsureRuntime attempts and caches
    /// the outcome so that repeated / concurrent calls are idempotent.
    pub struct RuntimeGuard {
        pub state: Mutex<RuntimeState>,
        /// Notified when a Starting -> Ready/Failed transition completes so
        /// that concurrent waiters can proceed.
        pub notify: Notify,
    }

    impl RuntimeGuard {
        pub fn new() -> Self {
            Self {
                state: Mutex::new(RuntimeState::NotStarted),
                notify: Notify::new(),
            }
        }
    }

    /// Returns the global RuntimeGuard singleton.
    pub fn runtime_guard() -> &'static RuntimeGuard {
        static GUARD: OnceLock<RuntimeGuard> = OnceLock::new();
        GUARD.get_or_init(RuntimeGuard::new)
    }

    /// Platform-independent, idempotent EnsureRuntime handler.
    ///
    /// - First caller with `start_if_needed=true` transitions NotStarted -> Starting -> Ready/Failed.
    /// - Concurrent callers wait for the first caller to finish and share the result.
    /// - After Ready, subsequent calls return "reused" immediately.
    /// - After Failed, a new `start_if_needed=true` call retries.
    /// - `start_if_needed=false` only probes without attempting to start.
    ///
    /// `start_fn` is invoked only by the driver; it performs the actual start sequence.
    /// `probe_fn` is invoked for start_if_needed=false to report current status.
    pub async fn ensure_runtime<F, P>(
        guard: &RuntimeGuard,
        start_if_needed: bool,
        start_fn: F,
        probe_fn: P,
    ) -> RuntimeEnsureResponse
    where
        F: std::future::Future<Output = RuntimeEnsureResponse>,
        P: std::future::Future<Output = RuntimeEnsureResponse>,
    {
        // Fast path: if already Ready, return immediately.
        {
            let state = guard.state.lock().await;
            if let RuntimeState::Ready { endpoint, message } = &*state {
                return RuntimeEnsureResponse {
                    ready: true,
                    endpoint: endpoint.clone(),
                    message: message.clone(),
                    status: STATUS_REUSED.to_string(),
                };
            }
        }

        // Probe-only mode: do not attempt to start.
        if !start_if_needed {
            return probe_fn.await;
        }

        // Attempt to become the driver of the start sequence.
        let i_am_driver = {
            let mut state = guard.state.lock().await;
            match &*state {
                RuntimeState::Ready { endpoint, message } => {
                    // Another caller finished while we waited for the lock.
                    return RuntimeEnsureResponse {
                        ready: true,
                        endpoint: endpoint.clone(),
                        message: message.clone(),
                        status: STATUS_REUSED.to_string(),
                    };
                }
                RuntimeState::Starting => false,
                RuntimeState::NotStarted | RuntimeState::Failed { .. } => {
                    *state = RuntimeState::Starting;
                    true
                }
            }
        };

        if i_am_driver {
            // We are the driver: perform the actual start sequence.
            let response = start_fn.await;

            // Publish outcome to the state machine.
            let mut state = guard.state.lock().await;
            if response.ready {
                *state = RuntimeState::Ready {
                    endpoint: response.endpoint.clone(),
                    message: response.message.clone(),
                };
            } else {
                *state = RuntimeState::Failed {
                    message: response.message.clone(),
                };
            }
            // Wake all waiters.
            guard.notify.notify_waiters();

            return response;
        }

        // We are a waiter: wait for the driver to finish.
        loop {
            // Register for notification BEFORE checking state to prevent lost
            // wakeups.  If the driver calls notify_waiters() between our state
            // check and the await, the future is already enabled and will
            // resolve immediately.
            let notified = guard.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let state = guard.state.lock().await;
            match &*state {
                RuntimeState::Ready { endpoint, message } => {
                    return RuntimeEnsureResponse {
                        ready: true,
                        endpoint: endpoint.clone(),
                        message: message.clone(),
                        status: STATUS_REUSED.to_string(),
                    };
                }
                RuntimeState::Failed { message } => {
                    return RuntimeEnsureResponse {
                        ready: false,
                        endpoint: String::new(),
                        message: message.clone(),
                        status: STATUS_FAILED.to_string(),
                    };
                }
                RuntimeState::Starting => {
                    // Release lock before waiting.
                    drop(state);
                    notified.await;
                    continue;
                }
                RuntimeState::NotStarted => {
                    // Should not happen, but treat as failed.
                    return RuntimeEnsureResponse {
                        ready: false,
                        endpoint: String::new(),
                        message: "unexpected state: NotStarted after notify".to_string(),
                        status: STATUS_FAILED.to_string(),
                    };
                }
            }
        }
    }
}

// =============================================================================
// Linux Implementation
// =============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::os::unix::io::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use bytes::Bytes;
    use prost::Message;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::process::{Child, ChildStdin, Command};
    use tokio::sync::{Mutex, RwLock, mpsc};
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

    use super::AGENT_PORT;
    use super::ensure_runtime;
    use crate::container::{
        ContainerHandle, ContainerRuntime, ContainerState, MountSpec, setup_container_rootfs,
    };
    use crate::log_watcher::{LogWatchOptions, watch_log_file};
    use crate::pty::{ExecSession, PtyHandle};
    use crate::rpc::{
        AGENT_VERSION, ErrorResponse, MessageType, RpcRequest, RpcResponse, parse_request,
        read_message, write_response,
    };
    use crate::shim::{
        BroadcastWriter, LogEntry as ShimLogEntry, LogWriter, ProcessShim, StreamType,
    };

    use arcbox_protocol::Timestamp;
    use arcbox_protocol::agent::{
        AttachInput, AttachOutput, AttachRequest, ContainerInfo, CreateContainerResponse,
        ExecOutput, ExecStartResponse, ListContainersResponse, LogEntry, LogsRequest, PingResponse,
        RuntimeEnsureRequest, RuntimeEnsureResponse, RuntimeStatusRequest, RuntimeStatusResponse,
        SystemInfo,
    };
    use chrono::{DateTime, Utc};

    /// Default guest-side raw Docker API proxy port on vsock.
    const DOCKER_API_VSOCK_PORT_DEFAULT: u32 = 2375;
    /// Docker Unix socket path in guest.
    const DOCKER_API_UNIX_SOCKET: &str = "/var/run/docker.sock";
    /// Containerd socket candidates.
    const CONTAINERD_SOCKET_CANDIDATES: [&str; 2] = [
        "/run/containerd/containerd.sock",
        "/var/run/containerd/containerd.sock",
    ];

    fn cmdline_value(key: &str) -> Option<String> {
        let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
        for token in cmdline.split_whitespace() {
            if let Some(value) = token.strip_prefix(key) {
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    fn docker_api_vsock_port() -> u32 {
        if let Some(port) = std::env::var("ARCBOX_GUEST_DOCKER_VSOCK_PORT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|port| *port > 0)
        {
            return port;
        }

        if let Some(port) = cmdline_value("arcbox.guest_docker_vsock_port=")
            .and_then(|raw| raw.parse::<u32>().ok())
            .filter(|port| *port > 0)
        {
            return port;
        }

        DOCKER_API_VSOCK_PORT_DEFAULT
    }

    fn boot_asset_version() -> Option<String> {
        std::env::var("ARCBOX_BOOT_ASSET_VERSION")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| cmdline_value("arcbox.boot_asset_version="))
    }

    /// Agent state shared across connections.
    pub struct AgentState {
        /// Container runtime.
        pub runtime: Arc<Mutex<ContainerRuntime>>,
        /// Active exec processes by ID.
        pub exec_processes: HashMap<String, Arc<Mutex<ExecProcess>>>,
    }

    impl AgentState {
        pub fn new() -> Self {
            Self {
                runtime: Arc::new(Mutex::new(ContainerRuntime::new())),
                exec_processes: HashMap::new(),
            }
        }
    }

    impl Default for AgentState {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Result from handling a request - either a single response or a stream.
    enum RequestResult {
        /// Single response.
        Single(RpcResponse),
        /// Streaming response (for logs follow=true).
        Stream(mpsc::Receiver<LogEntry>, mpsc::Sender<()>),
        /// Interactive attach session (bidirectional).
        Attach(AttachSession),
    }

    /// Attach session wiring for bidirectional streaming.
    struct AttachSession {
        /// Output stream from container.
        output_rx: mpsc::Receiver<AttachOutput>,
        /// Target process handle for stdin/resize.
        process: AttachTarget,
        /// Whether stdin is allowed.
        attach_stdin: bool,
        /// Whether container is TTY.
        tty: bool,
        /// Optional initial resize (cols, rows).
        initial_size: Option<(u16, u16)>,
    }

    /// Attach target (container or exec process).
    enum AttachTarget {
        Container(Arc<Mutex<crate::container::ProcessHandle>>),
        Exec(Arc<Mutex<ExecProcess>>),
    }

    /// Exec process handle for streaming.
    struct ExecProcess {
        child: Option<Child>,
        pid: u32,
        stdin: Option<ChildStdin>,
        pty: Option<PtyHandle>,
        broadcaster: Arc<BroadcastWriter>,
        tty: bool,
    }

    struct ParsedLogLine {
        stream: String,
        log: String,
        timestamp: Option<DateTime<Utc>>,
        raw_time: Option<String>,
    }

    fn nanos_to_timestamp(nanos: i64) -> Timestamp {
        Timestamp {
            seconds: nanos / 1_000_000_000,
            nanos: (nanos % 1_000_000_000) as i32,
        }
    }

    /// The Guest Agent.
    ///
    /// Listens on vsock and handles RPC requests from the host.
    pub struct Agent {
        /// Shared agent state.
        state: Arc<RwLock<AgentState>>,
    }

    impl Agent {
        /// Creates a new agent.
        pub fn new() -> Self {
            Self {
                state: Arc::new(RwLock::new(AgentState::new())),
            }
        }

        /// Runs the agent, listening on vsock.
        pub async fn run(&self) -> Result<()> {
            // Mount standard VirtioFS shares if not already mounted
            crate::mount::mount_standard_shares();

            // Best-effort: ensure guest vsock modules are available before we
            // attempt to bind listeners. This is especially important when the
            // agent is started by distro init systems after switch_root.
            ensure_vsock_modules_loaded().await;

            // Start guest-side Docker API proxy (vsock -> unix socket).
            tokio::spawn(async {
                if let Err(e) = run_docker_api_proxy().await {
                    tracing::warn!("Docker API proxy exited: {}", e);
                }
            });

            let mut listener =
                bind_vsock_listener_with_retry(AGENT_PORT, "agent rpc listener").await?;

            tracing::info!("Agent listening on vsock port {}", AGENT_PORT);

            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        tracing::info!("Accepted connection from {:?}", peer_addr);
                        eprintln!("[AGENT] Accepted connection from {:?}", peer_addr);
                        let state = Arc::clone(&self.state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, state).await {
                                tracing::error!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    async fn ensure_vsock_modules_loaded() {
        for module in [
            "vsock",
            "vmw_vsock_virtio_transport_common",
            "vmw_vsock_virtio_transport",
        ] {
            match Command::new("modprobe").arg(module).status().await {
                Ok(status) if status.success() => {
                    tracing::debug!(module, "loaded kernel module");
                }
                Ok(status) => {
                    tracing::debug!(
                        module,
                        exit_code = status.code().unwrap_or(-1),
                        "modprobe exited non-zero"
                    );
                }
                Err(e) => {
                    tracing::debug!(module, error = %e, "modprobe unavailable/failed");
                }
            }
        }
    }

    async fn bind_vsock_listener_with_retry(port: u32, component: &str) -> Result<VsockListener> {
        const INITIAL_DELAY_MS: u64 = 120;
        const MAX_DELAY_MS: u64 = 2_000;

        let mut delay_ms = INITIAL_DELAY_MS;

        loop {
            let addr = VsockAddr::new(VMADDR_CID_ANY, port);
            match VsockListener::bind(addr) {
                Ok(listener) => {
                    tracing::info!(port, component, "vsock listener bound");
                    return Ok(listener);
                }
                Err(e) => {
                    tracing::warn!(
                        port,
                        component,
                        retry_delay_ms = delay_ms,
                        error = %e,
                        "failed to bind vsock listener, retrying"
                    );
                }
            }

            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 3 / 2).min(MAX_DELAY_MS);
        }
    }

    async fn run_docker_api_proxy() -> Result<()> {
        let port = docker_api_vsock_port();
        let mut listener = bind_vsock_listener_with_retry(port, "docker api proxy").await?;
        tracing::info!("Docker API proxy listening on vsock port {}", port);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    tracing::debug!("Docker API proxy accepted connection from {:?}", peer_addr);
                    tokio::spawn(async move {
                        if let Err(e) = proxy_docker_api_connection(stream).await {
                            tracing::debug!("Docker API proxy connection ended: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Docker API proxy accept failed: {}", e);
                }
            }
        }
    }

    async fn proxy_docker_api_connection(mut vsock_stream: VsockStream) -> Result<()> {
        let mut unix_stream = UnixStream::connect(DOCKER_API_UNIX_SOCKET)
            .await
            .context("failed to connect guest docker unix socket")?;

        let _ = tokio::io::copy_bidirectional(&mut vsock_stream, &mut unix_stream)
            .await
            .context("docker api proxy copy failed")?;
        Ok(())
    }

    impl Default for Agent {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Handles a single vsock connection.
    ///
    /// Reads RPC requests, processes them, and writes responses.
    /// Supports both single responses and streaming responses (for logs follow=true).
    async fn handle_connection<S>(mut stream: S, state: Arc<RwLock<AgentState>>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            // Read the next request (V2 wire format with trace_id).
            let (msg_type, trace_id, payload) = match read_message(&mut stream).await {
                Ok(msg) => msg,
                Err(e) => {
                    // Check if it's an EOF (clean disconnect)
                    if e.to_string().contains("failed to read message header") {
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

            // Parse and handle the request
            let result = match parse_request(msg_type, &payload) {
                Ok(request) => handle_request(request, &state).await,
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
                RequestResult::Stream(mut log_rx, cancel_tx) => {
                    // Stream multiple LogEntry responses.
                    // This follows Docker's pattern where log streaming continues until:
                    // 1. The container stops (watcher channel closes)
                    // 2. The client disconnects
                    // 3. An error occurs
                    tracing::debug!("Starting log stream");

                    // Keep streaming until the receiver is closed or client disconnects.
                    loop {
                        tokio::select! {
                            biased; // Prioritize log entries over timeout checks

                            // Check for new log entries.
                            entry = log_rx.recv() => {
                                match entry {
                                    Some(log_entry) => {
                                        let response = RpcResponse::LogEntry(log_entry);
                                        if let Err(e) = write_response(&mut stream, &response, &trace_id).await {
                                            tracing::debug!("Client disconnected during streaming: {}", e);
                                            // Signal cancellation to the watcher.
                                            let _ = cancel_tx.send(()).await;
                                            return Ok(());
                                        }
                                    }
                                    None => {
                                        // Watcher channel closed - container stopped or log file removed.
                                        tracing::debug!("Log stream ended (watcher channel closed)");
                                        // Send empty response to signal end of stream.
                                        if let Err(e) = write_response(&mut stream, &RpcResponse::Empty, &trace_id).await {
                                            tracing::debug!("Failed to send stream end marker: {}", e);
                                        }
                                        break;
                                    }
                                }
                            }

                            // Periodic timeout to check connection liveness.
                            // This also allows the select! to be responsive to cancellation.
                            _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                                // Continue streaming - this timeout just prevents blocking forever.
                                tracing::trace!("Log stream heartbeat");
                                continue;
                            }
                        }
                    }
                }
                RequestResult::Attach(mut session) => {
                    tracing::info!(
                        "Entered Attach processing loop, tty={}, stdin={}",
                        session.tty,
                        session.attach_stdin
                    );
                    // Apply initial resize if requested.
                    if let (true, Some((cols, rows))) = (session.tty, session.initial_size) {
                        match &session.process {
                            AttachTarget::Container(handle) => {
                                if let Some(pty_handle) = handle.lock().await.pty.as_ref() {
                                    if let Err(e) = pty_handle.resize(cols, rows) {
                                        tracing::warn!("Attach initial resize failed: {}", e);
                                    }
                                }
                            }
                            AttachTarget::Exec(handle) => {
                                if let Some(pty_handle) = handle.lock().await.pty.as_ref() {
                                    if let Err(e) = pty_handle.resize(cols, rows) {
                                        tracing::warn!("Attach initial resize failed: {}", e);
                                    }
                                }
                            }
                        }
                    }

                    loop {
                        tokio::select! {
                            maybe_out = session.output_rx.recv() => {
                                match maybe_out {
                                    Some(out) => {
                                        tracing::info!("Attach: received output, stream={}, len={}", out.stream, out.data.len());
                                        let response = RpcResponse::AttachOutput(out);
                                        if let Err(e) = write_response(&mut stream, &response, &trace_id).await {
                                            tracing::warn!("Client disconnected during attach output: {}", e);
                                            break;
                                        }
                                        tracing::info!("Attach: sent AttachOutput response");
                                    }
                                    None => {
                                        // Output stream ended; signal end of stream.
                                        tracing::info!("Attach: output stream ended, sending Empty response");
                                        if let Err(e) = write_response(&mut stream, &RpcResponse::Empty, &trace_id).await {
                                            tracing::warn!("Attach: failed to send Empty response: {}", e);
                                        }
                                        break;
                                    }
                                }
                            }
                            inbound = read_message(&mut stream) => {
                                match inbound {
                                    Ok((MessageType::AttachInput, _inbound_trace, payload)) => {
                                        match AttachInput::decode(&payload[..]) {
                                            Ok(input) => {
                                                if let Err(e) = handle_attach_input(&session, input).await {
                                                    tracing::warn!("Attach input handling failed: {}", e);
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("Invalid attach input: {}", e);
                                            }
                                        }
                                    }
                                    Ok((other_type, _, _)) => {
                                        tracing::warn!("Unexpected message in attach session: {:?}", other_type);
                                    }
                                    Err(e) => {
                                        tracing::debug!("Attach session read error/close: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handles a single RPC request.
    async fn handle_request(request: RpcRequest, state: &Arc<RwLock<AgentState>>) -> RequestResult {
        match request {
            RpcRequest::Ping(req) => RequestResult::Single(handle_ping(req)),
            RpcRequest::GetSystemInfo => RequestResult::Single(handle_get_system_info().await),
            RpcRequest::EnsureRuntime(req) => {
                RequestResult::Single(handle_ensure_runtime(req).await)
            }
            RpcRequest::RuntimeStatus(req) => {
                RequestResult::Single(handle_runtime_status(req).await)
            }
            RpcRequest::CreateContainer(req) => {
                RequestResult::Single(handle_create_container(req, state).await)
            }
            RpcRequest::StartContainer(req) => {
                RequestResult::Single(handle_start_container(&req.id, state).await)
            }
            RpcRequest::StopContainer(req) => {
                RequestResult::Single(handle_stop_container(&req.id, req.timeout, state).await)
            }
            RpcRequest::RemoveContainer(req) => {
                RequestResult::Single(handle_remove_container(&req.id, req.force, state).await)
            }
            RpcRequest::ListContainers(req) => {
                RequestResult::Single(handle_list_containers(req.all, state).await)
            }
            RpcRequest::KillContainer(req) => {
                RequestResult::Single(handle_kill_container(&req.id, &req.signal, state).await)
            }
            RpcRequest::WaitContainer(req) => {
                RequestResult::Single(handle_wait_container(&req.id, state).await)
            }
            RpcRequest::PauseContainer(req) => {
                RequestResult::Single(handle_pause_container(&req.id, state).await)
            }
            RpcRequest::UnpauseContainer(req) => {
                RequestResult::Single(handle_unpause_container(&req.id, state).await)
            }
            RpcRequest::ContainerStats(req) => {
                RequestResult::Single(handle_container_stats(&req.id, state).await)
            }
            RpcRequest::ContainerTop(req) => {
                RequestResult::Single(handle_container_top(&req.id, &req.ps_args, state).await)
            }
            RpcRequest::Exec(req) => RequestResult::Single(handle_exec(req, state).await),
            RpcRequest::Logs(req) => handle_logs(req, state).await,
            RpcRequest::ExecStart(req) => {
                RequestResult::Single(handle_exec_start(req, state).await)
            }
            RpcRequest::ExecResize(req) => {
                RequestResult::Single(handle_exec_resize(req, state).await)
            }
            RpcRequest::Attach(req) => handle_attach(req, state).await,
            RpcRequest::AttachInput(_) => {
                // AttachInput is only valid within an attach session.
                RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                    400,
                    "AttachInput outside attach session",
                )))
            }
        }
    }

    /// Handles a Ping request.
    fn handle_ping(req: arcbox_protocol::agent::PingRequest) -> RpcResponse {
        tracing::debug!("Ping request: {:?}", req.message);
        RpcResponse::Ping(PingResponse {
            message: if req.message.is_empty() {
                "pong".to_string()
            } else {
                format!("pong: {}", req.message)
            },
            version: AGENT_VERSION.to_string(),
        })
    }

    /// Handles a GetSystemInfo request.
    async fn handle_get_system_info() -> RpcResponse {
        let info = collect_system_info();
        RpcResponse::SystemInfo(info)
    }

    /// Idempotent, concurrency-safe EnsureRuntime handler.
    ///
    /// Delegates to the platform-independent `ensure_runtime` module, injecting
    /// the actual start and probe functions that depend on Linux system state.
    async fn handle_ensure_runtime(req: RuntimeEnsureRequest) -> RpcResponse {
        let guard = ensure_runtime::runtime_guard();

        let response = ensure_runtime::ensure_runtime(
            guard,
            req.start_if_needed,
            do_ensure_runtime_start(),
            do_ensure_runtime_probe(),
        )
        .await;

        RpcResponse::RuntimeEnsure(response)
    }

    /// Performs the actual runtime start sequence (called only by the driver).
    async fn do_ensure_runtime_start() -> RuntimeEnsureResponse {
        let mut notes = Vec::new();
        let note = try_start_runtime_services().await;
        if !note.is_empty() {
            notes.push(note);
        }

        // Poll until docker socket is ready (up to ~6 seconds).
        let mut status = collect_runtime_status().await;
        for _ in 0..20 {
            if status.docker_ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            status = collect_runtime_status().await;
        }

        let mut message = status.detail.clone();
        if !notes.is_empty() {
            message = format!("{}; {}", notes.join("; "), status.detail);
        }

        let result_status = if status.docker_ready {
            ensure_runtime::STATUS_STARTED.to_string()
        } else {
            ensure_runtime::STATUS_FAILED.to_string()
        };

        RuntimeEnsureResponse {
            ready: status.docker_ready,
            endpoint: status.endpoint,
            message,
            status: result_status,
        }
    }

    /// Probes runtime status without attempting to start (for start_if_needed=false).
    async fn do_ensure_runtime_probe() -> RuntimeEnsureResponse {
        let status = collect_runtime_status().await;
        RuntimeEnsureResponse {
            ready: status.docker_ready,
            endpoint: status.endpoint,
            message: status.detail,
            status: if status.docker_ready {
                ensure_runtime::STATUS_REUSED.to_string()
            } else {
                ensure_runtime::STATUS_FAILED.to_string()
            },
        }
    }

    async fn handle_runtime_status(_req: RuntimeStatusRequest) -> RpcResponse {
        RpcResponse::RuntimeStatus(collect_runtime_status().await)
    }

    /// Service status constants.
    const SERVICE_STATUS_READY: &str = "ready";
    const SERVICE_STATUS_NOT_READY: &str = "not_ready";
    const SERVICE_STATUS_ERROR: &str = "error";

    async fn collect_runtime_status() -> RuntimeStatusResponse {
        use arcbox_protocol::agent::ServiceStatus;

        let containerd_ready = probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await;
        let docker_ready = probe_unix_socket(DOCKER_API_UNIX_SOCKET).await;

        // Build per-service status entries.
        let mut services = Vec::new();

        // containerd status
        services.push(if containerd_ready {
            ServiceStatus {
                name: "containerd".to_string(),
                status: SERVICE_STATUS_READY.to_string(),
                detail: format!(
                    "socket reachable: {}",
                    CONTAINERD_SOCKET_CANDIDATES
                        .iter()
                        .find(|p| Path::new(p).exists())
                        .unwrap_or(&CONTAINERD_SOCKET_CANDIDATES[0])
                ),
            }
        } else {
            let socket_paths = CONTAINERD_SOCKET_CANDIDATES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            ServiceStatus {
                name: "containerd".to_string(),
                status: SERVICE_STATUS_NOT_READY.to_string(),
                detail: format!("no reachable socket found; checked: {}", socket_paths),
            }
        });

        // dockerd status
        let docker_detail = if docker_ready {
            format!("socket reachable: {}", DOCKER_API_UNIX_SOCKET)
        } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
            format!(
                "socket exists but not reachable: {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else {
            format!("socket missing: {}", DOCKER_API_UNIX_SOCKET)
        };

        services.push(ServiceStatus {
            name: "dockerd".to_string(),
            status: if docker_ready {
                SERVICE_STATUS_READY.to_string()
            } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
                SERVICE_STATUS_ERROR.to_string()
            } else {
                SERVICE_STATUS_NOT_READY.to_string()
            },
            detail: docker_detail,
        });

        // youki status (OCI runtime)
        let youki_status = match detect_runtime_bin_dir() {
            Some(bin_dir) => {
                let youki_bin = bin_dir.join("youki");
                if youki_bin.exists() {
                    ServiceStatus {
                        name: "youki".to_string(),
                        status: SERVICE_STATUS_READY.to_string(),
                        detail: format!("binary found: {}", youki_bin.display()),
                    }
                } else {
                    ServiceStatus {
                        name: "youki".to_string(),
                        status: SERVICE_STATUS_NOT_READY.to_string(),
                        detail: format!("binary missing at {}", youki_bin.display()),
                    }
                }
            }
            None => ServiceStatus {
                name: "youki".to_string(),
                status: SERVICE_STATUS_NOT_READY.to_string(),
                detail: runtime_missing_detail(),
            },
        };
        services.push(youki_status);

        // Build the summary detail string for backward compatibility.
        let detail = if docker_ready {
            "docker socket ready".to_string()
        } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
            format!(
                "docker socket exists but not reachable: {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else if !Path::new("/run/systemd/system").exists()
            && !Path::new("/sbin/rc-service").exists()
            && !Path::new("/usr/sbin/rc-service").exists()
        {
            format!(
                "docker socket missing: {}; {}",
                DOCKER_API_UNIX_SOCKET,
                runtime_missing_detail()
            )
        } else {
            format!("docker socket missing: {}", DOCKER_API_UNIX_SOCKET)
        };

        RuntimeStatusResponse {
            containerd_ready,
            docker_ready,
            endpoint: format!("vsock:{}", docker_api_vsock_port()),
            detail,
            services,
        }
    }

    async fn probe_first_ready_socket(paths: &[&str]) -> bool {
        for path in paths {
            if probe_unix_socket(path).await {
                return true;
            }
        }
        false
    }

    async fn probe_unix_socket(path: &str) -> bool {
        if !Path::new(path).exists() {
            return false;
        }
        match tokio::time::timeout(Duration::from_millis(300), UnixStream::connect(path)).await {
            Ok(Ok(_stream)) => true,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    fn runtime_start_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn runtime_bin_dir_candidates() -> Vec<PathBuf> {
        let mut candidates = Vec::new();

        if let Ok(path) = std::env::var("ARCBOX_RUNTIME_BIN_DIR") {
            if !path.trim().is_empty() {
                candidates.push(PathBuf::from(path));
            }
        }

        if let Some(version) = boot_asset_version() {
            candidates.push(PathBuf::from(format!(
                "/arcbox/boot/{}/runtime/bin",
                version
            )));
        }

        candidates.push(PathBuf::from("/arcbox/runtime/bin"));
        candidates.push(PathBuf::from("/arcbox/boot/current/runtime/bin"));
        candidates
    }

    fn detect_runtime_bin_dir() -> Option<PathBuf> {
        runtime_bin_dir_candidates()
            .into_iter()
            .find(|dir| dir.join("containerd").exists() && dir.join("dockerd").exists())
    }

    fn runtime_missing_detail() -> String {
        let candidates: Vec<String> = runtime_bin_dir_candidates()
            .into_iter()
            .map(|p| p.display().to_string())
            .collect();
        format!(
            "bundled runtime binaries not found; expected containerd+dockerd under one of: {}",
            candidates.join(", ")
        )
    }

    /// Ensures the guest environment has the prerequisites that dockerd/containerd
    /// need: cgroup2, overlayfs, devpts, /dev/shm, /tmp, /run.
    fn ensure_runtime_prerequisites() -> Vec<String> {
        let mut notes = Vec::new();

        // Alpine initramfs does not set PATH, so bare command names may not be
        // found. Use /bin/busybox <applet> which is always present in Alpine.
        let busybox = "/bin/busybox";

        // Mount cgroup2 unified hierarchy (required by dockerd).
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            if let Err(e) = std::fs::create_dir_all("/sys/fs/cgroup") {
                notes.push(format!("mkdir /sys/fs/cgroup failed({})", e));
            } else {
                let rc = std::process::Command::new(busybox)
                    .args(["mount", "-t", "cgroup2", "cgroup2", "/sys/fs/cgroup"])
                    .status();
                match rc {
                    Ok(s) if s.success() => notes.push("mounted cgroup2".to_string()),
                    Ok(s) => notes.push(format!("mount cgroup2 exit={}", s.code().unwrap_or(-1))),
                    Err(e) => notes.push(format!("mount cgroup2 failed({})", e)),
                }
            }
        }

        // Mount devpts if missing (needed for PTY allocation).
        if !Path::new("/dev/pts/ptmx").exists() {
            let _ = std::fs::create_dir_all("/dev/pts");
            let _ = std::process::Command::new(busybox)
                .args([
                    "mount",
                    "-t",
                    "devpts",
                    "-o",
                    "gid=5,mode=0620,noexec,nosuid",
                    "devpts",
                    "/dev/pts",
                ])
                .status();
        }

        // Mount /dev/shm if missing.
        if !Path::new("/dev/shm").exists() {
            let _ = std::fs::create_dir_all("/dev/shm");
            let _ = std::process::Command::new(busybox)
                .args(["mount", "-t", "tmpfs", "-o", "nodev,nosuid,noexec", "shm", "/dev/shm"])
                .status();
        }

        // Ensure /tmp and /run exist as writable tmpfs.
        for dir in ["/tmp", "/run"] {
            if !Path::new(dir).exists() || std::fs::metadata(dir).is_ok_and(|m| m.permissions().readonly()) {
                let _ = std::fs::create_dir_all(dir);
                let _ = std::process::Command::new(busybox)
                    .args(["mount", "-t", "tmpfs", "tmpfs", dir])
                    .status();
            }
        }

        // Enable IPv4 forwarding so Docker can route traffic between docker0 and eth0.
        // VZ framework NAT masquerades all VM traffic, so no guest-side masquerade rule needed.
        if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n") {
            notes.push(format!("ip_forward failed({})", e));
        } else {
            notes.push("enabled ip_forward".to_string());
        }

        // Load overlay module (needed for Docker's overlay2 storage driver).
        if !Path::new("/sys/module/overlay").exists() {
            let rc = std::process::Command::new("/sbin/modprobe")
                .arg("overlay")
                .status();
            match rc {
                Ok(s) if s.success() => notes.push("loaded overlay module".to_string()),
                _ => {
                    // Fallback: try insmod with kernel version path.
                    if let Ok(uname) = std::process::Command::new(busybox).arg("uname").arg("-r").output() {
                        let kver = String::from_utf8_lossy(&uname.stdout).trim().to_string();
                        let ko = format!("/lib/modules/{}/kernel/fs/overlayfs/overlay.ko", kver);
                        if Path::new(&ko).exists() {
                            let _ = std::process::Command::new(busybox).args(["insmod", &ko]).status();
                            notes.push(format!("insmod overlay from {}", ko));
                        } else {
                            notes.push("overlay module not found".to_string());
                        }
                    }
                }
            }
        }

        // Sync system clock via NTP before spawning containerd/dockerd.
        // The VM guest clock starts at epoch (1970-01-01) because VZ framework's
        // virtualised RTC is not automatically read by the Alpine kernel on boot.
        // Without a correct clock, TLS certificate verification fails with
        // "x509: certificate is not yet valid".
        // busybox ntpd -q performs a one-shot adjustment and exits.
        let ntp = std::process::Command::new(busybox)
            .args(["ntpd", "-q", "-n", "-p", "pool.ntp.org"])
            .status();
        match ntp {
            Ok(s) if s.success() => notes.push("ntp synced".to_string()),
            Ok(s) => notes.push(format!("ntp exit={}", s.code().unwrap_or(-1))),
            Err(e) => notes.push(format!("ntp failed({})", e)),
        }

        notes
    }

    /// Redirects daemon stdout/stderr to a log file so crashes are diagnosable.
    ///
    /// Prefers `/arcbox/` (VirtioFS mount, visible from host as `~/.arcbox/`)
    /// so that logs survive guest restarts and are accessible without exec.
    /// Falls back to `/var/log/` (guest tmpfs) if VirtioFS is not mounted.
    fn daemon_log_file(name: &str) -> Stdio {
        let arcbox_path = format!("/arcbox/{}.log", name);
        let var_log_path = format!("/var/log/{}.log", name);

        let log_path = if Path::new("/arcbox").exists() {
            &arcbox_path
        } else {
            &var_log_path
        };

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
            Ok(f) => f.into(),
            Err(_) => {
                // Fallback to /var/log/ if /arcbox/ write fails.
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&var_log_path)
                {
                    Ok(f) => f.into(),
                    Err(_) => Stdio::null(),
                }
            }
        }
    }

    async fn try_start_bundled_runtime() -> String {
        let _guard = runtime_start_lock().lock().await;

        if probe_unix_socket(DOCKER_API_UNIX_SOCKET).await {
            return "docker socket already ready".to_string();
        }

        let Some(runtime_bin_dir) = detect_runtime_bin_dir() else {
            return runtime_missing_detail();
        };

        tracing::info!(
            runtime_bin_dir = %runtime_bin_dir.display(),
            "starting bundled runtime"
        );

        let containerd_bin = runtime_bin_dir.join("containerd");
        let dockerd_bin = runtime_bin_dir.join("dockerd");
        let youki_bin = runtime_bin_dir.join("youki");
        let mut notes = Vec::new();

        // Ensure kernel/filesystem prerequisites before spawning daemons.
        let prereq_notes = ensure_runtime_prerequisites();
        if !prereq_notes.is_empty() {
            tracing::info!(prerequisites = %prereq_notes.join("; "), "runtime prerequisites");
        }
        notes.extend(prereq_notes);

        for dir in [
            "/run/containerd",
            "/var/run/docker",
            "/var/lib/containerd",
            "/var/lib/docker",
            "/etc/docker",
            "/var/log",
        ] {
            if let Err(e) = std::fs::create_dir_all(dir) {
                notes.push(format!("mkdir {} failed({})", dir, e));
            }
        }

        // Alpine initramfs does not export PATH. Always include standard search
        // paths so containerd/dockerd can invoke modprobe, mount, etc.
        let path_env = {
            let standard = "/usr/sbin:/usr/bin:/sbin:/bin";
            match std::env::var("PATH") {
                Ok(existing) if !existing.is_empty() => {
                    format!("{}:{}:{}", runtime_bin_dir.display(), existing, standard)
                }
                _ => format!("{}:{}", runtime_bin_dir.display(), standard),
            }
        };

        if !probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await {
            // Write a minimal containerd config that disables the CRI plugin.
            // CRI (Kubernetes Container Runtime Interface) is not needed for
            // Docker-based container usage. The containerd CLI does not support
            // a --disable-plugin flag (v1.7); the only way to disable plugins is
            // via the TOML config file.
            let containerd_config = "/etc/containerd/config.toml";
            if let Err(e) = std::fs::create_dir_all("/etc/containerd") {
                notes.push(format!("mkdir /etc/containerd failed({})", e));
            }
            let config_toml = "version = 2\ndisabled_plugins = [\"io.containerd.grpc.v1.cri\"]\n";
            if let Err(e) = std::fs::write(containerd_config, config_toml) {
                notes.push(format!("write containerd config failed({})", e));
            }

            let mut cmd = Command::new(&containerd_bin);
            cmd.args([
                "--config",
                containerd_config,
                "--address",
                "/run/containerd/containerd.sock",
                "--root",
                "/var/lib/containerd",
                "--state",
                "/run/containerd",
            ])
            .env("PATH", &path_env)
            .stdin(Stdio::null())
            .stdout(daemon_log_file("containerd"))
            .stderr(daemon_log_file("containerd"));

            match cmd.spawn() {
                Ok(child) => {
                    let pid = child.id().unwrap_or_default();
                    tracing::info!(pid, "spawned bundled containerd");
                    notes.push(format!("spawned bundled containerd (pid={})", pid));
                }
                Err(e) => return format!("failed to spawn bundled containerd: {}", e),
            }
        }

        // Poll for containerd socket readiness before spawning dockerd.
        // containerd may take several seconds to initialise its gRPC socket,
        // especially on first boot when it has to set up its state directories.
        // We wait up to 8 s in 200 ms increments; failing to detect it is not
        // fatal — dockerd will retry on its own, but logging it helps debugging.
        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            let mut containerd_ok = false;
            while tokio::time::Instant::now() < deadline {
                if probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await {
                    containerd_ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let elapsed_ms = (tokio::time::Instant::now()
                .duration_since(deadline - Duration::from_secs(8)))
            .as_millis();
            tracing::info!(
                containerd_ready = containerd_ok,
                elapsed_ms,
                "containerd socket poll complete"
            );
            if !containerd_ok {
                notes.push("containerd socket not ready after 8s".to_string());
            }
        }

        if !probe_unix_socket(DOCKER_API_UNIX_SOCKET).await {
            let mut cmd = Command::new(&dockerd_bin);
            cmd.arg("--host=unix:///var/run/docker.sock")
                .arg("--containerd=/run/containerd/containerd.sock")
                .arg("--exec-root=/var/run/docker")
                .arg("--data-root=/var/lib/docker")
                .env("PATH", &path_env)
                .stdin(Stdio::null())
                .stdout(daemon_log_file("dockerd"))
                .stderr(daemon_log_file("dockerd"));

            // Register youki as the default OCI runtime.
            // 'runc' is a reserved name in dockerd and cannot be registered via
            // --add-runtime; it is already the built-in default. We only need to
            // register youki and set it as the default. If youki fails, the user can
            // fall back via `docker run --runtime=runc`.
            if youki_bin.exists() {
                cmd.arg("--add-runtime")
                    .arg(format!("youki={}", youki_bin.display()))
                    .arg("--default-runtime=youki");
                notes.push("OCI runtime: youki (default), runc (built-in fallback)".to_string());
            } else {
                notes.push("youki missing, dockerd will use built-in runc".to_string());
            }

            match cmd.spawn() {
                Ok(child) => {
                    let pid = child.id().unwrap_or_default();
                    tracing::info!(pid, "spawned bundled dockerd");
                    notes.push(format!("spawned bundled dockerd (pid={})", pid));
                }
                Err(e) => return format!("failed to spawn bundled dockerd: {}", e),
            }
        }

        notes.join("; ")
    }

    async fn try_start_runtime_services() -> String {
        let mut notes = Vec::new();
        let mut all_service_starts_succeeded = false;

        if Path::new("/run/systemd/system").exists() {
            all_service_starts_succeeded = true;
            for service in ["containerd.service", "docker.service"] {
                match Command::new("systemctl")
                    .args(["start", service])
                    .status()
                    .await
                {
                    Ok(status) if status.success() => {
                        notes.push(format!("started {}", service));
                    }
                    Ok(status) => {
                        all_service_starts_succeeded = false;
                        notes.push(format!(
                            "systemctl start {} failed(exit={})",
                            service,
                            status.code().unwrap_or(-1)
                        ));
                    }
                    Err(e) => {
                        all_service_starts_succeeded = false;
                        notes.push(format!("systemctl start {} error({})", service, e));
                    }
                }
            }
        } else if Path::new("/sbin/rc-service").exists()
            || Path::new("/usr/sbin/rc-service").exists()
            || Path::new("/bin/rc-service").exists()
        {
            all_service_starts_succeeded = true;
            for service in ["containerd", "docker"] {
                let status = Command::new("rc-service")
                    .args([service, "start"])
                    .status()
                    .await;
                match status {
                    Ok(status) if status.success() => {
                        notes.push(format!("started {}", service));
                    }
                    Ok(status) => {
                        all_service_starts_succeeded = false;
                        notes.push(format!(
                            "rc-service {} start failed(exit={})",
                            service,
                            status.code().unwrap_or(-1)
                        ));
                    }
                    Err(e) => {
                        all_service_starts_succeeded = false;
                        notes.push(format!("rc-service {} start error({})", service, e));
                    }
                }
            }
        } else {
            notes.push("no init service manager found, using bundled runtime".to_string());
        }

        if !all_service_starts_succeeded {
            let note = try_start_bundled_runtime().await;
            if !note.is_empty() {
                notes.push(note);
            }
        }

        notes.join("; ")
    }

    /// Collects system information from the guest.
    fn collect_system_info() -> SystemInfo {
        fn parse_ip_output(stdout: &[u8]) -> Vec<String> {
            let mut ips = Vec::new();
            let output = String::from_utf8_lossy(stdout);

            for token in output.split(|c: char| c.is_whitespace() || c == ',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }

                let Ok(addr) = token.parse::<IpAddr>() else {
                    continue;
                };
                if addr.is_loopback() {
                    continue;
                }

                let ip = addr.to_string();
                if !ips.iter().any(|existing| existing == &ip) {
                    ips.push(ip);
                }
            }

            ips
        }

        let mut info = SystemInfo::default();

        // Kernel version
        if let Ok(uname) = nix::sys::utsname::uname() {
            info.kernel_version = uname.release().to_string_lossy().to_string();
            info.os_name = uname.sysname().to_string_lossy().to_string();
            info.os_version = uname.version().to_string_lossy().to_string();
            info.arch = uname.machine().to_string_lossy().to_string();
            info.hostname = uname.nodename().to_string_lossy().to_string();
        }

        // Memory info
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        if let Ok(kb_val) = kb.parse::<u64>() {
                            info.total_memory = kb_val * 1024;
                        }
                    }
                } else if line.starts_with("MemAvailable:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        if let Ok(kb_val) = kb.parse::<u64>() {
                            info.available_memory = kb_val * 1024;
                        }
                    }
                }
            }
        }

        // CPU count
        info.cpu_count = std::thread::available_parallelism()
            .map(|p| p.get() as u32)
            .unwrap_or(1);

        // Load average
        if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = loadavg.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(load1) = parts[0].parse::<f64>() {
                    info.load_average.push(load1);
                }
                if let Ok(load5) = parts[1].parse::<f64>() {
                    info.load_average.push(load5);
                }
                if let Ok(load15) = parts[2].parse::<f64>() {
                    info.load_average.push(load15);
                }
            }
        }

        // Uptime
        if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
            if let Some(secs) = uptime.split_whitespace().next() {
                if let Ok(secs_val) = secs.parse::<f64>() {
                    info.uptime = secs_val as u64;
                }
            }
        }

        // IP addresses (excluding loopback).
        // Coreutils `hostname` supports `-I`, BusyBox supports `-i`.
        for flag in ["-I", "-i"] {
            let Ok(output) = std::process::Command::new("hostname").arg(flag).output() else {
                continue;
            };

            if !output.status.success() {
                continue;
            }

            let ips = parse_ip_output(&output.stdout);
            if !ips.is_empty() {
                info.ip_addresses = ips;
                break;
            }
        }

        info
    }

    /// Handles a CreateContainer request.
    async fn handle_create_container(
        req: arcbox_protocol::agent::CreateContainerRequest,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::info!("CreateContainer: name={}, image={}", req.name, req.image);

        let container_id = if req.id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            req.id.clone()
        };

        // Convert environment variables
        let env: Vec<(String, String)> = req.env.into_iter().collect();

        // Convert mounts from protocol type to internal type
        let mounts: Vec<MountSpec> = req
            .mounts
            .into_iter()
            .map(|m| MountSpec {
                source: m.source,
                target: m.target,
                readonly: m.readonly,
            })
            .collect();

        // Build the command
        let cmd = if !req.entrypoint.is_empty() {
            let mut full_cmd = req.entrypoint;
            full_cmd.extend(req.cmd);
            full_cmd
        } else if !req.cmd.is_empty() {
            req.cmd
        } else {
            vec!["/bin/sh".to_string()]
        };

        // Create container handle
        let handle = ContainerHandle {
            id: container_id.clone(),
            name: req.name,
            image: req.image,
            command: cmd,
            env,
            working_dir: if req.working_dir.is_empty() {
                "/".to_string()
            } else {
                req.working_dir
            },
            state: ContainerState::Created,
            pid: None,
            exit_code: None,
            created_at: chrono::Utc::now(),
            tty: req.tty,
            open_stdin: req.open_stdin,
            mounts,
            rootfs: if req.rootfs.is_empty() {
                None
            } else {
                Some(req.rootfs)
            },
        };

        // Store in runtime
        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let mut runtime = runtime.lock().await;
        runtime.add_container(handle);

        RpcResponse::CreateContainer(CreateContainerResponse { id: container_id })
    }

    /// Handles a StartContainer request.
    async fn handle_start_container(id: &str, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::info!("StartContainer: id={}", id);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let start_result = {
            let mut runtime = runtime.lock().await;
            runtime.start_container(id).await
        };
        match start_result {
            Ok(()) => {
                let runtime = Arc::clone(&runtime);
                let id = id.to_string();
                tokio::spawn(async move {
                    let process_handle = {
                        let runtime = runtime.lock().await;
                        runtime.get_process_handle(&id).await
                    };

                    let Some(process_handle) = process_handle else {
                        tracing::warn!("Reaper: process handle missing for {}", id);
                        return;
                    };

                    let child = {
                        let mut handle = process_handle.lock().await;
                        handle.child.take()
                    };

                    let Some(mut child) = child else {
                        tracing::debug!("Reaper: child already taken for {}", id);
                        return;
                    };

                    let exit_code = match child.wait().await {
                        Ok(status) => status.code().unwrap_or(-1),
                        Err(e) => {
                            tracing::warn!("Reaper: wait failed for {}: {}", id, e);
                            -1
                        }
                    };

                    {
                        let mut runtime = runtime.lock().await;
                        runtime.mark_container_stopped(&id, exit_code);
                    }

                    {
                        let mut handle = process_handle.lock().await;
                        handle.stdin.take();
                        handle.pty.take();
                    }

                    // Keep the process handle for late attach/log replay. It is removed on
                    // container removal.
                });

                RpcResponse::Empty
            }
            Err(e) => {
                tracing::error!("Failed to start container {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to start: {}", e)))
            }
        }
    }

    /// Handles a StopContainer request.
    async fn handle_stop_container(
        id: &str,
        timeout: u32,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::info!("StopContainer: id={}, timeout={}s", id, timeout);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let mut runtime = runtime.lock().await;
        match runtime.stop_container(id, timeout).await {
            Ok(()) => RpcResponse::Empty,
            Err(e) => {
                tracing::error!("Failed to stop container {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to stop: {}", e)))
            }
        }
    }

    /// Handles a RemoveContainer request.
    async fn handle_remove_container(
        id: &str,
        force: bool,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::info!("RemoveContainer: id={}, force={}", id, force);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let mut runtime = runtime.lock().await;
        match runtime.remove_container(id, force).await {
            Ok(()) => RpcResponse::Empty,
            Err(e) => {
                tracing::error!("Failed to remove container {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to remove: {}", e)))
            }
        }
    }

    /// Handles a KillContainer request.
    async fn handle_kill_container(
        id: &str,
        signal: &str,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::info!("KillContainer: id={}, signal={}", id, signal);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let mut runtime = runtime.lock().await;
        match runtime.signal_container(id, signal).await {
            Ok(()) => RpcResponse::Empty,
            Err(e) => {
                tracing::error!("Failed to kill container {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to kill: {}", e)))
            }
        }
    }

    /// Handles a WaitContainer request.
    ///
    /// Blocks until the container exits and returns its exit code.
    async fn handle_wait_container(id: &str, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::info!("WaitContainer: id={}", id);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        loop {
            let (container_state, exit_code) = {
                let runtime = runtime.lock().await;
                match runtime.get_container_state(id) {
                    Some(state) => state,
                    None => {
                        return RpcResponse::Error(ErrorResponse::new(404, "container not found"));
                    }
                }
            };

            if container_state == ContainerState::Stopped {
                let exit_code = exit_code.unwrap_or(-1);
                tracing::info!("Container {} exited with code {}", id, exit_code);
                return RpcResponse::WaitContainer(
                    arcbox_protocol::container::WaitContainerResponse {
                        status_code: i64::from(exit_code),
                        error: String::new(),
                    },
                );
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Handles a PauseContainer request.
    ///
    /// Pauses all processes in a container by sending SIGSTOP.
    async fn handle_pause_container(id: &str, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::info!("PauseContainer: id={}", id);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let mut runtime = runtime.lock().await;
        match runtime.pause_container(id).await {
            Ok(()) => RpcResponse::Empty,
            Err(e) => {
                tracing::error!("Failed to pause container {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to pause: {}", e)))
            }
        }
    }

    /// Handles an UnpauseContainer request.
    ///
    /// Resumes all processes in a paused container by sending SIGCONT.
    async fn handle_unpause_container(id: &str, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::info!("UnpauseContainer: id={}", id);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let mut runtime = runtime.lock().await;
        match runtime.unpause_container(id).await {
            Ok(()) => RpcResponse::Empty,
            Err(e) => {
                tracing::error!("Failed to unpause container {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to unpause: {}", e)))
            }
        }
    }

    /// Handles a ContainerStats request.
    ///
    /// Returns CPU, memory, and I/O statistics for a running container.
    async fn handle_container_stats(id: &str, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::debug!("ContainerStats: id={}", id);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let runtime = runtime.lock().await;
        match runtime.container_stats(id).await {
            Ok(stats) => RpcResponse::ContainerStats(stats),
            Err(e) => {
                tracing::error!("Failed to get container stats {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(
                    500,
                    format!("failed to get stats: {}", e),
                ))
            }
        }
    }

    /// Handles a ContainerTop request.
    ///
    /// Returns process list for a running container.
    async fn handle_container_top(
        id: &str,
        ps_args: &str,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::debug!("ContainerTop: id={}, ps_args={}", id, ps_args);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let runtime = runtime.lock().await;
        match runtime.container_top(id, ps_args).await {
            Ok(top) => RpcResponse::ContainerTop(top),
            Err(e) => {
                tracing::error!("Failed to get container top {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to get top: {}", e)))
            }
        }
    }

    /// Handles a ListContainers request.
    async fn handle_list_containers(all: bool, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::debug!("ListContainers: all={}", all);

        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let runtime = runtime.lock().await;
        let containers: Vec<ContainerInfo> = runtime
            .list_containers(all)
            .iter()
            .map(|h| ContainerInfo {
                id: h.id.clone(),
                name: h.name.clone(),
                image: h.image.clone(),
                state: h.state.as_str().to_string(),
                status: format_status(h),
                created: h.created_at.timestamp(),
            })
            .collect();

        RpcResponse::ListContainers(ListContainersResponse { containers })
    }

    /// Formats a human-readable status string for a container.
    fn format_status(handle: &ContainerHandle) -> String {
        match handle.state {
            ContainerState::Created => "Created".to_string(),
            ContainerState::Running => {
                if let Some(pid) = handle.pid {
                    format!("Running (PID: {})", pid)
                } else {
                    "Running".to_string()
                }
            }
            ContainerState::Paused => {
                if let Some(pid) = handle.pid {
                    format!("Paused (PID: {})", pid)
                } else {
                    "Paused".to_string()
                }
            }
            ContainerState::Stopped => {
                if let Some(code) = handle.exit_code {
                    format!("Exited ({})", code)
                } else {
                    "Stopped".to_string()
                }
            }
        }
    }

    /// Handles an Exec request.
    async fn handle_exec(
        req: arcbox_protocol::agent::ExecRequest,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::info!("Exec: container_id={}, cmd={:?}", req.container_id, req.cmd);

        if req.cmd.is_empty() {
            return RpcResponse::Error(ErrorResponse::new(400, "empty command"));
        }

        // If container_id is empty, execute on the host (guest VM level)
        if req.container_id.is_empty() {
            return execute_on_host(req).await;
        }

        // Otherwise, execute in the specified container.
        let (container_rootfs, container_mounts, container_workdir, container_state) = {
            let runtime = {
                let state = state.read().await;
                Arc::clone(&state.runtime)
            };
            let runtime = runtime.lock().await;
            match runtime.get_container(&req.container_id) {
                Some(container) => (
                    container.rootfs.clone(),
                    container.mounts.clone(),
                    container.working_dir.clone(),
                    container.state,
                ),
                None => {
                    return RpcResponse::Error(ErrorResponse::new(
                        404,
                        format!("container not found: {}", req.container_id),
                    ));
                }
            }
        };

        if container_state != ContainerState::Running {
            return RpcResponse::Error(ErrorResponse::new(
                400,
                format!("container is not running: {}", req.container_id),
            ));
        }

        execute_in_container(req, container_rootfs, container_mounts, container_workdir).await
    }

    /// Executes a command on the host (guest VM level).
    async fn execute_on_host(req: arcbox_protocol::agent::ExecRequest) -> RpcResponse {
        let env: HashMap<String, String> = req.env.into_iter().collect();
        let env_vec: Vec<(String, String)> = env.into_iter().collect();

        let working_dir = if req.working_dir.is_empty() {
            None
        } else {
            Some(req.working_dir.as_str())
        };

        match crate::exec::exec(&req.cmd, working_dir, &env_vec, None).await {
            Ok(result) => {
                // Combine stdout and stderr for the response
                let mut output = ExecOutput::default();
                output.stream = "stdout".to_string();
                output.data = result.stdout;
                output.exit_code = result.exit_code;
                output.done = true;
                RpcResponse::ExecOutput(output)
            }
            Err(e) => RpcResponse::Error(ErrorResponse::new(500, format!("exec failed: {}", e))),
        }
    }

    /// Executes a command inside a container rootfs.
    async fn execute_in_container(
        req: arcbox_protocol::agent::ExecRequest,
        container_rootfs: Option<String>,
        container_mounts: Vec<MountSpec>,
        container_workdir: String,
    ) -> RpcResponse {
        let workdir = if req.working_dir.is_empty() {
            container_workdir
        } else {
            req.working_dir.clone()
        };

        let mut cmd = Command::new(&req.cmd[0]);
        cmd.args(&req.cmd[1..]);
        cmd.current_dir(&workdir);
        for (k, v) in &req.env {
            cmd.env(k, v);
        }

        if let Some(rootfs_path) = container_rootfs {
            let mounts_for_exec = container_mounts;
            let workdir_for_exec = workdir.clone();
            // SAFETY: pre_exec runs after fork, before exec.
            unsafe {
                cmd.pre_exec(move || {
                    setup_container_rootfs(&rootfs_path, &workdir_for_exec, &mounts_for_exec)
                });
            }
        }

        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        match cmd.output().await {
            Ok(output) => {
                let mut response = ExecOutput::default();
                response.stream = "stdout".to_string();
                response.data = output.stdout;
                response.exit_code = output.status.code().unwrap_or(-1);
                response.done = true;
                RpcResponse::ExecOutput(response)
            }
            Err(e) => RpcResponse::Error(ErrorResponse::new(500, format!("exec failed: {}", e))),
        }
    }

    /// Handles an ExecStart request (with PTY support).
    async fn handle_exec_start(
        req: arcbox_protocol::agent::ExecStartRequest,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::info!(
            "ExecStart: exec_id={}, container_id={}, cmd={:?}, tty={}, detach={}",
            req.exec_id,
            req.container_id,
            req.cmd,
            req.tty,
            req.detach
        );

        if req.cmd.is_empty() {
            return RpcResponse::Error(ErrorResponse::new(400, "empty command"));
        }

        // Get container's state/rootfs/mounts/workdir for namespace setup.
        let (container_state, container_rootfs, container_mounts, container_workdir) = {
            let runtime = {
                let state = state.read().await;
                Arc::clone(&state.runtime)
            };
            let runtime = runtime.lock().await;
            match runtime.get_container(&req.container_id) {
                Some(container) => (
                    container.state,
                    container.rootfs.clone(),
                    container.mounts.clone(),
                    container.working_dir.clone(),
                ),
                None => {
                    return RpcResponse::Error(ErrorResponse::new(
                        404,
                        format!("container not found: {}", req.container_id),
                    ));
                }
            }
        };

        if container_state != ContainerState::Running {
            return RpcResponse::Error(ErrorResponse::new(
                400,
                format!("container is not running: {}", req.container_id),
            ));
        }

        // Determine terminal size (use defaults if not specified).
        let cols = if req.tty_width > 0 {
            req.tty_width as u16
        } else {
            80
        };
        let rows = if req.tty_height > 0 {
            req.tty_height as u16
        } else {
            24
        };

        // Build command.
        let mut cmd = Command::new(&req.cmd[0]);
        cmd.args(&req.cmd[1..]);
        if !req.working_dir.is_empty() {
            cmd.current_dir(&req.working_dir);
        }
        for (k, v) in &req.env {
            cmd.env(k, v);
        }

        let mut pty_handle = None;

        if req.tty {
            let pty = match PtyHandle::new(cols, rows) {
                Ok(p) => p,
                Err(e) => {
                    return RpcResponse::Error(ErrorResponse::new(
                        500,
                        format!("failed to create PTY: {}", e),
                    ));
                }
            };
            let slave_fd = pty.slave_fd();
            let rootfs_for_exec = container_rootfs.clone();
            let mounts_for_exec = container_mounts.clone();
            let workdir_for_exec = if req.working_dir.is_empty() {
                container_workdir.clone()
            } else {
                req.working_dir.clone()
            };
            // SAFETY: pre_exec runs after fork, before exec
            unsafe {
                cmd.pre_exec(move || {
                    // Setup rootfs isolation if container has a rootfs.
                    if let Some(ref rootfs_path) = rootfs_for_exec {
                        setup_container_rootfs(rootfs_path, &workdir_for_exec, &mounts_for_exec)?;
                    }

                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    #[cfg(target_os = "linux")]
                    let ioctl_result = libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
                    #[cfg(target_os = "macos")]
                    let ioctl_result = libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0);
                    if ioctl_result < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(slave_fd, libc::STDERR_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if slave_fd > libc::STDERR_FILENO {
                        libc::close(slave_fd);
                    }
                    Ok(())
                });
            }
            cmd.env("TERM", "xterm-256color");
            pty_handle = Some(pty);
        } else {
            // Non-TTY: setup rootfs isolation if container has a rootfs.
            if let Some(ref rootfs_path) = container_rootfs {
                let rootfs_for_exec = rootfs_path.clone();
                let mounts_for_exec = container_mounts.clone();
                let workdir_for_exec = if req.working_dir.is_empty() {
                    container_workdir.clone()
                } else {
                    req.working_dir.clone()
                };
                // SAFETY: pre_exec runs after fork, before exec
                unsafe {
                    cmd.pre_exec(move || {
                        setup_container_rootfs(
                            &rootfs_for_exec,
                            &workdir_for_exec,
                            &mounts_for_exec,
                        )
                    });
                }
            }
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return RpcResponse::Error(ErrorResponse::new(
                    500,
                    format!("failed to spawn exec process: {}", e),
                ));
            }
        };

        let pid = child.id().unwrap_or_default();
        let stdin_handle = child.stdin.take();

        // Close slave in parent to allow EOF/exit detection; master is kept for attach/resize.
        if let Some(ref mut pty) = pty_handle {
            let _ = pty.pty_mut().close_slave();
        }

        let broadcaster = if let Some(ref pty) = pty_handle {
            match ProcessShim::with_pty(req.exec_id.clone(), pty.master_fd()) {
                Ok(shim) => {
                    let broadcast = shim.broadcaster();
                    tokio::spawn(async move {
                        if let Err(e) = shim.run().await {
                            tracing::error!("Exec shim error (pty): {}", e);
                        }
                    });
                    broadcast
                }
                Err(e) => {
                    tracing::warn!("Exec shim create failed (pty): {}", e);
                    Arc::new(BroadcastWriter::new())
                }
            }
        } else {
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            if let (Some(stdout), Some(stderr)) = (stdout, stderr) {
                match ProcessShim::with_child_pipes(req.exec_id.clone(), stdout, stderr) {
                    Ok(shim) => {
                        let broadcast = shim.broadcaster();
                        tokio::spawn(async move {
                            if let Err(e) = shim.run().await {
                                tracing::error!("Exec shim error (pipes): {}", e);
                            }
                        });
                        broadcast
                    }
                    Err(e) => {
                        tracing::warn!("Exec shim create failed (pipes): {}", e);
                        Arc::new(BroadcastWriter::new())
                    }
                }
            } else {
                Arc::new(BroadcastWriter::new())
            }
        };

        {
            let mut guard = state.write().await;
            guard.exec_processes.insert(
                req.exec_id.clone(),
                Arc::new(Mutex::new(ExecProcess {
                    child: Some(child),
                    pid,
                    stdin: stdin_handle,
                    pty: pty_handle,
                    broadcaster,
                    tty: req.tty,
                })),
            );
        }

        // Cleanup task: wait for process exit, then delay removal so late attaches can still replay backlog.
        {
            let state = Arc::clone(state);
            let exec_id = req.exec_id.clone();
            let proc = {
                let state_guard = state.read().await;
                state_guard.exec_processes.get(&exec_id).cloned()
            };

            if let Some(proc) = proc {
                tokio::spawn(async move {
                    // Wait for child to exit.
                    // Take ownership of child to wait without blocking the mutex.
                    let child = {
                        let mut guard = proc.lock().await;
                        guard.child.take()
                    };

                    if let Some(mut child) = child {
                        if let Err(e) = child.wait().await {
                            tracing::warn!("Exec {} wait failed: {}", exec_id, e);
                        }
                    }

                    // Drop stdin/PTY handles but keep broadcaster for a short grace period.
                    {
                        let mut guard = proc.lock().await;
                        guard.stdin.take();
                        guard.pty.take();
                    }

                    // Keep session alive briefly to allow late attach to replay backlog.
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                    let mut guard = state.write().await;
                    guard.exec_processes.remove(&exec_id);
                });
            }
        }

        RpcResponse::ExecStart(ExecStartResponse { pid })
    }

    /// Executes a command with PTY support.
    ///
    /// Returns (pid, exit_code, stdout, stderr).
    async fn execute_with_pty(
        req: &arcbox_protocol::agent::ExecStartRequest,
        mut session: ExecSession,
    ) -> Result<(u32, Option<i32>, Vec<u8>, Vec<u8>)> {
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, fork};
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        let env: HashMap<String, String> = req.env.clone().into_iter().collect();
        let env_vec: Vec<(String, String)> = env.into_iter().collect();

        // Prepare command and args as CStrings.
        let cmd = match CString::new(req.cmd[0].as_str()) {
            Ok(c) => c,
            Err(e) => anyhow::bail!("invalid command: {}", e),
        };

        let args: Vec<CString> = req
            .cmd
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();

        let env_strings: Vec<CString> = env_vec
            .iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap_or_default())
            .collect();

        // Fork and exec.
        // SAFETY: fork() is unsafe but we handle both parent and child paths.
        let fork_result = unsafe { fork() };

        match fork_result {
            Ok(ForkResult::Parent { child }) => {
                // Parent process.
                let pid = child.as_raw() as u32;
                session.pid = Some(pid);
                session.running = true;

                // Close slave side in parent.
                if let Some(ref mut pty) = session.pty {
                    let _ = pty.pty_mut().close_slave();
                }

                if req.detach {
                    // In detach mode, return immediately without waiting.
                    return Ok((pid, None, Vec::new(), Vec::new()));
                }

                // Wait for child and collect output.
                let mut stdout = Vec::new();

                // Read from PTY master if we have one.
                if let Some(ref pty) = session.pty {
                    let mut buf = [0u8; 4096];
                    loop {
                        match pty.pty().read_output(&mut buf) {
                            Ok(0) => {
                                // Non-blocking read, no data available.
                                // Check if child has exited.
                                match waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                                    Ok(WaitStatus::Exited(_, code)) => {
                                        session.running = false;
                                        session.exit_code = Some(code);
                                        return Ok((pid, Some(code), stdout, Vec::new()));
                                    }
                                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                                        session.running = false;
                                        let code = 128 + sig as i32;
                                        session.exit_code = Some(code);
                                        return Ok((pid, Some(code), stdout, Vec::new()));
                                    }
                                    Ok(WaitStatus::StillAlive) => {
                                        // Still running, sleep briefly and continue.
                                        tokio::time::sleep(tokio::time::Duration::from_millis(10))
                                            .await;
                                        continue;
                                    }
                                    _ => {
                                        // Other status, continue waiting.
                                        tokio::time::sleep(tokio::time::Duration::from_millis(10))
                                            .await;
                                        continue;
                                    }
                                }
                            }
                            Ok(n) => {
                                stdout.extend_from_slice(&buf[..n]);
                            }
                            Err(e) => {
                                tracing::warn!("PTY read error: {}", e);
                                break;
                            }
                        }
                    }
                }

                // Wait for child to finish.
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        session.running = false;
                        session.exit_code = Some(code);
                        Ok((pid, Some(code), stdout, Vec::new()))
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        session.running = false;
                        let code = 128 + sig as i32;
                        session.exit_code = Some(code);
                        Ok((pid, Some(code), stdout, Vec::new()))
                    }
                    Ok(_) => {
                        // Unexpected status.
                        Ok((pid, Some(-1), stdout, Vec::new()))
                    }
                    Err(e) => {
                        anyhow::bail!("waitpid failed: {}", e);
                    }
                }
            }
            Ok(ForkResult::Child) => {
                // Child process.
                // Setup PTY slave as controlling terminal if in TTY mode.
                if let Some(ref pty) = session.pty {
                    // SAFETY: We're in the child process after fork.
                    if let Err(e) = unsafe { pty.pty().setup_slave_for_child() } {
                        eprintln!("Failed to setup PTY: {}", e);
                        std::process::exit(1);
                    }
                }

                // Change working directory if specified.
                if !req.working_dir.is_empty() {
                    if let Err(e) = std::env::set_current_dir(&req.working_dir) {
                        eprintln!("Failed to change directory: {}", e);
                        std::process::exit(1);
                    }
                }

                // Execute the command.
                let c_args: Vec<&std::ffi::CStr> = args.iter().map(|s| s.as_c_str()).collect();
                let c_env: Vec<&std::ffi::CStr> =
                    env_strings.iter().map(|s| s.as_c_str()).collect();

                // This never returns on success.
                let _ = nix::unistd::execve(&cmd, &c_args, &c_env);

                // If we get here, execve failed.
                eprintln!("execve failed: {}", std::io::Error::last_os_error());
                std::process::exit(127);
            }
            Err(e) => {
                anyhow::bail!("fork failed: {}", e);
            }
        }
    }

    /// Handles an ExecResize request.
    async fn handle_exec_resize(
        req: arcbox_protocol::agent::ExecResizeRequest,
        state: &Arc<RwLock<AgentState>>,
    ) -> RpcResponse {
        tracing::info!(
            "ExecResize: exec_id={}, width={}, height={}",
            req.exec_id,
            req.width,
            req.height
        );

        let proc = {
            let state = state.read().await;
            state.exec_processes.get(&req.exec_id).cloned()
        };

        let proc = match proc {
            Some(p) => p,
            None => {
                return RpcResponse::Error(ErrorResponse::new(
                    404,
                    format!("exec session not found: {}", req.exec_id),
                ));
            }
        };

        let mut handle = proc.lock().await;
        if let Some(ref pty) = handle.pty {
            if let Err(e) = pty.resize(req.width as u16, req.height as u16) {
                return RpcResponse::Error(ErrorResponse::new(
                    500,
                    format!("failed to resize: {}", e),
                ));
            }
            RpcResponse::Empty
        } else {
            RpcResponse::Error(ErrorResponse::new(400, "exec session does not have a TTY"))
        }
    }

    /// Handles an Attach request (sets up bidirectional streaming).
    async fn handle_attach(req: AttachRequest, state: &Arc<RwLock<AgentState>>) -> RequestResult {
        eprintln!(
            "[AGENT] handle_attach: container_id={}, exec_id={}",
            req.container_id, req.exec_id
        );
        tracing::info!(
            "Attach: container_id={}, exec_id={}, stdin={}, stdout={}, stderr={}, size={}x{}",
            req.container_id,
            req.exec_id,
            req.attach_stdin,
            req.attach_stdout,
            req.attach_stderr,
            req.tty_width,
            req.tty_height
        );

        if !req.attach_stdout && !req.attach_stderr {
            return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                400,
                "must attach to stdout or stderr",
            )));
        }

        // Access runtime.
        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };

        // Resolve target: exec or container.
        let (attach_stdin_allowed, is_tty, initial_size, target, broadcaster) = if !req
            .exec_id
            .is_empty()
        {
            let mut guard = state.write().await;
            let proc = match guard.exec_processes.get(&req.exec_id) {
                Some(p) => Arc::clone(p),
                None => {
                    return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                        404,
                        format!("exec session not found: {}", req.exec_id),
                    )));
                }
            };

            let is_tty = proc.lock().await.tty;
            let resize = if req.tty_width > 0 && req.tty_height > 0 {
                Some((req.tty_width as u16, req.tty_height as u16))
            } else {
                None
            };
            let broadcaster = proc.lock().await.broadcaster.clone();

            (
                req.attach_stdin,
                is_tty,
                resize,
                AttachTarget::Exec(proc),
                broadcaster,
            )
        } else {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);

            let mut attach_stdin_allowed = false;
            let mut is_tty = false;
            let mut initial_size = None;
            let mut process_handle = None;
            let mut broadcaster = None;

            loop {
                let (state, open_stdin, tty) = {
                    let runtime = runtime.lock().await;
                    let container = match runtime.get_container(&req.container_id) {
                        Some(c) => c,
                        None => {
                            return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                                404,
                                format!("container not found: {}", req.container_id),
                            )));
                        }
                    };
                    (container.state, container.open_stdin, container.tty)
                };

                let resize = if req.tty_width > 0 && req.tty_height > 0 {
                    Some((req.tty_width as u16, req.tty_height as u16))
                } else {
                    None
                };

                attach_stdin_allowed = req.attach_stdin && open_stdin;
                is_tty = tty;
                initial_size = resize;

                let handle = {
                    let runtime = runtime.lock().await;
                    runtime.get_process_handle(&req.container_id).await
                };

                tracing::info!(
                    "handle_attach: get_process_handle returned: {:?}",
                    handle.is_some()
                );

                if let Some(handle) = handle {
                    let handle_guard = handle.lock().await;
                    let log_broadcaster = handle_guard.broadcaster.clone();
                    tracing::info!(
                        "handle_attach: broadcaster from handle: {:?}",
                        log_broadcaster.is_some()
                    );
                    drop(handle_guard);

                    if let Some(b) = log_broadcaster {
                        process_handle = Some(handle);
                        broadcaster = Some(b);
                        tracing::info!("handle_attach: found broadcaster, breaking loop");
                        break;
                    }
                }

                if state == ContainerState::Stopped {
                    if let Some(b) = build_attach_backlog_broadcaster(
                        &req.container_id,
                        req.attach_stdout,
                        req.attach_stderr,
                    )
                    .await
                    {
                        let handle = Arc::new(Mutex::new(crate::container::ProcessHandle {
                            child: None,
                            stdin: None,
                            pty: None,
                            shim_shutdown: None,
                            broadcaster: Some(Arc::clone(&b)),
                        }));
                        process_handle = Some(handle);
                        broadcaster = Some(b);
                        attach_stdin_allowed = false;
                        break;
                    }
                }

                tracing::info!(
                    "handle_attach: loop iteration, container_id={}, state={:?}, has_process_handle={}, has_broadcaster={}",
                    req.container_id,
                    state,
                    process_handle.is_some(),
                    broadcaster.is_some()
                );

                match state {
                    ContainerState::Created => {
                        if std::time::Instant::now() >= deadline {
                            return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                                400,
                                "container is not running",
                            )));
                        }
                    }
                    ContainerState::Running => {
                        if std::time::Instant::now() >= deadline {
                            return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                                500,
                                "log broadcaster unavailable",
                            )));
                        }
                    }
                    ContainerState::Paused => {
                        if std::time::Instant::now() >= deadline {
                            return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                                500,
                                "log broadcaster unavailable",
                            )));
                        }
                    }
                    ContainerState::Stopped => {
                        if std::time::Instant::now() >= deadline {
                            return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                                400,
                                "container is not running",
                            )));
                        }
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            let process_handle = match process_handle {
                Some(handle) => handle,
                None => {
                    return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                        500,
                        "container process not found",
                    )));
                }
            };

            let broadcaster = match broadcaster {
                Some(b) => b,
                None => {
                    return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                        500,
                        "log broadcaster unavailable",
                    )));
                }
            };

            (
                attach_stdin_allowed,
                is_tty,
                initial_size,
                AttachTarget::Container(process_handle),
                broadcaster,
            )
        };

        let include_stdout = req.attach_stdout;
        let include_stderr = req.attach_stderr;
        tracing::info!(
            "handle_attach: about to subscribe to broadcaster, container_id={}",
            req.container_id
        );
        let mut log_rx = broadcaster.subscribe().await;
        tracing::info!(
            "handle_attach: subscribed to broadcaster, container_id={}",
            req.container_id
        );

        // Channel for outgoing attach output.
        let (tx, rx) = mpsc::channel(64);

        let container_id_for_log = req.container_id.clone();
        tokio::spawn(async move {
            let mut entry_count = 0u32;
            while let Some(entry) = log_rx.recv().await {
                entry_count += 1;
                let stream_name = match entry.stream {
                    StreamType::Stderr => "stderr",
                    _ => "stdout",
                };

                tracing::debug!(
                    "handle_attach: received entry #{} from broadcaster, stream={}, len={}, container_id={}",
                    entry_count,
                    stream_name,
                    entry.data.len(),
                    container_id_for_log
                );

                // Filter streams.
                if stream_name == "stdout" && !include_stdout {
                    continue;
                }
                if stream_name == "stderr" && !include_stderr {
                    continue;
                }

                let out = AttachOutput {
                    stream: stream_name.to_string(),
                    data: entry.data.to_vec(),
                };

                if tx.send(out).await.is_err() {
                    tracing::debug!(
                        "handle_attach: tx.send failed (receiver dropped), container_id={}",
                        container_id_for_log
                    );
                    break;
                }
            }
            tracing::debug!(
                "handle_attach: log_rx ended, total entries={}, container_id={}",
                entry_count,
                container_id_for_log
            );
        });

        RequestResult::Attach(AttachSession {
            output_rx: rx,
            process: target,
            attach_stdin: attach_stdin_allowed,
            tty: is_tty,
            initial_size,
        })
    }

    async fn build_attach_backlog_broadcaster(
        container_id: &str,
        stdout: bool,
        stderr: bool,
    ) -> Option<Arc<BroadcastWriter>> {
        let log_path = format!("/var/log/containers/{}.log", container_id);
        let log_data = match std::fs::read_to_string(&log_path) {
            Ok(data) => data,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return None;
                }
                tracing::warn!(
                    "Attach fallback: failed to read logs for {}: {}",
                    container_id,
                    e
                );
                return None;
            }
        };

        let broadcaster = Arc::new(BroadcastWriter::new());
        for line in log_data.lines() {
            if let Some(parsed) = parse_docker_log_line(line, stdout, stderr) {
                let stream = if parsed.stream == "stderr" {
                    StreamType::Stderr
                } else {
                    StreamType::Stdout
                };
                let timestamp = parsed
                    .timestamp
                    .and_then(|ts| ts.timestamp_nanos_opt())
                    .unwrap_or_else(|| Utc::now().timestamp_nanos_opt().unwrap_or(0));
                let entry = ShimLogEntry {
                    stream,
                    data: Bytes::from(parsed.log),
                    timestamp,
                    partial: false,
                };
                let _ = broadcaster.write(&entry).await;
            }
        }

        broadcaster.close().await;
        Some(broadcaster)
    }

    /// Applies stdin and resize operations for an attach session.
    async fn handle_attach_input(session: &AttachSession, input: AttachInput) -> Result<()> {
        // Handle resize first for TTY sessions.
        if session.tty && input.resize {
            match &session.process {
                AttachTarget::Container(handle) => {
                    if let Some(pty) = handle.lock().await.pty.as_ref() {
                        let cols = input.width.min(u32::from(u16::MAX)) as u16;
                        let rows = input.height.min(u32::from(u16::MAX)) as u16;
                        pty.resize(cols, rows)?;
                    }
                }
                AttachTarget::Exec(handle) => {
                    if let Some(pty) = handle.lock().await.pty.as_ref() {
                        let cols = input.width.min(u32::from(u16::MAX)) as u16;
                        let rows = input.height.min(u32::from(u16::MAX)) as u16;
                        pty.resize(cols, rows)?;
                    }
                }
            }
        }

        // Handle stdin data.
        if session.attach_stdin && !input.data.is_empty() {
            tracing::debug!("attach input: received {} bytes", input.data.len());
            match &session.process {
                AttachTarget::Container(handle) => {
                    let mut handle = handle.lock().await;
                    if let Some(ref pty) = handle.pty {
                        let _ = pty.write_input(&input.data)?;
                    } else if let Some(stdin) = handle.stdin.as_mut() {
                        stdin.write_all(&input.data).await?;
                    }
                }
                AttachTarget::Exec(handle) => {
                    let mut handle = handle.lock().await;
                    if let Some(ref pty) = handle.pty {
                        let _ = pty.write_input(&input.data)?;
                    } else if let Some(stdin) = handle.stdin.as_mut() {
                        stdin.write_all(&input.data).await?;
                    }
                }
            }
        } else if session.attach_stdin && input.data.is_empty() && !input.resize {
            // Client closed stdin; terminate exec stdin/PTY to allow process exit.
            tracing::debug!("attach input: client closed stdin");
            match &session.process {
                AttachTarget::Container(handle) => {
                    let mut handle = handle.lock().await;
                    // Best-effort: close stdin for non-TTY containers.
                    handle.stdin.take();
                }
                AttachTarget::Exec(handle) => {
                    let mut handle = handle.lock().await;
                    // Close stdin/PTY to deliver EOF; let the process exit naturally.
                    handle.stdin.take();
                    handle.pty.take();
                }
            }
        }

        Ok(())
    }

    /// Handles a Logs request.
    ///
    /// When follow=true, returns a streaming response that watches the log file.
    /// When follow=false, returns a single response with current log content.
    async fn handle_logs(req: LogsRequest, state: &Arc<RwLock<AgentState>>) -> RequestResult {
        tracing::info!(
            "Logs: container_id={}, follow={}, tail={}",
            req.container_id,
            req.follow,
            req.tail
        );

        // Verify container exists.
        {
            let runtime = {
                let state = state.read().await;
                Arc::clone(&state.runtime)
            };
            let runtime = runtime.lock().await;
            if runtime.get_container(&req.container_id).is_none() {
                return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                    404,
                    format!("container not found: {}", req.container_id),
                )));
            }
        }

        // Container log file path.
        let log_path = format!("/var/log/containers/{}.log", req.container_id);

        // Handle streaming mode (follow=true)
        if req.follow {
            return handle_logs_stream(req, log_path).await;
        }

        // Non-streaming mode: read current log content
        let log_data = match std::fs::read_to_string(&log_path) {
            Ok(data) => data,
            Err(e) => {
                // If log file doesn't exist, return empty log entry.
                if e.kind() == std::io::ErrorKind::NotFound {
                    return RequestResult::Single(RpcResponse::LogEntry(LogEntry {
                        stream: "stdout".to_string(),
                        message: Vec::new(),
                        timestamp: chrono::Utc::now()
                            .timestamp_nanos_opt()
                            .map(nanos_to_timestamp),
                    }));
                }
                return RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                    500,
                    format!("failed to read logs: {}", e),
                )));
            }
        };

        // Parse Docker JSON log format and extract log content
        let mut output_lines = Vec::new();
        for line in log_data.lines() {
            if let Some(parsed) = parse_docker_log_line(line, req.stdout, req.stderr) {
                if let Some(ts) = parsed.timestamp {
                    if req.since > 0 && ts.timestamp() < req.since {
                        continue;
                    }
                    if req.until > 0 && ts.timestamp() > req.until {
                        continue;
                    }
                }

                let formatted = if req.timestamps {
                    match parsed.raw_time.as_deref() {
                        Some(raw) => format!("{} {}", raw, parsed.log),
                        None => parsed.log,
                    }
                } else {
                    parsed.log
                };

                output_lines.push(formatted);
            }
        }

        // Apply tail filter if specified.
        let output_lines = if req.tail > 0 {
            let start = output_lines.len().saturating_sub(req.tail as usize);
            output_lines[start..].to_vec()
        } else {
            output_lines
        };

        let output = output_lines.join("");

        RequestResult::Single(RpcResponse::LogEntry(LogEntry {
            stream: if req.stdout { "stdout" } else { "stderr" }.to_string(),
            message: output.into_bytes(),
            timestamp: chrono::Utc::now()
                .timestamp_nanos_opt()
                .map(nanos_to_timestamp),
        }))
    }

    /// Handles streaming logs (follow=true).
    async fn handle_logs_stream(req: LogsRequest, log_path: String) -> RequestResult {
        let options = LogWatchOptions {
            stdout: req.stdout,
            stderr: req.stderr,
            timestamps: req.timestamps,
            tail: req.tail,
            since: req.since,
            until: req.until,
        };

        // Create cancellation channel
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>(1);

        // Start log watcher
        match watch_log_file(&log_path, options, cancel_rx).await {
            Ok(log_rx) => RequestResult::Stream(log_rx, cancel_tx),
            Err(e) => {
                tracing::error!("Failed to start log watcher: {}", e);
                RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                    500,
                    format!("failed to start log stream: {}", e),
                )))
            }
        }
    }

    /// Parses a Docker JSON log line and extracts the log content.
    ///
    /// Docker JSON log format: {"log":"content","stream":"stdout|stderr","time":"..."}
    ///
    /// Returns the log content if the line matches the requested streams,
    /// or None if it should be filtered out.
    fn parse_docker_log_line(line: &str, stdout: bool, stderr: bool) -> Option<ParsedLogLine> {
        // Try to parse as JSON
        let parsed: serde_json::Value = serde_json::from_str(line).ok()?;

        let stream = parsed.get("stream")?.as_str()?;
        let log = parsed.get("log")?.as_str()?;
        let raw_time = parsed
            .get("time")
            .and_then(|value| value.as_str())
            .map(|s| s.to_string());
        let timestamp = raw_time
            .as_deref()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|time| time.with_timezone(&Utc));

        // Filter by stream type
        match stream {
            "stdout" if stdout => Some(ParsedLogLine {
                stream: stream.to_string(),
                log: log.to_string(),
                timestamp,
                raw_time,
            }),
            "stderr" if stderr => Some(ParsedLogLine {
                stream: stream.to_string(),
                log: log.to_string(),
                timestamp,
                raw_time,
            }),
            _ => None,
        }
    }
}

// =============================================================================
// macOS Stub Implementation (for development/testing)
// =============================================================================

#[cfg(not(target_os = "linux"))]
mod stub {
    use anyhow::Result;

    use super::AGENT_PORT;

    /// The Guest Agent (stub for non-Linux platforms).
    pub struct Agent;

    impl Agent {
        /// Creates a new agent.
        pub fn new() -> Self {
            Self
        }

        /// Runs the agent (stub mode).
        ///
        /// On non-Linux platforms (e.g., macOS), vsock is not available.
        /// This stub allows development and testing on the host.
        pub async fn run(&self) -> Result<()> {
            tracing::warn!("Agent is running in stub mode (non-Linux platform)");
            tracing::info!("Agent would listen on vsock port {}", AGENT_PORT);

            // In stub mode, we just keep the agent running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                tracing::debug!("Agent stub heartbeat");
            }
        }
    }

    impl Default for Agent {
        fn default() -> Self {
            Self::new()
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

#[cfg(target_os = "linux")]
pub use linux::Agent;

#[cfg(not(target_os = "linux"))]
pub use stub::Agent;

/// Runs the agent.
pub async fn run() -> Result<()> {
    let agent = Agent::new();
    agent.run().await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Docker Log Format Parsing Tests
    // =========================================================================

    /// Helper to parse Docker JSON log line for testing.
    fn parse_docker_log_line(line: &str, stdout: bool, stderr: bool) -> Option<String> {
        let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
        let stream = parsed.get("stream")?.as_str()?;
        let log = parsed.get("log")?.as_str()?;

        match stream {
            "stdout" if stdout => Some(log.to_string()),
            "stderr" if stderr => Some(log.to_string()),
            _ => None,
        }
    }

    #[test]
    fn test_parse_docker_log_stdout() {
        let line = r#"{"log":"hello world","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, Some("hello world".to_string()));

        // Should filter out when stdout=false
        let result = parse_docker_log_line(line, false, true);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_docker_log_stderr() {
        let line = r#"{"log":"error message","stream":"stderr","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, false, true);
        assert_eq!(result, Some("error message".to_string()));

        // Should filter out when stderr=false
        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_docker_log_both_streams() {
        let stdout_line = r#"{"log":"stdout msg","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;
        let stderr_line = r#"{"log":"stderr msg","stream":"stderr","time":"2024-01-08T12:00:00Z"}"#;

        // Both enabled
        assert_eq!(
            parse_docker_log_line(stdout_line, true, true),
            Some("stdout msg".to_string())
        );
        assert_eq!(
            parse_docker_log_line(stderr_line, true, true),
            Some("stderr msg".to_string())
        );
    }

    #[test]
    fn test_parse_docker_log_invalid_json() {
        let invalid = "not json";
        assert_eq!(parse_docker_log_line(invalid, true, true), None);

        let incomplete = r#"{"log":"test"}"#; // Missing stream field
        assert_eq!(parse_docker_log_line(incomplete, true, true), None);
    }

    #[test]
    fn test_parse_docker_log_special_characters() {
        // Test with escaped characters
        let line = r#"{"log":"line with \"quotes\" and \\backslash","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(
            result,
            Some(r#"line with "quotes" and \backslash"#.to_string())
        );
    }

    #[test]
    fn test_parse_docker_log_empty_content() {
        let line = r#"{"log":"","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, Some("".to_string()));
    }

    #[test]
    fn test_parse_docker_log_multiline_content() {
        // Docker typically escapes newlines in log content
        let line = r#"{"log":"line1\\nline2","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert!(result.is_some());
        // The escaped newline should be preserved
        assert!(result.unwrap().contains("\\n"));
    }

    // =========================================================================
    // Agent Creation Tests
    // =========================================================================

    #[test]
    fn test_agent_creation() {
        let _agent = Agent::new();
    }

    // =========================================================================
    // EnsureRuntime State Machine Tests
    // =========================================================================

    use crate::agent::ensure_runtime::{
        self, RuntimeGuard, RuntimeState, STATUS_FAILED, STATUS_REUSED, STATUS_STARTED,
    };
    use arcbox_protocol::agent::RuntimeEnsureResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Helper: creates a successful RuntimeEnsureResponse.
    fn make_ready_response() -> RuntimeEnsureResponse {
        RuntimeEnsureResponse {
            ready: true,
            endpoint: "vsock:2375".to_string(),
            message: "docker socket ready".to_string(),
            status: STATUS_STARTED.to_string(),
        }
    }

    /// Helper: creates a failed RuntimeEnsureResponse.
    fn make_failed_response() -> RuntimeEnsureResponse {
        RuntimeEnsureResponse {
            ready: false,
            endpoint: String::new(),
            message: "docker socket missing".to_string(),
            status: STATUS_FAILED.to_string(),
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_first_call_started() {
        let guard = RuntimeGuard::new();
        let response =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!("probe should not be called when start_if_needed=true")
            })
            .await;

        assert!(response.ready);
        assert_eq!(response.status, STATUS_STARTED);
        assert_eq!(response.endpoint, "vsock:2375");
    }

    #[tokio::test]
    async fn test_ensure_runtime_second_call_reused() {
        let guard = RuntimeGuard::new();

        // First call: starts runtime.
        let r1 =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        assert_eq!(r1.status, STATUS_STARTED);

        // Second call: should reuse.
        let r2 = ensure_runtime::ensure_runtime(
            &guard,
            true,
            async { panic!("start_fn should not be called for reuse") },
            async { unreachable!() },
        )
        .await;
        assert!(r2.ready);
        assert_eq!(r2.status, STATUS_REUSED);
    }

    #[tokio::test]
    async fn test_ensure_runtime_20_sequential_calls_no_error() {
        let guard = RuntimeGuard::new();

        for i in 0..20 {
            let response = ensure_runtime::ensure_runtime(
                &guard,
                true,
                async { make_ready_response() },
                async { unreachable!() },
            )
            .await;
            assert!(response.ready, "call {} should succeed", i);
            if i == 0 {
                assert_eq!(response.status, STATUS_STARTED);
            } else {
                assert_eq!(response.status, STATUS_REUSED);
            }
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_probe_only_no_start() {
        let guard = RuntimeGuard::new();

        let response = ensure_runtime::ensure_runtime(
            &guard,
            false,
            async { panic!("start_fn should not be called when start_if_needed=false") },
            async {
                RuntimeEnsureResponse {
                    ready: false,
                    endpoint: String::new(),
                    message: "docker not available".to_string(),
                    status: STATUS_FAILED.to_string(),
                }
            },
        )
        .await;

        assert!(!response.ready);
        assert_eq!(response.status, STATUS_FAILED);
    }

    #[tokio::test]
    async fn test_ensure_runtime_failed_then_retry_succeeds() {
        let guard = RuntimeGuard::new();

        // First call: fails.
        let r1 =
            ensure_runtime::ensure_runtime(&guard, true, async { make_failed_response() }, async {
                unreachable!()
            })
            .await;
        assert!(!r1.ready);
        assert_eq!(r1.status, STATUS_FAILED);

        // Second call: retry, now succeeds.
        let r2 =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        assert!(r2.ready);
        assert_eq!(r2.status, STATUS_STARTED);

        // Third call: reused.
        let r3 = ensure_runtime::ensure_runtime(
            &guard,
            true,
            async { panic!("should not start again") },
            async { unreachable!() },
        )
        .await;
        assert!(r3.ready);
        assert_eq!(r3.status, STATUS_REUSED);
    }

    #[tokio::test]
    async fn test_ensure_runtime_concurrent_5_callers_consistent() {
        let guard = Arc::new(RuntimeGuard::new());
        let start_count = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(5));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let guard = Arc::clone(&guard);
            let start_count = Arc::clone(&start_count);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                // Synchronize all 5 tasks to start concurrently.
                barrier.wait().await;

                ensure_runtime::ensure_runtime(
                    &guard,
                    true,
                    async {
                        start_count.fetch_add(1, Ordering::SeqCst);
                        // Simulate some startup delay.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        make_ready_response()
                    },
                    async { unreachable!() },
                )
                .await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // All 5 should report ready.
        for (i, r) in results.iter().enumerate() {
            assert!(r.ready, "caller {} should see ready", i);
        }

        // Exactly 1 should have status "started", rest "reused".
        let started_count = results
            .iter()
            .filter(|r| r.status == STATUS_STARTED)
            .count();
        let reused_count = results.iter().filter(|r| r.status == STATUS_REUSED).count();
        assert_eq!(started_count, 1, "exactly one caller should be the driver");
        assert_eq!(reused_count, 4, "other callers should get reused");

        // start_fn should have been invoked exactly once.
        assert_eq!(start_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_ensure_runtime_concurrent_5_callers_failure_consistent() {
        let guard = Arc::new(RuntimeGuard::new());
        let barrier = Arc::new(tokio::sync::Barrier::new(5));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let guard = Arc::clone(&guard);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                ensure_runtime::ensure_runtime(
                    &guard,
                    true,
                    async {
                        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                        make_failed_response()
                    },
                    async { unreachable!() },
                )
                .await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // All 5 should report not ready.
        for (i, r) in results.iter().enumerate() {
            assert!(!r.ready, "caller {} should see not ready", i);
            assert_eq!(r.status, STATUS_FAILED, "caller {} should get failed", i);
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_no_lost_wakeup_when_driver_finishes_fast() {
        // Repeat to make the regression deterministic enough: this used to
        // hang intermittently when notify happened before waiter registered.
        for _ in 0..50 {
            let guard = Arc::new(RuntimeGuard::new());
            let entered_start_fn = Arc::new(tokio::sync::Notify::new());
            let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

            let guard_driver = Arc::clone(&guard);
            let entered_start_fn_driver = Arc::clone(&entered_start_fn);
            let driver = tokio::spawn(async move {
                ensure_runtime::ensure_runtime(
                    &guard_driver,
                    true,
                    async move {
                        entered_start_fn_driver.notify_waiters();
                        let _ = release_rx.await;
                        make_ready_response()
                    },
                    async { unreachable!() },
                )
                .await
            });

            // Ensure state has transitioned to Starting before spawning waiter.
            entered_start_fn.notified().await;

            let guard_waiter = Arc::clone(&guard);
            let waiter = tokio::spawn(async move {
                ensure_runtime::ensure_runtime(
                    &guard_waiter,
                    true,
                    async { panic!("waiter should never run start_fn") },
                    async { unreachable!() },
                )
                .await
            });

            // Give waiter a chance to enter wait path, then let driver finish.
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let _ = release_tx.send(());

            let driver_resp = tokio::time::timeout(std::time::Duration::from_millis(500), driver)
                .await
                .expect("driver timed out")
                .expect("driver task failed");
            let waiter_resp = tokio::time::timeout(std::time::Duration::from_millis(500), waiter)
                .await
                .expect("waiter timed out")
                .expect("waiter task failed");

            assert!(driver_resp.ready);
            assert_eq!(driver_resp.status, STATUS_STARTED);
            assert!(waiter_resp.ready);
            assert_eq!(waiter_resp.status, STATUS_REUSED);
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_state_machine_transitions() {
        let guard = RuntimeGuard::new();

        // Initially NotStarted.
        {
            let state = guard.state.lock().await;
            assert!(matches!(&*state, RuntimeState::NotStarted));
        }

        // After successful ensure: Ready.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        {
            let state = guard.state.lock().await;
            assert!(
                matches!(&*state, RuntimeState::Ready { .. }),
                "expected Ready, got {:?}",
                *state
            );
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_state_machine_failed_to_ready() {
        let guard = RuntimeGuard::new();

        // Fail first.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_failed_response() }, async {
                unreachable!()
            })
            .await;
        {
            let state = guard.state.lock().await;
            assert!(
                matches!(&*state, RuntimeState::Failed { .. }),
                "expected Failed, got {:?}",
                *state
            );
        }

        // Retry succeeds.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        {
            let state = guard.state.lock().await;
            assert!(
                matches!(&*state, RuntimeState::Ready { .. }),
                "expected Ready after retry, got {:?}",
                *state
            );
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_probe_after_ready_returns_reused() {
        let guard = RuntimeGuard::new();

        // Start first.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;

        // Probe (start_if_needed=false) should return reused immediately
        // from the cached state, without calling probe_fn.
        let r = ensure_runtime::ensure_runtime(
            &guard,
            false,
            async { panic!("start_fn should not be called") },
            async { panic!("probe_fn should not be called when state is Ready") },
        )
        .await;
        assert!(r.ready);
        assert_eq!(r.status, STATUS_REUSED);
    }
}
