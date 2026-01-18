//! Agent main loop and request handling.
//!
//! The Agent listens on vsock port 1024 and handles RPC requests from the host.
//! It manages container lifecycle and executes commands in the guest VM.

use anyhow::Result;

/// Vsock port for agent communication.
pub const AGENT_PORT: u32 = 1024;

// =============================================================================
// Linux Implementation
// =============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::os::unix::io::AsRawFd;
    use std::process::Stdio;
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use bytes::Bytes;
    use prost::Message;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use tokio::process::{Child, ChildStdin, Command};
    use tokio::sync::{Mutex, RwLock, mpsc};
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

    use super::AGENT_PORT;
    use crate::container::{ContainerHandle, ContainerRuntime, ContainerState, MountSpec, setup_container_rootfs};
    use crate::log_watcher::{LogWatchOptions, watch_log_file};
    use crate::pty::{ExecSession, PtyHandle};
    use crate::rpc::{
        AGENT_VERSION, ErrorResponse, MessageType, RpcRequest, RpcResponse, parse_request,
        read_message, write_response,
    };
    use crate::shim::{BroadcastWriter, LogEntry as ShimLogEntry, LogWriter, ProcessShim, StreamType};

    use arcbox_protocol::agent::{
        AttachInput, AttachOutput, AttachRequest, ContainerInfo, CreateContainerResponse,
        ExecOutput, ExecStartResponse, ListContainersResponse, LogEntry, LogsRequest, PingResponse,
        SystemInfo,
    };
    use chrono::{DateTime, Utc};

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
            let addr = VsockAddr::new(VMADDR_CID_ANY, AGENT_PORT);
            let mut listener =
                VsockListener::bind(addr).context("failed to bind vsock listener")?;

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
            // Read the next request
            let (msg_type, payload) = match read_message(&mut stream).await {
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

            tracing::info!("Received message type {:?}, payload_len={}", msg_type, payload.len());
            // Direct stderr output for debugging when console capture might fail
            eprintln!("[AGENT] Received message type {:?}, payload_len={}", msg_type, payload.len());

            // Parse and handle the request
            let result = match parse_request(msg_type, &payload) {
                Ok(request) => handle_request(request, &state).await,
                Err(e) => {
                    tracing::warn!("Failed to parse request: {}", e);
                    RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                        400,
                        format!("invalid request: {}", e),
                    )))
                }
            };

            // Handle the result
            match result {
                RequestResult::Single(response) => {
                    // Write single response
                    write_response(&mut stream, &response).await?;
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
                                        if let Err(e) = write_response(&mut stream, &response).await {
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
                                        if let Err(e) = write_response(&mut stream, &RpcResponse::Empty).await {
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
                    tracing::info!("Entered Attach processing loop, tty={}, stdin={}", session.tty, session.attach_stdin);
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
                                        if let Err(e) = write_response(&mut stream, &response).await {
                                            tracing::warn!("Client disconnected during attach output: {}", e);
                                            break;
                                        }
                                        tracing::info!("Attach: sent AttachOutput response");
                                    }
                                    None => {
                                        // Output stream ended; signal end of stream.
                                        tracing::info!("Attach: output stream ended, sending Empty response");
                                        if let Err(e) = write_response(&mut stream, &RpcResponse::Empty).await {
                                            tracing::warn!("Attach: failed to send Empty response: {}", e);
                                        }
                                        break;
                                    }
                                }
                            }
                            inbound = read_message(&mut stream) => {
                                match inbound {
                                    Ok((MessageType::AttachInput, payload)) => {
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
                                    Ok((other_type, _)) => {
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

    /// Collects system information from the guest.
    fn collect_system_info() -> SystemInfo {
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
                return RpcResponse::WaitContainer(arcbox_protocol::container::WaitContainerResponse {
                    status_code: i64::from(exit_code),
                    error: String::new(),
                });
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

        // Otherwise, execute in the specified container
        let runtime = {
            let state = state.read().await;
            Arc::clone(&state.runtime)
        };
        let runtime = runtime.lock().await;
        let container = match runtime.get_container(&req.container_id) {
            Some(c) => c,
            None => {
                return RpcResponse::Error(ErrorResponse::new(
                    404,
                    format!("container not found: {}", req.container_id),
                ));
            }
        };

        if container.state != ContainerState::Running {
            return RpcResponse::Error(ErrorResponse::new(
                400,
                format!("container is not running: {}", req.container_id),
            ));
        }

        // Execute in container (simplified: just run the command)
        // In a full implementation, we would enter the container's namespaces
        execute_on_host(req).await
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

        // Get container's rootfs, mounts, and working_dir for namespace setup.
        let (container_rootfs, container_mounts, container_workdir) = {
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
                ),
                None => {
                    return RpcResponse::Error(ErrorResponse::new(
                        404,
                        format!("container not found: {}", req.container_id),
                    ));
                }
            }
        };

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
                        setup_container_rootfs(&rootfs_for_exec, &workdir_for_exec, &mounts_for_exec)
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
                let stdout_fd = stdout.as_raw_fd();
                let stderr_fd = stderr.as_raw_fd();
                std::mem::forget(stdout);
                std::mem::forget(stderr);
                match ProcessShim::with_pipes(req.exec_id.clone(), stdout_fd, stderr_fd) {
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
        eprintln!("[AGENT] handle_attach: container_id={}, exec_id={}", req.container_id, req.exec_id);
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
        let (attach_stdin_allowed, is_tty, initial_size, target, broadcaster) =
            if !req.exec_id.is_empty() {
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
                                return RequestResult::Single(RpcResponse::Error(
                                    ErrorResponse::new(
                                        404,
                                        format!("container not found: {}", req.container_id),
                                    ),
                                ));
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
                                return RequestResult::Single(RpcResponse::Error(
                                    ErrorResponse::new(400, "container is not running"),
                                ));
                            }
                        }
                        ContainerState::Running => {
                            if std::time::Instant::now() >= deadline {
                                return RequestResult::Single(RpcResponse::Error(
                                    ErrorResponse::new(500, "log broadcaster unavailable"),
                                ));
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
                        data: Vec::new(),
                        timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
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
            data: output.into_bytes(),
            timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
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
}
