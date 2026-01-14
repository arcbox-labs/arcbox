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
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::sync::{mpsc, Mutex, RwLock};
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    use super::AGENT_PORT;
    use crate::container::{ContainerHandle, ContainerRuntime, ContainerState, MountSpec};
    use crate::log_watcher::{watch_log_file, LogWatchOptions};
    use crate::pty::ExecSession;
    use crate::rpc::{
        parse_request, read_message, write_response, ErrorResponse, RpcRequest, RpcResponse,
        AGENT_VERSION,
    };

    use arcbox_protocol::agent::{
        ContainerInfo, CreateContainerResponse, ExecOutput, ExecStartResponse,
        ListContainersResponse, LogEntry, LogsRequest, PingResponse, SystemInfo,
    };
    use chrono::{DateTime, Utc};

    /// Agent state shared across connections.
    pub struct AgentState {
        /// Container runtime.
        pub runtime: Arc<Mutex<ContainerRuntime>>,
        /// Active exec sessions by ID.
        pub exec_sessions: HashMap<String, ExecSession>,
    }

    impl AgentState {
        pub fn new() -> Self {
            Self {
                runtime: Arc::new(Mutex::new(ContainerRuntime::new())),
                exec_sessions: HashMap::new(),
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

            tracing::debug!("Received message type {:?}", msg_type);

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
            }
        }
    }

    /// Handles a single RPC request.
    async fn handle_request(
        request: RpcRequest,
        state: &Arc<RwLock<AgentState>>,
    ) -> RequestResult {
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
            RpcRequest::Exec(req) => RequestResult::Single(handle_exec(req, state).await),
            RpcRequest::Logs(req) => handle_logs(req, state).await,
            RpcRequest::ExecStart(req) => {
                RequestResult::Single(handle_exec_start(req, state).await)
            }
            RpcRequest::ExecResize(req) => {
                RequestResult::Single(handle_exec_resize(req, state).await)
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
        let mut runtime = runtime.lock().await;
        match runtime.start_container(id).await {
            Ok(()) => RpcResponse::Empty,
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

        let (container_state, exit_code, process_handle) = {
            let runtime = runtime.lock().await;
            let (state, code) = match runtime.get_container_state(id) {
                Some(state) => state,
                None => {
                    return RpcResponse::Error(ErrorResponse::new(404, "container not found"));
                }
            };
            let process_handle = if state == ContainerState::Running {
                runtime.get_process_handle(id).await
            } else {
                None
            };
            (state, code, process_handle)
        };

        if container_state == ContainerState::Stopped {
            let exit_code = exit_code.unwrap_or(-1);
            tracing::info!("Container {} exited with code {}", id, exit_code);
            return RpcResponse::WaitContainer(arcbox_protocol::container::WaitContainerResponse {
                status_code: i64::from(exit_code),
                error: String::new(),
            });
        }

        let process_handle = match process_handle {
            Some(handle) => handle,
            None => {
                return RpcResponse::Error(ErrorResponse::new(
                    500,
                    "container process not found",
                ));
            }
        };

        let exit_code = match process_handle.lock().await.child.wait().await {
            Ok(status) => status.code().unwrap_or(-1),
            Err(e) => {
                tracing::error!("Failed to wait for container {}: {}", id, e);
                return RpcResponse::Error(ErrorResponse::new(500, format!("failed to wait: {}", e)));
            }
        };

        {
            let mut runtime = runtime.lock().await;
            runtime.mark_container_stopped(id, exit_code);
        }
        {
            let runtime = runtime.lock().await;
            runtime.remove_process_handle(id).await;
        }

        tracing::info!("Container {} exited with code {}", id, exit_code);
        RpcResponse::WaitContainer(arcbox_protocol::container::WaitContainerResponse {
            status_code: i64::from(exit_code),
            error: String::new(),
        })
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
        tracing::info!(
            "Exec: container_id={}, cmd={:?}",
            req.container_id,
            req.cmd
        );

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

        // Determine terminal size (use defaults if not specified).
        let cols = if req.tty_width > 0 { req.tty_width as u16 } else { 80 };
        let rows = if req.tty_height > 0 { req.tty_height as u16 } else { 24 };

        // Create exec session.
        let session = match ExecSession::new(req.exec_id.clone(), req.tty, cols, rows) {
            Ok(s) => s,
            Err(e) => {
                return RpcResponse::Error(ErrorResponse::new(
                    500,
                    format!("failed to create exec session: {}", e),
                ));
            }
        };

        // Execute the command using fork+exec with PTY.
        let result = execute_with_pty(&req, session).await;

        match result {
            Ok((pid, exit_code, stdout, stderr)) => {
                // Store session if detached (for future resize/management).
                if req.detach && exit_code.is_none() {
                    // In detach mode with no exit code, process is still running.
                    // Session management would go here in a full implementation.
                    tracing::debug!("Exec {} running in detached mode with pid {}", req.exec_id, pid);
                }

                RpcResponse::ExecStart(ExecStartResponse { pid })
            }
            Err(e) => {
                RpcResponse::Error(ErrorResponse::new(500, format!("exec_start failed: {}", e)))
            }
        }
    }

    /// Executes a command with PTY support.
    ///
    /// Returns (pid, exit_code, stdout, stderr).
    async fn execute_with_pty(
        req: &arcbox_protocol::agent::ExecStartRequest,
        mut session: ExecSession,
    ) -> Result<(u32, Option<i32>, Vec<u8>, Vec<u8>)> {
        use nix::sys::wait::{waitpid, WaitStatus};
        use nix::unistd::{fork, ForkResult};
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
                                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                                        continue;
                                    }
                                    _ => {
                                        // Other status, continue waiting.
                                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
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
                let c_env: Vec<&std::ffi::CStr> = env_strings.iter().map(|s| s.as_c_str()).collect();

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

        let mut state = state.write().await;

        // Find the exec session.
        let session = match state.exec_sessions.get_mut(&req.exec_id) {
            Some(s) => s,
            None => {
                return RpcResponse::Error(ErrorResponse::new(
                    404,
                    format!("exec session not found: {}", req.exec_id),
                ));
            }
        };

        // Check if session has PTY.
        if !session.has_tty() {
            return RpcResponse::Error(ErrorResponse::new(
                400,
                "exec session does not have a TTY",
            ));
        }

        // Check if session is still running.
        if !session.running {
            return RpcResponse::Error(ErrorResponse::new(
                400,
                "exec session is not running",
            ));
        }

        // Resize the PTY.
        if let Err(e) = session.resize(req.width as u16, req.height as u16) {
            return RpcResponse::Error(ErrorResponse::new(
                500,
                format!("failed to resize: {}", e),
            ));
        }

        RpcResponse::Empty
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
        let raw_time = parsed.get("time").and_then(|value| value.as_str()).map(|s| s.to_string());
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
