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
    use tokio::sync::RwLock;
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    use super::AGENT_PORT;
    use crate::container::{ContainerHandle, ContainerRuntime, ContainerState};
    use crate::rpc::{
        parse_request, read_message, write_response, ErrorResponse, RpcRequest, RpcResponse,
        AGENT_VERSION,
    };

    use arcbox_protocol::agent::{
        ContainerInfo, CreateContainerResponse, ExecOutput, ListContainersResponse, PingResponse,
        SystemInfo,
    };

    /// Agent state shared across connections.
    pub struct AgentState {
        /// Container runtime.
        pub runtime: ContainerRuntime,
    }

    impl AgentState {
        pub fn new() -> Self {
            Self {
                runtime: ContainerRuntime::new(),
            }
        }
    }

    impl Default for AgentState {
        fn default() -> Self {
            Self::new()
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
            let addr = VsockAddr::new(VMADDR_CID_ANY, AGENT_PORT);
            let listener =
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
            let response = match parse_request(msg_type, &payload) {
                Ok(request) => handle_request(request, &state).await,
                Err(e) => {
                    tracing::warn!("Failed to parse request: {}", e);
                    RpcResponse::Error(ErrorResponse::new(400, format!("invalid request: {}", e)))
                }
            };

            // Write the response
            write_response(&mut stream, &response).await?;
        }
    }

    /// Handles a single RPC request.
    async fn handle_request(request: RpcRequest, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        match request {
            RpcRequest::Ping(req) => handle_ping(req),
            RpcRequest::GetSystemInfo => handle_get_system_info().await,
            RpcRequest::CreateContainer(req) => handle_create_container(req, state).await,
            RpcRequest::StartContainer(req) => handle_start_container(&req.id, state).await,
            RpcRequest::StopContainer(req) => {
                handle_stop_container(&req.id, req.timeout, state).await
            }
            RpcRequest::RemoveContainer(req) => {
                handle_remove_container(&req.id, req.force, state).await
            }
            RpcRequest::ListContainers(req) => handle_list_containers(req.all, state).await,
            RpcRequest::Exec(req) => handle_exec(req, state).await,
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

        let container_id = uuid::Uuid::new_v4().to_string();

        // Convert environment variables
        let env: Vec<(String, String)> = req.env.into_iter().collect();

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
        };

        // Store in runtime
        {
            let mut state = state.write().await;
            state.runtime.add_container(handle);
        }

        RpcResponse::CreateContainer(CreateContainerResponse { id: container_id })
    }

    /// Handles a StartContainer request.
    async fn handle_start_container(id: &str, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::info!("StartContainer: id={}", id);

        let mut state = state.write().await;
        match state.runtime.start_container(id).await {
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

        let mut state = state.write().await;
        match state.runtime.stop_container(id, timeout).await {
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

        let mut state = state.write().await;
        match state.runtime.remove_container(id, force).await {
            Ok(()) => RpcResponse::Empty,
            Err(e) => {
                tracing::error!("Failed to remove container {}: {}", id, e);
                RpcResponse::Error(ErrorResponse::new(500, format!("failed to remove: {}", e)))
            }
        }
    }

    /// Handles a ListContainers request.
    async fn handle_list_containers(all: bool, state: &Arc<RwLock<AgentState>>) -> RpcResponse {
        tracing::debug!("ListContainers: all={}", all);

        let state = state.read().await;
        let containers: Vec<ContainerInfo> = state
            .runtime
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
        let state = state.read().await;
        let container = match state.runtime.get_container(&req.container_id) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let _agent = Agent::new();
    }
}
