//! Agent client for communicating with the guest VM.
//!
//! Provides RPC communication with the arcbox-agent running inside guest VMs.

use crate::error::{CoreError, Result};
use arcbox_container::AgentConnection;
use arcbox_protocol::Empty;
use arcbox_protocol::agent::{
    AttachInput, AttachOutput, AttachRequest, CreateContainerRequest, CreateContainerResponse,
    ExecOutput, ExecRequest, ExecResizeRequest, ExecStartRequest, ExecStartResponse,
    ListContainersRequest, ListContainersResponse, LogEntry, LogsRequest, PingRequest,
    PingResponse, RemoveContainerRequest, RuntimeEnsureRequest, RuntimeEnsureResponse,
    RuntimeStatusRequest, RuntimeStatusResponse, StartContainerRequest, StopContainerRequest,
    SystemInfo,
};
use arcbox_protocol::container::{
    ContainerStatsRequest, ContainerStatsResponse, ContainerTopRequest, ContainerTopResponse,
    KillContainerRequest, PauseContainerRequest, UnpauseContainerRequest, WaitContainerRequest,
    WaitContainerResponse,
};
use arcbox_transport::Transport;
use arcbox_transport::vsock::{VsockAddr, VsockTransport};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;

/// Default vsock port for agent communication.
pub const AGENT_PORT: u32 = 1024;

/// RPC message types (must match guest agent's rpc.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum MessageType {
    // Request types
    PingRequest = 0x0001,
    GetSystemInfoRequest = 0x0002,
    EnsureRuntimeRequest = 0x0003,
    RuntimeStatusRequest = 0x0004,
    CreateContainerRequest = 0x0010,
    StartContainerRequest = 0x0011,
    StopContainerRequest = 0x0012,
    RemoveContainerRequest = 0x0013,
    ListContainersRequest = 0x0014,
    KillContainerRequest = 0x0015,
    WaitContainerRequest = 0x0016,
    PauseContainerRequest = 0x0017,
    UnpauseContainerRequest = 0x0018,
    ContainerStatsRequest = 0x0019,
    ContainerTopRequest = 0x001A,
    ExecRequest = 0x0020,
    LogsRequest = 0x0021,
    ExecStartRequest = 0x0022,
    ExecResizeRequest = 0x0023,
    AttachRequest = 0x0024,
    AttachInput = 0x0025,

    // Response types
    PingResponse = 0x1001,
    WaitContainerResponse = 0x1016,
    GetSystemInfoResponse = 0x1002,
    EnsureRuntimeResponse = 0x1003,
    RuntimeStatusResponse = 0x1004,
    CreateContainerResponse = 0x1010,
    ListContainersResponse = 0x1014,
    ContainerStatsResponse = 0x1019,
    ContainerTopResponse = 0x101A,
    ExecOutput = 0x1020,
    LogEntry = 0x1021,
    ExecStartResponse = 0x1022,
    AttachOutput = 0x1023,

    // Special types
    EmptyResponse = 0x0000,
    Error = 0xFFFF,
}

impl MessageType {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0001 => Some(Self::PingRequest),
            0x0002 => Some(Self::GetSystemInfoRequest),
            0x0003 => Some(Self::EnsureRuntimeRequest),
            0x0004 => Some(Self::RuntimeStatusRequest),
            0x0010 => Some(Self::CreateContainerRequest),
            0x0011 => Some(Self::StartContainerRequest),
            0x0012 => Some(Self::StopContainerRequest),
            0x0013 => Some(Self::RemoveContainerRequest),
            0x0014 => Some(Self::ListContainersRequest),
            0x0015 => Some(Self::KillContainerRequest),
            0x0016 => Some(Self::WaitContainerRequest),
            0x0017 => Some(Self::PauseContainerRequest),
            0x0018 => Some(Self::UnpauseContainerRequest),
            0x0019 => Some(Self::ContainerStatsRequest),
            0x001A => Some(Self::ContainerTopRequest),
            0x0020 => Some(Self::ExecRequest),
            0x0021 => Some(Self::LogsRequest),
            0x0022 => Some(Self::ExecStartRequest),
            0x0023 => Some(Self::ExecResizeRequest),
            0x0024 => Some(Self::AttachRequest),
            0x0025 => Some(Self::AttachInput),
            0x1001 => Some(Self::PingResponse),
            0x1016 => Some(Self::WaitContainerResponse),
            0x1002 => Some(Self::GetSystemInfoResponse),
            0x1003 => Some(Self::EnsureRuntimeResponse),
            0x1004 => Some(Self::RuntimeStatusResponse),
            0x1010 => Some(Self::CreateContainerResponse),
            0x1014 => Some(Self::ListContainersResponse),
            0x1019 => Some(Self::ContainerStatsResponse),
            0x101A => Some(Self::ContainerTopResponse),
            0x1020 => Some(Self::ExecOutput),
            0x1021 => Some(Self::LogEntry),
            0x1022 => Some(Self::ExecStartResponse),
            0x1023 => Some(Self::AttachOutput),
            0x0000 => Some(Self::EmptyResponse),
            0xFFFF => Some(Self::Error),
            _ => None,
        }
    }
}

/// Agent client for a single VM.
pub struct AgentClient {
    /// VM CID (Context ID).
    cid: u32,
    /// Transport (connected or not).
    transport: VsockTransport,
    /// Whether connected.
    connected: bool,
}

impl AgentClient {
    /// Creates a new agent client for the given VM CID.
    #[must_use]
    pub fn new(cid: u32) -> Self {
        let addr = VsockAddr::new(cid, AGENT_PORT);
        Self {
            cid,
            transport: VsockTransport::new(addr),
            connected: false,
        }
    }

    /// Creates an agent client from an existing vsock file descriptor.
    ///
    /// This is used on macOS where vsock connections are obtained through
    /// the hypervisor layer (Virtualization.framework) rather than directly
    /// through AF_VSOCK.
    ///
    /// # Arguments
    /// * `cid` - The VM's CID (for tracking purposes)
    /// * `fd` - A connected vsock file descriptor from the hypervisor
    ///
    /// # Errors
    /// Returns an error if the fd is invalid.
    #[cfg(target_os = "macos")]
    pub fn from_fd(cid: u32, fd: std::os::unix::io::RawFd) -> Result<Self> {
        let addr = VsockAddr::new(cid, AGENT_PORT);
        let transport = VsockTransport::from_raw_fd(fd, addr)
            .map_err(|e| CoreError::Machine(format!("invalid vsock fd: {}", e)))?;

        Ok(Self {
            cid,
            transport,
            connected: true,
        })
    }

    /// Returns the VM CID.
    #[must_use]
    pub fn cid(&self) -> u32 {
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

        self.transport
            .connect()
            .await
            .map_err(|e| CoreError::Machine(format!("failed to connect to agent: {}", e)))?;

        self.connected = true;
        tracing::debug!(cid = self.cid, "connected to agent");
        Ok(())
    }

    /// Disconnects from the agent.
    pub async fn disconnect(&mut self) -> Result<()> {
        if self.connected {
            self.transport
                .disconnect()
                .await
                .map_err(|e| CoreError::Machine(format!("failed to disconnect: {}", e)))?;
            self.connected = false;
        }
        Ok(())
    }

    /// Sends an RPC request and receives a response.
    async fn rpc_call(&mut self, msg_type: MessageType, payload: &[u8]) -> Result<(u32, Vec<u8>)> {
        if !self.connected {
            self.connect().await?;
        }

        // Build message: length (4B BE) + type (4B BE) + payload
        let length = 4 + payload.len() as u32;
        let mut buf = BytesMut::with_capacity(8 + payload.len());
        buf.put_u32(length);
        buf.put_u32(msg_type as u32);
        buf.extend_from_slice(payload);

        // Send request
        self.transport
            .send(buf.freeze())
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send request: {}", e)))?;

        // Receive response
        let response = self
            .transport
            .recv()
            .await
            .map_err(|e| CoreError::Machine(format!("failed to receive response: {}", e)))?;

        // Parse response: length (4B BE) + type (4B BE) + payload
        if response.len() < 8 {
            return Err(CoreError::Machine("response too short".to_string()));
        }

        let mut cursor = std::io::Cursor::new(&response[..]);
        let _length = cursor.get_u32();
        let resp_type = cursor.get_u32();
        let payload = response[8..].to_vec();

        // Check for error response
        if resp_type == MessageType::Error as u32 {
            let error_msg = parse_error_response(&payload)?;
            return Err(CoreError::Machine(error_msg));
        }

        Ok((resp_type, payload))
    }

    /// Pings the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the ping fails.
    pub async fn ping(&mut self) -> Result<PingResponse> {
        let req = PingRequest {
            message: "ping".to_string(),
        };
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self.rpc_call(MessageType::PingRequest, &payload).await?;

        if resp_type != MessageType::PingResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        PingResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Gets system information from the guest.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn get_system_info(&mut self) -> Result<SystemInfo> {
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::GetSystemInfoRequest, &[])
            .await?;

        if resp_type != MessageType::GetSystemInfoResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        SystemInfo::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
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
                "unexpected response type: {}",
                resp_type
            )));
        }

        RuntimeEnsureResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
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
                "unexpected response type: {}",
                resp_type
            )));
        }

        RuntimeStatusResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Creates a container in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if container creation fails.
    pub async fn create_container(&mut self, req: CreateContainerRequest) -> Result<String> {
        let payload = req.encode_to_vec();
        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::CreateContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::CreateContainerResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        let resp = CreateContainerResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))?;

        Ok(resp.id)
    }

    /// Starts a container in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be started.
    pub async fn start_container(&mut self, id: &str) -> Result<()> {
        let req = StartContainerRequest { id: id.to_string() };
        let payload = req.encode_to_vec();

        let (resp_type, _) = self
            .rpc_call(MessageType::StartContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::EmptyResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Stops a container in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be stopped.
    pub async fn stop_container(&mut self, id: &str, timeout: u32) -> Result<()> {
        let req = StopContainerRequest {
            id: id.to_string(),
            timeout,
        };
        let payload = req.encode_to_vec();

        let (resp_type, _) = self
            .rpc_call(MessageType::StopContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::EmptyResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Kills a container in the guest VM with a signal.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be killed.
    pub async fn kill_container(&mut self, id: &str, signal: &str) -> Result<()> {
        let req = KillContainerRequest {
            id: id.to_string(),
            signal: signal.to_string(),
        };
        let payload = req.encode_to_vec();

        let (resp_type, _) = self
            .rpc_call(MessageType::KillContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::EmptyResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Waits for a container to exit in the guest VM.
    ///
    /// Blocks until the container exits and returns its exit code.
    ///
    /// # Errors
    ///
    /// Returns an error if the wait fails.
    pub async fn wait_container(&mut self, id: &str) -> Result<i32> {
        let req = WaitContainerRequest {
            id: id.to_string(),
            condition: String::new(),
        };
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::WaitContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::WaitContainerResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        let resp = WaitContainerResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))?;

        Ok(resp.status_code as i32)
    }

    /// Pauses a container in the guest VM.
    ///
    /// Sends SIGSTOP to suspend all processes in the container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be paused.
    pub async fn pause_container(&mut self, id: &str) -> Result<()> {
        let req = PauseContainerRequest { id: id.to_string() };
        let payload = req.encode_to_vec();

        let (resp_type, _) = self
            .rpc_call(MessageType::PauseContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::EmptyResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Unpauses a container in the guest VM.
    ///
    /// Sends SIGCONT to resume all processes in the container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be unpaused.
    pub async fn unpause_container(&mut self, id: &str) -> Result<()> {
        let req = UnpauseContainerRequest { id: id.to_string() };
        let payload = req.encode_to_vec();

        let (resp_type, _) = self
            .rpc_call(MessageType::UnpauseContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::EmptyResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Gets container statistics from the guest VM.
    ///
    /// Returns CPU, memory, and I/O statistics for a running container.
    ///
    /// # Errors
    ///
    /// Returns an error if the stats cannot be retrieved.
    pub async fn container_stats(&mut self, id: &str) -> Result<ContainerStatsResponse> {
        let req = ContainerStatsRequest { id: id.to_string() };
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::ContainerStatsRequest, &payload)
            .await?;

        if resp_type != MessageType::ContainerStatsResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        ContainerStatsResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Gets the process list for a container in the guest VM.
    ///
    /// Returns process information similar to `docker top`.
    ///
    /// # Errors
    ///
    /// Returns an error if the process list cannot be retrieved.
    pub async fn container_top(&mut self, id: &str, ps_args: &str) -> Result<ContainerTopResponse> {
        let req = ContainerTopRequest {
            id: id.to_string(),
            ps_args: ps_args.to_string(),
        };
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::ContainerTopRequest, &payload)
            .await?;

        if resp_type != MessageType::ContainerTopResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        ContainerTopResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Removes a container from the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be removed.
    pub async fn remove_container(&mut self, id: &str, force: bool) -> Result<()> {
        let req = RemoveContainerRequest {
            id: id.to_string(),
            force,
        };
        let payload = req.encode_to_vec();

        let (resp_type, _) = self
            .rpc_call(MessageType::RemoveContainerRequest, &payload)
            .await?;

        if resp_type != MessageType::EmptyResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Lists containers in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub async fn list_containers(&mut self, all: bool) -> Result<ListContainersResponse> {
        let req = ListContainersRequest { all };
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::ListContainersRequest, &payload)
            .await?;

        if resp_type != MessageType::ListContainersResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        ListContainersResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Executes a command in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the exec fails.
    pub async fn exec(&mut self, req: ExecRequest) -> Result<ExecOutput> {
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self.rpc_call(MessageType::ExecRequest, &payload).await?;

        if resp_type != MessageType::ExecOutput as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        ExecOutput::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Gets container logs from the guest VM (single response).
    ///
    /// # Errors
    ///
    /// Returns an error if the logs request fails.
    pub async fn logs(&mut self, req: LogsRequest) -> Result<LogEntry> {
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self.rpc_call(MessageType::LogsRequest, &payload).await?;

        if resp_type != MessageType::LogEntry as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        LogEntry::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Gets container logs as a stream (for follow mode).
    ///
    /// Creates a dedicated streaming connection to avoid blocking the main client.
    /// The stream continues until the container stops, an error occurs, or the
    /// receiver is dropped.
    ///
    /// # Architecture
    ///
    /// ## Linux
    /// Creates a new AF_VSOCK connection specifically for streaming, following
    /// Docker's pattern where log streaming uses a dedicated channel.
    ///
    /// ## macOS
    /// On macOS, vsock connections must go through the hypervisor layer
    /// (VZVirtioSocketDevice) rather than AF_VSOCK. This method cannot create
    /// new connections internally. Instead, it takes ownership of the current
    /// transport via `logs_stream_shared()`. Callers must ensure each logs_stream
    /// call uses a fresh AgentClient obtained from `MachineManager::connect_agent()`.
    ///
    /// # Errors
    ///
    /// Returns an error if connection or initial request fails.
    pub async fn logs_stream(
        &mut self,
        req: LogsRequest,
    ) -> Result<ReceiverStream<Result<LogEntry>>> {
        // Create a dedicated transport for streaming.
        // This avoids blocking the main client connection.
        let addr = VsockAddr::new(self.cid, AGENT_PORT);
        let mut stream_transport = VsockTransport::new(addr);

        // Connect the streaming transport.
        #[cfg(target_os = "macos")]
        {
            // On macOS, vsock connections require hypervisor layer involvement.
            // We take ownership of the existing transport for dedicated streaming.
            // This is safe because Runtime creates a fresh AgentClient for each
            // logs_stream call via MachineManager::connect_agent().
            return self.logs_stream_shared(req).await;
        }

        #[cfg(target_os = "linux")]
        {
            stream_transport.connect().await.map_err(|e| {
                CoreError::Machine(format!("failed to connect stream transport: {}", e))
            })?;
        }

        let payload = req.encode_to_vec();

        // Build message: length (4B BE) + type (4B BE) + payload
        let length = 4 + payload.len() as u32;
        let mut buf = BytesMut::with_capacity(8 + payload.len());
        buf.put_u32(length);
        buf.put_u32(MessageType::LogsRequest as u32);
        buf.extend_from_slice(&payload);

        // Send request on the dedicated stream transport.
        stream_transport
            .send(buf.freeze())
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send request: {}", e)))?;

        // Create channel for streaming responses.
        // Buffer size of 256 provides good throughput while limiting memory usage.
        let (tx, rx) = mpsc::channel(256);
        let cid = self.cid;

        // Spawn background task to continuously read log entries.
        tokio::spawn(async move {
            let _cleanup = LogStreamCleanup { cid };

            loop {
                // Read response with timeout to detect stale connections.
                let recv_result = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    stream_transport.recv(),
                )
                .await;

                let response = match recv_result {
                    Ok(Ok(data)) => data,
                    Ok(Err(e)) => {
                        tracing::debug!(cid = cid, "log stream transport error: {}", e);
                        let _ = tx.send(Err(CoreError::Machine(e.to_string()))).await;
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue waiting for more logs.
                        // This is normal for containers with infrequent output.
                        tracing::trace!(cid = cid, "log stream timeout, continuing...");
                        continue;
                    }
                };

                if response.len() < 8 {
                    tracing::warn!(cid = cid, "log stream received short response");
                    continue;
                }

                let mut cursor = std::io::Cursor::new(&response[..]);
                let _length = cursor.get_u32();
                let resp_type = cursor.get_u32();
                let resp_payload = response[8..].to_vec();

                // Check for error response.
                if resp_type == MessageType::Error as u32 {
                    let error_msg = parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| "unknown error".to_string());
                    let _ = tx.send(Err(CoreError::Machine(error_msg))).await;
                    break;
                }

                // Check for stream end marker.
                if resp_type == MessageType::EmptyResponse as u32 {
                    tracing::debug!(cid = cid, "log stream ended (received end marker)");
                    break;
                }

                if resp_type != MessageType::LogEntry as u32 {
                    tracing::warn!(
                        cid = cid,
                        "unexpected response type in log stream: {}",
                        resp_type
                    );
                    continue;
                }

                // Parse log entry.
                let entry = match LogEntry::decode(&resp_payload[..]) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(cid = cid, "failed to decode log entry: {}", e);
                        continue;
                    }
                };

                // Send to channel. If receiver is dropped, exit gracefully.
                if tx.send(Ok(entry)).await.is_err() {
                    tracing::debug!(cid = cid, "log stream receiver dropped");
                    break;
                }
            }

            tracing::debug!(cid = cid, "log stream task exiting");
        });

        tracing::debug!(cid = self.cid, "started log stream");
        Ok(ReceiverStream::new(rx))
    }

    /// Takes ownership of the transport and runs log streaming in a background task.
    ///
    /// # macOS-specific Implementation
    ///
    /// On macOS, vsock connections must go through the hypervisor layer
    /// (Virtualization.framework's VZVirtioSocketDevice). Unlike Linux where we can
    /// create new AF_VSOCK connections directly, macOS requires the hypervisor to
    /// provide file descriptors.
    ///
    /// This method takes ownership of the existing transport for dedicated log
    /// streaming. After calling this method, the AgentClient is marked as disconnected
    /// and should not be reused.
    ///
    /// # Safety Contract
    ///
    /// Callers MUST use a fresh AgentClient obtained from `MachineManager::connect_agent()`
    /// for each logs_stream call. The Runtime layer enforces this pattern.
    #[cfg(target_os = "macos")]
    async fn logs_stream_shared(
        &mut self,
        req: LogsRequest,
    ) -> Result<ReceiverStream<Result<LogEntry>>> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();

        // Build message: length (4B BE) + type (4B BE) + payload
        let length = 4 + payload.len() as u32;
        let mut buf = BytesMut::with_capacity(8 + payload.len());
        buf.put_u32(length);
        buf.put_u32(MessageType::LogsRequest as u32);
        buf.extend_from_slice(&payload);

        // Send request.
        self.transport
            .send(buf.freeze())
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send request: {}", e)))?;

        // Create channel for streaming responses.
        let (tx, rx) = mpsc::channel(256);
        let cid = self.cid;

        // Take ownership of the transport for dedicated streaming.
        // See doc comment for safety contract.
        let addr = VsockAddr::new(self.cid, AGENT_PORT);
        let mut stream_transport =
            std::mem::replace(&mut self.transport, VsockTransport::new(addr));
        self.connected = false;

        // Spawn background task to continuously read log entries.
        tokio::spawn(async move {
            let _cleanup = LogStreamCleanup { cid };

            loop {
                // Read response with timeout.
                let recv_result = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    stream_transport.recv(),
                )
                .await;

                let response = match recv_result {
                    Ok(Ok(data)) => data,
                    Ok(Err(e)) => {
                        tracing::debug!(cid = cid, "log stream transport error: {}", e);
                        let _ = tx.send(Err(CoreError::Machine(e.to_string()))).await;
                        break;
                    }
                    Err(_) => {
                        // Timeout - continue waiting for more logs.
                        tracing::trace!(cid = cid, "log stream timeout, continuing...");
                        continue;
                    }
                };

                if response.len() < 8 {
                    tracing::warn!(cid = cid, "log stream received short response");
                    continue;
                }

                let mut cursor = std::io::Cursor::new(&response[..]);
                let _length = cursor.get_u32();
                let resp_type = cursor.get_u32();
                let resp_payload = response[8..].to_vec();

                // Check for error response.
                if resp_type == MessageType::Error as u32 {
                    let error_msg = parse_error_response(&resp_payload)
                        .unwrap_or_else(|_| "unknown error".to_string());
                    let _ = tx.send(Err(CoreError::Machine(error_msg))).await;
                    break;
                }

                // Check for stream end marker.
                if resp_type == MessageType::EmptyResponse as u32 {
                    tracing::debug!(cid = cid, "log stream ended (received end marker)");
                    break;
                }

                if resp_type != MessageType::LogEntry as u32 {
                    tracing::warn!(
                        cid = cid,
                        "unexpected response type in log stream: {}",
                        resp_type
                    );
                    continue;
                }

                // Parse log entry.
                let entry = match LogEntry::decode(&resp_payload[..]) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(cid = cid, "failed to decode log entry: {}", e);
                        continue;
                    }
                };

                // Send to channel. If receiver is dropped, exit gracefully.
                if tx.send(Ok(entry)).await.is_err() {
                    tracing::debug!(cid = cid, "log stream receiver dropped");
                    break;
                }
            }

            tracing::debug!(cid = cid, "log stream task exiting");
        });

        tracing::debug!(cid = cid, "started log stream (macOS)");
        Ok(ReceiverStream::new(rx))
    }

    /// Starts an exec instance in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the exec start fails.
    pub async fn exec_start(&mut self, req: ExecStartRequest) -> Result<ExecStartResponse> {
        let payload = req.encode_to_vec();

        let (resp_type, resp_payload) = self
            .rpc_call(MessageType::ExecStartRequest, &payload)
            .await?;

        if resp_type != MessageType::ExecStartResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        ExecStartResponse::decode(&resp_payload[..])
            .map_err(|e| CoreError::Machine(format!("failed to decode response: {}", e)))
    }

    /// Resizes an exec instance's TTY in the guest VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the resize fails.
    pub async fn exec_resize(&mut self, req: ExecResizeRequest) -> Result<()> {
        let payload = req.encode_to_vec();

        let (resp_type, _) = self
            .rpc_call(MessageType::ExecResizeRequest, &payload)
            .await?;

        if resp_type != MessageType::EmptyResponse as u32 {
            return Err(CoreError::Machine(format!(
                "unexpected response type: {}",
                resp_type
            )));
        }

        Ok(())
    }

    /// Attaches to a running container for bidirectional I/O.
    ///
    /// Returns a stream of outputs and a sender for stdin/resize messages.
    ///
    /// # Ownership
    ///
    /// This method takes ownership of the transport for dedicated bidirectional
    /// streaming. After calling this method, the AgentClient is marked as disconnected
    /// and should not be reused. Callers should use a fresh AgentClient obtained
    /// from `MachineManager::connect_agent()`.
    pub async fn attach_stream(
        &mut self,
        req: AttachRequest,
    ) -> Result<(
        ReceiverStream<Result<AttachOutput>>,
        mpsc::Sender<AttachInput>,
    )> {
        if !self.connected {
            self.connect().await?;
        }

        let payload = req.encode_to_vec();
        tracing::debug!(
            "attach_stream: sending AttachRequest, container_id={}, exec_id={}",
            req.container_id,
            req.exec_id
        );

        // Build message: length (4B BE) + type (4B BE) + payload
        let length = 4 + payload.len() as u32;
        let mut buf = BytesMut::with_capacity(8 + payload.len());
        buf.put_u32(length);
        buf.put_u32(MessageType::AttachRequest as u32);
        buf.extend_from_slice(&payload);

        // Send request.
        self.transport
            .send(buf.freeze())
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send attach request: {}", e)))?;
        tracing::debug!("attach_stream: AttachRequest sent successfully");

        // Take ownership of transport for streaming.
        let addr = VsockAddr::new(self.cid, AGENT_PORT);
        let transport = std::mem::replace(&mut self.transport, VsockTransport::new(addr));
        self.connected = false;

        let transport = Arc::new(tokio::sync::Mutex::new(transport));
        let (tx_out, rx_out) = mpsc::channel(256);
        let (tx_in, mut rx_in) = mpsc::channel::<AttachInput>(64);
        let cid = self.cid;

        // Reader task: forward attach outputs.
        {
            let transport = Arc::clone(&transport);
            let tx_out = tx_out.clone();
            tokio::spawn(async move {
                let _cleanup = AttachStreamCleanup { cid };
                tracing::debug!(cid = cid, "attach reader task started");
                loop {
                    tracing::debug!(cid = cid, "attach reader: waiting for response...");
                    // Use a 90-second timeout to allow agent's 60-second broadcaster wait plus margin.
                    let response = {
                        let mut locked = transport.lock().await;
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(90),
                            locked.recv(),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => {
                                tracing::warn!(
                                    cid = cid,
                                    "attach reader: recv timed out after 90 seconds"
                                );
                                Err(arcbox_transport::error::TransportError::io(
                                    std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        "attach recv timed out",
                                    ),
                                ))
                            }
                        }
                    };

                    let data = match response {
                        Ok(d) => {
                            tracing::debug!(cid = cid, "attach reader: received {} bytes", d.len());
                            d
                        }
                        Err(e) => {
                            tracing::debug!(cid = cid, "attach reader: recv error: {}", e);
                            let _ = tx_out.send(Err(CoreError::Machine(e.to_string()))).await;
                            break;
                        }
                    };

                    if data.len() < 8 {
                        let _ = tx_out
                            .send(Err(CoreError::Machine("short attach response".to_string())))
                            .await;
                        break;
                    }

                    let mut cursor = std::io::Cursor::new(&data[..]);
                    let _length = cursor.get_u32();
                    let resp_type = cursor.get_u32();
                    let resp_payload = data[8..].to_vec();

                    tracing::debug!(
                        cid = cid,
                        "attach reader: received response type={}, payload_len={}",
                        resp_type,
                        resp_payload.len()
                    );

                    if resp_type == MessageType::Error as u32 {
                        let error_msg = parse_error_response(&resp_payload)
                            .unwrap_or_else(|_| "unknown error".to_string());
                        let _ = tx_out.send(Err(CoreError::Machine(error_msg))).await;
                        break;
                    }

                    if resp_type == MessageType::EmptyResponse as u32 {
                        // End of stream
                        tracing::debug!(
                            cid = cid,
                            "attach reader: received EmptyResponse, ending stream"
                        );
                        break;
                    }

                    if resp_type != MessageType::AttachOutput as u32 {
                        tracing::warn!(
                            cid = cid,
                            "unexpected response type in attach stream: {}",
                            resp_type
                        );
                        continue;
                    }

                    match AttachOutput::decode(&resp_payload[..]) {
                        Ok(out) => {
                            if tx_out.send(Ok(out)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(cid = cid, "failed to decode attach output: {}", e);
                        }
                    }
                }
            });
        }

        // Writer task: forward stdin/resizes.
        {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move {
                while let Some(input) = rx_in.recv().await {
                    let payload = input.encode_to_vec();
                    let length = 4 + payload.len() as u32;
                    let mut buf = BytesMut::with_capacity(8 + payload.len());
                    buf.put_u32(length);
                    buf.put_u32(MessageType::AttachInput as u32);
                    buf.extend_from_slice(&payload);

                    let send_result = {
                        let mut locked = transport.lock().await;
                        locked.send(buf.freeze()).await
                    };

                    if let Err(e) = send_result {
                        tracing::warn!(cid = cid, "failed to send attach input: {}", e);
                        break;
                    }
                }
            });
        }

        Ok((ReceiverStream::new(rx_out), tx_in))
    }
}

/// Cleanup guard for log stream tasks.
///
/// Ensures proper logging when the streaming task exits.
struct LogStreamCleanup {
    cid: u32,
}

impl Drop for LogStreamCleanup {
    fn drop(&mut self) {
        tracing::trace!(cid = self.cid, "log stream cleanup complete");
    }
}

/// Cleanup guard for attach stream tasks.
struct AttachStreamCleanup {
    cid: u32,
}

impl Drop for AttachStreamCleanup {
    fn drop(&mut self) {
        tracing::trace!(cid = self.cid, "attach stream cleanup complete");
    }
}

/// Parses an error response from the agent.
fn parse_error_response(payload: &[u8]) -> Result<String> {
    if payload.len() < 8 {
        return Ok("unknown error".to_string());
    }

    let mut cursor = std::io::Cursor::new(payload);
    let _code = cursor.get_i32();
    let msg_len = cursor.get_u32() as usize;

    if payload.len() < 8 + msg_len {
        return Ok("truncated error message".to_string());
    }

    String::from_utf8(payload[8..8 + msg_len].to_vec())
        .map_err(|_| CoreError::Machine("invalid error message encoding".to_string()))
}

/// Agent connection pool for managing connections to multiple VMs.
pub struct AgentPool {
    /// Connections by VM CID.
    connections: RwLock<HashMap<u32, Arc<RwLock<AgentClient>>>>,
}

impl AgentPool {
    /// Creates a new agent pool.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Gets or creates a connection to the agent for the given VM CID.
    pub async fn get(&self, cid: u32) -> Arc<RwLock<AgentClient>> {
        // Check if we already have a connection
        {
            let connections = self.connections.read().await;
            if let Some(client) = connections.get(&cid) {
                return Arc::clone(client);
            }
        }

        // Create new connection
        let client = Arc::new(RwLock::new(AgentClient::new(cid)));

        // Store it
        {
            let mut connections = self.connections.write().await;
            connections.insert(cid, Arc::clone(&client));
        }

        client
    }

    /// Removes a connection from the pool.
    pub async fn remove(&self, cid: u32) {
        let mut connections = self.connections.write().await;
        connections.remove(&cid);
    }
}

impl Default for AgentPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper for `AgentClient` that implements `AgentConnection` trait.
///
/// This wrapper allows `AgentClient` to be used with `ContainerManager`.
pub struct AgentClientWrapper {
    client: RwLock<AgentClient>,
}

impl AgentClientWrapper {
    /// Creates a new wrapper from an `AgentClient`.
    #[must_use]
    pub fn new(client: AgentClient) -> Self {
        Self {
            client: RwLock::new(client),
        }
    }
}

#[async_trait]
impl AgentConnection for AgentClientWrapper {
    async fn start_container(&self, id: &str) -> std::result::Result<(), String> {
        let mut client = self.client.write().await;
        client.start_container(id).await.map_err(|e| e.to_string())
    }

    async fn stop_container(&self, id: &str, timeout: u32) -> std::result::Result<(), String> {
        let mut client = self.client.write().await;
        client
            .stop_container(id, timeout)
            .await
            .map_err(|e| e.to_string())
    }

    async fn kill_container(&self, id: &str, signal: &str) -> std::result::Result<(), String> {
        let mut client = self.client.write().await;
        client
            .kill_container(id, signal)
            .await
            .map_err(|e| e.to_string())
    }

    async fn wait_container(&self, id: &str) -> std::result::Result<i32, String> {
        let mut client = self.client.write().await;
        client.wait_container(id).await.map_err(|e| e.to_string())
    }
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
            MessageType::from_u32(MessageType::CreateContainerRequest as u32),
            Some(MessageType::CreateContainerRequest)
        );
    }

    #[test]
    fn test_agent_client_new() {
        let client = AgentClient::new(3);
        assert_eq!(client.cid(), 3);
        assert!(!client.connected);
    }

    #[test]
    fn test_agent_pool_new() {
        let pool = AgentPool::new();
        // Pool should be empty initially
        let connections = pool.connections.blocking_read();
        assert!(connections.is_empty());
    }
}
