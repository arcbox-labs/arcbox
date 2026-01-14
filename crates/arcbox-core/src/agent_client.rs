//! Agent client for communicating with the guest VM.
//!
//! Provides RPC communication with the arcbox-agent running inside guest VMs.

use crate::error::{CoreError, Result};
use arcbox_container::AgentConnection;
use arcbox_protocol::agent::{
    CreateContainerRequest, CreateContainerResponse, ExecOutput, ExecRequest,
    ExecResizeRequest, ExecStartRequest, ExecStartResponse, ListContainersRequest,
    ListContainersResponse, LogEntry, LogsRequest, PingRequest, PingResponse,
    RemoveContainerRequest, StartContainerRequest, StopContainerRequest, SystemInfo,
};
use arcbox_protocol::container::{KillContainerRequest, WaitContainerRequest, WaitContainerResponse};
use arcbox_protocol::Empty;
use arcbox_transport::vsock::{VsockAddr, VsockTransport};
use arcbox_transport::Transport;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
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
    CreateContainerRequest = 0x0010,
    StartContainerRequest = 0x0011,
    StopContainerRequest = 0x0012,
    RemoveContainerRequest = 0x0013,
    ListContainersRequest = 0x0014,
    KillContainerRequest = 0x0015,
    WaitContainerRequest = 0x0016,
    ExecRequest = 0x0020,
    LogsRequest = 0x0021,
    ExecStartRequest = 0x0022,
    ExecResizeRequest = 0x0023,

    // Response types
    PingResponse = 0x1001,
    WaitContainerResponse = 0x1016,
    GetSystemInfoResponse = 0x1002,
    CreateContainerResponse = 0x1010,
    ListContainersResponse = 0x1014,
    ExecOutput = 0x1020,
    LogEntry = 0x1021,
    ExecStartResponse = 0x1022,

    // Special types
    EmptyResponse = 0x0000,
    Error = 0xFFFF,
}

impl MessageType {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0001 => Some(Self::PingRequest),
            0x0002 => Some(Self::GetSystemInfoRequest),
            0x0010 => Some(Self::CreateContainerRequest),
            0x0011 => Some(Self::StartContainerRequest),
            0x0012 => Some(Self::StopContainerRequest),
            0x0013 => Some(Self::RemoveContainerRequest),
            0x0014 => Some(Self::ListContainersRequest),
            0x0015 => Some(Self::KillContainerRequest),
            0x0016 => Some(Self::WaitContainerRequest),
            0x0020 => Some(Self::ExecRequest),
            0x0021 => Some(Self::LogsRequest),
            0x0022 => Some(Self::ExecStartRequest),
            0x0023 => Some(Self::ExecResizeRequest),
            0x1001 => Some(Self::PingResponse),
            0x1016 => Some(Self::WaitContainerResponse),
            0x1002 => Some(Self::GetSystemInfoResponse),
            0x1010 => Some(Self::CreateContainerResponse),
            0x1014 => Some(Self::ListContainersResponse),
            0x1020 => Some(Self::ExecOutput),
            0x1021 => Some(Self::LogEntry),
            0x1022 => Some(Self::ExecStartResponse),
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

        let (resp_type, resp_payload) =
            self.rpc_call(MessageType::ExecRequest, &payload).await?;

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

        let (resp_type, resp_payload) =
            self.rpc_call(MessageType::LogsRequest, &payload).await?;

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
    /// This method creates a new vsock connection specifically for streaming,
    /// following Docker's pattern where log streaming uses a dedicated channel.
    /// This allows the main AgentClient to remain usable for other operations.
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
            // On macOS, we need to get a new fd from the hypervisor.
            // For now, reuse the existing transport for the initial request,
            // then hand off to a background task.
            // TODO: Support creating new vsock connections on macOS.
            return self.logs_stream_shared(req).await;
        }

        #[cfg(target_os = "linux")]
        {
            stream_transport
                .connect()
                .await
                .map_err(|e| CoreError::Machine(format!("failed to connect stream transport: {}", e)))?;
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
    /// On macOS, each call to `connect_agent` creates a new AgentClient with its
    /// own transport, so we can safely take ownership here.
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

        // Take ownership of the transport for the background task.
        // This is safe on macOS because each logs_stream call uses a fresh AgentClient
        // created by connect_agent, so the transport is not shared.
        let addr = VsockAddr::new(self.cid, AGENT_PORT);
        let mut stream_transport = std::mem::replace(
            &mut self.transport,
            VsockTransport::new(addr),
        );
        self.connected = false; // Mark as disconnected since we took the transport

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
        client.stop_container(id, timeout).await.map_err(|e| e.to_string())
    }

    async fn kill_container(&self, id: &str, signal: &str) -> std::result::Result<(), String> {
        let mut client = self.client.write().await;
        client.kill_container(id, signal).await.map_err(|e| e.to_string())
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
