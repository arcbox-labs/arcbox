//! Agent client for communicating with the guest VM.
//!
//! Provides RPC communication with the arcbox-agent running inside guest VMs.

use crate::error::{CoreError, Result};
use arcbox_constants::ports::AGENT_PORT;
use arcbox_constants::wire::{
    ERROR_HEADER_SIZE, FRAME_HEADER_SIZE, MessageType, TRACE_LEN_FIELD_SIZE, TYPE_FIELD_SIZE,
};
use arcbox_protocol::agent::{
    PingRequest, PingResponse, RuntimeEnsureRequest, RuntimeEnsureResponse, RuntimeStatusRequest,
    RuntimeStatusResponse, SystemInfo,
};
use arcbox_transport::Transport;
use arcbox_transport::vsock::{VsockAddr, VsockTransport};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message;

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

    /// Builds a V2 wire message with an optional trace_id.
    ///
    /// Wire format V2:
    /// ```text
    /// +----------------+----------------+------------------+----------------+
    /// | Length (4B BE) | Type (4B BE)   | TraceLen (2B BE) | TraceID bytes  | Payload
    /// +----------------+----------------+------------------+----------------+
    /// ```
    fn build_message(msg_type: MessageType, trace_id: &str, payload: &[u8]) -> Bytes {
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

    /// Parses a V2 wire response. Returns (resp_type, trace_id, payload).
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

    /// Sends an RPC request with a trace_id and receives a response.
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

        // Send request.
        self.transport
            .send(buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to send request: {}", e)))?;

        // Receive response.
        let response = self
            .transport
            .recv()
            .await
            .map_err(|e| CoreError::Machine(format!("failed to receive response: {}", e)))?;

        let (resp_type, _resp_trace, payload) = Self::parse_response(&response)?;

        // Check for error response.
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
