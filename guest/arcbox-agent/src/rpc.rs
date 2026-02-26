//! RPC protocol implementation for Guest Agent.
//!
//! This module implements a simple length-prefixed RPC protocol over vsock.
//! The protocol uses protobuf for message serialization.
//!
//! ## Wire Format
//!
//! ```text
//! +----------------+----------------+----------------+
//! | Length (4B BE) | Type (4B BE)   | Payload        |
//! +----------------+----------------+----------------+
//! ```
//!
//! - Length: Total size of Type + Payload in big-endian
//! - Type: Message type identifier
//! - Payload: Protobuf-encoded message

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use arcbox_protocol::Empty;
use arcbox_protocol::agent::{
    CreateContainerRequest, CreateContainerResponse, ExecOutput, ExecRequest, ExecResizeRequest,
    ExecStartRequest, ExecStartResponse, ListContainersRequest, ListContainersResponse, LogEntry,
    LogsRequest, PingRequest, PingResponse, PortBindingsChanged, PortBindingsRemoved,
    RemoveContainerRequest, RuntimeEnsureRequest, RuntimeEnsureResponse, RuntimeStatusRequest,
    RuntimeStatusResponse, StartContainerRequest, StopContainerRequest, SystemInfo,
};
use arcbox_protocol::container::{
    ContainerStatsRequest, ContainerStatsResponse, ContainerTopRequest, ContainerTopResponse,
    KillContainerRequest, PauseContainerRequest, UnpauseContainerRequest, WaitContainerRequest,
    WaitContainerResponse,
};

/// Agent version string.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// RPC message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MessageType {
    // Request types (0x0000 - 0x0FFF)
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

    // Response types (0x1000 - 0x1FFF)
    PingResponse = 0x1001,
    GetSystemInfoResponse = 0x1002,
    EnsureRuntimeResponse = 0x1003,
    RuntimeStatusResponse = 0x1004,
    CreateContainerResponse = 0x1010,
    StartContainerResponse = 0x1011,
    StopContainerResponse = 0x1012,
    RemoveContainerResponse = 0x1013,
    ListContainersResponse = 0x1014,
    KillContainerResponse = 0x1015,
    WaitContainerResponse = 0x1016,
    PauseContainerResponse = 0x1017,
    UnpauseContainerResponse = 0x1018,
    ContainerStatsResponse = 0x1019,
    ContainerTopResponse = 0x101A,
    ExecOutput = 0x1020,
    LogEntry = 0x1021,
    ExecStartResponse = 0x1022,
    AttachOutput = 0x1023,
    PortBindingsChanged = 0x1030,
    PortBindingsRemoved = 0x1031,

    // Special types
    Empty = 0x0000,
    Error = 0xFFFF,
}

impl MessageType {
    /// Converts a u32 to a MessageType.
    pub fn from_u32(value: u32) -> Option<Self> {
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
            0x1002 => Some(Self::GetSystemInfoResponse),
            0x1003 => Some(Self::EnsureRuntimeResponse),
            0x1004 => Some(Self::RuntimeStatusResponse),
            0x1010 => Some(Self::CreateContainerResponse),
            0x1011 => Some(Self::StartContainerResponse),
            0x1012 => Some(Self::StopContainerResponse),
            0x1013 => Some(Self::RemoveContainerResponse),
            0x1014 => Some(Self::ListContainersResponse),
            0x1015 => Some(Self::KillContainerResponse),
            0x1016 => Some(Self::WaitContainerResponse),
            0x1017 => Some(Self::PauseContainerResponse),
            0x1018 => Some(Self::UnpauseContainerResponse),
            0x1019 => Some(Self::ContainerStatsResponse),
            0x101A => Some(Self::ContainerTopResponse),
            0x1020 => Some(Self::ExecOutput),
            0x1021 => Some(Self::LogEntry),
            0x1022 => Some(Self::ExecStartResponse),
            0x1023 => Some(Self::AttachOutput),
            0x1030 => Some(Self::PortBindingsChanged),
            0x1031 => Some(Self::PortBindingsRemoved),
            0x0000 => Some(Self::Empty),
            0xFFFF => Some(Self::Error),
            _ => None,
        }
    }
}

/// Error response message.
#[derive(Debug, Clone)]
pub struct ErrorResponse {
    pub code: i32,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.put_i32(self.code);
        let msg_bytes = self.message.as_bytes();
        buf.put_u32(msg_bytes.len() as u32);
        buf.extend_from_slice(msg_bytes);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        if data.len() < 8 {
            anyhow::bail!("error response too short");
        }
        let code = cursor.get_i32();
        let msg_len = cursor.get_u32() as usize;
        if data.len() < 8 + msg_len {
            anyhow::bail!("error response message truncated");
        }
        let message = String::from_utf8(data[8..8 + msg_len].to_vec())?;
        Ok(Self { code, message })
    }
}

/// RPC request envelope.
#[derive(Debug)]
pub enum RpcRequest {
    Ping(PingRequest),
    GetSystemInfo,
    EnsureRuntime(RuntimeEnsureRequest),
    RuntimeStatus(RuntimeStatusRequest),
    CreateContainer(CreateContainerRequest),
    StartContainer(StartContainerRequest),
    StopContainer(StopContainerRequest),
    RemoveContainer(RemoveContainerRequest),
    ListContainers(ListContainersRequest),
    KillContainer(KillContainerRequest),
    WaitContainer(WaitContainerRequest),
    PauseContainer(PauseContainerRequest),
    UnpauseContainer(UnpauseContainerRequest),
    ContainerStats(ContainerStatsRequest),
    ContainerTop(ContainerTopRequest),
    Exec(ExecRequest),
    Logs(LogsRequest),
    ExecStart(ExecStartRequest),
    ExecResize(ExecResizeRequest),
    Attach(arcbox_protocol::agent::AttachRequest),
    AttachInput(arcbox_protocol::agent::AttachInput),
}

/// RPC response envelope.
#[derive(Debug)]
pub enum RpcResponse {
    Ping(PingResponse),
    SystemInfo(SystemInfo),
    RuntimeEnsure(RuntimeEnsureResponse),
    RuntimeStatus(RuntimeStatusResponse),
    CreateContainer(CreateContainerResponse),
    Empty,
    ListContainers(ListContainersResponse),
    WaitContainer(WaitContainerResponse),
    ContainerStats(ContainerStatsResponse),
    ContainerTop(ContainerTopResponse),
    ExecOutput(ExecOutput),
    LogEntry(LogEntry),
    ExecStart(ExecStartResponse),
    AttachOutput(arcbox_protocol::agent::AttachOutput),
    PortBindingsChanged(PortBindingsChanged),
    PortBindingsRemoved(PortBindingsRemoved),
    Error(ErrorResponse),
}

impl RpcResponse {
    /// Returns the message type for this response.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Ping(_) => MessageType::PingResponse,
            Self::SystemInfo(_) => MessageType::GetSystemInfoResponse,
            Self::RuntimeEnsure(_) => MessageType::EnsureRuntimeResponse,
            Self::RuntimeStatus(_) => MessageType::RuntimeStatusResponse,
            Self::CreateContainer(_) => MessageType::CreateContainerResponse,
            Self::Empty => MessageType::Empty,
            Self::ListContainers(_) => MessageType::ListContainersResponse,
            Self::WaitContainer(_) => MessageType::WaitContainerResponse,
            Self::ContainerStats(_) => MessageType::ContainerStatsResponse,
            Self::ContainerTop(_) => MessageType::ContainerTopResponse,
            Self::ExecOutput(_) => MessageType::ExecOutput,
            Self::LogEntry(_) => MessageType::LogEntry,
            Self::ExecStart(_) => MessageType::ExecStartResponse,
            Self::AttachOutput(_) => MessageType::AttachOutput,
            Self::PortBindingsChanged(_) => MessageType::PortBindingsChanged,
            Self::PortBindingsRemoved(_) => MessageType::PortBindingsRemoved,
            Self::Error(_) => MessageType::Error,
        }
    }

    /// Encodes the response payload.
    pub fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::Ping(msg) => msg.encode_to_vec(),
            Self::SystemInfo(msg) => msg.encode_to_vec(),
            Self::RuntimeEnsure(msg) => msg.encode_to_vec(),
            Self::RuntimeStatus(msg) => msg.encode_to_vec(),
            Self::CreateContainer(msg) => msg.encode_to_vec(),
            Self::Empty => Empty::default().encode_to_vec(),
            Self::ListContainers(msg) => msg.encode_to_vec(),
            Self::WaitContainer(msg) => msg.encode_to_vec(),
            Self::ContainerStats(msg) => msg.encode_to_vec(),
            Self::ContainerTop(msg) => msg.encode_to_vec(),
            Self::ExecOutput(msg) => msg.encode_to_vec(),
            Self::LogEntry(msg) => msg.encode_to_vec(),
            Self::ExecStart(msg) => msg.encode_to_vec(),
            Self::AttachOutput(msg) => msg.encode_to_vec(),
            Self::PortBindingsChanged(msg) => msg.encode_to_vec(),
            Self::PortBindingsRemoved(msg) => msg.encode_to_vec(),
            Self::Error(err) => err.encode(),
        }
    }
}

/// Reads a single RPC message from the stream.
///
/// Wire format V2:
/// ```text
/// +----------------+----------------+------------------+----------------+
/// | Length (4B BE) | Type (4B BE)   | TraceLen (2B BE) | TraceID bytes  | Payload
/// +----------------+----------------+------------------+----------------+
/// ```
/// Length = sizeof(Type) + sizeof(TraceLen) + TraceLen + PayloadLen
///        = 4 + 2 + TraceLen + PayloadLen
///
/// Returns (message_type, trace_id, payload).
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(MessageType, String, Vec<u8>)> {
    // Read header: 4 bytes length + 4 bytes type
    let mut header = [0u8; 8];
    reader
        .read_exact(&mut header)
        .await
        .context("failed to read message header")?;

    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let msg_type_raw = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    let msg_type =
        MessageType::from_u32(msg_type_raw).context("unknown message type: {msg_type_raw}")?;

    // Remaining bytes = length - 4 (type already consumed from length).
    let remaining = length.saturating_sub(4);

    if remaining < 2 {
        // Minimal frame: just a 2-byte trace_len of 0, no payload.
        // Read whatever remains.
        let mut tail = vec![0u8; remaining];
        if remaining > 0 {
            reader
                .read_exact(&mut tail)
                .await
                .context("failed to read remaining")?;
        }
        return Ok((msg_type, String::new(), tail));
    }

    // Read trace_len (2 bytes BE).
    let mut trace_len_buf = [0u8; 2];
    reader
        .read_exact(&mut trace_len_buf)
        .await
        .context("failed to read trace length")?;
    let trace_len = u16::from_be_bytes(trace_len_buf) as usize;

    // Read trace_id bytes.
    let trace_id = if trace_len > 0 {
        let mut trace_buf = vec![0u8; trace_len];
        reader
            .read_exact(&mut trace_buf)
            .await
            .context("failed to read trace id")?;
        String::from_utf8(trace_buf).unwrap_or_default()
    } else {
        String::new()
    };

    // Payload = remaining - 2 (trace_len field) - trace_len.
    let payload_len = remaining.saturating_sub(2 + trace_len);
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("failed to read message payload")?;
    }

    Ok((msg_type, trace_id, payload))
}

/// Writes a single RPC message to the stream.
///
/// Wire format V2 (see `read_message` for layout).
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg_type: MessageType,
    trace_id: &str,
    payload: &[u8],
) -> Result<()> {
    let trace_bytes = trace_id.as_bytes();
    let trace_len = trace_bytes.len().min(u16::MAX as usize);

    // Length = type(4) + trace_len_field(2) + trace_bytes + payload
    let length = 4 + 2 + trace_len + payload.len();

    let mut buf = BytesMut::with_capacity(8 + 2 + trace_len + payload.len());
    buf.put_u32(length as u32);
    buf.put_u32(msg_type as u32);
    buf.put_u16(trace_len as u16);
    if trace_len > 0 {
        buf.extend_from_slice(&trace_bytes[..trace_len]);
    }
    buf.extend_from_slice(payload);

    writer
        .write_all(&buf)
        .await
        .context("failed to write message")?;
    writer.flush().await.context("failed to flush")?;

    Ok(())
}

/// Writes an RPC response to the stream with a trace ID.
pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &RpcResponse,
    trace_id: &str,
) -> Result<()> {
    let payload = response.encode_payload();
    write_message(writer, response.message_type(), trace_id, &payload).await
}

/// Parses an RPC request from message type and payload.
pub fn parse_request(msg_type: MessageType, payload: &[u8]) -> Result<RpcRequest> {
    match msg_type {
        MessageType::PingRequest => {
            let req = PingRequest::decode(payload)?;
            Ok(RpcRequest::Ping(req))
        }
        MessageType::GetSystemInfoRequest => Ok(RpcRequest::GetSystemInfo),
        MessageType::EnsureRuntimeRequest => {
            let req = RuntimeEnsureRequest::decode(payload)?;
            Ok(RpcRequest::EnsureRuntime(req))
        }
        MessageType::RuntimeStatusRequest => {
            let req = RuntimeStatusRequest::decode(payload)?;
            Ok(RpcRequest::RuntimeStatus(req))
        }
        MessageType::CreateContainerRequest => {
            let req = CreateContainerRequest::decode(payload)?;
            Ok(RpcRequest::CreateContainer(req))
        }
        MessageType::StartContainerRequest => {
            let req = StartContainerRequest::decode(payload)?;
            Ok(RpcRequest::StartContainer(req))
        }
        MessageType::StopContainerRequest => {
            let req = StopContainerRequest::decode(payload)?;
            Ok(RpcRequest::StopContainer(req))
        }
        MessageType::RemoveContainerRequest => {
            let req = RemoveContainerRequest::decode(payload)?;
            Ok(RpcRequest::RemoveContainer(req))
        }
        MessageType::ListContainersRequest => {
            let req = ListContainersRequest::decode(payload)?;
            Ok(RpcRequest::ListContainers(req))
        }
        MessageType::KillContainerRequest => {
            let req = KillContainerRequest::decode(payload)?;
            Ok(RpcRequest::KillContainer(req))
        }
        MessageType::WaitContainerRequest => {
            let req = WaitContainerRequest::decode(payload)?;
            Ok(RpcRequest::WaitContainer(req))
        }
        MessageType::PauseContainerRequest => {
            let req = PauseContainerRequest::decode(payload)?;
            Ok(RpcRequest::PauseContainer(req))
        }
        MessageType::UnpauseContainerRequest => {
            let req = UnpauseContainerRequest::decode(payload)?;
            Ok(RpcRequest::UnpauseContainer(req))
        }
        MessageType::ContainerStatsRequest => {
            let req = ContainerStatsRequest::decode(payload)?;
            Ok(RpcRequest::ContainerStats(req))
        }
        MessageType::ContainerTopRequest => {
            let req = ContainerTopRequest::decode(payload)?;
            Ok(RpcRequest::ContainerTop(req))
        }
        MessageType::ExecRequest => {
            let req = ExecRequest::decode(payload)?;
            Ok(RpcRequest::Exec(req))
        }
        MessageType::LogsRequest => {
            let req = LogsRequest::decode(payload)?;
            Ok(RpcRequest::Logs(req))
        }
        MessageType::ExecStartRequest => {
            let req = ExecStartRequest::decode(payload)?;
            Ok(RpcRequest::ExecStart(req))
        }
        MessageType::ExecResizeRequest => {
            let req = ExecResizeRequest::decode(payload)?;
            Ok(RpcRequest::ExecResize(req))
        }
        MessageType::AttachRequest => {
            let req = arcbox_protocol::agent::AttachRequest::decode(payload)?;
            Ok(RpcRequest::Attach(req))
        }
        MessageType::AttachInput => {
            let req = arcbox_protocol::agent::AttachInput::decode(payload)?;
            Ok(RpcRequest::AttachInput(req))
        }
        _ => anyhow::bail!("unexpected message type: {:?}", msg_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // =========================================================================
    // MessageType Tests
    // =========================================================================

    #[test]
    fn test_message_type_from_u32_requests() {
        assert_eq!(
            MessageType::from_u32(0x0001),
            Some(MessageType::PingRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0002),
            Some(MessageType::GetSystemInfoRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0003),
            Some(MessageType::EnsureRuntimeRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0004),
            Some(MessageType::RuntimeStatusRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0010),
            Some(MessageType::CreateContainerRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0011),
            Some(MessageType::StartContainerRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0012),
            Some(MessageType::StopContainerRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0013),
            Some(MessageType::RemoveContainerRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0014),
            Some(MessageType::ListContainersRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0020),
            Some(MessageType::ExecRequest)
        );
        assert_eq!(
            MessageType::from_u32(0x0024),
            Some(MessageType::AttachRequest)
        );
    }

    #[test]
    fn test_message_type_from_u32_responses() {
        assert_eq!(
            MessageType::from_u32(0x1001),
            Some(MessageType::PingResponse)
        );
        assert_eq!(
            MessageType::from_u32(0x1002),
            Some(MessageType::GetSystemInfoResponse)
        );
        assert_eq!(
            MessageType::from_u32(0x1003),
            Some(MessageType::EnsureRuntimeResponse)
        );
        assert_eq!(
            MessageType::from_u32(0x1004),
            Some(MessageType::RuntimeStatusResponse)
        );
        assert_eq!(
            MessageType::from_u32(0x1010),
            Some(MessageType::CreateContainerResponse)
        );
        assert_eq!(
            MessageType::from_u32(0x1014),
            Some(MessageType::ListContainersResponse)
        );
        assert_eq!(MessageType::from_u32(0x1020), Some(MessageType::ExecOutput));
        assert_eq!(
            MessageType::from_u32(0x1023),
            Some(MessageType::AttachOutput)
        );
    }

    #[test]
    fn test_message_type_from_u32_special() {
        assert_eq!(MessageType::from_u32(0x0000), Some(MessageType::Empty));
        assert_eq!(MessageType::from_u32(0xFFFF), Some(MessageType::Error));
    }

    #[test]
    fn test_message_type_from_u32_invalid() {
        assert_eq!(MessageType::from_u32(0x9999), None);
        assert_eq!(MessageType::from_u32(0x0005), None);
        assert_eq!(MessageType::from_u32(0x1005), None);
        assert_eq!(MessageType::from_u32(0x0026), None);
    }

    // =========================================================================
    // ErrorResponse Tests
    // =========================================================================

    #[test]
    fn test_error_response_roundtrip() {
        let err = ErrorResponse::new(500, "internal error");
        let encoded = err.encode();
        let decoded = ErrorResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.code, 500);
        assert_eq!(decoded.message, "internal error");
    }

    #[test]
    fn test_error_response_empty_message() {
        let err = ErrorResponse::new(404, "");
        let encoded = err.encode();
        let decoded = ErrorResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.code, 404);
        assert_eq!(decoded.message, "");
    }

    #[test]
    fn test_error_response_unicode_message() {
        let err = ErrorResponse::new(400, "错误: 无效的请求");
        let encoded = err.encode();
        let decoded = ErrorResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.code, 400);
        assert_eq!(decoded.message, "错误: 无效的请求");
    }

    #[test]
    fn test_error_response_decode_too_short() {
        let data = [0u8; 4]; // Only 4 bytes, need at least 8
        let result = ErrorResponse::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_response_decode_truncated_message() {
        // Create data with length field claiming more bytes than available
        let mut data = Vec::new();
        data.put_i32(500); // code
        data.put_u32(100); // message length = 100
        data.extend_from_slice(b"short"); // only 5 bytes

        let result = ErrorResponse::decode(&data);
        assert!(result.is_err());
    }

    // =========================================================================
    // Message Read/Write Tests
    // =========================================================================

    #[tokio::test]
    async fn test_message_roundtrip_ping() {
        let mut buf = Vec::new();

        let ping = PingRequest {
            message: "hello".to_string(),
        };
        write_message(
            &mut buf,
            MessageType::PingRequest,
            "",
            &ping.encode_to_vec(),
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(&buf);
        let (msg_type, trace_id, payload) = read_message(&mut cursor).await.unwrap();

        assert_eq!(msg_type, MessageType::PingRequest);
        assert!(trace_id.is_empty());
        let decoded = PingRequest::decode(&payload[..]).unwrap();
        assert_eq!(decoded.message, "hello");
    }

    #[tokio::test]
    async fn test_message_roundtrip_with_trace_id() {
        let mut buf = Vec::new();

        let ping = PingRequest {
            message: "traced".to_string(),
        };
        write_message(
            &mut buf,
            MessageType::PingRequest,
            "abc-123-trace",
            &ping.encode_to_vec(),
        )
        .await
        .unwrap();

        let mut cursor = Cursor::new(&buf);
        let (msg_type, trace_id, payload) = read_message(&mut cursor).await.unwrap();

        assert_eq!(msg_type, MessageType::PingRequest);
        assert_eq!(trace_id, "abc-123-trace");
        let decoded = PingRequest::decode(&payload[..]).unwrap();
        assert_eq!(decoded.message, "traced");
    }

    #[tokio::test]
    async fn test_message_roundtrip_empty_payload() {
        let mut buf = Vec::new();

        write_message(&mut buf, MessageType::GetSystemInfoRequest, "", &[])
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let (msg_type, _trace_id, payload) = read_message(&mut cursor).await.unwrap();

        assert_eq!(msg_type, MessageType::GetSystemInfoRequest);
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn test_message_roundtrip_large_payload() {
        let mut buf = Vec::new();

        // Create a large payload (64KB)
        let large_payload = vec![0xABu8; 65536];
        write_message(&mut buf, MessageType::ExecOutput, "", &large_payload)
            .await
            .unwrap();

        let mut cursor = Cursor::new(&buf);
        let (msg_type, _trace_id, payload) = read_message(&mut cursor).await.unwrap();

        assert_eq!(msg_type, MessageType::ExecOutput);
        assert_eq!(payload.len(), 65536);
        assert!(payload.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn test_multiple_messages_roundtrip() {
        let mut buf = Vec::new();

        // Write multiple messages
        let ping1 = PingRequest {
            message: "first".to_string(),
        };
        let ping2 = PingRequest {
            message: "second".to_string(),
        };

        write_message(
            &mut buf,
            MessageType::PingRequest,
            "t1",
            &ping1.encode_to_vec(),
        )
        .await
        .unwrap();
        write_message(
            &mut buf,
            MessageType::PingRequest,
            "t2",
            &ping2.encode_to_vec(),
        )
        .await
        .unwrap();

        // Read them back
        let mut cursor = Cursor::new(&buf);

        let (msg_type1, trace1, payload1) = read_message(&mut cursor).await.unwrap();
        assert_eq!(msg_type1, MessageType::PingRequest);
        assert_eq!(trace1, "t1");
        let decoded1 = PingRequest::decode(&payload1[..]).unwrap();
        assert_eq!(decoded1.message, "first");

        let (msg_type2, trace2, payload2) = read_message(&mut cursor).await.unwrap();
        assert_eq!(msg_type2, MessageType::PingRequest);
        assert_eq!(trace2, "t2");
        let decoded2 = PingRequest::decode(&payload2[..]).unwrap();
        assert_eq!(decoded2.message, "second");
    }

    #[tokio::test]
    async fn test_read_message_eof() {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(&buf);

        let result = read_message(&mut cursor).await;
        assert!(result.is_err());
    }

    // =========================================================================
    // parse_request Tests
    // =========================================================================

    #[test]
    fn test_parse_request_ping() {
        let req = PingRequest {
            message: "test".to_string(),
        };
        let payload = req.encode_to_vec();

        let parsed = parse_request(MessageType::PingRequest, &payload).unwrap();
        match parsed {
            RpcRequest::Ping(p) => assert_eq!(p.message, "test"),
            _ => panic!("expected Ping request"),
        }
    }

    #[test]
    fn test_parse_request_get_system_info() {
        let parsed = parse_request(MessageType::GetSystemInfoRequest, &[]).unwrap();
        match parsed {
            RpcRequest::GetSystemInfo => {}
            _ => panic!("expected GetSystemInfo request"),
        }
    }

    #[test]
    fn test_parse_request_ensure_runtime() {
        let req = RuntimeEnsureRequest {
            start_if_needed: true,
        };
        let payload = req.encode_to_vec();
        let parsed = parse_request(MessageType::EnsureRuntimeRequest, &payload).unwrap();
        match parsed {
            RpcRequest::EnsureRuntime(r) => assert!(r.start_if_needed),
            _ => panic!("expected EnsureRuntime request"),
        }
    }

    #[test]
    fn test_parse_request_runtime_status() {
        let req = RuntimeStatusRequest {};
        let payload = req.encode_to_vec();
        let parsed = parse_request(MessageType::RuntimeStatusRequest, &payload).unwrap();
        match parsed {
            RpcRequest::RuntimeStatus(_) => {}
            _ => panic!("expected RuntimeStatus request"),
        }
    }

    #[test]
    fn test_parse_request_create_container() {
        let req = CreateContainerRequest {
            name: "test-container".to_string(),
            image: "alpine:latest".to_string(),
            cmd: vec!["echo".to_string(), "hello".to_string()],
            ..Default::default()
        };
        let payload = req.encode_to_vec();

        let parsed = parse_request(MessageType::CreateContainerRequest, &payload).unwrap();
        match parsed {
            RpcRequest::CreateContainer(c) => {
                assert_eq!(c.name, "test-container");
                assert_eq!(c.image, "alpine:latest");
                assert_eq!(c.cmd, vec!["echo", "hello"]);
            }
            _ => panic!("expected CreateContainer request"),
        }
    }

    #[test]
    fn test_parse_request_exec() {
        let req = ExecRequest {
            container_id: "abc123".to_string(),
            cmd: vec!["ls".to_string(), "-la".to_string()],
            ..Default::default()
        };
        let payload = req.encode_to_vec();

        let parsed = parse_request(MessageType::ExecRequest, &payload).unwrap();
        match parsed {
            RpcRequest::Exec(e) => {
                assert_eq!(e.container_id, "abc123");
                assert_eq!(e.cmd, vec!["ls", "-la"]);
            }
            _ => panic!("expected Exec request"),
        }
    }

    #[test]
    fn test_parse_request_attach() {
        let req = arcbox_protocol::agent::AttachRequest {
            container_id: "c1".to_string(),
            attach_stdin: true,
            attach_stdout: true,
            attach_stderr: false,
            tty_width: 120,
            tty_height: 33,
            exec_id: String::new(),
        };
        let payload = req.encode_to_vec();

        let parsed = parse_request(MessageType::AttachRequest, &payload).unwrap();
        match parsed {
            RpcRequest::Attach(a) => {
                assert_eq!(a.container_id, "c1");
                assert!(a.attach_stdin);
                assert!(a.attach_stdout);
                assert!(!a.attach_stderr);
                assert_eq!(a.tty_width, 120);
                assert_eq!(a.tty_height, 33);
                assert!(a.exec_id.is_empty());
            }
            _ => panic!("expected Attach request"),
        }
    }

    #[test]
    fn test_parse_request_unexpected_type() {
        // Response types should not be parseable as requests
        let result = parse_request(MessageType::PingResponse, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_invalid_payload() {
        // Invalid protobuf data
        let invalid_payload = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result = parse_request(MessageType::PingRequest, &invalid_payload);
        assert!(result.is_err());
    }

    // =========================================================================
    // RpcResponse Tests
    // =========================================================================

    #[test]
    fn test_rpc_response_message_type() {
        assert_eq!(
            RpcResponse::Ping(PingResponse::default()).message_type(),
            MessageType::PingResponse
        );
        assert_eq!(
            RpcResponse::SystemInfo(SystemInfo::default()).message_type(),
            MessageType::GetSystemInfoResponse
        );
        assert_eq!(
            RpcResponse::RuntimeEnsure(RuntimeEnsureResponse::default()).message_type(),
            MessageType::EnsureRuntimeResponse
        );
        assert_eq!(
            RpcResponse::RuntimeStatus(RuntimeStatusResponse::default()).message_type(),
            MessageType::RuntimeStatusResponse
        );
        assert_eq!(
            RpcResponse::CreateContainer(CreateContainerResponse::default()).message_type(),
            MessageType::CreateContainerResponse
        );
        assert_eq!(RpcResponse::Empty.message_type(), MessageType::Empty);
        assert_eq!(
            RpcResponse::ListContainers(ListContainersResponse::default()).message_type(),
            MessageType::ListContainersResponse
        );
        assert_eq!(
            RpcResponse::ExecOutput(ExecOutput::default()).message_type(),
            MessageType::ExecOutput
        );
        assert_eq!(
            RpcResponse::Error(ErrorResponse::new(500, "error")).message_type(),
            MessageType::Error
        );
        assert_eq!(
            RpcResponse::AttachOutput(arcbox_protocol::agent::AttachOutput {
                stream: "stdout".to_string(),
                data: vec![1, 2, 3],
            })
            .message_type(),
            MessageType::AttachOutput
        );
    }

    #[test]
    fn test_rpc_response_encode_payload_ping() {
        let response = RpcResponse::Ping(PingResponse {
            message: "pong".to_string(),
            version: "1.0.0".to_string(),
        });
        let payload = response.encode_payload();

        // Decode and verify
        let decoded = PingResponse::decode(&payload[..]).unwrap();
        assert_eq!(decoded.message, "pong");
        assert_eq!(decoded.version, "1.0.0");
    }

    #[test]
    fn test_rpc_response_encode_payload_empty() {
        let response = RpcResponse::Empty;
        let payload = response.encode_payload();

        // Empty message should decode successfully
        let decoded = Empty::decode(&payload[..]).unwrap();
        assert_eq!(decoded, Empty::default());
    }

    #[test]
    fn test_rpc_response_encode_payload_attach_output() {
        let response = RpcResponse::AttachOutput(arcbox_protocol::agent::AttachOutput {
            stream: "stderr".to_string(),
            data: vec![9, 8, 7],
        });
        let payload = response.encode_payload();

        let decoded = arcbox_protocol::agent::AttachOutput::decode(&payload[..]).unwrap();
        assert_eq!(decoded.stream, "stderr");
        assert_eq!(decoded.data, vec![9, 8, 7]);
    }

    #[tokio::test]
    async fn test_write_response_roundtrip() {
        let mut buf = Vec::new();

        let response = RpcResponse::Ping(PingResponse {
            message: "pong".to_string(),
            version: "0.1.0".to_string(),
        });

        write_response(&mut buf, &response, "").await.unwrap();

        // Read it back
        let mut cursor = Cursor::new(&buf);
        let (msg_type, _trace_id, payload) = read_message(&mut cursor).await.unwrap();

        assert_eq!(msg_type, MessageType::PingResponse);
        let decoded = PingResponse::decode(&payload[..]).unwrap();
        assert_eq!(decoded.message, "pong");
        assert_eq!(decoded.version, "0.1.0");
    }
}
