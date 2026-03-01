//! RPC protocol implementation for Guest Agent.
//!
//! This module implements a length-prefixed RPC protocol over vsock.
//! Payloads are protobuf-encoded messages.

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use arcbox_constants::wire::MessageType;
use arcbox_protocol::Empty;
use arcbox_protocol::agent::{
    PingRequest, PingResponse, PortBindingsChanged, PortBindingsRemoved, RuntimeEnsureRequest,
    RuntimeEnsureResponse, RuntimeStatusRequest, RuntimeStatusResponse, SystemInfo,
};

/// Agent version string.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
}

/// RPC response envelope.
#[derive(Debug)]
pub enum RpcResponse {
    Ping(PingResponse),
    SystemInfo(SystemInfo),
    RuntimeEnsure(RuntimeEnsureResponse),
    RuntimeStatus(RuntimeStatusResponse),
    Empty,
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
            Self::Empty => MessageType::Empty,
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
            Self::Empty => Empty::default().encode_to_vec(),
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
    // Read header: 4 bytes length + 4 bytes type.
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
        _ => anyhow::bail!("unexpected message type: {:?}", msg_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_message_type_from_u32_special() {
        assert_eq!(MessageType::from_u32(0x0000), Some(MessageType::Empty));
        assert_eq!(MessageType::from_u32(0xFFFF), Some(MessageType::Error));
    }

    #[test]
    fn test_message_type_from_u32_invalid() {
        assert_eq!(MessageType::from_u32(0x9999), None);
        assert_eq!(MessageType::from_u32(0x0010), None);
        assert_eq!(MessageType::from_u32(0x1010), None);
    }

    #[test]
    fn test_error_response_roundtrip() {
        let err = ErrorResponse::new(500, "internal error");
        let encoded = err.encode();
        let decoded = ErrorResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.code, 500);
        assert_eq!(decoded.message, "internal error");
    }

    #[test]
    fn test_parse_request_ping() {
        let req = PingRequest {
            message: "ping".to_string(),
        };
        let payload = req.encode_to_vec();

        let parsed = parse_request(MessageType::PingRequest, &payload).unwrap();
        match parsed {
            RpcRequest::Ping(p) => assert_eq!(p.message, "ping"),
            _ => panic!("Expected Ping request"),
        }
    }
}
