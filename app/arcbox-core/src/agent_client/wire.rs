use crate::error::{CoreError, Result};
use arcbox_constants::wire::{
    ERROR_HEADER_SIZE, FRAME_HEADER_SIZE, MessageType, TRACE_LEN_FIELD_SIZE, TYPE_FIELD_SIZE,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Builds a V2 wire message with an optional `trace_id`.
///
/// Wire format V2:
/// ```text
/// +----------------+----------------+------------------+----------------+
/// | Length (4B BE) | Type (4B BE)   | TraceLen (2B BE) | TraceID bytes  | Payload
/// +----------------+----------------+------------------+----------------+
/// ```
pub(super) fn build_message(msg_type: MessageType, trace_id: &str, payload: &[u8]) -> Bytes {
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
pub(super) fn parse_response(response: &[u8]) -> Result<(u32, String, Vec<u8>)> {
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

    let trace_id = String::from_utf8(response[trace_start..trace_end].to_vec()).unwrap_or_default();
    let payload = if response.len() > payload_start {
        response[payload_start..].to_vec()
    } else {
        Vec::new()
    };

    Ok((resp_type, trace_id, payload))
}

/// Parses an error response from the agent into `(status code, message)`.
///
/// The code is HTTP-style (400/404/409/412/500/503) and is mapped onto a
/// gRPC status by the API layer via `CoreError::Agent`.
pub(super) fn parse_error_response(payload: &[u8]) -> Result<(i32, String)> {
    if payload.len() < ERROR_HEADER_SIZE {
        return Ok((500, "unknown error".to_string()));
    }

    let mut cursor = std::io::Cursor::new(payload);
    let code = cursor.get_i32();
    let msg_len = cursor.get_u32() as usize;

    if payload.len() < ERROR_HEADER_SIZE + msg_len {
        return Ok((code, "truncated error message".to_string()));
    }

    let message =
        String::from_utf8(payload[ERROR_HEADER_SIZE..ERROR_HEADER_SIZE + msg_len].to_vec())
            .map_err(|_| CoreError::Machine("invalid error message encoding".to_string()))?;
    Ok((code, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of the agent's `ErrorResponse::encode` framing.
    fn encode_error(code: i32, message: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&code.to_be_bytes());
        buf.extend_from_slice(&(message.len() as u32).to_be_bytes());
        buf.extend_from_slice(message.as_bytes());
        buf
    }

    #[test]
    fn error_response_roundtrips_code_and_message() {
        let payload = encode_error(412, "nested virtualization required");
        let (code, message) = parse_error_response(&payload).unwrap();
        assert_eq!(code, 412);
        assert_eq!(message, "nested virtualization required");
    }

    #[test]
    fn short_error_payload_degrades_to_500() {
        let (code, message) = parse_error_response(&[0x01]).unwrap();
        assert_eq!(code, 500);
        assert_eq!(message, "unknown error");
    }
}
