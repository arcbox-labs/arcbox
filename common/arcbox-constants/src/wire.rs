/// Number of bytes in the fixed RPC frame header (`length` + `type`).
pub const FRAME_HEADER_SIZE: usize = 8;

/// Number of bytes in the fixed RPC error header (`code` + `message_len`).
pub const ERROR_HEADER_SIZE: usize = 8;

/// Number of bytes in the message type field.
pub const TYPE_FIELD_SIZE: usize = 4;

/// Number of bytes in the trace length field.
pub const TRACE_LEN_FIELD_SIZE: usize = 2;

/// RPC message types used by host and guest agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MessageType {
    // Request types (0x0000 - 0x0FFF).
    PingRequest = 0x0001,
    GetSystemInfoRequest = 0x0002,
    EnsureRuntimeRequest = 0x0003,
    RuntimeStatusRequest = 0x0004,

    // Response types (0x1000 - 0x1FFF).
    PingResponse = 0x1001,
    GetSystemInfoResponse = 0x1002,
    EnsureRuntimeResponse = 0x1003,
    RuntimeStatusResponse = 0x1004,
    PortBindingsChanged = 0x1030,
    PortBindingsRemoved = 0x1031,

    // Special types.
    Empty = 0x0000,
    Error = 0xFFFF,
}

impl MessageType {
    /// Converts a numeric wire value into a typed message kind.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x0001 => Some(Self::PingRequest),
            0x0002 => Some(Self::GetSystemInfoRequest),
            0x0003 => Some(Self::EnsureRuntimeRequest),
            0x0004 => Some(Self::RuntimeStatusRequest),
            0x1001 => Some(Self::PingResponse),
            0x1002 => Some(Self::GetSystemInfoResponse),
            0x1003 => Some(Self::EnsureRuntimeResponse),
            0x1004 => Some(Self::RuntimeStatusResponse),
            0x1030 => Some(Self::PortBindingsChanged),
            0x1031 => Some(Self::PortBindingsRemoved),
            0x0000 => Some(Self::Empty),
            0xFFFF => Some(Self::Error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MessageType;

    #[test]
    fn message_type_roundtrip_known_values() {
        const CASES: &[(u32, MessageType)] = &[
            (0x0001, MessageType::PingRequest),
            (0x0002, MessageType::GetSystemInfoRequest),
            (0x0003, MessageType::EnsureRuntimeRequest),
            (0x0004, MessageType::RuntimeStatusRequest),
            (0x1001, MessageType::PingResponse),
            (0x1002, MessageType::GetSystemInfoResponse),
            (0x1003, MessageType::EnsureRuntimeResponse),
            (0x1004, MessageType::RuntimeStatusResponse),
            (0x1030, MessageType::PortBindingsChanged),
            (0x1031, MessageType::PortBindingsRemoved),
            (0x0000, MessageType::Empty),
            (0xFFFF, MessageType::Error),
        ];

        for (raw, expected) in CASES {
            assert_eq!(MessageType::from_u32(*raw), Some(*expected));
        }
    }

    #[test]
    fn message_type_rejects_unknown_values() {
        assert_eq!(MessageType::from_u32(0x9999), None);
        assert_eq!(MessageType::from_u32(0x1010), None);
    }
}
