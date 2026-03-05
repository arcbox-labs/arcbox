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

    // Sandbox CRUD request types (0x0020 - 0x0024).
    SandboxCreateRequest = 0x0020,
    SandboxStopRequest = 0x0021,
    SandboxRemoveRequest = 0x0022,
    SandboxInspectRequest = 0x0023,
    SandboxListRequest = 0x0024,

    // Sandbox workload request types (0x0030 - 0x0033).
    SandboxRunRequest = 0x0030,
    SandboxExecRequest = 0x0031,
    SandboxEventsRequest = 0x0032,

    // Sandbox snapshot request types (0x0040 - 0x0043).
    SandboxCheckpointRequest = 0x0040,
    SandboxRestoreRequest = 0x0041,
    SandboxListSnapshotsRequest = 0x0042,
    SandboxDeleteSnapshotRequest = 0x0043,

    // Response types (0x1000 - 0x1FFF).
    PingResponse = 0x1001,
    GetSystemInfoResponse = 0x1002,
    EnsureRuntimeResponse = 0x1003,
    RuntimeStatusResponse = 0x1004,
    PortBindingsChanged = 0x1030,
    PortBindingsRemoved = 0x1031,

    // Sandbox CRUD response types (0x1020 - 0x1024).
    SandboxCreateResponse = 0x1020,
    SandboxStopResponse = 0x1021,
    SandboxRemoveResponse = 0x1022,
    SandboxInspectResponse = 0x1023,
    SandboxListResponse = 0x1024,

    // Sandbox workload response types (streaming).
    SandboxRunOutput = 0x1035,
    SandboxExecOutput = 0x1036,
    SandboxEvent = 0x1037,

    // Sandbox snapshot response types (0x1040 - 0x1043).
    SandboxCheckpointResponse = 0x1040,
    SandboxRestoreResponse = 0x1041,
    SandboxListSnapshotsResponse = 0x1042,
    SandboxDeleteSnapshotResponse = 0x1043,

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
            // Sandbox CRUD requests.
            0x0020 => Some(Self::SandboxCreateRequest),
            0x0021 => Some(Self::SandboxStopRequest),
            0x0022 => Some(Self::SandboxRemoveRequest),
            0x0023 => Some(Self::SandboxInspectRequest),
            0x0024 => Some(Self::SandboxListRequest),
            // Sandbox workload requests.
            0x0030 => Some(Self::SandboxRunRequest),
            0x0031 => Some(Self::SandboxExecRequest),
            0x0032 => Some(Self::SandboxEventsRequest),
            // Sandbox snapshot requests.
            0x0040 => Some(Self::SandboxCheckpointRequest),
            0x0041 => Some(Self::SandboxRestoreRequest),
            0x0042 => Some(Self::SandboxListSnapshotsRequest),
            0x0043 => Some(Self::SandboxDeleteSnapshotRequest),
            // Responses.
            0x1001 => Some(Self::PingResponse),
            0x1002 => Some(Self::GetSystemInfoResponse),
            0x1003 => Some(Self::EnsureRuntimeResponse),
            0x1004 => Some(Self::RuntimeStatusResponse),
            0x1030 => Some(Self::PortBindingsChanged),
            0x1031 => Some(Self::PortBindingsRemoved),
            // Sandbox CRUD responses.
            0x1020 => Some(Self::SandboxCreateResponse),
            0x1021 => Some(Self::SandboxStopResponse),
            0x1022 => Some(Self::SandboxRemoveResponse),
            0x1023 => Some(Self::SandboxInspectResponse),
            0x1024 => Some(Self::SandboxListResponse),
            // Sandbox workload responses (streaming).
            0x1035 => Some(Self::SandboxRunOutput),
            0x1036 => Some(Self::SandboxExecOutput),
            0x1037 => Some(Self::SandboxEvent),
            // Sandbox snapshot responses.
            0x1040 => Some(Self::SandboxCheckpointResponse),
            0x1041 => Some(Self::SandboxRestoreResponse),
            0x1042 => Some(Self::SandboxListSnapshotsResponse),
            0x1043 => Some(Self::SandboxDeleteSnapshotResponse),
            0x0000 => Some(Self::Empty),
            0xFFFF => Some(Self::Error),
            _ => None,
        }
    }

    /// Returns true if this message type is a sandbox request that should be
    /// handled by the sandbox service rather than the standard RPC dispatcher.
    #[must_use]
    pub const fn is_sandbox_request(self) -> bool {
        matches!(
            self,
            Self::SandboxCreateRequest
                | Self::SandboxStopRequest
                | Self::SandboxRemoveRequest
                | Self::SandboxInspectRequest
                | Self::SandboxListRequest
                | Self::SandboxRunRequest
                | Self::SandboxExecRequest
                | Self::SandboxEventsRequest
                | Self::SandboxCheckpointRequest
                | Self::SandboxRestoreRequest
                | Self::SandboxListSnapshotsRequest
                | Self::SandboxDeleteSnapshotRequest
        )
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
            // Sandbox CRUD.
            (0x0020, MessageType::SandboxCreateRequest),
            (0x0021, MessageType::SandboxStopRequest),
            (0x0022, MessageType::SandboxRemoveRequest),
            (0x0023, MessageType::SandboxInspectRequest),
            (0x0024, MessageType::SandboxListRequest),
            (0x1020, MessageType::SandboxCreateResponse),
            (0x1021, MessageType::SandboxStopResponse),
            (0x1022, MessageType::SandboxRemoveResponse),
            (0x1023, MessageType::SandboxInspectResponse),
            (0x1024, MessageType::SandboxListResponse),
            // Sandbox workload.
            (0x0030, MessageType::SandboxRunRequest),
            (0x0031, MessageType::SandboxExecRequest),
            (0x0032, MessageType::SandboxEventsRequest),
            (0x1035, MessageType::SandboxRunOutput),
            (0x1036, MessageType::SandboxExecOutput),
            (0x1037, MessageType::SandboxEvent),
            // Sandbox snapshots.
            (0x0040, MessageType::SandboxCheckpointRequest),
            (0x0041, MessageType::SandboxRestoreRequest),
            (0x0042, MessageType::SandboxListSnapshotsRequest),
            (0x0043, MessageType::SandboxDeleteSnapshotRequest),
            (0x1040, MessageType::SandboxCheckpointResponse),
            (0x1041, MessageType::SandboxRestoreResponse),
            (0x1042, MessageType::SandboxListSnapshotsResponse),
            (0x1043, MessageType::SandboxDeleteSnapshotResponse),
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

    #[test]
    fn is_sandbox_request_classifies_correctly() {
        assert!(MessageType::SandboxCreateRequest.is_sandbox_request());
        assert!(MessageType::SandboxRunRequest.is_sandbox_request());
        assert!(MessageType::SandboxCheckpointRequest.is_sandbox_request());
        assert!(!MessageType::PingRequest.is_sandbox_request());
        assert!(!MessageType::SandboxCreateResponse.is_sandbox_request());
    }
}
