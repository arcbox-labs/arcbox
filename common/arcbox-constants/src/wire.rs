/// Host↔agent RPC protocol version this build speaks.
///
/// Carried in `AgentPingResponse.protocol_version` and checked by the
/// host during the boot handshake. Bump when a change alters the
/// *meaning* of existing messages (new required semantics, repurposed
/// fields, behavioral contracts) — purely additive, ignorable changes
/// don't need a bump. Unknown `MessageType`s already fail cleanly; this
/// version catches the silent proto3 field-skew class instead.
///
/// "Existing" means *released*: the sandbox execution redesign
/// (CORE-55/56) re-typed payloads that no release had ever shipped, so it
/// did not warrant a bump. 0.6.0 briefly shipped `2`/`2` for it before
/// this was rolled back — **`2` is burned**: 0.6.0 daemons in the wild
/// read it as "speaks the redesigned sandbox payloads", so the next real
/// bump must go to `3`, never reuse `2` for a different meaning.
pub const AGENT_PROTOCOL_VERSION: u32 = 1;

/// Oldest agent protocol version this host still accepts.
///
/// Agents reporting less (`0` — agents that predate the handshake field)
/// are rejected at boot with an actionable error instead of silently
/// misbehaving under field skew. A pre-0.6.0 agent boots and works on
/// every released surface. Driving the (unreleased) sandbox surface from
/// such an agent is undefined behavior by decision: with the version
/// signal retired back to `1`, old and new agents are indistinguishable
/// on the wire, so there is nothing to gate on. The only exposure is a
/// stale dev-tree binary, fixed by rebuilding
/// (`cargo build --release -p arcbox-agent --target aarch64-unknown-linux-musl`).
pub const MIN_AGENT_PROTOCOL_VERSION: u32 = 1;

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
    KubernetesStartRequest = 0x0005,
    KubernetesStopRequest = 0x0006,
    KubernetesDeleteRequest = 0x0007,
    KubernetesStatusRequest = 0x0008,
    KubernetesKubeconfigRequest = 0x0009,
    ShutdownRequest = 0x000A,
    /// Test-only: force the guest to mmap + read a file so the VirtioFS
    /// DAX path issues `FUSE_SETUPMAPPING`. Used by the ABX-362 E2E
    /// harness; not wired to any production CLI path.
    MmapReadFileRequest = 0x000B,
    /// Request the guest to run `fstrim` on data mount points so the host
    /// sparse image reclaims freed blocks.
    DiskTrimRequest = 0x000C,
    /// Opens a guest-driven readiness event stream.
    WatchReadinessRequest = 0x000D,
    /// Test-only: ask the agent to exit so PID 1 (busybox init) respawns it,
    /// exercising the supervision path. Used by the hv_e2e harness; not wired to
    /// any production CLI path.
    KillAgentRequest = 0x000E,
    /// Opens a guest-driven memory pressure event stream (used by the host
    /// while the idle balloon is shrunk).
    WatchMemoryPressureRequest = 0x000F,
    /// Opens a guest-driven machine resource stats stream (payload:
    /// `arcbox.v1.WatchStatsRequest`).
    WatchStatsRequest = 0x0010,
    /// Resolve a container's filesystem layer directories from containerd
    /// snapshot metadata (payload: `arcbox.agent.ContainerFsPathsRequest`).
    ContainerFsPathsRequest = 0x0011,
    /// Resolve an image's layer directories from containerd snapshot
    /// metadata (payload: `arcbox.agent.ImageFsPathsRequest`).
    ImageFsPathsRequest = 0x0012,
    /// Bring up the read-only NFS export of the docker data mount (payload:
    /// `arcbox.agent.EnsureNfsExportRequest`). Sent by the host daemon only
    /// when the `~/ArcBox` mount is enabled; a `--no-mount-nfs` daemon never
    /// sends it, so the guest runs no nfsd.
    EnsureNfsExportRequest = 0x0013,

    // Sandbox CRUD request types (0x0020 - 0x0026).
    SandboxCreateRequest = 0x0020,
    SandboxStopRequest = 0x0021,
    SandboxRemoveRequest = 0x0022,
    SandboxInspectRequest = 0x0023,
    SandboxListRequest = 0x0024,
    /// DNAT a reserved guest port to a sandbox port (payload:
    /// `arcbox.v1.SandboxPortForwardRequest`).
    SandboxPortForwardRequest = 0x0025,
    /// Remove a sandbox DNAT mapping (payload:
    /// `arcbox.v1.SandboxPortForwardRemoveRequest`).
    SandboxPortForwardRemoveRequest = 0x0026,

    // Sandbox workload request types.
    // 0x0030 (SandboxRunRequest), 0x0031 (SandboxExecRequest),
    // 0x0033 (SandboxExecInput), and 0x0034 (SandboxExecResize) were
    // retired by the execution redesign (CORE-55/56); do not reuse.
    SandboxEventsRequest = 0x0032,
    /// Read a file from a sandbox (payload: `arcbox.sandbox.v1.ReadFileRequest`).
    /// The agent answers with a stream of [`Self::SandboxFileData`] frames.
    SandboxFileReadRequest = 0x0035,
    /// Open a file-write stream into a sandbox (payload:
    /// `arcbox.sandbox.v1.WriteFileOpen`), followed by [`Self::SandboxFileChunk`]
    /// frames and answered with [`Self::SandboxFileWriteResponse`].
    SandboxFileWriteRequest = 0x0036,
    /// One chunk of file content during a write stream (payload:
    /// `arcbox.sandbox.v1.FileChunk`; `done == true` on the last chunk).
    SandboxFileChunk = 0x0037,

    // Sandbox snapshot request types (0x0040 - 0x0043).
    SandboxCheckpointRequest = 0x0040,
    SandboxRestoreRequest = 0x0041,
    SandboxListSnapshotsRequest = 0x0042,
    SandboxDeleteSnapshotRequest = 0x0043,

    // Sandbox execution request types (0x0060 - 0x0066), from the
    // execution redesign (CORE-55/56).
    /// Start an addressable execution (payload:
    /// `arcbox.sandbox.v1.StartExecutionRequest`). Answered with
    /// [`Self::SandboxExecStartResponse`].
    SandboxExecStartRequest = 0x0060,
    /// Attach to an execution's output from per-channel offsets (payload:
    /// `arcbox.sandbox.v1.AttachExecutionRequest`). The agent answers with a
    /// stream of [`Self::SandboxExecEvent`] frames ending in an `exited`
    /// event.
    SandboxExecAttachRequest = 0x0061,
    /// Offset-idempotent stdin write (payload:
    /// `arcbox.sandbox.v1.WriteStdinRequest`). Answered with
    /// [`Self::SandboxStdinStatus`].
    SandboxStdinWriteRequest = 0x0062,
    /// Query stdin acceptance state (payload:
    /// `arcbox.sandbox.v1.GetStdinStatusRequest`). Answered with
    /// [`Self::SandboxStdinStatus`].
    SandboxStdinStatusRequest = 0x0063,
    /// Signal an execution's process group (payload:
    /// `arcbox.sandbox.v1.SignalExecutionRequest`). Answered with
    /// [`Self::SandboxExecSignalResponse`].
    SandboxExecSignalRequest = 0x0064,
    /// Resize a TTY execution's terminal (payload:
    /// `arcbox.sandbox.v1.ResizeExecutionTtyRequest`). Answered with
    /// [`Self::SandboxExecResizeResponse`].
    SandboxExecResizeRequest = 0x0065,
    /// Wait for an execution to exit (payload:
    /// `arcbox.sandbox.v1.WaitExecutionRequest`). Answered with
    /// [`Self::SandboxExecWaitResponse`].
    SandboxExecWaitRequest = 0x0066,

    /// Starts a machine-level exec: runs a command in the machine root (the
    /// agent's own mount namespace), streamed back as
    /// [`Self::MachineExecOutput`] frames (payload:
    /// `arcbox.v1.MachineExecRequest`).
    MachineExecRequest = 0x0050,
    /// Stdin bytes for an interactive machine session (raw payload; empty
    /// payload means stdin EOF).
    MachineExecInput = 0x0051,
    /// Terminal resize for an interactive machine session (payload:
    /// `arcbox.v1.TerminalSize`).
    MachineExecResize = 0x0052,

    // Response types (0x1000 - 0x1FFF).
    PingResponse = 0x1001,
    GetSystemInfoResponse = 0x1002,
    EnsureRuntimeResponse = 0x1003,
    RuntimeStatusResponse = 0x1004,
    KubernetesStartResponse = 0x1005,
    KubernetesStopResponse = 0x1006,
    KubernetesDeleteResponse = 0x1007,
    KubernetesStatusResponse = 0x1008,
    KubernetesKubeconfigResponse = 0x1009,
    ShutdownResponse = 0x100A,
    /// Test-only: response for `MmapReadFileRequest` (ABX-362).
    MmapReadFileResponse = 0x100B,
    /// Response to `DiskTrimRequest` with per-mount trim summary.
    DiskTrimResponse = 0x100C,
    /// Guest-driven readiness event frame.
    ReadinessEvent = 0x100D,
    /// Test-only: acknowledgement for `KillAgentRequest`.
    KillAgentResponse = 0x100E,
    /// Guest-driven memory pressure event frame.
    MemoryPressureEvent = 0x100F,
    /// One machine resource sample frame (payload:
    /// `arcbox.v1.MachineStats`).
    MachineStats = 0x1010,
    /// Answers [`Self::ContainerFsPathsRequest`] (payload:
    /// `arcbox.agent.ContainerFsPathsResponse`).
    ContainerFsPathsResponse = 0x1011,
    /// Answers [`Self::ImageFsPathsRequest`] (payload:
    /// `arcbox.agent.ImageFsPathsResponse`).
    ImageFsPathsResponse = 0x1012,
    /// Answers [`Self::EnsureNfsExportRequest`] (payload:
    /// `arcbox.agent.EnsureNfsExportResponse`).
    EnsureNfsExportResponse = 0x1013,
    PortBindingsChanged = 0x1030,
    PortBindingsRemoved = 0x1031,

    // Sandbox CRUD response types (0x1020 - 0x1026).
    SandboxCreateResponse = 0x1020,
    SandboxStopResponse = 0x1021,
    SandboxRemoveResponse = 0x1022,
    SandboxInspectResponse = 0x1023,
    SandboxListResponse = 0x1024,
    /// Answers [`Self::SandboxPortForwardRequest`] (payload:
    /// `arcbox.v1.SandboxPortForwardResponse`).
    SandboxPortForwardResponse = 0x1025,
    /// Acknowledges [`Self::SandboxPortForwardRemoveRequest`] (empty payload).
    SandboxPortForwardRemoveResponse = 0x1026,

    // Sandbox workload response types (streaming).
    // 0x1035 (SandboxRunOutput) and 0x1036 (SandboxExecOutput) were
    // retired by the execution redesign (CORE-55/56); do not reuse.
    /// One lifecycle event answering [`Self::SandboxEventsRequest`]
    /// (payload: `arcbox.sandbox.v1.SandboxEvent`).
    SandboxEvent = 0x1037,
    /// One chunk of file content answering [`Self::SandboxFileReadRequest`]
    /// (payload: `arcbox.sandbox.v1.FileChunk`; `done == true` on the last chunk).
    SandboxFileData = 0x1038,
    /// Acknowledges a completed file-write stream (empty payload).
    SandboxFileWriteResponse = 0x1039,

    // Sandbox snapshot response types (0x1040 - 0x1043).
    SandboxCheckpointResponse = 0x1040,
    SandboxRestoreResponse = 0x1041,
    SandboxListSnapshotsResponse = 0x1042,
    SandboxDeleteSnapshotResponse = 0x1043,

    // Sandbox execution response types (0x1060 - 0x1066), from the
    // execution redesign (CORE-55/56).
    /// Answers [`Self::SandboxExecStartRequest`] (payload:
    /// `arcbox.sandbox.v1.Execution`).
    SandboxExecStartResponse = 0x1060,
    /// One frame of an execution attach stream (payload:
    /// `arcbox.sandbox.v1.ExecutionEvent`; the `exited` event is terminal).
    SandboxExecEvent = 0x1061,
    /// Answers [`Self::SandboxStdinWriteRequest`] and
    /// [`Self::SandboxStdinStatusRequest`] (payload:
    /// `arcbox.sandbox.v1.StdinStatus`).
    SandboxStdinStatus = 0x1062,
    /// Acknowledges [`Self::SandboxExecSignalRequest`] (empty payload).
    SandboxExecSignalResponse = 0x1064,
    /// Acknowledges [`Self::SandboxExecResizeRequest`] (empty payload).
    SandboxExecResizeResponse = 0x1065,
    /// Answers [`Self::SandboxExecWaitRequest`] (payload:
    /// `arcbox.sandbox.v1.Execution`).
    SandboxExecWaitResponse = 0x1066,

    /// One machine exec output frame (payload: `arcbox.v1.MachineExecOutput`;
    /// `done == true` on the final frame carrying the exit code).
    MachineExecOutput = 0x1050,

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
            0x0005 => Some(Self::KubernetesStartRequest),
            0x0006 => Some(Self::KubernetesStopRequest),
            0x0007 => Some(Self::KubernetesDeleteRequest),
            0x0008 => Some(Self::KubernetesStatusRequest),
            0x0009 => Some(Self::KubernetesKubeconfigRequest),
            0x000A => Some(Self::ShutdownRequest),
            0x000B => Some(Self::MmapReadFileRequest),
            0x000C => Some(Self::DiskTrimRequest),
            0x000D => Some(Self::WatchReadinessRequest),
            0x000E => Some(Self::KillAgentRequest),
            0x000F => Some(Self::WatchMemoryPressureRequest),
            0x0010 => Some(Self::WatchStatsRequest),
            0x0011 => Some(Self::ContainerFsPathsRequest),
            0x0012 => Some(Self::ImageFsPathsRequest),
            0x0013 => Some(Self::EnsureNfsExportRequest),
            // Sandbox CRUD requests.
            0x0020 => Some(Self::SandboxCreateRequest),
            0x0021 => Some(Self::SandboxStopRequest),
            0x0022 => Some(Self::SandboxRemoveRequest),
            0x0023 => Some(Self::SandboxInspectRequest),
            0x0024 => Some(Self::SandboxListRequest),
            0x0025 => Some(Self::SandboxPortForwardRequest),
            0x0026 => Some(Self::SandboxPortForwardRemoveRequest),
            // Sandbox workload requests.
            0x0032 => Some(Self::SandboxEventsRequest),
            0x0035 => Some(Self::SandboxFileReadRequest),
            0x0036 => Some(Self::SandboxFileWriteRequest),
            0x0037 => Some(Self::SandboxFileChunk),
            // Sandbox snapshot requests.
            0x0040 => Some(Self::SandboxCheckpointRequest),
            0x0041 => Some(Self::SandboxRestoreRequest),
            0x0042 => Some(Self::SandboxListSnapshotsRequest),
            0x0043 => Some(Self::SandboxDeleteSnapshotRequest),
            // Sandbox execution requests (execution redesign, CORE-55/56).
            0x0060 => Some(Self::SandboxExecStartRequest),
            0x0061 => Some(Self::SandboxExecAttachRequest),
            0x0062 => Some(Self::SandboxStdinWriteRequest),
            0x0063 => Some(Self::SandboxStdinStatusRequest),
            0x0064 => Some(Self::SandboxExecSignalRequest),
            0x0065 => Some(Self::SandboxExecResizeRequest),
            0x0066 => Some(Self::SandboxExecWaitRequest),
            // Machine-level exec.
            0x0050 => Some(Self::MachineExecRequest),
            0x0051 => Some(Self::MachineExecInput),
            0x0052 => Some(Self::MachineExecResize),
            // Responses.
            0x1001 => Some(Self::PingResponse),
            0x1002 => Some(Self::GetSystemInfoResponse),
            0x1003 => Some(Self::EnsureRuntimeResponse),
            0x1004 => Some(Self::RuntimeStatusResponse),
            0x1005 => Some(Self::KubernetesStartResponse),
            0x1006 => Some(Self::KubernetesStopResponse),
            0x1007 => Some(Self::KubernetesDeleteResponse),
            0x1008 => Some(Self::KubernetesStatusResponse),
            0x1009 => Some(Self::KubernetesKubeconfigResponse),
            0x100A => Some(Self::ShutdownResponse),
            0x100B => Some(Self::MmapReadFileResponse),
            0x100C => Some(Self::DiskTrimResponse),
            0x100D => Some(Self::ReadinessEvent),
            0x100E => Some(Self::KillAgentResponse),
            0x100F => Some(Self::MemoryPressureEvent),
            0x1010 => Some(Self::MachineStats),
            0x1011 => Some(Self::ContainerFsPathsResponse),
            0x1012 => Some(Self::ImageFsPathsResponse),
            0x1013 => Some(Self::EnsureNfsExportResponse),
            0x1030 => Some(Self::PortBindingsChanged),
            0x1031 => Some(Self::PortBindingsRemoved),
            // Sandbox CRUD responses.
            0x1020 => Some(Self::SandboxCreateResponse),
            0x1021 => Some(Self::SandboxStopResponse),
            0x1022 => Some(Self::SandboxRemoveResponse),
            0x1023 => Some(Self::SandboxInspectResponse),
            0x1024 => Some(Self::SandboxListResponse),
            0x1025 => Some(Self::SandboxPortForwardResponse),
            0x1026 => Some(Self::SandboxPortForwardRemoveResponse),
            // Sandbox workload responses (streaming).
            0x1037 => Some(Self::SandboxEvent),
            0x1038 => Some(Self::SandboxFileData),
            0x1039 => Some(Self::SandboxFileWriteResponse),
            // Sandbox snapshot responses.
            0x1040 => Some(Self::SandboxCheckpointResponse),
            0x1041 => Some(Self::SandboxRestoreResponse),
            0x1042 => Some(Self::SandboxListSnapshotsResponse),
            0x1043 => Some(Self::SandboxDeleteSnapshotResponse),
            // Sandbox execution responses (execution redesign, CORE-55/56).
            0x1060 => Some(Self::SandboxExecStartResponse),
            0x1061 => Some(Self::SandboxExecEvent),
            0x1062 => Some(Self::SandboxStdinStatus),
            0x1064 => Some(Self::SandboxExecSignalResponse),
            0x1065 => Some(Self::SandboxExecResizeResponse),
            0x1066 => Some(Self::SandboxExecWaitResponse),
            0x1050 => Some(Self::MachineExecOutput),
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
                | Self::SandboxEventsRequest
                | Self::SandboxFileReadRequest
                | Self::SandboxFileWriteRequest
                | Self::SandboxPortForwardRequest
                | Self::SandboxPortForwardRemoveRequest
                | Self::SandboxCheckpointRequest
                | Self::SandboxRestoreRequest
                | Self::SandboxListSnapshotsRequest
                | Self::SandboxDeleteSnapshotRequest
                | Self::SandboxExecStartRequest
                | Self::SandboxExecAttachRequest
                | Self::SandboxStdinWriteRequest
                | Self::SandboxStdinStatusRequest
                | Self::SandboxExecSignalRequest
                | Self::SandboxExecResizeRequest
                | Self::SandboxExecWaitRequest
        )
    }

    /// Returns true if this message type is a Kubernetes management request.
    #[must_use]
    pub const fn is_kubernetes_request(self) -> bool {
        matches!(
            self,
            Self::KubernetesStartRequest
                | Self::KubernetesStopRequest
                | Self::KubernetesDeleteRequest
                | Self::KubernetesStatusRequest
                | Self::KubernetesKubeconfigRequest
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{AGENT_PROTOCOL_VERSION, MIN_AGENT_PROTOCOL_VERSION, MessageType};

    #[test]
    fn protocol_version_2_is_burned() {
        // `2` is burned: 0.6.0 daemons in the wild interpret it as "speaks
        // the redesigned sandbox payloads" (see the AGENT_PROTOCOL_VERSION
        // doc). A future mechanical +1 bump must fail here and jump to 3.
        let version = AGENT_PROTOCOL_VERSION;
        assert!(
            version == 1 || version >= 3,
            "AGENT_PROTOCOL_VERSION must never be 2 — it is burned; bump to 3"
        );
        let min = MIN_AGENT_PROTOCOL_VERSION;
        assert!(
            min == 1 || min >= 3,
            "MIN_AGENT_PROTOCOL_VERSION must never be 2 — it is burned; bump to 3"
        );
    }

    #[test]
    fn message_type_roundtrip_known_values() {
        const CASES: &[(u32, MessageType)] = &[
            (0x0001, MessageType::PingRequest),
            (0x0002, MessageType::GetSystemInfoRequest),
            (0x0003, MessageType::EnsureRuntimeRequest),
            (0x0004, MessageType::RuntimeStatusRequest),
            (0x0005, MessageType::KubernetesStartRequest),
            (0x0006, MessageType::KubernetesStopRequest),
            (0x0007, MessageType::KubernetesDeleteRequest),
            (0x0008, MessageType::KubernetesStatusRequest),
            (0x0009, MessageType::KubernetesKubeconfigRequest),
            (0x000A, MessageType::ShutdownRequest),
            (0x000B, MessageType::MmapReadFileRequest),
            (0x000C, MessageType::DiskTrimRequest),
            (0x000D, MessageType::WatchReadinessRequest),
            (0x000E, MessageType::KillAgentRequest),
            (0x000F, MessageType::WatchMemoryPressureRequest),
            (0x0010, MessageType::WatchStatsRequest),
            (0x0011, MessageType::ContainerFsPathsRequest),
            (0x0012, MessageType::ImageFsPathsRequest),
            (0x0013, MessageType::EnsureNfsExportRequest),
            (0x100F, MessageType::MemoryPressureEvent),
            (0x1010, MessageType::MachineStats),
            (0x1011, MessageType::ContainerFsPathsResponse),
            (0x1012, MessageType::ImageFsPathsResponse),
            (0x1013, MessageType::EnsureNfsExportResponse),
            (0x1001, MessageType::PingResponse),
            (0x1002, MessageType::GetSystemInfoResponse),
            (0x1003, MessageType::EnsureRuntimeResponse),
            (0x1004, MessageType::RuntimeStatusResponse),
            (0x1005, MessageType::KubernetesStartResponse),
            (0x1006, MessageType::KubernetesStopResponse),
            (0x1007, MessageType::KubernetesDeleteResponse),
            (0x1008, MessageType::KubernetesStatusResponse),
            (0x1009, MessageType::KubernetesKubeconfigResponse),
            (0x100A, MessageType::ShutdownResponse),
            (0x100B, MessageType::MmapReadFileResponse),
            (0x100C, MessageType::DiskTrimResponse),
            (0x100D, MessageType::ReadinessEvent),
            (0x100E, MessageType::KillAgentResponse),
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
            (0x0025, MessageType::SandboxPortForwardRequest),
            (0x0026, MessageType::SandboxPortForwardRemoveRequest),
            (0x1025, MessageType::SandboxPortForwardResponse),
            (0x1026, MessageType::SandboxPortForwardRemoveResponse),
            // Sandbox workload.
            (0x0032, MessageType::SandboxEventsRequest),
            (0x0035, MessageType::SandboxFileReadRequest),
            (0x0036, MessageType::SandboxFileWriteRequest),
            (0x0037, MessageType::SandboxFileChunk),
            (0x1037, MessageType::SandboxEvent),
            (0x1038, MessageType::SandboxFileData),
            (0x1039, MessageType::SandboxFileWriteResponse),
            // Sandbox executions (execution redesign, CORE-55/56).
            (0x0060, MessageType::SandboxExecStartRequest),
            (0x0061, MessageType::SandboxExecAttachRequest),
            (0x0062, MessageType::SandboxStdinWriteRequest),
            (0x0063, MessageType::SandboxStdinStatusRequest),
            (0x0064, MessageType::SandboxExecSignalRequest),
            (0x0065, MessageType::SandboxExecResizeRequest),
            (0x0066, MessageType::SandboxExecWaitRequest),
            (0x1060, MessageType::SandboxExecStartResponse),
            (0x1061, MessageType::SandboxExecEvent),
            (0x1062, MessageType::SandboxStdinStatus),
            (0x1064, MessageType::SandboxExecSignalResponse),
            (0x1065, MessageType::SandboxExecResizeResponse),
            (0x1066, MessageType::SandboxExecWaitResponse),
            // Sandbox snapshots.
            (0x0040, MessageType::SandboxCheckpointRequest),
            (0x0041, MessageType::SandboxRestoreRequest),
            (0x0042, MessageType::SandboxListSnapshotsRequest),
            (0x0043, MessageType::SandboxDeleteSnapshotRequest),
            (0x1040, MessageType::SandboxCheckpointResponse),
            (0x1041, MessageType::SandboxRestoreResponse),
            (0x1042, MessageType::SandboxListSnapshotsResponse),
            (0x1043, MessageType::SandboxDeleteSnapshotResponse),
            // Machine-level exec.
            (0x0050, MessageType::MachineExecRequest),
            (0x0051, MessageType::MachineExecInput),
            (0x0052, MessageType::MachineExecResize),
            (0x1050, MessageType::MachineExecOutput),
        ];

        for (raw, expected) in CASES {
            assert_eq!(MessageType::from_u32(*raw), Some(*expected));
        }
    }

    #[test]
    fn message_type_rejects_unknown_values() {
        assert_eq!(MessageType::from_u32(0x9999), None);
        assert_eq!(MessageType::from_u32(0x1F00), None);
    }

    #[test]
    fn is_sandbox_request_classifies_correctly() {
        assert!(MessageType::SandboxCreateRequest.is_sandbox_request());
        assert!(MessageType::SandboxExecStartRequest.is_sandbox_request());
        assert!(MessageType::SandboxExecAttachRequest.is_sandbox_request());
        assert!(MessageType::SandboxStdinWriteRequest.is_sandbox_request());
        assert!(MessageType::SandboxExecWaitRequest.is_sandbox_request());
        assert!(MessageType::SandboxFileReadRequest.is_sandbox_request());
        assert!(MessageType::SandboxFileWriteRequest.is_sandbox_request());
        assert!(MessageType::SandboxCheckpointRequest.is_sandbox_request());
        assert!(!MessageType::PingRequest.is_sandbox_request());
        assert!(!MessageType::SandboxCreateResponse.is_sandbox_request());
    }

    #[test]
    fn retired_sandbox_values_stay_unknown() {
        // Retired by the execution redesign (CORE-55/56); the values must
        // not be resurrected or reused.
        for retired in [0x0030, 0x0031, 0x0033, 0x0034, 0x1035, 0x1036] {
            assert_eq!(MessageType::from_u32(retired), None, "0x{retired:04x}");
        }
    }

    #[test]
    fn is_kubernetes_request_classifies_correctly() {
        assert!(MessageType::KubernetesStartRequest.is_kubernetes_request());
        assert!(MessageType::KubernetesKubeconfigRequest.is_kubernetes_request());
        assert!(!MessageType::PingRequest.is_kubernetes_request());
        assert!(!MessageType::KubernetesStatusResponse.is_kubernetes_request());
    }
}
