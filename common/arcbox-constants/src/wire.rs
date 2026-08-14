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
///
/// v3: runtime startup requires the host-provided
/// `arcbox.runtime_generation` kernel parameter and materializes runtime
/// assets onto the guest Btrfs data disk before execution. Sandbox
/// Stop/Remove responses also carry a durable cleanup generation, completed
/// through Prepare/Finalize after host listeners are gone.
pub const AGENT_PROTOCOL_VERSION: u32 = 3;

/// Oldest agent protocol version this host still accepts.
///
/// Agents reporting less (including `0` — agents that predate the
/// handshake field) are rejected at boot with an actionable error
/// instead of silently misbehaving under field skew.
pub const MIN_AGENT_PROTOCOL_VERSION: u32 = 3;

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
    /// Validate one exact durable cleanup generation before the host removes
    /// listeners (payload: `arcbox.v1.SandboxCleanupTicket`).
    SandboxCleanupPrepareRequest = 0x0027,
    /// Confirm host cleanup, delete the matching guest DNAT generation, and
    /// recycle its quarantined network allocation (payload:
    /// `arcbox.v1.SandboxCleanupTicket`).
    SandboxCleanupFinalizeRequest = 0x0028,
    /// Opens the internal durable cleanup ticket stream (payload:
    /// `arcbox.v1.WatchSandboxCleanupRequest`).
    WatchSandboxCleanupRequest = 0x0029,

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
    /// Stat one path inside a sandbox (payload:
    /// `arcbox.sandbox.v1.StatFileRequest`). Answered with
    /// [`Self::SandboxFileStatResponse`].
    SandboxFileStatRequest = 0x0038,
    /// List a sandbox directory non-recursively (payload:
    /// `arcbox.sandbox.v1.ListDirRequest`). Answered with
    /// [`Self::SandboxFileListDirResponse`].
    SandboxFileListDirRequest = 0x0039,
    /// Create a directory with `mkdir -p` semantics (payload:
    /// `arcbox.sandbox.v1.MakeDirRequest`). Answered with
    /// [`Self::SandboxFileMakeDirResponse`].
    SandboxFileMakeDirRequest = 0x003A,
    /// Remove a file, symlink, or directory (payload:
    /// `arcbox.sandbox.v1.RemoveEntryRequest`). Answered with
    /// [`Self::SandboxFileRemoveResponse`].
    SandboxFileRemoveRequest = 0x003B,
    /// Rename / move an entry within a sandbox (payload:
    /// `arcbox.sandbox.v1.MoveEntryRequest`). Answered with
    /// [`Self::SandboxFileMoveResponse`].
    SandboxFileMoveRequest = 0x003C,
    /// Open a filesystem watch stream (payload:
    /// `arcbox.sandbox.v1.WatchDirRequest`). The agent answers with a
    /// stream of [`Self::SandboxFileWatchEvent`] frames, terminated by
    /// [`Self::SandboxFileWatchEnd`] when the sandbox stops.
    SandboxFileWatchRequest = 0x003D,

    // Sandbox snapshot request types (0x0040 - 0x0043).
    SandboxCheckpointRequest = 0x0040,
    SandboxRestoreRequest = 0x0041,
    SandboxListSnapshotsRequest = 0x0042,
    SandboxDeleteSnapshotRequest = 0x0043,

    // Sandbox pause/resume request types (0x0044 - 0x0045), CORE-21.
    /// Pause a sandbox: checkpoint, then release its VM while keeping the
    /// record and disk under the same id (payload:
    /// `arcbox.sandbox.v1.PauseSandboxRequest`). Answered with
    /// [`Self::SandboxPauseResponse`].
    SandboxPauseRequest = 0x0044,
    /// Resume a paused sandbox in place (payload:
    /// `arcbox.v1.SandboxResumeCommand`, which carries the resume reason
    /// the RESUMED event surfaces). Answered with
    /// [`Self::SandboxResumeResponse`].
    SandboxResumeRequest = 0x0045,
    /// Replace a sandbox's lifecycle deadlines — TTL re-armed from now,
    /// idle timeout/policy replaced (payload:
    /// `arcbox.sandbox.v1.SetLifecycleRequest`, CORE-60). Answered with
    /// [`Self::SandboxSetLifecycleResponse`].
    SandboxSetLifecycleRequest = 0x0046,

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
    /// List a sandbox's retained executions (payload:
    /// `arcbox.sandbox.v1.ListExecutionsRequest`). Answered with
    /// [`Self::SandboxExecListResponse`].
    SandboxExecListRequest = 0x0067,
    /// Wait for a TCP listener inside a sandbox (payload:
    /// `arcbox.sandbox.v1.WaitForPortRequest`). Answered with
    /// [`Self::SandboxWaitForPortResponse`]; an elapsed deadline is an
    /// `Error` frame with code 504.
    SandboxWaitForPortRequest = 0x0068,

    // Sandbox template catalog request types (0x0070 - 0x0074), CORE-107.
    /// Build a template from a source and register it as the catalog draft
    /// (payload: `arcbox.sandbox.v1.BuildTemplateRequest`). Blocks until the
    /// build completes. Answered with
    /// [`Self::SandboxTemplateBuildResponse`].
    SandboxTemplateBuildRequest = 0x0070,
    /// Freeze a template's draft as an immutable version (payload:
    /// `arcbox.sandbox.v1.PublishTemplateRequest`). Answered with
    /// [`Self::SandboxTemplatePublishResponse`].
    SandboxTemplatePublishRequest = 0x0071,
    /// Resolve a `name[:version]` template reference (payload:
    /// `arcbox.sandbox.v1.GetTemplateRequest`). Answered with
    /// [`Self::SandboxTemplateGetResponse`].
    SandboxTemplateGetRequest = 0x0072,
    /// List catalog templates (payload:
    /// `arcbox.sandbox.v1.ListTemplatesRequest`). Answered with
    /// [`Self::SandboxTemplateListResponse`].
    SandboxTemplateListRequest = 0x0073,
    /// Delete a template version, or a whole template with its artifacts
    /// (payload: `arcbox.sandbox.v1.DeleteTemplateRequest`). Answered with
    /// [`Self::SandboxTemplateDeleteResponse`].
    SandboxTemplateDeleteRequest = 0x0074,

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
    /// Acknowledges [`Self::SandboxCleanupPrepareRequest`].
    SandboxCleanupPrepareResponse = 0x1027,
    /// Acknowledges [`Self::SandboxCleanupFinalizeRequest`].
    SandboxCleanupFinalizeResponse = 0x1028,
    /// One durable cleanup ticket answering [`Self::WatchSandboxCleanupRequest`].
    SandboxCleanupEvent = 0x1029,
    /// Answers [`Self::SandboxPauseRequest`] (payload:
    /// `arcbox.v1.SandboxCleanupResponse` — pause quarantines the network
    /// like Stop, so it hands back the same durable cleanup ticket).
    SandboxPauseResponse = 0x1044,
    /// Answers [`Self::SandboxResumeRequest`] (payload:
    /// `arcbox.v1.SandboxResumeResponse` with the fresh IP).
    SandboxResumeResponse = 0x1045,
    /// Acknowledges [`Self::SandboxSetLifecycleRequest`] (empty payload).
    SandboxSetLifecycleResponse = 0x1046,

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
    /// Answers [`Self::SandboxFileStatRequest`] (payload:
    /// `arcbox.sandbox.v1.FileStat`).
    SandboxFileStatResponse = 0x103A,
    /// Answers [`Self::SandboxFileListDirRequest`] (payload:
    /// `arcbox.sandbox.v1.ListDirResponse`).
    SandboxFileListDirResponse = 0x103B,
    /// Acknowledges [`Self::SandboxFileMakeDirRequest`] (empty payload).
    SandboxFileMakeDirResponse = 0x103C,
    /// Acknowledges [`Self::SandboxFileRemoveRequest`] (empty payload).
    SandboxFileRemoveResponse = 0x103D,
    /// Acknowledges [`Self::SandboxFileMoveRequest`] (empty payload).
    SandboxFileMoveResponse = 0x103E,
    /// One frame of a directory-watch stream answering
    /// [`Self::SandboxFileWatchRequest`] (payload:
    /// `arcbox.sandbox.v1.WatchDirResponse` — an event or a keepalive).
    SandboxFileWatchEvent = 0x103F,
    /// Clean end of a directory-watch stream (empty payload): the sandbox
    /// stopped, so no further events can come. Lives past the snapshot and
    /// pause/resume blocks because 0x1040-0x1046 were already assigned.
    SandboxFileWatchEnd = 0x1047,

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
    /// Answers [`Self::SandboxExecListRequest`] (payload:
    /// `arcbox.sandbox.v1.ListExecutionsResponse`).
    SandboxExecListResponse = 0x1067,
    /// Acknowledges [`Self::SandboxWaitForPortRequest`] (empty payload):
    /// the listener exists.
    SandboxWaitForPortResponse = 0x1068,

    // Sandbox template catalog response types (0x1070 - 0x1074), CORE-107.
    /// Answers [`Self::SandboxTemplateBuildRequest`] (payload:
    /// `arcbox.sandbox.v1.Template` — the registered draft).
    SandboxTemplateBuildResponse = 0x1070,
    /// Answers [`Self::SandboxTemplatePublishRequest`] (payload:
    /// `arcbox.sandbox.v1.Template` — the frozen version).
    SandboxTemplatePublishResponse = 0x1071,
    /// Answers [`Self::SandboxTemplateGetRequest`] (payload:
    /// `arcbox.sandbox.v1.Template`).
    SandboxTemplateGetResponse = 0x1072,
    /// Answers [`Self::SandboxTemplateListRequest`] (payload:
    /// `arcbox.sandbox.v1.ListTemplatesResponse`).
    SandboxTemplateListResponse = 0x1073,
    /// Acknowledges [`Self::SandboxTemplateDeleteRequest`] (empty payload).
    SandboxTemplateDeleteResponse = 0x1074,

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
            0x0027 => Some(Self::SandboxCleanupPrepareRequest),
            0x0028 => Some(Self::SandboxCleanupFinalizeRequest),
            0x0029 => Some(Self::WatchSandboxCleanupRequest),
            // Sandbox workload requests.
            0x0032 => Some(Self::SandboxEventsRequest),
            0x0035 => Some(Self::SandboxFileReadRequest),
            0x0036 => Some(Self::SandboxFileWriteRequest),
            0x0037 => Some(Self::SandboxFileChunk),
            0x0038 => Some(Self::SandboxFileStatRequest),
            0x0039 => Some(Self::SandboxFileListDirRequest),
            0x003A => Some(Self::SandboxFileMakeDirRequest),
            0x003B => Some(Self::SandboxFileRemoveRequest),
            0x003C => Some(Self::SandboxFileMoveRequest),
            0x003D => Some(Self::SandboxFileWatchRequest),
            // Sandbox snapshot requests.
            0x0040 => Some(Self::SandboxCheckpointRequest),
            0x0041 => Some(Self::SandboxRestoreRequest),
            0x0042 => Some(Self::SandboxListSnapshotsRequest),
            0x0043 => Some(Self::SandboxDeleteSnapshotRequest),
            0x0044 => Some(Self::SandboxPauseRequest),
            0x0045 => Some(Self::SandboxResumeRequest),
            0x0046 => Some(Self::SandboxSetLifecycleRequest),
            // Sandbox execution requests (execution redesign, CORE-55/56).
            0x0060 => Some(Self::SandboxExecStartRequest),
            0x0061 => Some(Self::SandboxExecAttachRequest),
            0x0062 => Some(Self::SandboxStdinWriteRequest),
            0x0063 => Some(Self::SandboxStdinStatusRequest),
            0x0064 => Some(Self::SandboxExecSignalRequest),
            0x0065 => Some(Self::SandboxExecResizeRequest),
            0x0066 => Some(Self::SandboxExecWaitRequest),
            0x0067 => Some(Self::SandboxExecListRequest),
            0x0068 => Some(Self::SandboxWaitForPortRequest),
            0x0070 => Some(Self::SandboxTemplateBuildRequest),
            0x0071 => Some(Self::SandboxTemplatePublishRequest),
            0x0072 => Some(Self::SandboxTemplateGetRequest),
            0x0073 => Some(Self::SandboxTemplateListRequest),
            0x0074 => Some(Self::SandboxTemplateDeleteRequest),
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
            0x1027 => Some(Self::SandboxCleanupPrepareResponse),
            0x1028 => Some(Self::SandboxCleanupFinalizeResponse),
            0x1029 => Some(Self::SandboxCleanupEvent),
            0x1044 => Some(Self::SandboxPauseResponse),
            0x1045 => Some(Self::SandboxResumeResponse),
            0x1046 => Some(Self::SandboxSetLifecycleResponse),
            // Sandbox workload responses (streaming).
            0x1037 => Some(Self::SandboxEvent),
            0x1038 => Some(Self::SandboxFileData),
            0x1039 => Some(Self::SandboxFileWriteResponse),
            0x103A => Some(Self::SandboxFileStatResponse),
            0x103B => Some(Self::SandboxFileListDirResponse),
            0x103C => Some(Self::SandboxFileMakeDirResponse),
            0x103D => Some(Self::SandboxFileRemoveResponse),
            0x103E => Some(Self::SandboxFileMoveResponse),
            0x103F => Some(Self::SandboxFileWatchEvent),
            0x1047 => Some(Self::SandboxFileWatchEnd),
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
            0x1067 => Some(Self::SandboxExecListResponse),
            0x1068 => Some(Self::SandboxWaitForPortResponse),
            0x1070 => Some(Self::SandboxTemplateBuildResponse),
            0x1071 => Some(Self::SandboxTemplatePublishResponse),
            0x1072 => Some(Self::SandboxTemplateGetResponse),
            0x1073 => Some(Self::SandboxTemplateListResponse),
            0x1074 => Some(Self::SandboxTemplateDeleteResponse),
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
                | Self::SandboxFileStatRequest
                | Self::SandboxFileListDirRequest
                | Self::SandboxFileMakeDirRequest
                | Self::SandboxFileRemoveRequest
                | Self::SandboxFileMoveRequest
                | Self::SandboxFileWatchRequest
                | Self::SandboxPortForwardRequest
                | Self::SandboxPortForwardRemoveRequest
                | Self::SandboxCleanupPrepareRequest
                | Self::SandboxCleanupFinalizeRequest
                | Self::WatchSandboxCleanupRequest
                | Self::SandboxCheckpointRequest
                | Self::SandboxRestoreRequest
                | Self::SandboxListSnapshotsRequest
                | Self::SandboxDeleteSnapshotRequest
                | Self::SandboxPauseRequest
                | Self::SandboxResumeRequest
                | Self::SandboxSetLifecycleRequest
                | Self::SandboxExecStartRequest
                | Self::SandboxExecAttachRequest
                | Self::SandboxStdinWriteRequest
                | Self::SandboxStdinStatusRequest
                | Self::SandboxExecSignalRequest
                | Self::SandboxExecResizeRequest
                | Self::SandboxExecWaitRequest
                | Self::SandboxExecListRequest
                | Self::SandboxWaitForPortRequest
                | Self::SandboxTemplateBuildRequest
                | Self::SandboxTemplatePublishRequest
                | Self::SandboxTemplateGetRequest
                | Self::SandboxTemplateListRequest
                | Self::SandboxTemplateDeleteRequest
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
            (0x0027, MessageType::SandboxCleanupPrepareRequest),
            (0x0028, MessageType::SandboxCleanupFinalizeRequest),
            (0x0029, MessageType::WatchSandboxCleanupRequest),
            (0x1025, MessageType::SandboxPortForwardResponse),
            (0x1026, MessageType::SandboxPortForwardRemoveResponse),
            (0x1027, MessageType::SandboxCleanupPrepareResponse),
            (0x1028, MessageType::SandboxCleanupFinalizeResponse),
            (0x1029, MessageType::SandboxCleanupEvent),
            // Sandbox workload.
            (0x0032, MessageType::SandboxEventsRequest),
            (0x0035, MessageType::SandboxFileReadRequest),
            (0x0036, MessageType::SandboxFileWriteRequest),
            (0x0037, MessageType::SandboxFileChunk),
            (0x0038, MessageType::SandboxFileStatRequest),
            (0x0039, MessageType::SandboxFileListDirRequest),
            (0x003A, MessageType::SandboxFileMakeDirRequest),
            (0x003B, MessageType::SandboxFileRemoveRequest),
            (0x003C, MessageType::SandboxFileMoveRequest),
            (0x003D, MessageType::SandboxFileWatchRequest),
            (0x1037, MessageType::SandboxEvent),
            (0x1038, MessageType::SandboxFileData),
            (0x1039, MessageType::SandboxFileWriteResponse),
            (0x103A, MessageType::SandboxFileStatResponse),
            (0x103B, MessageType::SandboxFileListDirResponse),
            (0x103C, MessageType::SandboxFileMakeDirResponse),
            (0x103D, MessageType::SandboxFileRemoveResponse),
            (0x103E, MessageType::SandboxFileMoveResponse),
            (0x103F, MessageType::SandboxFileWatchEvent),
            (0x1047, MessageType::SandboxFileWatchEnd),
            // Sandbox executions (execution redesign, CORE-55/56).
            (0x0060, MessageType::SandboxExecStartRequest),
            (0x0061, MessageType::SandboxExecAttachRequest),
            (0x0062, MessageType::SandboxStdinWriteRequest),
            (0x0063, MessageType::SandboxStdinStatusRequest),
            (0x0064, MessageType::SandboxExecSignalRequest),
            (0x0065, MessageType::SandboxExecResizeRequest),
            (0x0066, MessageType::SandboxExecWaitRequest),
            (0x0067, MessageType::SandboxExecListRequest),
            (0x0068, MessageType::SandboxWaitForPortRequest),
            (0x0070, MessageType::SandboxTemplateBuildRequest),
            (0x0071, MessageType::SandboxTemplatePublishRequest),
            (0x0072, MessageType::SandboxTemplateGetRequest),
            (0x0073, MessageType::SandboxTemplateListRequest),
            (0x0074, MessageType::SandboxTemplateDeleteRequest),
            (0x1060, MessageType::SandboxExecStartResponse),
            (0x1061, MessageType::SandboxExecEvent),
            (0x1062, MessageType::SandboxStdinStatus),
            (0x1064, MessageType::SandboxExecSignalResponse),
            (0x1065, MessageType::SandboxExecResizeResponse),
            (0x1066, MessageType::SandboxExecWaitResponse),
            (0x1067, MessageType::SandboxExecListResponse),
            (0x1068, MessageType::SandboxWaitForPortResponse),
            (0x1070, MessageType::SandboxTemplateBuildResponse),
            (0x1071, MessageType::SandboxTemplatePublishResponse),
            (0x1072, MessageType::SandboxTemplateGetResponse),
            (0x1073, MessageType::SandboxTemplateListResponse),
            (0x1074, MessageType::SandboxTemplateDeleteResponse),
            // Sandbox snapshots.
            (0x0040, MessageType::SandboxCheckpointRequest),
            (0x0041, MessageType::SandboxRestoreRequest),
            (0x0042, MessageType::SandboxListSnapshotsRequest),
            (0x0043, MessageType::SandboxDeleteSnapshotRequest),
            (0x0044, MessageType::SandboxPauseRequest),
            (0x0045, MessageType::SandboxResumeRequest),
            (0x0046, MessageType::SandboxSetLifecycleRequest),
            (0x1044, MessageType::SandboxPauseResponse),
            (0x1045, MessageType::SandboxResumeResponse),
            (0x1046, MessageType::SandboxSetLifecycleResponse),
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
        assert!(MessageType::SandboxFileStatRequest.is_sandbox_request());
        assert!(MessageType::SandboxFileListDirRequest.is_sandbox_request());
        assert!(MessageType::SandboxFileMakeDirRequest.is_sandbox_request());
        assert!(MessageType::SandboxFileRemoveRequest.is_sandbox_request());
        assert!(MessageType::SandboxFileMoveRequest.is_sandbox_request());
        assert!(MessageType::SandboxFileWatchRequest.is_sandbox_request());
        assert!(MessageType::SandboxCheckpointRequest.is_sandbox_request());
        assert!(MessageType::SandboxPauseRequest.is_sandbox_request());
        assert!(MessageType::SandboxResumeRequest.is_sandbox_request());
        assert!(MessageType::SandboxSetLifecycleRequest.is_sandbox_request());
        assert!(MessageType::SandboxTemplateBuildRequest.is_sandbox_request());
        assert!(MessageType::SandboxTemplateDeleteRequest.is_sandbox_request());
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
