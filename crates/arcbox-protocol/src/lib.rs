//! # arcbox-protocol
//!
//! Protocol definitions for ArcBox communication.
//!
//! This crate defines the message types and service interfaces used for
//! communication between:
//!
//! - CLI <-> Daemon (ttrpc over Unix socket)
//! - Host <-> Guest (ttrpc over vsock)
//! - Docker CLI <-> Daemon (REST API, handled by arcbox-docker)
//!
//! ## Protocol Buffers
//!
//! The protocol is defined using Protocol Buffers for efficient serialization.
//! Message types are generated at build time from `.proto` files.
//!
//! All types are defined under the `arcbox.v1` package and re-exported here.
//!
//! ## Module Structure
//!
//! Types can be accessed via:
//! - `arcbox_protocol::v1::TypeName` - canonical path
//! - `arcbox_protocol::TypeName` - convenient re-exports
//! - `arcbox_protocol::agent::TypeName` - backward compatible submodules
//!
//! ## Services
//!
//! Service definitions are available for:
//! - Container lifecycle operations
//! - Image management
//! - Virtual machine management
//! - Guest agent operations
//! - Network, volume, and system operations (API layer)

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// Generated protobuf code has many clippy warnings that we cannot control.
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::zero_sized_map_values)]

mod generated;

// Re-export the generated module as v1 (canonical path)
pub use generated::arcbox_v1 as v1;

// =============================================================================
// Backward compatible module re-exports
// =============================================================================

/// Common types (from common.proto).
///
/// Re-exports all types for backward compatibility.
pub mod common {
    pub use super::v1::{Empty, KeyValue, Mount, PortBinding, ResourceLimits, Timestamp};
}

/// Machine types (from machine.proto).
///
/// Re-exports all machine-related types for backward compatibility.
pub mod machine {
    pub use super::v1::{
        CreateMachineRequest, CreateMachineResponse, DirectoryMount, InspectMachineRequest,
        ListMachinesRequest, ListMachinesResponse, MachineExecOutput, MachineExecRequest,
        MachineHardware, MachineInfo, MachineNetwork, MachineOs, MachineStorage, MachineSummary,
        RemoveMachineRequest, SshInfoRequest, SshInfoResponse, StartMachineRequest,
        StopMachineRequest,
    };
}

/// Container types (from container.proto).
///
/// Re-exports all container-related types for backward compatibility.
pub mod container {
    pub use super::v1::{
        AttachInput, AttachOutput, ContainerConfig, ContainerInfo, ContainerState,
        ContainerStatsRequest, ContainerStatsResponse, ContainerSummary, ContainerTopRequest,
        ContainerTopResponse, CreateContainerRequest, CreateContainerResponse, ExecCreateRequest,
        ExecCreateResponse, ExecOutput, ExecStartRequest, InspectContainerRequest,
        KillContainerRequest, ListContainersRequest, ListContainersResponse, LogEntry,
        LogsRequest, MountPoint, NetworkSettings, PauseContainerRequest, ProcessRow,
        RemoveContainerRequest, StartContainerRequest, StopContainerRequest,
        UnpauseContainerRequest, WaitContainerRequest, WaitContainerResponse,
    };
}

/// Image types (from image.proto).
///
/// Re-exports all image-related types for backward compatibility.
pub mod image {
    pub use super::v1::{
        BuildContext, BuildProgress, ExistsImageRequest, ExistsImageResponse, ImageConfig,
        ImageInfo, ImageSummary, InspectImageRequest, ListImagesRequest, ListImagesResponse,
        PullImageRequest, PullProgress, PushImageRequest, PushProgress, RemoveImageRequest,
        RemoveImageResponse, RootFs, TagImageRequest,
    };
}

/// Agent types (from agent.proto).
///
/// Re-exports all agent-related types for backward compatibility.
pub mod agent {
    pub use super::v1::{
        AgentAttachInput, AgentAttachOutput, AgentAttachRequest, AgentBlockStats,
        AgentContainerInfo, AgentContainerStats, AgentCpuStats, AgentCreateContainerRequest,
        AgentCreateContainerResponse, AgentExecOutput, AgentExecRequest, AgentExecResizeRequest,
        AgentExecStartRequest, AgentExecStartResponse, AgentListContainersRequest,
        AgentListContainersResponse, AgentLogEntry, AgentLogsRequest, AgentMemoryStats,
        AgentNetworkStats, AgentPingRequest, AgentPingResponse, AgentRemoveContainerRequest,
        AgentStartContainerRequest, AgentStatsRequest, AgentStopContainerRequest, FileChunk,
        ReadFileRequest, SystemInfo, WriteFileResponse,
    };

    // Re-export container types that are commonly used in agent context.
    pub use super::v1::LogEntry;

    // Note: `ContainerInfo` in agent context refers to `AgentContainerInfo`
    // (the simplified container info returned by agent). The full `ContainerInfo`
    // from container.proto is re-exported at the crate level.
    pub type ContainerInfo = super::v1::AgentContainerInfo;

    // Backward compatibility type aliases (short names without Agent prefix).
    pub type AttachInput = super::v1::AgentAttachInput;
    pub type AttachOutput = super::v1::AgentAttachOutput;
    pub type AttachRequest = super::v1::AgentAttachRequest;
    pub type ContainerStats = super::v1::AgentContainerStats;
    pub type CpuStats = super::v1::AgentCpuStats;
    pub type MemoryStats = super::v1::AgentMemoryStats;
    pub type ExecRequest = super::v1::AgentExecRequest;
    pub type ExecOutput = super::v1::AgentExecOutput;
    pub type ExecResizeRequest = super::v1::AgentExecResizeRequest;
    pub type ExecStartRequest = super::v1::AgentExecStartRequest;
    pub type ExecStartResponse = super::v1::AgentExecStartResponse;
    pub type PingRequest = super::v1::AgentPingRequest;
    pub type PingResponse = super::v1::AgentPingResponse;
    pub type CreateContainerRequest = super::v1::AgentCreateContainerRequest;
    pub type CreateContainerResponse = super::v1::AgentCreateContainerResponse;
    pub type StartContainerRequest = super::v1::AgentStartContainerRequest;
    pub type StopContainerRequest = super::v1::AgentStopContainerRequest;
    pub type RemoveContainerRequest = super::v1::AgentRemoveContainerRequest;
    pub type ListContainersRequest = super::v1::AgentListContainersRequest;
    pub type ListContainersResponse = super::v1::AgentListContainersResponse;
    pub type LogsRequest = super::v1::AgentLogsRequest;
}

/// API types (from api.proto).
///
/// Re-exports network, volume, and system service types.
pub mod api {
    // Network service types
    pub use super::v1::{
        CreateNetworkRequest, CreateNetworkResponse, InspectNetworkRequest, IpamConfig,
        IpamSubnet, ListNetworksRequest, ListNetworksResponse, NetworkContainer, NetworkInfo,
        NetworkSummary, RemoveNetworkRequest,
    };

    // System service types
    pub use super::v1::{
        Event, EventActor, EventsRequest, GetInfoRequest, GetInfoResponse, GetVersionRequest,
        GetVersionResponse, PruneRequest, PruneResponse, SystemPingRequest, SystemPingResponse,
    };

    // Volume service types
    pub use super::v1::{
        CreateVolumeRequest, CreateVolumeResponse, InspectVolumeRequest, ListVolumesRequest,
        ListVolumesResponse, RemoveVolumeRequest, VolumeInfo, VolumeUsage,
    };

    // Shell/interactive session types
    pub use super::v1::{ShellInput, ShellOutput, TerminalSize};
}

// =============================================================================
// Convenient crate-level re-exports
// =============================================================================

// Common types
pub use v1::{Empty, KeyValue, Mount, PortBinding, ResourceLimits, Timestamp};

// Machine types
pub use v1::{
    CreateMachineRequest, CreateMachineResponse, DirectoryMount, InspectMachineRequest,
    ListMachinesRequest, ListMachinesResponse, MachineExecOutput, MachineExecRequest,
    MachineHardware, MachineInfo, MachineNetwork, MachineOs, MachineStorage, MachineSummary,
    RemoveMachineRequest, SshInfoRequest, SshInfoResponse, StartMachineRequest, StopMachineRequest,
};

// Container types
pub use v1::{
    AttachInput, AttachOutput, ContainerConfig, ContainerInfo, ContainerState,
    ContainerStatsRequest, ContainerStatsResponse, ContainerSummary, ContainerTopRequest,
    ContainerTopResponse, CreateContainerRequest, CreateContainerResponse, ExecCreateRequest,
    ExecCreateResponse, ExecOutput, ExecStartRequest, InspectContainerRequest, KillContainerRequest,
    ListContainersRequest, ListContainersResponse, LogEntry, LogsRequest, MountPoint,
    NetworkSettings, PauseContainerRequest, ProcessRow, RemoveContainerRequest,
    StartContainerRequest, StopContainerRequest, UnpauseContainerRequest, WaitContainerRequest,
    WaitContainerResponse,
};

// Image types
pub use v1::{
    BuildContext, BuildProgress, ExistsImageRequest, ExistsImageResponse, ImageConfig, ImageInfo,
    ImageSummary, InspectImageRequest, ListImagesRequest, ListImagesResponse, PullImageRequest,
    PullProgress, PushImageRequest, PushProgress, RemoveImageRequest, RemoveImageResponse, RootFs,
    TagImageRequest,
};

// Agent types
pub use v1::{
    AgentAttachInput, AgentAttachOutput, AgentAttachRequest, AgentBlockStats, AgentContainerInfo,
    AgentContainerStats, AgentCpuStats, AgentCreateContainerRequest, AgentCreateContainerResponse,
    AgentExecOutput, AgentExecRequest, AgentExecResizeRequest, AgentExecStartRequest,
    AgentExecStartResponse, AgentListContainersRequest, AgentListContainersResponse, AgentLogEntry,
    AgentLogsRequest, AgentMemoryStats, AgentNetworkStats, AgentPingRequest, AgentPingResponse,
    AgentRemoveContainerRequest, AgentStartContainerRequest, AgentStatsRequest,
    AgentStopContainerRequest, FileChunk, ReadFileRequest, SystemInfo, WriteFileResponse,
};

// API types - Network
pub use v1::{
    CreateNetworkRequest, CreateNetworkResponse, InspectNetworkRequest, IpamConfig, IpamSubnet,
    ListNetworksRequest, ListNetworksResponse, NetworkContainer, NetworkInfo, NetworkSummary,
    RemoveNetworkRequest,
};

// API types - System
pub use v1::{
    Event, EventActor, EventsRequest, GetInfoRequest, GetInfoResponse, GetVersionRequest,
    GetVersionResponse, PruneRequest, PruneResponse, SystemPingRequest, SystemPingResponse,
};

// API types - Volume
pub use v1::{
    CreateVolumeRequest, CreateVolumeResponse, InspectVolumeRequest, ListVolumesRequest,
    ListVolumesResponse, RemoveVolumeRequest, VolumeInfo, VolumeUsage,
};

// API types - Shell
pub use v1::{ShellInput, ShellOutput, TerminalSize};

// =============================================================================
// Backward compatibility type aliases at crate level
// =============================================================================

/// Backward compatibility: Container stats from agent.
pub type ContainerStats = AgentContainerStats;

/// Backward compatibility: CPU stats from agent.
pub type CpuStats = AgentCpuStats;

/// Backward compatibility: Memory stats from agent.
pub type MemoryStats = AgentMemoryStats;

/// Backward compatibility: Exec request (alias for AgentExecRequest).
pub type ExecRequest = AgentExecRequest;

/// Backward compatibility: Ping request (alias for AgentPingRequest).
pub type PingRequest = AgentPingRequest;

/// Backward compatibility: Ping response (alias for AgentPingResponse).
pub type PingResponse = AgentPingResponse;
