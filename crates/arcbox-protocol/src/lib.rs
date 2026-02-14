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
//! ## Services
//!
//! - [`container`] - Container lifecycle operations
//! - [`image`] - Image management
//! - [`machine`] - Virtual machine management
//! - [`agent`] - Guest agent operations

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

// Include generated protobuf code
pub mod common {
    include!(concat!(env!("OUT_DIR"), "/arcbox.common.rs"));
}

pub mod container {
    include!(concat!(env!("OUT_DIR"), "/arcbox.container.rs"));
}

pub mod image {
    include!(concat!(env!("OUT_DIR"), "/arcbox.image.rs"));
}

pub mod machine {
    include!(concat!(env!("OUT_DIR"), "/arcbox.machine.rs"));
}

pub mod agent {
    include!(concat!(env!("OUT_DIR"), "/arcbox.agent.rs"));
}

// Re-export common types at the crate level for convenience
pub use common::{Empty, KeyValue, Mount, PortBinding, ResourceLimits, Timestamp};

// Re-export container types
pub use container::{
    ContainerConfig, ContainerInfo, ContainerState, ContainerSummary, CreateContainerRequest,
    CreateContainerResponse, InspectContainerRequest, ListContainersRequest,
    ListContainersResponse, LogEntry, LogsRequest, RemoveContainerRequest, StartContainerRequest,
    StopContainerRequest,
};

// Re-export image types
pub use image::{
    ImageConfig, ImageInfo, ImageSummary, InspectImageRequest, ListImagesRequest,
    ListImagesResponse, PullImageRequest, PullProgress, RemoveImageRequest, RemoveImageResponse,
};

// Re-export machine types
pub use machine::{
    CreateMachineRequest, CreateMachineResponse, InspectMachineRequest, ListMachinesRequest,
    ListMachinesResponse, MachineHardware, MachineInfo, MachineNetwork, MachineSummary,
    StartMachineRequest, StopMachineRequest,
};

// Re-export agent types
pub use agent::{
    ContainerStats, CpuStats, ExecOutput, ExecRequest, MemoryStats, PingRequest, PingResponse,
    SystemInfo,
};
