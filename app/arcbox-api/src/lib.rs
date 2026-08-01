//! # arcbox-api
//!
//! gRPC service implementations for `ArcBox`.
//!
//! This crate hosts service implementations consumed by the `arcbox-daemon`
//! binary. It provides machine, sandbox, migration, and system gRPC services.

pub mod connect;
pub mod error;
// tonic::Status is ~176 bytes — every gRPC method returns Result<_, Status>,
// so this lint is unavoidable throughout the module tree.
#[allow(clippy::result_large_err)]
pub mod grpc;

// Re-export gRPC service types from arcbox-grpc for convenience.
pub use arcbox_grpc::v1::{
    kubernetes_service_client, kubernetes_service_server, machine_service_client,
    machine_service_server, migration_service_client, migration_service_server,
    stats_service_client, stats_service_server,
};
#[cfg(target_os = "macos")]
pub use arcbox_grpc::v1::{macos_service_client, macos_service_server};

pub use arcbox_protocol::v1::setup_status::Phase as SetupPhase;
pub use connect::{
    IconServiceImpl, KubernetesServiceImpl, MigrationServiceImpl, SandboxFilesystemServiceImpl,
    SandboxProcessServiceImpl, SandboxServiceImpl, SandboxSnapshotServiceImpl, StatsServiceImpl,
};
pub use connect::{SetupState, SystemServiceImpl};
pub use error::{ApiError, Result};
#[cfg(target_os = "macos")]
pub use grpc::MacosServiceImpl;
pub use grpc::{MachineServiceImpl, SharedRuntime};
