//! # arcbox-api
//!
//! The daemon's API service implementations, served over Connect (one set
//! of handlers answers Connect, gRPC, and gRPC-Web): machine, sandbox,
//! migration, kubernetes, stats, and system services.

pub mod connect;
pub mod error;

pub use arcbox_connect::v1::setup_status::Phase as SetupPhase;
#[cfg(target_os = "macos")]
pub use connect::MacosServiceImpl;
pub use connect::SharedRuntime;
pub use connect::{
    IconServiceImpl, KubernetesServiceImpl, MachineServiceImpl, MigrationServiceImpl,
    SandboxFilesystemServiceImpl, SandboxProcessServiceImpl, SandboxServiceImpl,
    SandboxSnapshotServiceImpl, StatsServiceImpl,
};
pub use connect::{SetupState, SystemServiceImpl};
pub use error::{ApiError, Result};
