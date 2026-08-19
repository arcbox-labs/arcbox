//! Runtime configuration types.
//!
//! One module per concern — `jailer` for the sandboxing parameters and
//! `runtime` for the top-level `vmm.toml` shape — re-exported here so
//! callers keep writing `crate::config::JailerConfig`. The modules are
//! private; only these re-exports are the surface.

mod jailer;
mod runtime;

// `SnapshotType` moved to `arcbox-snapshot` with the catalog that gives
// it meaning; re-exported so `crate::config::SnapshotType` still resolves.
pub use arcbox_snapshot::SnapshotType;
pub use jailer::JailerConfig;
pub use runtime::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, RuntimeConfig, SandboxDatapath,
};
