//! VMM daemon configuration types.
//!
//! One module per concern — `jailer` for the sandboxing parameters and
//! `vmm` for the top-level `config.toml` shape — re-exported here so
//! callers keep writing `crate::config::JailerConfig`. The modules are
//! private; only these re-exports are the surface.

mod jailer;
mod vmm;

// `SnapshotType` moved to `arcbox-snapshot` with the catalog that gives
// it meaning; re-exported so `crate::config::SnapshotType` still resolves.
pub use arcbox_snapshot::SnapshotType;
pub use jailer::JailerConfig;
pub use vmm::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, SandboxDatapath, VmmConfig,
};
