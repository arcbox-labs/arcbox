//! VMM daemon configuration types.
//!
//! One module per concern — `jailer` for the sandboxing parameters, `vmm`
//! for the top-level `config.toml` shape, `snapshot` for the Firecracker
//! snapshot-type vocabulary — re-exported here so callers keep writing
//! `crate::config::JailerConfig`. The modules are private; only these
//! re-exports are the surface.

mod jailer;
mod snapshot;
mod vmm;

pub use jailer::JailerConfig;
pub use snapshot::SnapshotType;
pub use vmm::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, SandboxDatapath, VmmConfig,
};
