//! VMM daemon configuration types.
//!
//! Three unrelated concerns, one module: jailer sandboxing parameters, the
//! top-level `config.toml` shape, and the Firecracker snapshot-type vocabulary.

mod jailer;
mod snapshot;
mod vmm;

pub use jailer::JailerConfig;
pub use snapshot::SnapshotType;
pub use vmm::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, SandboxDatapath, VmmConfig,
};
