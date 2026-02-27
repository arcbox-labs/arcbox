//! tonic gRPC server and service implementations.
//!
//! Exposes two services defined in `sandbox.proto`:
//! - `sandbox.v1.SandboxService`         — core sandbox lifecycle
//! - `sandbox.v1.SandboxSnapshotService` — checkpoint / restore

pub mod sandbox_svc;
pub mod server;

pub use sandbox_svc::{SandboxServiceImpl, SandboxSnapshotServiceImpl};
pub use server::serve;
