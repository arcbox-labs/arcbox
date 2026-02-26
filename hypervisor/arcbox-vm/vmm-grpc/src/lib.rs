//! `vmm-grpc` — tonic gRPC server and service implementations.
//!
//! Exposes two services defined in `vmm-grpc/proto/sandbox.proto`:
//! - `sandbox.v1.SandboxService`         — core sandbox lifecycle
//! - `sandbox.v1.SandboxSnapshotService` — checkpoint / restore

// Generated protobuf/tonic code (package sandbox.v1).
pub mod proto {
    /// `sandbox.v1` — sandbox, snapshot, and common types.
    pub mod sandbox {
        tonic::include_proto!("sandbox.v1");
    }
}

pub mod sandbox_svc;
pub mod server;

pub use server::serve;
