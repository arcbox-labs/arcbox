//! `vmm-grpc` — tonic gRPC server and service implementations.
//!
//! Exposes two services:
//! - `arcbox.v1.MachineService` — VM CRUD + lifecycle (arcbox-protocol compatible)
//! - `arcbox.v1.SystemService`  — system info, version, liveness, events

// Generated protobuf/tonic code.
pub mod proto {
    /// `arcbox.v1` — machine, system, and common types.
    pub mod arcbox {
        tonic::include_proto!("arcbox.v1");
    }
}

pub mod machine_svc;
pub mod server;
pub mod system_svc;

pub use server::serve;

/// Convert a `chrono::DateTime<Utc>` to the arcbox `Timestamp` proto message.
pub(crate) fn timestamp(dt: chrono::DateTime<chrono::Utc>) -> proto::arcbox::Timestamp {
    proto::arcbox::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}
