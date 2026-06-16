//! Generated tonic client stubs for the Fleet gateway contract.
//!
//! The schema is the public module published at `buf.build/arcboxlabs/fleet`
//! (`FleetGatewayService`: `Enroll` + `Attach`). The internal dispatch service
//! is intentionally absent — it lives in the platform's unpublished module.

/// Fleet gateway protocol (`arcbox.fleet.v1` package).
pub mod v1 {
    tonic::include_proto!("arcbox.fleet.v1");
}
