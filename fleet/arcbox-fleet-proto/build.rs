//! Generates the Fleet gateway client stubs from the vendored proto.
//!
//! The proto is the public `buf.build/arcboxlabs/fleet` module, vendored under
//! `proto/` (refresh with `make fleet-proto-sync`). The agent is a client of
//! the gateway, never a server — the server stubs are generated only so the
//! agent's tests can stand up a mock gateway.

fn main() {
    let proto = "proto/arcbox/fleet/v1/fleet.proto";

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &["proto"])
        .expect("Failed to compile fleet.proto");

    println!("cargo:rerun-if-changed={proto}");
}
