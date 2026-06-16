//! Generates the Fleet gateway client stubs from the vendored proto.
//!
//! The proto is the public `buf.build/arcboxlabs/fleet` module, vendored under
//! `proto/` (refresh with `make fleet-proto-sync`). Only the client is built —
//! the agent is a client of the gateway, never a server.

fn main() {
    let proto = "proto/arcbox/fleet/v1/fleet.proto";

    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(&[proto], &["proto"])
        .expect("Failed to compile fleet.proto");

    println!("cargo:rerun-if-changed={proto}");
}
