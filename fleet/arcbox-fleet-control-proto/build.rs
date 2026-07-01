//! Generates the fleet agent's local control-plane server/client stubs.
//!
//! Unlike `arcbox-fleet-proto` (the vendored, client-only gateway contract),
//! this proto is internal-only: the agent is the server, the
//! `arcbox-fleet-agent` CLI and the desktop app are clients.

fn main() {
    let proto = "proto/arcbox/fleet/control/v1/control.proto";

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &["proto"])
        .expect("Failed to compile control.proto");

    println!("cargo:rerun-if-changed={proto}");
}
