//! Build script for the sandbox Connect RPC surface.
//!
//! Generates buffa message types plus ConnectRPC service traits and clients
//! for the four `arcbox.sandbox.v1` protos. Only the sandbox package is
//! compiled here: the rest of the daemon's gRPC surface stays on
//! tonic/prost (`arcbox-grpc`), and the host↔guest vsock payloads stay on
//! the prost types in `arcbox-protocol`. buffa and prost both emit standard
//! protobuf bytes, so the two representations are wire-identical and the
//! guest agent needs no change.

fn main() {
    let proto_dir = "../arcbox-protocol/proto";

    let protos = [
        "../arcbox-protocol/proto/arcbox/sandbox/v1/sandbox.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/process.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/filesystem.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/snapshot.proto",
    ];

    connectrpc_build::Config::new()
        .files(&protos)
        .includes(&[proto_dir])
        .include_file("_connectrpc.rs")
        .generate_json(true)
        .compile()
        .expect("Failed to compile sandbox protos for Connect");
}
