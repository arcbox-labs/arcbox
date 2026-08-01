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
        // The daemon's own surface (CORE-68). These all share one `arcbox.v1`
        // package, so message generation is all-or-nothing here even though
        // the services move onto Connect one at a time. `common.proto` must be
        // listed explicitly: it defines this package's hand-rolled `Timestamp`
        // and `Mount`, which are NOT the well-known types.
        "../arcbox-protocol/proto/common.proto",
        "../arcbox-protocol/proto/machine.proto",
        "../arcbox-protocol/proto/macos.proto",
        "../arcbox-protocol/proto/container.proto",
        "../arcbox-protocol/proto/image.proto",
        "../arcbox-protocol/proto/agent.proto",
        "../arcbox-protocol/proto/api.proto",
        "../arcbox-protocol/proto/kubernetes.proto",
        "../arcbox-protocol/proto/stats.proto",
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
        // `arcbox.v1` files sit at the proto root rather than in `arcbox/v1/`
        // (the PACKAGE_DIRECTORY_MATCH violation `buf lint` already reports),
        // so without this the generator emits one module per file and
        // intra-package references do not resolve.
        .file_per_package(true)
        .compile()
        .expect("Failed to compile protos for Connect");
}
