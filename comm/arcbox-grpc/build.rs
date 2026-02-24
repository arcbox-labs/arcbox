//! Build script for gRPC service code generation.
//!
//! This generates Rust client and server code for gRPC services
//! defined in the proto files using tonic-build.
//!
//! Message types are imported from arcbox-protocol (prost-generated).
//! All protos use the unified `arcbox.v1` package namespace.

fn main() {
    // Use proto files from arcbox-protocol
    let proto_dir = "../arcbox-protocol/proto";

    let protos = [
        "../arcbox-protocol/proto/machine.proto",
        "../arcbox-protocol/proto/container.proto",
        "../arcbox-protocol/proto/image.proto",
        "../arcbox-protocol/proto/agent.proto",
        "../arcbox-protocol/proto/api.proto",
    ];

    // Configure tonic-build
    tonic_build::configure()
        // Map arcbox.v1 package to arcbox_protocol::v1 types
        .extern_path(".arcbox.v1", "::arcbox_protocol::v1")
        // Generate client code
        .build_client(true)
        // Generate server code
        .build_server(true)
        // Compile protos from arcbox-protocol
        .compile_protos(&protos, &[proto_dir])
        .expect("Failed to compile protos");

    // Tell cargo to recompile if any proto file changes
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed={proto_dir}/common.proto");
}
