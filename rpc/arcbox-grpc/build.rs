//! Build script for gRPC service code generation.
//!
//! This generates Rust client and server code for gRPC services
//! defined in the proto files using tonic-prost-build.
//!
//! Message types are imported from arcbox-protocol (prost-generated).
//! All protos use the unified `arcbox.v1` package namespace.

fn main() {
    // Use proto files from arcbox-protocol
    let proto_dir = "../arcbox-protocol/proto";

    let protos = [
        "../arcbox-protocol/proto/machine.proto",
        "../arcbox-protocol/proto/macos.proto",
        "../arcbox-protocol/proto/container.proto",
        "../arcbox-protocol/proto/image.proto",
        "../arcbox-protocol/proto/agent.proto",
        "../arcbox-protocol/proto/api.proto",
        "../arcbox-protocol/proto/kubernetes.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/sandbox.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/process.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/filesystem.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/snapshot.proto",
        "../arcbox-protocol/proto/arcbox/sandbox/v1/errors.proto",
        "../arcbox-protocol/proto/stats.proto",
    ];

    let descriptor_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"))
            .join("arcbox_descriptor.bin");

    // Configure tonic-prost-build (tonic 0.14 split prost integration out of tonic-build)
    tonic_prost_build::configure()
        // Emit the file descriptor set for gRPC server reflection.
        .file_descriptor_set_path(&descriptor_path)
        // Map arcbox.v1 package to arcbox_protocol::v1 types
        .extern_path(".arcbox.v1", "::arcbox_protocol::v1")
        // Map sandbox.v1 package to arcbox_protocol::sandbox_v1 types
        .extern_path(".arcbox.sandbox.v1", "::arcbox_protocol::sandbox_v1")
        // Well-known types map to pbjson-types, matching arcbox-protocol's
        // prost build — the two extern_path calls must stay in lockstep so
        // Timestamp/Empty are the same Rust types across both codegens.
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "::pbjson_types")
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
