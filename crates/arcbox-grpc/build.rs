//! Build script for gRPC service code generation.
//!
//! This generates Rust client and server code for gRPC services
//! defined in the proto files using tonic-build.
//!
//! Message types are imported from arcbox-protocol (prost-generated).

fn main() {
    let proto_dir = "proto";

    let protos = [
        "proto/machine.proto",
        "proto/container.proto",
        "proto/image.proto",
        "proto/agent.proto",
    ];

    // Configure tonic-build
    tonic_build::configure()
        // Use message types from arcbox-protocol
        .extern_path(".arcbox.common", "::arcbox_protocol::common")
        .extern_path(".arcbox.machine", "::arcbox_protocol::machine")
        .extern_path(".arcbox.container", "::arcbox_protocol::container")
        .extern_path(".arcbox.image", "::arcbox_protocol::image")
        .extern_path(".arcbox.agent", "::arcbox_protocol::agent")
        // Generate client code
        .build_client(true)
        // Generate server code
        .build_server(true)
        // Compile
        .compile_protos(&protos, &[proto_dir])
        .expect("Failed to compile protos");

    // Tell cargo to recompile if any proto file changes
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed={proto_dir}/common.proto");
}
