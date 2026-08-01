//! Build script for protocol buffer compilation.
//!
//! This generates Rust code from the .proto files in the proto/ directory.
//! Generated code is placed in src/generated/ for better IDE support.
//!
//! Note: Service code generation (tonic) is handled by arcbox-grpc crate.
//! This crate only generates message types using prost-build.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let proto_dir = PathBuf::from("proto");
    let out_dir = PathBuf::from("src/generated");

    // Ensure output directory exists.
    std::fs::create_dir_all(&out_dir).expect("Failed to create output directory");

    // All proto files to compile.
    // arcbox.v1 package: shared types for the main ArcBox protocol.
    // sandbox.v1 package: sandbox (microVM) lifecycle types.
    let protos = [
        "proto/common.proto",
        "proto/machine.proto",
        "proto/macos.proto",
        "proto/container.proto",
        "proto/image.proto",
        "proto/agent.proto",
        "proto/api.proto",
        "proto/kubernetes.proto",
        "proto/arcbox/sandbox/v1/sandbox.proto",
        "proto/arcbox/sandbox/v1/process.proto",
        "proto/arcbox/sandbox/v1/filesystem.proto",
        "proto/arcbox/sandbox/v1/snapshot.proto",
        "proto/stats.proto",
    ];

    // Configure prost-build (no tonic - services are in arcbox-grpc).
    let mut config = prost_build::Config::new();

    // Output to src/generated/ for IDE support.
    config.out_dir(&out_dir);
    // Keep compatibility with older protoc versions used in CI.
    // Newer protoc versions simply ignore this switch.
    config.protoc_arg("--experimental_allow_proto3_optional");

    // Generate serde derives for all messages.
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");

    // Well-known types (Timestamp, Empty) map to pbjson-types, whose types
    // carry serde impls following the canonical protobuf JSON mapping —
    // prost-types has no serde support, which would break the blanket
    // serde derives above. compile_well_known_types() drops prost-build's
    // implicit prost-types mapping so the extern_path below can take over.
    config.compile_well_known_types();
    config.extern_path(".google.protobuf", "::pbjson_types");

    // Compile proto files.
    config
        .compile_protos(&protos, &[proto_dir])
        .expect("Failed to compile protobuf files");

    // Format generated code so `cargo fmt --check` stays clean.
    let generated_file = out_dir.join("arcbox.v1.rs");
    let _ = Command::new("rustfmt").arg(&generated_file).status();
    let generated_file = out_dir.join("arcbox.sandbox.v1.rs");
    let _ = Command::new("rustfmt").arg(&generated_file).status();

    // Tell cargo to recompile if any proto file changes.
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
}
