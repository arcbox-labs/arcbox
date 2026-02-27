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

    // All proto files to compile (unified arcbox.v1 package).
    let protos = [
        "proto/common.proto",
        "proto/machine.proto",
        "proto/container.proto",
        "proto/image.proto",
        "proto/agent.proto",
        "proto/api.proto",
    ];

    // Configure prost-build (no tonic - services are in arcbox-grpc).
    let mut config = prost_build::Config::new();

    // Output to src/generated/ for IDE support.
    config.out_dir(&out_dir);

    // Generate serde derives for all messages.
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");

    // Compile proto files.
    config
        .compile_protos(&protos, &[proto_dir])
        .expect("Failed to compile protobuf files");

    // Format generated code so `cargo fmt --check` stays clean.
    let generated_file = out_dir.join("arcbox.v1.rs");
    let _ = Command::new("rustfmt").arg(&generated_file).status();

    // Tell cargo to recompile if any proto file changes.
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
}
