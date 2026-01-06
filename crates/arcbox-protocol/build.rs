//! Build script for protocol buffer compilation.
//!
//! This generates Rust code from the .proto files in the proto/ directory.

use std::path::PathBuf;

fn main() {
    let proto_dir = PathBuf::from("proto");

    // Proto files to compile
    let protos = [
        "proto/common.proto",
        "proto/container.proto",
        "proto/image.proto",
        "proto/machine.proto",
        "proto/agent.proto",
    ];

    // Configure prost-build
    let mut config = prost_build::Config::new();

    // Generate serde derives for all messages
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");

    // Compile protos
    config
        .compile_protos(&protos, &[proto_dir])
        .expect("Failed to compile protobuf files");

    // Tell cargo to recompile if any proto file changes
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
}
