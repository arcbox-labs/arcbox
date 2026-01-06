//! Build script for gRPC service generation.

fn main() {
    // Compile gRPC services from proto files.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/generated")
        .compile_protos(&["proto/api.proto"], &["proto/"])
        .expect("Failed to compile protos");

    println!("cargo:rerun-if-changed=proto/");
}
