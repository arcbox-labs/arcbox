//! Build script for gRPC service generation.

fn main() {
    // TODO: When .proto files are added, compile them here:
    //
    // tonic_build::configure()
    //     .build_server(true)
    //     .build_client(true)
    //     .compile(
    //         &["proto/container.proto", "proto/machine.proto"],
    //         &["proto/"],
    //     )
    //     .expect("Failed to compile protos");

    println!("cargo:rerun-if-changed=proto/");
}
