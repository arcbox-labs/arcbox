use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Proto files live alongside this crate in vmm-grpc/proto/.
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proto");

    // Compile sandbox.v1 — the single public API surface of this daemon.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_dir.join("sandbox.proto")], &[&proto_dir])?;

    Ok(())
}
