use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // sandbox.proto lives in arcbox-protocol; reference it by relative path.
    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../comm/arcbox-protocol/proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto_dir.join("sandbox.proto")], &[&proto_dir])?;

    Ok(())
}
