use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CARGO_MANIFEST_DIR is the directory containing this build.rs (vmm-grpc/).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // vmm-grpc/ is one level below the workspace root, which is a sibling of arcbox/.
    let arcbox_proto = manifest
        .join("../../arcbox/comm/arcbox-protocol/proto")
        .canonicalize()
        .expect("arcbox proto dir not found; expected at ../../arcbox/comm/arcbox-protocol/proto");

    // Compile arcbox.v1 protos (MachineService + SystemService).
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                arcbox_proto.join("machine.proto"),
                arcbox_proto.join("api.proto"),
                arcbox_proto.join("common.proto"),
            ],
            &[&arcbox_proto],
        )?;

    Ok(())
}
