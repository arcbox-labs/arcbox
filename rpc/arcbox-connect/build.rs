//! Build script for the ArcBox Connect RPC surface.
//!
//! Generates buffa message types plus ConnectRPC service traits and clients
//! for every ArcBox-owned proto (`arcbox.v1` and `arcbox.sandbox.v1`).
//! These types serve the daemon's client-facing Connect surface and both
//! ends of the host↔guest vsock wire (CORE-73); the host `AgentClient`
//! still decodes the surfaces that cross into `arcbox-api` handlers as
//! prost twins (sandbox, machine exec, kubernetes, machine stats) until
//! the remaining convergence phases land — safe because buffa and prost
//! emit identical protobuf bytes.

fn main() {
    let proto_dir = "../arcbox-protocol/proto";

    let protos = [
        // The daemon's own surface (CORE-68). These all share one `arcbox.v1`
        // package, so message generation is all-or-nothing here even though
        // the services move onto Connect one at a time. `common.proto` must be
        // listed explicitly: it defines this package's hand-rolled `Timestamp`
        // and `Mount`, which are NOT the well-known types.
        "common.proto",
        "machine.proto",
        "macos.proto",
        "container.proto",
        "image.proto",
        "agent.proto",
        "api.proto",
        "kubernetes.proto",
        "stats.proto",
        "arcbox/sandbox/v1/sandbox.proto",
        "arcbox/sandbox/v1/process.proto",
        "arcbox/sandbox/v1/filesystem.proto",
        "arcbox/sandbox/v1/snapshot.proto",
    ];

    // Run protoc ourselves and hand connectrpc-build the descriptor set:
    // its own protoc invocation cannot pass extra flags, and the older
    // protoc still found on some CI runners requires
    // --experimental_allow_proto3_optional (newer versions ignore it) —
    // the same compatibility stance as arcbox-protocol/build.rs. Binary
    // discovery mirrors connectrpc-build: $PROTOC, else PATH.
    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR unset"));
    let descriptor = out_dir.join("arcbox_connect.protoset");
    let protoc = std::env::var("PROTOC").unwrap_or_else(|_| "protoc".to_string());
    let status = std::process::Command::new(&protoc)
        .arg("--experimental_allow_proto3_optional")
        .arg("--include_imports")
        .arg("--include_source_info")
        .arg(format!("--descriptor_set_out={}", descriptor.display()))
        .arg(format!("--proto_path={proto_dir}"))
        .args(protos)
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke {protoc}: {e}"));
    assert!(
        status.success(),
        "protoc failed building the Connect descriptor set"
    );

    // Precompiled mode emits no rerun directives for the sources; declare
    // them so a proto edit regenerates.
    for proto in protos {
        println!("cargo:rerun-if-changed={proto_dir}/{proto}");
    }

    connectrpc_build::Config::new()
        .files(&protos)
        .descriptor_set(&descriptor)
        .emit_rerun_directives(false)
        .include_file("_connectrpc.rs")
        .generate_json(true)
        // `arcbox.v1` files sit at the proto root rather than in `arcbox/v1/`
        // (the PACKAGE_DIRECTORY_MATCH violation `buf lint` already reports),
        // so without this the generator emits one module per file and
        // intra-package references do not resolve.
        .file_per_package(true)
        .compile()
        .expect("Failed to compile protos for Connect");
}
