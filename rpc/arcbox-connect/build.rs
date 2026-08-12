//! Build script for the ArcBox Connect RPC surface.
//!
//! Generates buffa message types plus ConnectRPC service traits and clients
//! for every ArcBox-owned proto (`arcbox.v1` and `arcbox.sandbox.v1`).
//! These types serve the daemon's client-facing Connect surface and both
//! ends of the host↔guest vsock wire (CORE-73). Remaining prost consumers
//! of the same protos interoperate byte-for-byte: buffa and prost emit
//! identical protobuf bytes from the same `.proto` sources.
//!
//! # Why the descriptor set is committed
//!
//! The `.proto` sources live in `arcbox-protocol`, a different package.
//! Cargo packages are directory-scoped: `cargo package` cannot reach outside
//! this directory, so a build script that read `../arcbox-protocol/proto`
//! produced a crate that compiled in the workspace and failed for everyone
//! who got it from crates.io — `protoc` reported the proto path did not
//! exist, three layers from the cause.
//!
//! So `descriptor/arcbox_connect.protoset` is committed and is the input to
//! code generation, in the workspace and from the registry alike. There is no
//! second code path to diverge, and `protoc` is no longer needed to *build*
//! this crate at all — only to refresh the descriptor after a proto edit.
//!
//! Drift is caught by hashing the `.proto` sources rather than the generated
//! descriptor: protoc's output is not guaranteed byte-identical across
//! versions, but the sources are exactly what changed.

use std::path::{Path, PathBuf};

const DESCRIPTOR: &str = "descriptor/arcbox_connect.protoset";
const SOURCE_HASH: &str = "descriptor/protos.sha256";
const PROTO_LIST: &str = "descriptor/protos.txt";
const REFRESH: &str = "make refresh-connect-descriptor";

/// The protos compiled into this crate's surface, read from the same file
/// `refresh.sh` reads.
///
/// Deliberately not a `const` array here: a second copy of the list is a
/// second thing to forget when a proto is added, and forgetting it fails the
/// build with a stale-descriptor message that points at the wrong cause.
fn protos() -> Vec<String> {
    let list = std::fs::read_to_string(PROTO_LIST)
        .unwrap_or_else(|e| panic!("reading {PROTO_LIST}: {e}"));
    list.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn main() {
    let descriptor = PathBuf::from(DESCRIPTOR);
    let protos = protos();
    assert!(
        descriptor.is_file(),
        "{DESCRIPTOR} is missing; regenerate it with `{REFRESH}`"
    );
    println!("cargo:rerun-if-changed={DESCRIPTOR}");

    // In the workspace the sources are next door, so we can tell whether the
    // committed descriptor still describes them. From the registry they are
    // absent and there is nothing to check — the descriptor is all there is.
    let proto_dir = Path::new("../arcbox-protocol/proto");
    if proto_dir.is_dir() {
        check_descriptor_is_current(proto_dir, &protos);
    }

    connectrpc_build::Config::new()
        .files(&protos)
        .descriptor_set(&descriptor)
        // `FILE_DESCRIPTOR_SET` includes this from OUT_DIR — the path the
        // build script wrote to when it still ran protoc. A precompiled set
        // is written through byte-for-byte, so reflection sees exactly the
        // committed bytes, source info included.
        .emit_descriptor_set("arcbox_connect.protoset")
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

/// Fail the build when a proto has been edited without refreshing the
/// committed descriptor, which would otherwise generate stale code silently.
fn check_descriptor_is_current(proto_dir: &Path, protos: &[String]) {
    println!("cargo:rerun-if-changed={PROTO_LIST}");
    for proto in protos {
        println!("cargo:rerun-if-changed={}", proto_dir.join(proto).display());
    }
    println!("cargo:rerun-if-changed={SOURCE_HASH}");

    let recorded = std::fs::read_to_string(SOURCE_HASH)
        .unwrap_or_else(|e| panic!("reading {SOURCE_HASH}: {e}; regenerate with `{REFRESH}`"));
    let actual = hash_sources(proto_dir, protos);
    assert!(
        recorded.trim() == actual,
        "the .proto sources changed but {DESCRIPTOR} was not refreshed, so this \
         crate would generate code from stale definitions.\n  \
         recorded: {}\n  actual:   {actual}\n  \
         refresh with `{REFRESH}`",
        recorded.trim()
    );
}

/// SHA-256 over every compiled proto, name and contents, in a fixed order.
///
/// Hashes the sources rather than the descriptor: two protoc versions can
/// encode the same protos differently, and that is not drift.
fn hash_sources(proto_dir: &Path, protos: &[String]) -> String {
    use sha2::{Digest, Sha256};

    let mut names: Vec<&str> = protos.iter().map(String::as_str).collect();
    names.sort_unstable();

    let mut hasher = Sha256::new();
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        let path = proto_dir.join(name);
        hasher.update(
            std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display())),
        );
    }
    format!("{:x}", hasher.finalize())
}
