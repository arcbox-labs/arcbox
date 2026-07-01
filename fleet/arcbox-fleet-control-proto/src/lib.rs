//! Generated tonic client/server stubs for the fleet agent's local
//! control-plane API.
//!
//! Served by `arcbox-fleet-agent` on `~/.arcbox/fleet/agent.sock`; consumed
//! by the `arcbox-fleet-agent` CLI and the desktop app. Internal-only —
//! unlike `arcbox-fleet-proto`, this contract is never published.

/// Fleet agent control-plane protocol (`arcbox.fleet.control.v1` package).
// `tonic_build` turns the `.proto` message comments into Rust doc comments;
// some first paragraphs exceed Clippy's length limit. This is generated code
// whose wording is owned by the proto, so the doc-style lint doesn't apply.
#[allow(clippy::too_long_first_doc_paragraph)]
pub mod v1 {
    tonic::include_proto!("arcbox.fleet.control.v1");
}
