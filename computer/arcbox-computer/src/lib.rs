//! # arcbox-computer
//!
//! The agent-computer domain layer for `ArcBox`: the transport-free
//! sandbox protocols (durable cleanup tickets, per-sandbox operation
//! locks, transparent resume, and port exposure), written against the
//! [`SandboxHost`] seam the composing runtime implements.
//!
//! Layer rules: this crate speaks the wire *message* vocabulary
//! (`arcbox-connect` types) but never the transport — no `connectrpc`
//! import, ever — and it must compile and pass unit tests on Linux as
//! well as macOS.

pub mod capability;
pub mod cleanup;
pub mod host;
pub mod locks;
pub mod ports;
pub mod resume;

pub use capability::{NestedVirtCapability, nested_virt_for_backend};
pub use host::SandboxHost;
