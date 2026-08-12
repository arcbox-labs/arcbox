//! # arcbox-computer
//!
//! The agent-computer domain layer for `ArcBox`: the transport-free
//! sandbox protocols (durable cleanup tickets, per-sandbox operation
//! locks, and — in later cuts — the resume and port-exposure
//! protocols), written against the [`SandboxHost`] seam the composing
//! runtime implements.
//!
//! Layer rules: this crate speaks the wire *message* vocabulary
//! (`arcbox-connect` types) but never the transport — no `connectrpc`
//! import, ever — and it must compile and pass unit tests on Linux as
//! well as macOS.

pub mod cleanup;
pub mod host;
pub mod locks;

pub use host::SandboxHost;
