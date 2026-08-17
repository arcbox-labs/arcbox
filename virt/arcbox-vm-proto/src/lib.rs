//! `arcbox-vm-proto` — the wire vocabulary between a sandbox host and the
//! `vm-agent` init inside the sandbox.
//!
//! Three channels, three modules:
//!
//! - [`boot`] — what the host passes through the kernel command line
//!   (`ip=`) and the net-reconfigure command it sends after a snapshot
//!   restore.
//! - [`exec`] — the exec channel (guest vsock port [`exec::AGENT_PORT`]):
//!   frame opcodes, the session-start command, the listen-table wait
//!   request, and the readiness dial-out port.
//! - [`mod@file`] — the file channel (guest vsock port [`file::FILE_PORT`]):
//!   frame opcodes, request payloads, and the stat/event DTOs.
//!
//! Every frame on both channels is `[u8 type][u32 LE len][payload]`; the
//! JSON payloads are the `serde` types here. This crate depends on `serde`
//! alone so the agent — a static musl binary staged into every sandbox
//! rootfs — links it without pulling in the manager, and the manager
//! (`arcbox-computer-runtime`) links it so both ends decode the same bytes.
//!
//! # Compatibility
//!
//! A restored snapshot resumes whatever `vm-agent` it was checkpointed
//! with, so old agents stay in service indefinitely. Payloads are
//! therefore evolved additively: new JSON fields carry `#[serde(default)]`,
//! new frame types are ignored by agents that predate them, and readers key
//! variable-length binary payloads on their length rather than on the
//! sender's version.

pub mod boot;
pub mod exec;
pub mod file;
