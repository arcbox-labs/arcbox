//! `arcbox-vm-agent` — the guest-side half of the sandbox stack.
//!
//! This crate builds the `vm-agent` binary (`src/main.rs`) that becomes
//! PID 1 inside every sandbox microVM, cross-compiled to static musl and
//! staged into every sandbox rootfs at `/sbin/vm-agent`. The binary is a
//! separate deliverable from the sandbox manager (`arcbox-vm`): a consumer
//! may ship the binary, link the manager, or both. That is why this crate
//! depends on the shared wire vocabulary (`arcbox-vm-proto`) and never on
//! the manager — the crate graph, not a convention, keeps the init small.
//!
//! The library half holds the agent's pure helpers, kept out of the binary
//! so they compile and are unit-tested on every host platform:
//!
//! - [`file_watch`] — inotify event-buffer parsing and rename pairing.
//! - [`listen_table`] — `/proc/net/tcp*` parsing for the listen-port wait.
//! - [`user_spec`] — Docker-style `user` resolution against passwd/group.
//!
//! The syscall halves (accept4, fork, openpty, inotify) live in the binary
//! and are gated on `target_os = "linux"`.

pub mod file_watch;
pub mod listen_table;
pub mod user_spec;
