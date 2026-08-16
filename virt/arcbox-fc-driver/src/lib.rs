//! `arcbox-fc-driver` — the Firecracker adapter for the VM driver port.
//!
//! [`arcbox_vm_driver`] is the vocabulary of "a VM on this host"; this crate
//! is what makes a [`VmSpec`](arcbox_vm_driver::VmSpec) run under
//! Firecracker. It is the only crate that names `fc-sdk`, the jailer's
//! chroot layout, or the hybrid-vsock Unix-socket handshake — everything
//! above it (the sandbox manager today, the computer runtime tomorrow)
//! sees a `dyn VmDriver` and never a Firecracker.
//!
//! # What lives here
//!
//! - [`config`] — [`FcDriverConfig`], the node-wide knobs: binaries,
//!   seccomp, log level, the API-socket wait, jailer resource limits.
//! - [`error`] — [`FcError`], the adapter's typed failures, folded into the
//!   port's `Error::Driver` at the boundary.
//! - [`jail`] — the jailer's chroot layout and how host files are staged
//!   into it (link-or-copy, copy, block-device node).
//! - [`spawn`] — the `firecracker` / `jailer` process spawn.
//!
//! The remaining modules — the spec renderer, jail staging, process
//! spawning and ownership, the vsock handshake, the prepared VM, the
//! handle, and the driver itself — land one at a time as their code is
//! moved out of `arcbox-vm` (design: company repo
//! `engineering/arcbox/architecture/vm-stack-redesign.md`, D-VM1 / D-VM9).
//!
//! # Rules the crate is held to
//!
//! - It depends on the port and on `fc-sdk`, never on the snapshot
//!   catalog, the engine, or any orchestrator.
//! - Every path Firecracker sees is computed in one place (`render`); the
//!   jailer's chroot relativity is not re-derived anywhere else.
//! - Host resources are RAII guards with explicit release: a process is
//!   killed on drop unless a handle took it and was detached.

#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod jail;
pub mod spawn;

pub use config::FcDriverConfig;
pub use error::FcError;

/// The driver's name.
///
/// [`VmDriver::name`](arcbox_vm_driver::VmDriver::name), recorded in every
/// [`VmRecord`](arcbox_vm_driver::VmRecord) and named by every
/// [`Error::Driver`](arcbox_vm_driver::Error::Driver) this crate raises.
pub const NAME: &str = "firecracker";

/// The on-disk checkpoint format this driver writes and the only one it
/// restores: Firecracker's `vmstate` + `mem` pair in one directory.
pub const CHECKPOINT_FORMAT: &str = "firecracker/v1";
