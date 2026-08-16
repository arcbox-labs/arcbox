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
//! - [`render`] — [`VmSpec`](arcbox_vm_driver::VmSpec) → [`render::FcPlan`]
//!   and [`RestoreSpec`](arcbox_vm_driver::RestoreSpec) →
//!   [`render::FcRestorePlan`]: every path Firecracker sees, and the
//!   jailer's chroot relativity, is decided there and nowhere else.
//! - [`jail`] — the jailer's chroot layout and how host files are staged
//!   into it (link-or-copy, copy, block-device node), including
//!   [`jail::apply`] for a rendered plan.
//! - [`spawn`] — the `firecracker` / `jailer` process spawn from a
//!   [`render::SpawnPlan`].
//! - [`vsock`] — the hybrid-vsock Unix-socket handshake and the
//!   `{uds}_{port}` listener for guest dial-outs.
//! - [`process`] — the VMM process guard: one waiter task reaps the
//!   child and publishes its exit; kill, wait, and detach never race it.
//! - [`api`] — the few Firecracker API calls a running VM needs, over the
//!   raw client (pause, resume, snapshot, ctrl-alt-del).
//! - [`listener`] — the port's `VsockListener` over a `{uds}_{port}`
//!   socket, failing once the VM is gone.
//! - [`handle`] — [`FcHandle`], the port's `VmHandle` over a running VM:
//!   state and events from the guard, `Kill` and `Graceful` shutdown, and
//!   the vsock, listen, checkpoint (pause → snapshot → resume or hold),
//!   and detach capabilities.
//! - [`prepared`] — [`FcPrepared`], the port's `PreparedVm`: a spawned
//!   VMM waiting for a spec, listeners bound before the guest starts.
//! - [`discover`] — finding a Firecracker that outlived the process which
//!   booted it: the recorded pid while it is still a Firecracker, else a
//!   `/proc` scan by `--id`, `--api-sock`, or jail root.
//! - [`driver`] — [`FcDriver`], the port's `VmDriver` with `Prepare` and
//!   `Adopt`; `boot`/`restore` are prepare-then-boot/restore.
//!
//! Design: company repo `engineering/arcbox/architecture/vm-stack-redesign.md`
//! (Adapters → `virt/arcbox-fc-driver`; D-VM1, D-VM9).
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

pub mod api;
pub mod config;
pub mod discover;
pub mod driver;
pub mod error;
pub mod handle;
pub mod jail;
pub mod listener;
pub mod prepared;
pub mod process;
pub mod render;
pub mod spawn;
pub mod vsock;

pub use config::FcDriverConfig;
pub use driver::FcDriver;
pub use error::FcError;
pub use handle::FcHandle;
pub use prepared::FcPrepared;

/// The driver's name.
///
/// [`VmDriver::name`](arcbox_vm_driver::VmDriver::name), recorded in every
/// [`VmRecord`](arcbox_vm_driver::VmRecord) and named by every
/// [`Error::Driver`](arcbox_vm_driver::Error::Driver) this crate raises.
pub const NAME: &str = "firecracker";

/// The on-disk checkpoint format this driver writes and the only one it
/// restores: Firecracker's `vmstate` + `mem` pair in one directory.
pub const CHECKPOINT_FORMAT: &str = "firecracker/v1";
