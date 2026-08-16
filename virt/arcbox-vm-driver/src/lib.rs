//! `arcbox-vm-driver` — the VM driver port: the vocabulary of "a VM on this
//! host", and nothing else.
//!
//! ArcBox runs VMs under several VMMs — Firecracker and Cloud Hypervisor as
//! external processes, Virtualization.framework as a managed VMM, its own
//! Hypervisor.framework engine in-process. Orchestrators (the computer
//! runtime, the engine's machine registry) must not know which. This crate
//! is the seam between them: adapters implement it, orchestrators consume
//! it, and only a composition root names both.
//!
//! # What is here
//!
//! - [`spec`] — the serializable per-VM shape: [`VmSpec`] and its parts.
//! - [`driver`] — the port: [`VmDriver`] boots a spec into a [`VmHandle`],
//!   whose mandatory surface is identify (`id`/`record`), observe
//!   (`state`/`events`), and stop (`shutdown`); plus the handle vocabulary
//!   ([`VmState`], [`VmEvent`], [`ExitStatus`], [`ShutdownMode`],
//!   [`VmRecord`]) and [`DriverCapabilities`], what a driver claims.
//! - [`capability`] — everything optional, one trait each: [`Vsock`],
//!   [`VsockListen`], [`Checkpoint`], [`Adopt`]/[`Detach`], [`Prepare`],
//!   [`Balloon`], [`Console`], [`DebugSnapshot`]. A handle (or the driver,
//!   for `Adopt` and `Prepare`) exposes each through an `Option<&dyn Cap>`
//!   accessor, `Some` only when the driver can and the spec asked;
//!   `capabilities()` must agree with the accessors.
//! - [`net`] — the second port: [`net::GuestNetwork`] plans and builds
//!   what a NIC is attached to and hands the driver a [`NicSpec`];
//!   [`net::NetworkReconcile`] is its token-guarded cleanup protocol.
//! - [`error`] — the one [`Error`] every port method speaks. There is no
//!   `Unsupported` variant: what a driver cannot do is a capability
//!   accessor returning `None`, never an error at call time.
//!
//! - `testkit` (feature) — the fakes and the contract test-kit: a
//!   `FakeDriver` and `FakeNetwork` for runtime unit tests on any host, and
//!   `driver_contract!`, the checks every adapter must pass.
//!
//! # Rules the crate is held to
//!
//! - No `arcbox-*` dependency, ever: the port sits below every adapter.
//! - Data is `serde`; behavior is a trait object. A [`VmSpec`] can be
//!   written in a TOML file; a driver cannot.
//! - Node-wide knobs (binary paths, seccomp, jailer defaults) are the
//!   adapter's own config, not part of the spec.
//!
//! Design: company repo `engineering/arcbox/architecture/vm-stack-redesign.md`
//! (D-VM1, D-VM7, D-VM9).

#![warn(missing_docs)]

pub mod capability;
pub mod driver;
pub mod error;
pub mod net;
pub mod spec;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use capability::{
    Adopt, AfterCheckpoint, Balloon, BalloonStats, Checkpoint, CheckpointFormat, CheckpointImage,
    CheckpointKind, CheckpointOptions, Console, DebugSnapshot, Detach, Prepare, PreparedVm, Vsock,
    VsockListen, VsockListener,
};
pub use driver::{
    DriverCapabilities, ExitStatus, IoMode, NestedVirt, ProcessRecord, RestoreSpec, ShutdownMode,
    VmDriver, VmEvent, VmHandle, VmRecord, VmState, VsockConn,
};
pub use error::{Error, Result};
pub use spec::{
    BootSpec, CacheMode, CgroupSpec, ConsoleSpec, DiskSpec, IsolationSpec, MacAddr, NicAttachment,
    NicSpec, ShareSpec, VmId, VmSpec, VsockSpec,
};
