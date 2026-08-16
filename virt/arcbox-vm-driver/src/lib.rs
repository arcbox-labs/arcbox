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
//! - [`spec`] — the serializable per-VM shape, starting with the identity
//!   vocabulary: [`VmId`] and [`MacAddr`].
//! - [`error`] — the one [`Error`] every port method speaks. There is no
//!   `Unsupported` variant: what a driver cannot do is a capability
//!   accessor returning `None`, never an error at call time.
//!
//! The full `VmSpec`, the driver and handle traits, the capability traits,
//! the guest-network port, and the `testkit` feature (fake driver, fake
//! network, contract test-kit) land in the sibling modules.
//!
//! # Rules the crate is held to
//!
//! - No `arcbox-*` dependency, ever: the port sits below every adapter.
//! - Data is `serde`; behavior is a trait object. A VM spec can be
//!   written in a TOML file; a driver cannot.
//! - Node-wide knobs (binary paths, seccomp, jailer defaults) are the
//!   adapter's own config, not part of the spec.
//!
//! Design: company repo `engineering/arcbox/architecture/vm-stack-redesign.md`
//! (D-VM1, D-VM7, D-VM9).

#![warn(missing_docs)]

pub mod error;
pub mod spec;

pub use error::{Error, Result};
pub use spec::{MacAddr, VmId};
