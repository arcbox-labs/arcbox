//! `arcbox-computer-runtime` — guest-side sandbox orchestration.
//!
//! # Scope
//!
//! This crate runs **inside** the Linux guest VM, managing nested microVMs
//! for workload isolation (sandboxes) through a `VmDriver`
//! (`arcbox_vm_driver`) — the reference driver is `arcbox-fc-driver`,
//! Firecracker. It is consumed exclusively by `arcbox-agent`.
//!
//! The **host-side** VMM that boots the guest is [`arcbox-vmm`], which sits on
//! top of `arcbox-hypervisor` (Virtualization.framework on macOS, KVM on
//! Linux).  These two crates serve fundamentally different layers and should
//! not be confused:
//!
//! | Crate | Runs on | Purpose | Backend |
//! |-------|---------|---------|---------|
//! | `arcbox-vmm` | host | boot + manage the guest VM | Virtualization.framework / KVM |
//! | `arcbox-computer-runtime` | guest | nested sandbox microVMs | a `VmDriver` (Firecracker via `arcbox-fc-driver`) |
//!
//! The `vm-agent` binary that becomes PID 1 *inside* each sandbox is a
//! separate crate, `arcbox-vm-agent`, and the wire vocabulary the two
//! sides share (boot parameters, exec and file frames) is
//! `arcbox-vm-proto`. Both this manager and the agent link the proto crate;
//! neither links the other, so the crate graph — not a convention — keeps
//! the agent (cross-compiled to static musl and staged into every sandbox
//! rootfs) free of the manager and its dependencies. `boot_proto` and
//! `file_proto` remain reachable through this crate as re-exports.
//!
//! # Public API
//!
//! - [`ComputerManager`] — top-level computer orchestrator
//! - [`NodeEnvironment`] — the four environment-specific components a
//!   composer supplies, all required: the VM driver, the guest network,
//!   the guest-agent factory, and the copy-on-write rootfs manager
//! - [`agent`] — the guest-agent port: how the runtime reaches the agent
//!   inside a Computer (exec, files, clock, readiness), with the
//!   `arcbox-vm-proto` vsock client as its one implementation
//! - [`RootfsBuilder`] — OCI/overlay2 → ext4 with `/sbin/vm-agent` injected,
//!   and the default busybox image; the composer supplies [`RootfsPaths`]
//! - [`ComputerState`] — a computer's public lifecycle state
//! - [`RuntimeConfig`] / [`ComputerSpec`] — configuration types
//!
//! This crate names no VMM and no network implementation. Sandboxes reach
//! both only through `arcbox-vm-driver`'s ports, and the composer supplies
//! the implementations as a [`NodeEnvironment`]; a consumer that needs an
//! adapter's own vocabulary depends on that adapter itself.
//!
//! Snapshot lineage — the checkpoint catalog, the copy-on-write rootfs
//! manager, and the template catalog — lives in `arcbox-snapshot` in the
//! engine layer. The `crate::{snapshot, snapshot_cow, template_catalog}`
//! paths are re-exports of it so existing imports keep resolving; name
//! `arcbox_snapshot` directly in new code.

pub mod agent;
pub mod config;
pub mod environment;
pub mod error;
mod lifecycle;
pub mod rootfs;
pub mod sandbox;
#[cfg(feature = "testkit")]
pub mod testkit;

/// Boot-parameter vocabulary shared with `vm-agent` (`arcbox_vm_proto::boot`).
pub use arcbox_vm_proto::boot as boot_proto;

/// File-channel vocabulary shared with `vm-agent` (`arcbox_vm_proto::file`):
/// the stat/event DTOs and the size caps a caller validates against.
pub use arcbox_vm_proto::file as file_proto;

// The snapshot lineage moved to the engine layer (arcbox-snapshot); these
// paths stay so `arcbox-agent` and this crate's own modules keep compiling.
pub use arcbox_snapshot::{snapshot, snapshot_cow, template_catalog};

pub use agent::{ExecInputMsg, ExitStatus, OutputChunk, PortWait, StartCommand};
pub use config::{ComputerConfig, DefaultVmConfig, GrpcConfig, NetworkConfig, RuntimeConfig};
pub use environment::NodeEnvironment;
pub use error::{ComputerError, Result};
pub use rootfs::{RootfsBuilder, RootfsPaths};
pub use sandbox::pause_reason;
pub use sandbox::{
    CheckpointInfo, CheckpointSummary, ComputerEvent, ComputerId, ComputerInfo, ComputerManager,
    ComputerMountSpec, ComputerNetworkIdentity, ComputerNetworkInfo, ComputerNetworkSpec,
    ComputerSpec, ComputerState, ComputerSummary, IdleAction, LifecycleUpdate, RestoreComputerSpec,
    TemplateWarmRef,
};
pub use sandbox::{
    ExecutionChannel, ExecutionOutput, ExecutionSnapshot, ExecutionSpec, StdinState,
};
pub use snapshot::{SnapshotCatalog, SnapshotInfo};
