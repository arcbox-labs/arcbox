//! `arcbox-vm` — guest-side Firecracker sandbox orchestration.
//!
//! # Scope
//!
//! This crate runs **inside** the Linux guest VM, managing nested Firecracker
//! microVMs for workload isolation (sandboxes).  It is consumed exclusively by
//! `arcbox-agent`.
//!
//! The **host-side** VMM that boots the guest is [`arcbox-vmm`], which sits on
//! top of `arcbox-hypervisor` (Virtualization.framework on macOS, KVM on
//! Linux).  These two crates serve fundamentally different layers and should
//! not be confused:
//!
//! | Crate | Runs on | Purpose | Backend |
//! |-------|---------|---------|---------|
//! | `arcbox-vmm` | host | boot + manage the guest VM | Virtualization.framework / KVM |
//! | `arcbox-vm` | guest | nested sandbox microVMs | Firecracker (`fc-sdk`) |
//!
//! The `vm-agent` binary that becomes PID 1 *inside* each sandbox is a
//! separate crate, `arcbox-vm-agent`, and the wire vocabulary the two
//! sides share (boot parameters, exec and file frames) is
//! `arcbox-vm-proto`. Both this manager and the agent link the proto crate;
//! neither links the other, so the crate graph — not a convention — keeps
//! the agent (cross-compiled to static musl and staged into every sandbox
//! rootfs) free of the manager and its dependencies. `boot_proto` and
//! `file_io::proto` remain reachable through this crate as re-exports.
//!
//! # Public API
//!
//! - [`SandboxManager`] — top-level sandbox orchestrator
//! - [`SandboxEnvironment`] — the environment-specific components a
//!   composer supplies (block tooling today; more seams follow)
//! - [`RootfsBuilder`] — OCI/overlay2 → ext4 with `/sbin/vm-agent` injected,
//!   and the default busybox image; the composer supplies [`RootfsPaths`]
//! - [`SandboxInstance`] / [`SandboxState`] — per-sandbox runtime state
//! - [`NetworkManager`] — TAP lifecycle & IP allocation
//! - [`VmmConfig`] / [`SandboxSpec`] — configuration types
//!
//! Snapshot lineage — the checkpoint catalog, the copy-on-write rootfs
//! manager, and the template catalog — lives in `arcbox-snapshot` in the
//! engine layer. The `crate::{snapshot, snapshot_cow, template_catalog}`
//! paths are re-exports of it so existing imports keep resolving; name
//! `arcbox_snapshot` directly in new code.

pub mod config;
pub mod environment;
pub mod error;
pub mod file_io;
pub mod network;
pub mod rootfs;
pub mod sandbox;
pub mod vsock;

/// Boot-parameter vocabulary shared with `vm-agent` (`arcbox_vm_proto::boot`).
pub use arcbox_vm_proto::boot as boot_proto;

// The snapshot lineage moved to the engine layer (arcbox-snapshot); these
// paths stay so `arcbox-agent` and this crate's own modules keep compiling.
pub use arcbox_snapshot::{snapshot, snapshot_cow, template_catalog};

pub use config::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, SandboxDatapath, VmmConfig,
};
pub use environment::SandboxEnvironment;
pub use error::{Result, VmmError};
pub use network::{ExposeTarget, NetworkAllocation, NetworkManager};
pub use rootfs::{RootfsBuilder, RootfsPaths};
pub use sandbox::pause_reason;
pub use sandbox::{
    CheckpointInfo, CheckpointSummary, IdleAction, LifecycleUpdate, RestoreSandboxSpec,
    SandboxEvent, SandboxId, SandboxInfo, SandboxManager, SandboxMountSpec, SandboxNetworkIdentity,
    SandboxNetworkInfo, SandboxNetworkSpec, SandboxSpec, SandboxState, SandboxSummary,
    TemplateWarmRef,
};
pub use sandbox::{
    ExecutionChannel, ExecutionOutput, ExecutionSnapshot, ExecutionSpec, StdinState,
};
pub use snapshot::{SnapshotCatalog, SnapshotInfo};
pub use vsock::{ExecInputMsg, ExitStatus, OutputChunk, PortWait, StartCommand};
