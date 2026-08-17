//! The guest-agent port: how the runtime reaches the agent inside a Computer.
//!
//! Everything above this seam — the boot readiness gate, exec, files, clock
//! sync, the post-restore network reconfiguration — speaks [`GuestAgent`]
//! and [`GuestFiles`]. Nothing above it knows that today's only
//! implementation, [`vm_proto`], reaches the guest over a vsock connection
//! the driver port hands out. A Computer that is not reachable that way —
//! no vsock device at all, or an agent that answers on its own network
//! address — supplies another factory through
//! [`SandboxEnvironment::agent`](crate::environment::SandboxEnvironment::agent).
//!
//! Readiness is the part that differs most between transports, so it has a
//! vocabulary of its own: [`Readiness`] says *how* a guest announces that
//! it is serving, [`GuestAgentFactory::arm_readiness`] arms the observer
//! before the guest starts, and [`ReadyGate::wait`] is what the boot flow
//! waits on afterwards under its own deadline.

use std::sync::Arc;
use std::time::Duration;

use arcbox_vm_driver::net::NetworkIdentity;
use arcbox_vm_driver::{PreparedVm, VmHandle};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::boot_proto::NetReconfigCommand;
use crate::error::Result;
use crate::file_proto::FileStatDto;

pub mod vm_proto;

pub use vm_proto::{DirWatch, VmProtoAgent, VmProtoAgentFactory};

/// The command vocabulary the guest agent starts processes from, shared
/// with `vm-agent` through `arcbox-vm-proto`.
pub use arcbox_vm_proto::exec::StartCommand;

/// The write half of an interactive session: stdin bytes, TTY resizes,
/// signals, and the EOF that closes the process's stdin.
pub type ExecInput = mpsc::Sender<ExecInputMsg>;

/// Builds the agent client for one Computer, and knows how that Computer's
/// guest announces it is serving.
#[async_trait]
pub trait GuestAgentFactory: Send + Sync {
    /// How a guest built by this factory announces readiness.
    fn readiness(&self) -> Readiness;

    /// Arm the readiness observer **before the guest starts**.
    ///
    /// [`Readiness::DialOut`] has no other option: the guest dials the host
    /// the moment it is serving, and a VMM forwards that connect only if
    /// someone is already listening — otherwise the guest is reset and the
    /// one readiness event is lost. The other shapes bind nothing here and
    /// do their work in [`ReadyGate::wait`].
    async fn arm_readiness(&self, prepared: &dyn PreparedVm) -> Result<Box<dyn ReadyGate>>;

    /// The agent client for a VM that has booted or restored.
    ///
    /// `net` is what the guest was told over its interface, for an agent
    /// reached at that address rather than through the VM handle; `None`
    /// when the Computer is networkless.
    fn connect(
        &self,
        handle: Arc<dyn VmHandle>,
        net: Option<&NetworkIdentity>,
    ) -> Result<Arc<dyn GuestAgent>>;
}

/// How a guest announces that its agent is serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// The guest dials the host on `port` once it is serving. The host must
    /// be listening before the guest starts, so the gate is armed pre-boot
    /// and the wait is a single `accept`. This is [`vm_proto`]'s answer.
    DialOut { port: u32 },
    /// The host dials the guest's `port` until the agent accepts. Nothing
    /// to arm — the wait needs the running VM.
    Poll { port: u32 },
    /// No transport-level announcement: readiness is the first agent call
    /// that succeeds, which the boot flow makes anyway. The wait returns
    /// immediately.
    Probe,
}

/// An armed readiness observer, awaited once.
#[async_trait]
pub trait ReadyGate: Send {
    /// Wait for the guest agent to announce itself.
    ///
    /// `handle` is the VM that booted after this gate was armed: a
    /// [`Readiness::DialOut`] gate ignores it — its observer has been
    /// listening since before the guest started — while [`Readiness::Poll`]
    /// dials the guest through it, because there was nothing to dial when
    /// the gate was armed. The caller owns the deadline.
    async fn wait(&mut self, handle: &Arc<dyn VmHandle>) -> Result<()>;
}

/// The agent inside one running Computer.
#[async_trait]
pub trait GuestAgent: Send + Sync {
    /// Run a command and stream its output. The final [`OutputChunk`] is
    /// always [`OutputChunk::Exit`].
    async fn run(&self, start: StartCommand) -> Result<mpsc::Receiver<Result<OutputChunk>>>;

    /// Start an interactive session: input sink, output stream.
    async fn exec(
        &self,
        start: StartCommand,
    ) -> Result<(ExecInput, mpsc::Receiver<Result<OutputChunk>>)>;

    /// Set the guest wall clock to the host's now.
    ///
    /// `Err` is a failed round trip; [`ClockSync::AgentError`] is an agent
    /// that answered but could not set the clock, which still proves
    /// liveness.
    async fn sync_clock(&self) -> Result<ClockSync>;

    /// Re-address the guest after a restore onto a fresh network.
    async fn reconfigure_network(&self, cmd: &NetReconfigCommand) -> Result<()>;

    /// Wait until the guest's own listen table has a listener on `port` —
    /// never a connect probe, which would perturb the workload.
    async fn wait_for_port(&self, port: u16, timeout: Duration) -> Result<PortWait>;

    /// The file channel into this Computer.
    fn files(&self) -> &dyn GuestFiles;
}

/// File operations inside one running Computer.
#[async_trait]
pub trait GuestFiles: Send + Sync {
    /// Read a whole file.
    async fn read(&self, path: &str) -> Result<Vec<u8>>;
    /// Write a whole file, creating it with `mode`.
    async fn write(&self, path: &str, mode: u32, data: &[u8]) -> Result<()>;
    /// Stat one path; symlinks are reported, not followed.
    async fn stat(&self, path: &str) -> Result<FileStatDto>;
    /// List a directory, non-recursively, with full per-entry metadata.
    async fn list(&self, path: &str) -> Result<Vec<FileStatDto>>;
    /// Create a directory and any missing parents; succeeds if it exists.
    async fn make_dir(&self, path: &str, mode: u32) -> Result<()>;
    /// Remove a file, symlink or directory; a non-empty directory needs
    /// `recursive`.
    async fn remove(&self, path: &str, recursive: bool) -> Result<()>;
    /// Rename an entry within the Computer.
    async fn rename(&self, from: &str, to: &str) -> Result<()>;
    /// Open a directory watch. The stream ends cleanly when the Computer
    /// stops; dropping it cancels the watch.
    async fn watch(&self, path: &str, recursive: bool) -> Result<DirWatch>;
}

/// How a guest workload terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// The process exited normally with this code.
    Code(i32),
    /// The process was killed by this POSIX signal.
    Signaled(i32),
}

impl ExitStatus {
    /// Shell-convention scalar: the exit code itself, or `128 + signal` for a
    /// signal death. For consumers that can only carry one integer.
    #[must_use]
    pub const fn conventional_code(self) -> i32 {
        match self {
            Self::Code(code) => code,
            Self::Signaled(signal) => 128 + signal,
        }
    }
}

/// A chunk of output emitted by a guest process.
#[derive(Debug, Clone)]
pub enum OutputChunk {
    /// Bytes from the process's stdout (the merged PTY stream for `tty` sessions).
    Stdout(Vec<u8>),
    /// Bytes from the process's stderr (never emitted for `tty` sessions).
    Stderr(Vec<u8>),
    /// The process terminated. Always the final chunk of a session.
    Exit(ExitStatus),
}

/// A message the host sends to the guest during an exec/run session.
#[derive(Debug)]
pub enum ExecInputMsg {
    /// Raw bytes to forward to the process's stdin.
    Stdin(Vec<u8>),
    /// Resize the pseudo-TTY.
    Resize { width: u16, height: u16 },
    /// Deliver a POSIX signal to the workload's process group.
    Signal(i32),
    /// Signal EOF on the process's stdin.
    Eof,
}

/// Outcome of a guest listen-table wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortWait {
    /// A listener on the port exists.
    Listening,
    /// The deadline elapsed with no listener.
    Deadline,
}

/// Outcome of a completed clock-sync round trip.
///
/// Both variants prove liveness — the agent accepted the connection, parsed
/// the frame, and replied — which is what a readiness gate needs. Only
/// [`ClockSync::Synced`] means the guest wall clock was actually set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSync {
    /// The agent set the clock.
    Synced,
    /// The agent answered but could not set the clock (e.g. `clock_settime`
    /// failed); it carries the agent-reported exit code.
    AgentError(i32),
}
