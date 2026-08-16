//! What a handle *may* be able to do, one small trait per capability.
//!
//! A handle exposes each of these through an `Option<&dyn Cap>` accessor
//! (`VmHandle::vsock`, `VmHandle::checkpoint`, ...). `None` is the answer for
//! "this driver cannot" *and* for "this VM was not built with the device";
//! a method on one of these traits never returns an "unsupported" error as
//! its normal answer. [`crate::DriverCapabilities`] says which accessors a
//! driver's handles can ever return `Some` for.

use std::fmt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::driver::{ExitStatus, RestoreSpec, VmHandle, VmRecord, VsockConn};
use crate::error::Result;
use crate::spec::{IsolationSpec, VmId, VmSpec};

/// Dial a vsock port inside the guest.
#[async_trait]
pub trait Vsock: Send + Sync {
    /// Connects to `port` in the guest and returns the stream.
    ///
    /// Fails with [`crate::Error::WrongState`] when the VM is not running,
    /// and with [`crate::Error::Io`] of kind
    /// [`ConnectionRefused`](std::io::ErrorKind::ConnectionRefused) when
    /// the guest has no listener on `port` yet — the one outcome a caller
    /// retries on; every other error is final.
    async fn dial(&self, port: u32) -> Result<VsockConn>;
}

/// Spawn the VMM before there is a guest to boot.
///
/// External-process VMMs pay for the process spawn, the jailer setup, and
/// the API socket up front. A warm pool prepares its slots long before a
/// boot is asked for, journals the pid before any guest runs, and binds the
/// READY vsock listener while nothing can race it. The split is invisible
/// to a plain boot: `VmDriver::boot(spec, dir)` MUST behave exactly like
/// `prepare(&spec.id, &spec.isolation, dir)` followed by
/// [`PreparedVm::boot`] with `spec`, and `restore` likewise — the contract
/// asserts it. Present iff [`crate::DriverCapabilities::prepare`].
#[async_trait]
pub trait Prepare: Send + Sync {
    /// Spawns the VMM process for `id` under `isolation`, with
    /// `runtime_dir` as its private scratch space, without booting a guest.
    async fn prepare(
        &self,
        id: &VmId,
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> Result<Box<dyn PreparedVm>>;
}

/// A spawned VMM waiting for a spec.
///
/// Dropping it kills the process unless a `boot` or `restore` succeeded,
/// after which the returned handle owns it.
#[async_trait]
pub trait PreparedVm: Send + Sync {
    /// The VM's identity.
    fn id(&self) -> &VmId;

    /// The durable record — pid and API socket are already known, and the
    /// handle that `boot`/`restore` returns reports this same record.
    fn record(&self) -> VmRecord;

    /// `true` while the VMM process is up. Never signals a reaped pid: once
    /// this answers `false` it stays `false`.
    fn alive(&self) -> bool;

    /// Bind a vsock listener now; it is live before the guest starts, so a
    /// dial-out the guest makes at boot cannot be missed. `Some` iff
    /// [`crate::DriverCapabilities::vsock_listen`].
    fn vsock_listener(&self) -> Option<&dyn VsockListen> {
        None
    }

    /// Boots `spec` on this process. `spec.id` and `spec.isolation` must
    /// equal what `prepare` was given ([`crate::Error::InvalidSpec`]
    /// otherwise); the handle shares this process. At most one `boot` or
    /// `restore` succeeds per prepared VM.
    async fn boot(&self, spec: VmSpec) -> Result<Box<dyn VmHandle>>;

    /// Boots a checkpoint on this process; the same rules as [`boot`](Self::boot).
    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
    ) -> Result<Box<dyn VmHandle>>;

    /// Kills and reaps the process now. Idempotent, and valid after a boot
    /// too (it kills that VM); the status is how the process ended.
    async fn discard(&self) -> Result<ExitStatus>;
}

/// Accept vsock connections the guest initiates (the READY dial-out).
#[async_trait]
pub trait VsockListen: Send + Sync {
    /// Starts listening on host-side `port`; the guest connects to it.
    async fn listen(&self, port: u32) -> Result<Box<dyn VsockListener>>;
}

/// A bound vsock listener; one guest connection per `accept`.
#[async_trait]
pub trait VsockListener: Send {
    /// Waits for the next guest connection.
    ///
    /// Fails once the VM has exited — nothing more can arrive.
    async fn accept(&mut self) -> Result<VsockConn>;
}

/// Capture the VM's state to disk.
///
/// Quiescing is this capability's own business: the driver freezes the guest
/// for the capture and, per [`CheckpointOptions::after`], either resumes it
/// or leaves it [`crate::VmState::Quiesced`]. There is no pause verb on the
/// handle.
#[async_trait]
pub trait Checkpoint: Send + Sync {
    /// Writes a checkpoint of the VM into `dst` (created if missing).
    async fn checkpoint(&self, dst: &Path, opts: CheckpointOptions) -> Result<CheckpointImage>;
}

/// How to take a checkpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckpointOptions {
    /// What the guest does once the capture is on disk.
    pub after: AfterCheckpoint,
    /// Full image or incremental.
    pub kind: CheckpointKind,
}

/// What the guest does once a checkpoint is captured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AfterCheckpoint {
    /// Keep running.
    #[default]
    Resume,
    /// Stay frozen; the handle reports [`crate::VmState::Quiesced`] until it
    /// is shut down. This is how an orchestrator implements "pause": hold,
    /// then `shutdown(Kill)`; "resume" is a restore.
    HoldQuiesced,
}

/// Full or incremental capture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    /// Everything: memory and device state.
    #[default]
    Full,
    /// Only pages dirtied since the previous checkpoint (needs
    /// [`crate::VmSpec::dirty_tracking`] and a driver whose
    /// [`crate::DriverCapabilities::diff_checkpoint`] is set).
    Diff,
}

/// A checkpoint on disk: where it is and who can read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointImage {
    /// The directory holding the image files.
    pub dir: PathBuf,
    /// The on-disk format, named by the driver that wrote it.
    pub format: CheckpointFormat,
    /// Full or incremental.
    pub kind: CheckpointKind,
}

/// A checkpoint's on-disk format, e.g. `firecracker/v1`.
///
/// A driver refuses to restore a format it did not write
/// ([`crate::Error::ForeignCheckpoint`]); the name is how it tells.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckpointFormat(String);

impl CheckpointFormat {
    /// Names a format.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The format name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CheckpointFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CheckpointFormat {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Find a VM that outlived the process which booted it.
///
/// Present on external-process VMMs only: an in-process VM dies with its
/// process, so "adopt" has no meaning there and the accessor is `None`.
#[async_trait]
pub trait Adopt: Send + Sync {
    /// Rebuilds a handle for the VM `record` names.
    ///
    /// `Ok(None)` means nothing survived — a stale record, a dead pid — which
    /// is an outcome, not an absence of the capability.
    async fn adopt(&self, record: &VmRecord) -> Result<Option<Box<dyn VmHandle>>>;
}

/// Give up ownership of a running VM without stopping it.
///
/// After `detach`, dropping the handle no longer kills the VM; the returned
/// record is what [`Adopt::adopt`] takes to pick it up again. Present iff
/// the driver has [`Adopt`].
#[async_trait]
pub trait Detach: Send + Sync {
    /// Releases the VM from this handle and returns its durable record.
    async fn detach(&self) -> Result<VmRecord>;
}

/// The guest memory balloon.
#[async_trait]
pub trait Balloon: Send + Sync {
    /// Asks the guest to give back memory until it holds `bytes`.
    async fn set_target(&self, bytes: u64) -> Result<()>;
    /// What the balloon was told and what it reports.
    async fn stats(&self) -> Result<BalloonStats>;
}

/// The balloon's target and, when the guest reports it, its actual size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BalloonStats {
    /// The most recent target, in bytes.
    pub target_bytes: u64,
    /// The size the guest reports, in bytes, when it does.
    pub current_bytes: Option<u64>,
}

/// The guest console's output.
#[async_trait]
pub trait Console: Send + Sync {
    /// Takes up to `max_bytes` of console output not yet read.
    async fn read_output(&self, max_bytes: usize) -> Result<Vec<u8>>;
}

/// A point-in-time view of the VM's internals for diagnostics.
pub trait DebugSnapshot: Send + Sync {
    /// The driver's own JSON — queues, counters, whatever helps a post-mortem.
    fn snapshot(&self) -> serde_json::Value;
}
