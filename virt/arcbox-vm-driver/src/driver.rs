//! The port itself: what a driver does, what a handle to a running VM is.
//!
//! The vocabulary here is what every orchestrator needs from every VMM and
//! nothing a single VMM happens to offer: identify a VM, observe it, stop
//! it. Everything else — vsock, checkpoints, adopt/detach, balloon, console,
//! debug — is a capability reached through an `Option<&dyn Cap>` accessor
//! ([`crate::capability`]), present only when both the driver can do it and
//! the spec asked for the device.

use std::fmt;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::capability::{
    Adopt, Balloon, Checkpoint, CheckpointImage, Console, DebugSnapshot, Detach, Vsock, VsockListen,
};
use crate::error::Result;
use crate::spec::{IsolationSpec, NicSpec, VmId, VmSpec};

/// A VMM adapter: boots specs into handles.
///
/// Object-safe on purpose — roots keep an `Arc<dyn VmDriver>` and never name
/// the adapter again.
#[async_trait]
pub trait VmDriver: Send + Sync {
    /// A short stable name (`"fc"`, `"vz"`, `"hv"`), recorded in
    /// [`VmRecord::driver`] and [`crate::Error::Driver`].
    fn name(&self) -> &'static str;

    /// What this driver can do, independent of any one VM.
    fn capabilities(&self) -> DriverCapabilities;

    /// Boots `spec` with `runtime_dir` as the VM's private scratch space
    /// (sockets, logs, staged files) and returns a handle to the running VM.
    ///
    /// The driver validates the spec ([`VmSpec::validate`]) and fails with
    /// [`crate::Error::InvalidSpec`] before touching the host. A returned
    /// handle owns the VM: dropping it kills the VM unless a
    /// [`Detach`] released it first.
    async fn boot(&self, spec: VmSpec, runtime_dir: &Path) -> Result<Box<dyn VmHandle>>;

    /// Boots a new VM from a checkpoint this driver wrote.
    ///
    /// Fails with [`crate::Error::ForeignCheckpoint`] for a
    /// [`CheckpointImage::format`] the driver does not recognise as its own.
    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
        runtime_dir: &Path,
    ) -> Result<Box<dyn VmHandle>>;

    /// The adopt capability, for VMs that outlive the process which booted
    /// them (external-process VMMs). `Some` iff
    /// [`DriverCapabilities::adopt`].
    fn adopt(&self) -> Option<&dyn Adopt>;
}

/// A running (or just-exited) VM.
///
/// The mandatory surface is identify ([`id`](Self::id) /
/// [`record`](Self::record)), observe ([`state`](Self::state) /
/// [`events`](Self::events)), and stop ([`shutdown`](Self::shutdown)).
/// Every other verb is a capability accessor that returns `Some` only when
/// the driver can and the spec asked. Dropping the handle kills the VM
/// unless [`Detach`] released it.
#[async_trait]
pub trait VmHandle: Send + Sync {
    /// The VM's identity.
    fn id(&self) -> &VmId;

    /// The durable record; identical for the handle's whole life.
    fn record(&self) -> VmRecord;

    /// Where the VM is right now. Observational: never blocks.
    fn state(&self) -> VmState;

    /// Subscribes to what the VM does on its own. Observational: never
    /// blocks. [`VmEvent::Exited`] is delivered exactly once; a subscriber
    /// that arrives after the exit reads it from [`state`](Self::state).
    fn events(&self) -> broadcast::Receiver<VmEvent>;

    /// Stops the VM.
    ///
    /// [`ShutdownMode::Kill`] always succeeds for a live VM.
    /// [`ShutdownMode::Graceful`] asks the guest and kills it at the
    /// deadline; the returned [`ExitStatus`] says which happened. Calling
    /// it on an exited VM returns the recorded status.
    async fn shutdown(&self, mode: ShutdownMode) -> Result<ExitStatus>;

    /// Dial guest vsock ports. `Some` iff the driver has vsock and the spec
    /// had a [`crate::VsockSpec`].
    fn vsock(&self) -> Option<&dyn Vsock> {
        None
    }

    /// Checkpoint the VM. `Some` iff [`DriverCapabilities::checkpoint`].
    fn checkpoint(&self) -> Option<&dyn Checkpoint> {
        None
    }

    /// Accept guest-initiated vsock connections. `Some` iff the driver can
    /// listen and the spec had a [`crate::VsockSpec`].
    fn vsock_listener(&self) -> Option<&dyn VsockListen> {
        None
    }

    /// Give the VM up without stopping it. `Some` iff
    /// [`DriverCapabilities::adopt`].
    fn detach(&self) -> Option<&dyn Detach> {
        None
    }

    /// The memory balloon. `Some` iff the driver has one and the spec set
    /// [`VmSpec::balloon`].
    fn balloon(&self) -> Option<&dyn Balloon> {
        None
    }

    /// The guest console output. `Some` iff the driver exposes it and the
    /// spec's [`VmSpec::console`] is not `Off`.
    fn console(&self) -> Option<&dyn Console> {
        None
    }

    /// A diagnostic snapshot. `Some` iff [`DriverCapabilities::debug`].
    fn debug(&self) -> Option<&dyn DebugSnapshot> {
        None
    }
}

/// What a driver can do, independent of any one VM.
///
/// `capabilities()` describes the driver; a handle exposes a capability only
/// when the spec also asked for the device (a VM booted without
/// [`crate::VsockSpec`] has nothing to dial). The contract test-kit boots a
/// spec that asks for everything the driver claims and checks that each
/// flag here agrees with the matching handle accessor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriverCapabilities {
    /// Handles can dial guest vsock ports ([`Vsock`]).
    pub vsock: bool,
    /// Handles can listen for guest-initiated vsock connections
    /// ([`VsockListen`]).
    pub vsock_listen: bool,
    /// Handles can be checkpointed ([`Checkpoint`]) and the driver can
    /// restore the result.
    pub checkpoint: bool,
    /// Checkpoints can be incremental
    /// ([`CheckpointKind::Diff`](crate::CheckpointKind::Diff)).
    pub diff_checkpoint: bool,
    /// VMs outlive this process and can be adopted back ([`Adopt`] /
    /// [`Detach`]).
    pub adopt: bool,
    /// Handles expose a memory balloon.
    pub balloon: bool,
    /// Handles expose the guest console output.
    pub console: bool,
    /// Handles expose a debug snapshot.
    pub debug: bool,
    /// Whether guests may run their own hypervisor.
    pub nested_virt: NestedVirt,
}

/// Whether guests under this driver may run their own hypervisor, and if
/// not, why — in the platform's own words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NestedVirt {
    /// Nested virtualization is available to guests.
    pub supported: bool,
    /// Why not, when `supported` is false; empty otherwise.
    pub reason: String,
}

impl NestedVirt {
    /// Nested virtualization is available.
    pub fn supported() -> Self {
        Self {
            supported: true,
            reason: String::new(),
        }
    }

    /// Nested virtualization is unavailable for `reason`.
    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            supported: false,
            reason: reason.into(),
        }
    }
}

/// Where a VM is in its life.
///
/// `Quiesced` is reached only through the [`Checkpoint`] capability's
/// [`HoldQuiesced`](crate::AfterCheckpoint::HoldQuiesced) option; there is
/// no pause verb on the handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    /// The guest is executing.
    Running,
    /// The guest is frozen after a checkpoint that asked to hold it.
    Quiesced,
    /// The VM is gone; the status says how.
    Exited(ExitStatus),
}

impl fmt::Display for VmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("running"),
            Self::Quiesced => f.write_str("quiesced"),
            Self::Exited(status) => write!(f, "exited ({status})"),
        }
    }
}

/// Something the VM did on its own, delivered through [`VmHandle::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmEvent {
    /// The VM stopped, whether asked to or not. Delivered exactly once.
    Exited(ExitStatus),
    /// The guest asked for a reset (a reboot); the orchestrator decides
    /// whether to honor it with a stop-and-boot.
    ResetRequested,
}

/// How a VM ended.
///
/// External-process VMMs report the process's wait status; in-process VMMs
/// synthesize one (a stop on request is a clean exit, a forced kill is
/// `signal: Some(SIGKILL)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus {
    /// The exit code, when the VM exited normally.
    pub code: Option<i32>,
    /// The signal that killed the VM, when it did not.
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// A normal exit with `code`.
    pub const fn exited(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }

    /// A death by `signal`.
    pub const fn signaled(signal: i32) -> Self {
        Self {
            code: None,
            signal: Some(signal),
        }
    }

    /// `true` for a normal exit with code 0 and no signal.
    pub const fn is_clean(&self) -> bool {
        matches!(self.code, Some(0)) && self.signal.is_none()
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.code, self.signal) {
            (Some(code), None) => write!(f, "exit code {code}"),
            (None, Some(signal)) => write!(f, "signal {signal}"),
            (Some(code), Some(signal)) => write!(f, "exit code {code}, signal {signal}"),
            (None, None) => f.write_str("unknown status"),
        }
    }
}

impl From<std::process::ExitStatus> for ExitStatus {
    /// The wait status of an external VMM process, as the port sees it.
    fn from(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt as _;
        Self {
            code: status.code(),
            signal: status.signal(),
        }
    }
}

/// How to stop a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    /// Ask the guest to power off and wait up to `timeout`; a guest still
    /// alive at the deadline is killed, and the returned status says which
    /// happened.
    Graceful {
        /// How long the guest gets before it is killed.
        timeout: Duration,
    },
    /// Stop the VM without asking the guest.
    Kill,
}

/// The durable identity of a VM: what survives this process and what
/// [`Adopt`] consumes to find the VM again.
///
/// Stable for a handle's whole life — the same value before, during, and
/// after the VM runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmRecord {
    /// The VM's identity.
    pub id: VmId,
    /// The driver that booted it ([`VmDriver::name`]).
    pub driver: String,
    /// The per-VM directory the driver was given at boot.
    pub runtime_dir: PathBuf,
    /// The VMM process, for external-process VMMs; `None` in-process.
    #[serde(default)]
    pub process: Option<ProcessRecord>,
}

/// An external VMM process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessRecord {
    /// The VMM's pid.
    pub pid: u32,
    /// The VMM's control socket, when it has one.
    #[serde(default)]
    pub api_socket: Option<PathBuf>,
}

/// What may change when a checkpoint is restored into a new VM.
///
/// Everything else — CPUs, memory, disks, devices — is fixed by the image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestoreSpec {
    /// The restored VM's identity.
    pub id: VmId,
    /// The NICs to attach, in the image's bus order (a restored VM usually
    /// lands on fresh host attachments).
    #[serde(default)]
    pub nics: Vec<NicSpec>,
    /// How the restored VMM process is confined.
    #[serde(default)]
    pub isolation: IsolationSpec,
}

/// A connected vsock stream to the guest.
///
/// The consumer builds its transport from `fd` — the port hands over a raw
/// stream socket, not an I/O object — and picks the transport style from
/// `mode`. The descriptor's blocking flag is unspecified; the consumer sets
/// what its reactor needs.
#[derive(Debug)]
pub struct VsockConn {
    /// The connected stream socket, owned by the consumer from here on.
    pub fd: OwnedFd,
    /// Which transport style the driver requires on this socket.
    pub mode: IoMode,
}

/// The one transport fact a driver has to tell its consumer.
///
/// The Hypervisor.framework socketpair stalls the kqueue reactor under rapid
/// connect/teardown, so its driver hands back `Blocking`; every other
/// adapter hands back `Async`. This is where the old backend match on the
/// transport side stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    /// Register the socket with an async reactor.
    Async,
    /// Drive the socket with blocking I/O on a dedicated thread.
    Blocking,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_is_clean_only_for_code_zero_without_signal() {
        assert!(ExitStatus::exited(0).is_clean());
        assert!(!ExitStatus::exited(1).is_clean());
        assert!(!ExitStatus::signaled(9).is_clean());
        assert!(
            !ExitStatus {
                code: Some(0),
                signal: Some(15)
            }
            .is_clean()
        );
        assert!(
            !ExitStatus {
                code: None,
                signal: None
            }
            .is_clean()
        );
    }

    #[test]
    fn exit_status_display_names_what_ended_the_vm() {
        assert_eq!(ExitStatus::exited(3).to_string(), "exit code 3");
        assert_eq!(ExitStatus::signaled(9).to_string(), "signal 9");
        assert_eq!(
            ExitStatus {
                code: None,
                signal: None
            }
            .to_string(),
            "unknown status"
        );
        assert_eq!(
            VmState::Exited(ExitStatus::exited(0)).to_string(),
            "exited (exit code 0)"
        );
    }

    #[test]
    fn process_exit_status_maps_code_and_signal() {
        use std::os::unix::process::ExitStatusExt as _;
        let exited = std::process::ExitStatus::from_raw(3 << 8);
        assert_eq!(ExitStatus::from(exited), ExitStatus::exited(3));
        let killed = std::process::ExitStatus::from_raw(9);
        assert_eq!(ExitStatus::from(killed), ExitStatus::signaled(9));
    }

    #[test]
    fn vm_record_round_trips_and_defaults_the_process() {
        let record = VmRecord {
            id: VmId::new("vm-1").unwrap(),
            driver: "fc".into(),
            runtime_dir: "/run/arcbox/vm-1".into(),
            process: Some(ProcessRecord {
                pid: 4242,
                api_socket: Some("/run/arcbox/vm-1/api.sock".into()),
            }),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<VmRecord>(&json).unwrap(), record);

        let in_process: VmRecord = serde_json::from_value(serde_json::json!({
            "id": "vm-2",
            "driver": "hv",
            "runtime_dir": "/run/arcbox/vm-2",
        }))
        .unwrap();
        assert_eq!(in_process.process, None);
    }
}
