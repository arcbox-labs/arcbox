//! The [`GuestAgent`] port over the `arcbox-vm-proto` channels.
//!
//! Nothing here decides anything: it is the mapping from the port's verbs
//! onto the protocol functions in the sibling modules, plus the three
//! readiness shapes [`Readiness`] names, each armed on the driver port's
//! vsock capabilities.

use std::sync::Arc;
use std::time::Duration;

use arcbox_vm_driver::net::NetworkIdentity;
use arcbox_vm_driver::{PreparedVm, VmHandle, Vsock, VsockListener};
use async_trait::async_trait;
use tokio::sync::mpsc;

use super::files::{self, DirWatch};
use super::{HandleVsock, READY_PORT, clock, connect_to_port, exec, net, wait_port, wait_ready};
use crate::agent::{
    ClockSync, ExecInput, GuestAgent, GuestAgentFactory, GuestFiles, OutputChunk, PortWait,
    Readiness, ReadyGate, StartCommand,
};
use crate::boot_proto::NetReconfigCommand;
use crate::error::Result;
use crate::file_proto::FileStatDto;

/// The guest agent of one running VM, reached over its vsock device.
pub struct VmProtoAgent {
    vsock: Arc<dyn Vsock>,
}

impl VmProtoAgent {
    /// The agent inside `handle`'s guest.
    ///
    /// The port lends the vsock capability out of the handle
    /// (`VmHandle::vsock` borrows) while callers hold the agent across
    /// awaits and hand it to detached tasks, so the agent owns the handle.
    #[must_use]
    pub fn over(handle: Arc<dyn VmHandle>) -> Self {
        Self {
            vsock: Arc::new(HandleVsock(handle)),
        }
    }
}

#[async_trait]
impl GuestAgent for VmProtoAgent {
    async fn run(&self, start: StartCommand) -> Result<mpsc::Receiver<Result<OutputChunk>>> {
        exec::run(self.vsock.as_ref(), start).await
    }

    async fn exec(
        &self,
        start: StartCommand,
    ) -> Result<(ExecInput, mpsc::Receiver<Result<OutputChunk>>)> {
        exec::exec(self.vsock.as_ref(), start).await
    }

    async fn sync_clock(&self) -> Result<ClockSync> {
        clock::sync_clock(self.vsock.as_ref()).await
    }

    async fn reconfigure_network(&self, cmd: &NetReconfigCommand) -> Result<()> {
        net::reconfigure_network(self.vsock.as_ref(), cmd).await
    }

    async fn wait_for_port(&self, port: u16, timeout: Duration) -> Result<PortWait> {
        wait_port::wait_for_port(self.vsock.as_ref(), port, timeout).await
    }

    fn files(&self) -> &dyn GuestFiles {
        self
    }
}

#[async_trait]
impl GuestFiles for VmProtoAgent {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        files::read_file(self.vsock.as_ref(), path).await
    }

    async fn write(&self, path: &str, mode: u32, data: &[u8]) -> Result<()> {
        files::write_file(self.vsock.as_ref(), path, mode, data).await
    }

    async fn stat(&self, path: &str) -> Result<FileStatDto> {
        files::stat_file(self.vsock.as_ref(), path).await
    }

    async fn list(&self, path: &str) -> Result<Vec<FileStatDto>> {
        files::list_dir(self.vsock.as_ref(), path).await
    }

    async fn make_dir(&self, path: &str, mode: u32) -> Result<()> {
        files::make_dir(self.vsock.as_ref(), path, mode).await
    }

    async fn remove(&self, path: &str, recursive: bool) -> Result<()> {
        files::remove_entry(self.vsock.as_ref(), path, recursive).await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        files::move_entry(self.vsock.as_ref(), from, to).await
    }

    async fn watch(&self, path: &str, recursive: bool) -> Result<DirWatch> {
        files::watch_dir(self.vsock.as_ref(), path, recursive).await
    }
}

/// Builds [`VmProtoAgent`]s, and knows how their guests announce readiness.
///
/// The default is what `vm-agent` does: dial the host back on
/// [`READY_PORT`] once its exec and file listeners are up. The other two
/// [`Readiness`] shapes are here because the port promises them to
/// implementations whose guest cannot dial out — a composer selects one
/// with [`Self::with_readiness`].
pub struct VmProtoAgentFactory {
    readiness: Readiness,
}

impl Default for VmProtoAgentFactory {
    fn default() -> Self {
        Self {
            readiness: Readiness::DialOut { port: READY_PORT },
        }
    }
}

impl VmProtoAgentFactory {
    /// A factory whose guests announce themselves the given way.
    #[must_use]
    pub const fn with_readiness(readiness: Readiness) -> Self {
        Self { readiness }
    }
}

#[async_trait]
impl GuestAgentFactory for VmProtoAgentFactory {
    fn readiness(&self) -> Readiness {
        self.readiness
    }

    async fn arm_readiness(&self, prepared: &dyn PreparedVm) -> Result<Box<dyn ReadyGate>> {
        match self.readiness {
            // Bind the readiness listener BEFORE the guest starts: vm-agent
            // dials host port READY_PORT as soon as it is serving, and the
            // VMM forwards that guest-initiated connect only if someone is
            // already listening — otherwise the guest is reset and the one
            // readiness event is lost. The prepared VM binds it where the
            // guest's dial-out lands.
            Readiness::DialOut { port } => {
                let listener = match prepared.vsock_listener() {
                    Some(listen) => listen.listen(port).await,
                    None => Err(arcbox_vm_driver::Error::InvalidSpec(
                        "the vm driver cannot listen for the guest's readiness dial-out".into(),
                    )),
                }?;
                Ok(Box::new(DialOutGate { listener }))
            }
            Readiness::Poll { port } => Ok(Box::new(PollGate { port })),
            Readiness::Probe => Ok(Box::new(ProbeGate)),
        }
    }

    fn connect(
        &self,
        handle: Arc<dyn VmHandle>,
        _net: Option<&NetworkIdentity>,
    ) -> Result<Arc<dyn GuestAgent>> {
        Ok(Arc::new(VmProtoAgent::over(handle)))
    }
}

/// [`Readiness::DialOut`]: accept the guest's one connection on the
/// pre-bound listener and read the single byte it writes.
struct DialOutGate {
    listener: Box<dyn VsockListener>,
}

#[async_trait]
impl ReadyGate for DialOutGate {
    async fn wait(&mut self, _handle: &Arc<dyn VmHandle>) -> Result<()> {
        wait_ready(&mut *self.listener).await
    }
}

/// [`Readiness::Poll`]: dial the guest until its agent accepts.
///
/// `connect_to_port`'s retry set is what makes this a wait rather than a
/// race: a guest that is not listening yet answers `ConnectionRefused`,
/// the one transient outcome, and a VM that never gets there ends the wait
/// on that budget.
struct PollGate {
    port: u32,
}

#[async_trait]
impl ReadyGate for PollGate {
    async fn wait(&mut self, handle: &Arc<dyn VmHandle>) -> Result<()> {
        let vsock = HandleVsock(Arc::clone(handle));
        connect_to_port(&vsock, self.port).await.map(drop)
    }
}

/// [`Readiness::Probe`]: nothing announces this guest, so there is nothing
/// to wait for — the first agent call the boot flow makes is the check.
struct ProbeGate;

#[async_trait]
impl ReadyGate for ProbeGate {
    async fn wait(&mut self, _handle: &Arc<dyn VmHandle>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use arcbox_vm_driver::testkit::FakeDriver;
    use arcbox_vm_driver::{
        BootSpec, ConsoleSpec, IsolationSpec, VmDriver as _, VmId, VmSpec, VsockSpec,
    };

    use super::*;

    fn vm_spec(id: &VmId) -> VmSpec {
        VmSpec {
            id: id.clone(),
            cpus: 1,
            memory_mib: 128,
            boot: BootSpec::Kernel {
                image: "/vmlinux".into(),
                cmdline: String::new(),
                initrd: None,
            },
            disks: vec![],
            nics: vec![],
            vsock: Some(VsockSpec { guest_cid: 3 }),
            shares: vec![],
            console: ConsoleSpec::Off,
            balloon: false,
            entropy: false,
            dirty_tracking: false,
            isolation: IsolationSpec::None,
        }
    }

    /// Arm a gate on a prepared VM, boot it, and return both.
    async fn armed(
        readiness: Readiness,
        dir: &std::path::Path,
    ) -> (FakeDriver, VmId, Arc<dyn VmHandle>, Box<dyn ReadyGate>) {
        let driver = FakeDriver::new();
        let id = VmId::new("gate").unwrap();
        let prepared = driver
            .prepare()
            .unwrap()
            .prepare(&id, &IsolationSpec::None, dir)
            .await
            .unwrap();
        let gate = VmProtoAgentFactory::with_readiness(readiness)
            .arm_readiness(prepared.as_ref())
            .await
            .unwrap();
        let handle: Arc<dyn VmHandle> = Arc::from(prepared.boot(vm_spec(&id)).await.unwrap());
        (driver, id, handle, gate)
    }

    /// The dial-out gate is the guest's one connection plus its one byte,
    /// on a listener that was bound before the guest existed.
    #[tokio::test]
    async fn dial_out_gate_takes_the_guests_one_byte() {
        let dir = tempfile::tempdir().unwrap();
        let (driver, id, handle, mut gate) =
            armed(Readiness::DialOut { port: READY_PORT }, dir.path()).await;

        let mut guest = driver.guest_dial(&id, READY_PORT).unwrap();
        guest.write_all(&[1]).unwrap();

        gate.wait(&handle).await.unwrap();
    }

    /// The poll gate reaches the guest through the booted VM — it had
    /// nothing to bind when it was armed.
    #[tokio::test]
    async fn poll_gate_dials_the_booted_guest() {
        let dir = tempfile::tempdir().unwrap();
        let (_driver, _id, handle, mut gate) =
            armed(Readiness::Poll { port: 52 }, dir.path()).await;

        gate.wait(&handle).await.unwrap();
    }

    /// The probe gate has nothing to observe and says so immediately.
    #[tokio::test]
    async fn probe_gate_does_not_wait() {
        let dir = tempfile::tempdir().unwrap();
        let (_driver, _id, handle, mut gate) = armed(Readiness::Probe, dir.path()).await;

        gate.wait(&handle).await.unwrap();
    }
}
