//! An in-memory [`VmDriver`] for tests that need a VM without a hypervisor.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::oneshot;

use super::fake_prepared::Preparer;
use super::fake_staging::StagingArea;
use super::fake_vm::{FakeVm, VmInner};
use super::fake_vsock::Inbound;
use super::lock;
use crate::capability::{Adopt, CheckpointImage, Prepare, PreparedVm as _};
use crate::driver::{
    DriverCapabilities, ExitStatus, NestedVirt, RestoreSpec, ShutdownMode, VmDriver, VmHandle,
    VmRecord, VmState,
};
use crate::error::{Error, Result};
use crate::spec::{IsolationSpec, VmId, VmSpec};

/// Scripted failures, armed once and consumed by the next matching call.
#[derive(Debug, Default)]
pub(super) struct Knobs {
    pub(super) fail_boot: AtomicBool,
    pub(super) fail_checkpoint: AtomicBool,
    pub(super) freeze_checkpoint: AtomicBool,
}

/// An in-memory VM driver.
///
/// VMs are a real state machine (`Running` → `Quiesced` under
/// `HoldQuiesced` → `Exited` on shutdown, kill, or drop) with an events
/// broadcast, and every capability is implemented: `Vsock::dial` returns
/// one end of a socketpair whose other end echoes; `VsockListen` accepts
/// what [`FakeDriver::guest_dial`] pushes; `Checkpoint` writes the
/// `vmstate` + `mem` pair a catalog commits and a jail stages, and
/// `restore` reads the vmstate back; `Adopt`/`Detach` go through
/// the driver's registry; `Prepare` hands out a process with a synthetic
/// pid that `boot`/`restore` then run on — the driver's own `boot` is
/// exactly that pair; `Staging` brings files into a `staged/` directory
/// under the runtime dir, which outlives the discard as a real driver's
/// staging area does today; `Console` returns what
/// [`FakeDriver::push_console`] pushed. [`FakeDriver::builder`] narrows
/// the claimed capabilities — the accessors follow the claims, so the
/// contract can be run against a reduced set — and `fail_next_*` scripts
/// one-shot failures at the moment a scenario needs them.
///
/// The driver's name is `"fake"`; its checkpoint format is `"fake/v1"`.
#[derive(Clone)]
pub struct FakeDriver {
    inner: Arc<DriverInner>,
    adopter: Adopter,
    preparer: Preparer,
}

/// The driver's name, as `VmDriver::name` reports it.
pub(super) const NAME: &str = "fake";

/// The first synthetic pid a prepared fake process gets.
const FIRST_PID: u32 = 100_000;

/// What [`FakeDriver::kill`] reports, matching a real SIGKILL.
const SIGKILL: i32 = 9;

pub(super) struct DriverInner {
    pub(super) caps: DriverCapabilities,
    pub(super) knobs: Arc<Knobs>,
    next_pid: AtomicU32,
    /// What `id_budget` answers under jailer isolation.
    jailed_id_budget: Option<usize>,
    /// Every VM booted or restored and not yet seen exited.
    vms: Mutex<HashMap<VmId, Arc<VmInner>>>,
    /// Every `Adopt::discard_area`, in order, with what it was told the VM
    /// ran under.
    discarded_areas: Mutex<Vec<(VmId, IsolationSpec)>>,
    /// Armed by [`FakeDriver::park_next_boot`], consumed by the next boot
    /// or restore: it sends, then parks.
    pub(super) park_boot: Mutex<Option<oneshot::Sender<()>>>,
    /// Every prepared VM torn down through `PreparedVm::discard`, in order.
    pub(super) discarded_processes: Mutex<Vec<VmId>>,
}

/// Configures a [`FakeDriver`].
#[derive(Debug)]
pub struct FakeDriverBuilder {
    caps: DriverCapabilities,
    knobs: Knobs,
    jailed_id_budget: Option<usize>,
}

impl FakeDriverBuilder {
    /// Claims exactly `caps`; the handles' accessors follow the claims.
    pub fn capabilities(mut self, caps: DriverCapabilities) -> Self {
        self.caps = caps;
        self
    }

    /// What [`VmDriver::id_budget`] answers under jailer isolation;
    /// direct mode keeps the port's default of no bound.
    ///
    /// Shaped like a real adapter's, where the bound comes from the path a
    /// jail lays down and running the VMM directly lays none — so a
    /// consumer tested over this fake exercises both answers.
    pub fn jailed_id_budget(mut self, budget: usize) -> Self {
        self.jailed_id_budget = Some(budget);
        self
    }

    /// Builds the driver.
    pub fn build(self) -> FakeDriver {
        let inner = Arc::new(DriverInner {
            caps: self.caps,
            knobs: Arc::new(self.knobs),
            next_pid: AtomicU32::new(FIRST_PID),
            jailed_id_budget: self.jailed_id_budget,
            vms: Mutex::new(HashMap::new()),
            discarded_areas: Mutex::new(Vec::new()),
            park_boot: Mutex::new(None),
            discarded_processes: Mutex::new(Vec::new()),
        });
        FakeDriver {
            adopter: Adopter(Arc::clone(&inner)),
            preparer: Preparer(Arc::clone(&inner)),
            inner,
        }
    }
}

impl FakeDriver {
    /// A driver claiming every capability, with no scripted failures.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// A driver to configure; starts from every capability claimed.
    pub fn builder() -> FakeDriverBuilder {
        FakeDriverBuilder {
            caps: DriverCapabilities {
                vsock: true,
                vsock_listen: true,
                checkpoint: true,
                diff_checkpoint: true,
                adopt: true,
                prepare: true,
                staging: true,
                balloon: true,
                console: true,
                debug: true,
                nested_virt: NestedVirt::unsupported("the fake driver runs no hypervisor"),
            },
            knobs: Knobs::default(),
            jailed_id_budget: None,
        }
    }

    /// The guest side of a vsock connection to host-side `port` on `vm`.
    ///
    /// The returned stream is what the "guest" writes; the host end is
    /// queued for the VM's `VsockListener::accept` on that port (before or
    /// after `listen` — the queue is per port, not per listener).
    pub fn guest_dial(&self, vm: &VmId, port: u32) -> Result<UnixStream> {
        let vm = self.inner.live(vm)?;
        let (host, guest) = UnixStream::pair()?;
        vm.push_inbound(port, host);
        Ok(guest)
    }

    /// The next `boot` or `restore` fails with [`Error::Driver`].
    ///
    /// Armed on the driver rather than on its builder because a scenario
    /// arms it *between* operations — a fixture that boots before the
    /// interesting call would otherwise feed the knob to the wrong one.
    pub fn fail_next_boot(&self) -> &Self {
        self.inner.knobs.fail_boot.store(true, Ordering::Release);
        self
    }

    /// The next `boot` or `restore` never returns: it signals the
    /// returned receiver and then parks until the task awaiting it is
    /// dropped.
    ///
    /// The wedge a caller cannot script any other way. `fail_next_boot`
    /// ends the boot, which releases everything the half-built VM took;
    /// this one leaves it standing — the VMM prepared and journalled, the
    /// disks staged, the boot task still in flight — which is the state a
    /// forced teardown has to preempt. Hands back the signal rather than
    /// taking one, so a scenario cannot arm the park without a way to
    /// observe that a boot reached it.
    #[must_use = "the receiver is how a test learns a boot reached the park"]
    pub fn park_next_boot(&self) -> oneshot::Receiver<()> {
        let (reached, park) = oneshot::channel();
        *lock(&self.inner.park_boot) = Some(reached);
        park
    }

    /// Every prepared VM torn down through `PreparedVm::discard`, in order.
    ///
    /// The prepared-VM counterpart of [`Self::shutdowns`]: a teardown that
    /// merely dropped the prepared VM kills the process just the same, so
    /// only this says the teardown *asked*.
    pub fn discarded_processes(&self) -> Vec<VmId> {
        lock(&self.inner.discarded_processes).clone()
    }

    /// The next `Checkpoint::checkpoint` on any VM fails with
    /// [`Error::Driver`], leaving the guest as it found it: recoverable,
    /// and the caller keeps the VM.
    pub fn fail_next_checkpoint(&self) -> &Self {
        self.inner
            .knobs
            .fail_checkpoint
            .store(true, Ordering::Release);
        self
    }

    /// The next `Checkpoint::checkpoint` on any VM fails with
    /// [`Error::Driver`] **and leaves the guest quiesced** — the driver's
    /// own resume after the capture failed.
    ///
    /// The unrecoverable half, and the reason it is a second knob: the
    /// port has no verb that thaws a guest, so a caller reading
    /// `VmState::Quiesced` back from a capture it asked to resume has to
    /// dispose of the VM rather than reuse it.
    pub fn freeze_next_checkpoint(&self) -> &Self {
        self.inner
            .knobs
            .freeze_checkpoint
            .store(true, Ordering::Release);
        self
    }

    /// Every `shutdown` mode `vm` was asked for, in order — empty for a VM
    /// this driver never had, or one that only ever died with its handle.
    ///
    /// The way to prove a teardown *asked* a VM to die: the fake reports
    /// the same exit status whether it was killed or dropped, so a path
    /// that forgot its shutdown and merely let the handle fall out of
    /// scope looks identical from the outside.
    pub fn shutdowns(&self, vm: &VmId) -> Vec<ShutdownMode> {
        self.inner
            .registered(vm)
            .map(|vm| vm.shutdowns())
            .unwrap_or_default()
    }

    /// End `vm` as if its VMM process had been killed out from under
    /// whoever holds it — the shape of a node that lost its VMMs while its
    /// manager was away. Answers with the status it ended on, or `None`
    /// for a VM this driver never had.
    pub fn kill(&self, vm: &VmId) -> Option<ExitStatus> {
        self.inner
            .registered(vm)
            .map(|vm| vm.exit(ExitStatus::signaled(SIGKILL)))
    }

    /// The VMs that came up from a checkpoint rather than from a boot.
    ///
    /// The one observable that tells a restore from a cold boot: both end
    /// with a running guest under the caller's id, so a warm or pooled
    /// path that quietly regressed into booting looks identical from
    /// above.
    pub fn restored_vms(&self) -> Vec<VmId> {
        self.inner.filtered(VmInner::is_restored)
    }

    /// The live VMs a handle still holds — exactly the ones
    /// [`Adopt::adopt`] would refuse.
    ///
    /// What a test waits on when it stands a second owner up over the same
    /// driver: an owner lets go on its own schedule, and the successor's
    /// adoption is only meaningful once it has.
    pub fn owned_vms(&self) -> Vec<VmId> {
        self.inner.owned_vms()
    }

    /// Every [`Adopt::discard_area`] this driver was asked for, in order,
    /// paired with the isolation the caller said the VM had run under.
    ///
    /// A sweep is expected to discard each dead VM's area exactly once and
    /// to leave alone the ones it must not touch, and neither is visible
    /// from the filesystem afterwards: a second discard of an
    /// already-cleared area looks like the first, and an area nobody ever
    /// staged into looks like one correctly skipped.
    pub fn discarded_areas(&self) -> Vec<(VmId, IsolationSpec)> {
        lock(&self.inner.discarded_areas).clone()
    }

    /// Appends `bytes` to what `Console::read_output` returns for `vm`.
    pub fn push_console(&self, vm: &VmId, bytes: &[u8]) -> Result<()> {
        self.inner.live(vm)?.push_console(bytes);
        Ok(())
    }
}

impl Default for FakeDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverInner {
    pub(super) fn next_pid(&self) -> u32 {
        self.next_pid.fetch_add(1, Ordering::Relaxed)
    }

    /// Enters a running VM into the registry; the id must not be live.
    pub(super) fn register(
        &self,
        spec: VmSpec,
        record: VmRecord,
        balloon_target_bytes: u64,
        inbound: Arc<Inbound>,
        restored: bool,
    ) -> Result<Arc<VmInner>> {
        let mut vms = lock(&self.vms);
        if let Some(existing) = vms.get(&spec.id) {
            match existing.state() {
                VmState::Exited(_) => {}
                state => {
                    return Err(Error::WrongState {
                        id: spec.id.clone(),
                        state,
                        expected: "no vm with this id",
                    });
                }
            }
        }
        let vm = VmInner::new(
            spec,
            record,
            self.caps.clone(),
            Arc::clone(&self.knobs),
            balloon_target_bytes,
            inbound,
            restored,
        );
        vms.insert(vm.id().clone(), Arc::clone(&vm));
        Ok(vm)
    }

    fn owned_vms(&self) -> Vec<VmId> {
        self.filtered(|vm| !matches!(vm.state(), VmState::Exited(_)) && vm.is_owned())
    }

    fn filtered(&self, keep: impl Fn(&VmInner) -> bool) -> Vec<VmId> {
        let mut ids: Vec<VmId> = lock(&self.vms)
            .values()
            .filter(|vm| keep(vm))
            .map(|vm| vm.id().clone())
            .collect();
        ids.sort();
        ids
    }

    /// The VM under `id`, alive or exited — unlike [`Self::live`], this
    /// forgets nothing, because a post-mortem read is the point.
    fn registered(&self, id: &VmId) -> Option<Arc<VmInner>> {
        lock(&self.vms).get(id).map(Arc::clone)
    }

    /// The VM if it has not exited; an exited entry is forgotten here.
    fn live(&self, id: &VmId) -> Result<Arc<VmInner>> {
        let mut vms = lock(&self.vms);
        match vms.get(id) {
            Some(vm) if !matches!(vm.state(), VmState::Exited(_)) => Ok(Arc::clone(vm)),
            Some(_) => {
                vms.remove(id);
                Err(Error::NotFound(id.clone()))
            }
            None => Err(Error::NotFound(id.clone())),
        }
    }
}

#[async_trait]
impl VmDriver for FakeDriver {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> DriverCapabilities {
        self.inner.caps.clone()
    }

    async fn boot(&self, spec: VmSpec, runtime_dir: &Path) -> Result<Box<dyn VmHandle>> {
        self.preparer
            .prepare_sync(&spec.id, &spec.isolation, runtime_dir)
            .boot(spec)
            .await
    }

    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
        runtime_dir: &Path,
    ) -> Result<Box<dyn VmHandle>> {
        self.preparer
            .prepare_sync(&spec.id, &spec.isolation, runtime_dir)
            .restore(image, spec)
            .await
    }

    fn id_budget(&self, isolation: &IsolationSpec) -> Option<usize> {
        match isolation {
            IsolationSpec::Jailer { .. } => self.inner.jailed_id_budget,
            IsolationSpec::None => None,
        }
    }

    fn adopt(&self) -> Option<&dyn Adopt> {
        self.inner.caps.adopt.then_some(&self.adopter)
    }

    fn prepare(&self) -> Option<&dyn Prepare> {
        self.inner.caps.prepare.then_some(&self.preparer)
    }
}

/// The `Adopt` capability, on its own type so its `adopt` method does not
/// shadow the driver's accessor of the same name.
#[derive(Clone)]
struct Adopter(Arc<DriverInner>);

#[async_trait]
impl Adopt for Adopter {
    async fn adopt(&self, record: &VmRecord) -> Result<Option<Box<dyn VmHandle>>> {
        let vm = match self.0.live(&record.id) {
            Ok(vm) => vm,
            Err(Error::NotFound(_)) => return Ok(None),
            Err(other) => return Err(other),
        };
        if vm.is_owned() {
            return Err(Error::Driver {
                driver: NAME,
                message: format!("vm {} is still owned by a live handle", record.id),
                source: None,
            });
        }
        Ok(Some(Box::new(FakeVm::new(vm))))
    }

    /// Removes `{runtime_dir}/staged`, and records the call.
    ///
    /// A VM that has not been seen to exit is refused: the port says this
    /// is never asked of a running VM, and the fake is where a caller that
    /// asks anyway is caught — on disk, tearing a live VM's area down looks
    /// exactly like tearing a dead one's down.
    async fn discard_area(&self, record: &VmRecord, isolation: &IsolationSpec) -> Result<()> {
        if let Some(vm) = self.0.registered(&record.id) {
            let state = vm.state();
            if !matches!(state, VmState::Exited(_)) {
                return Err(Error::WrongState {
                    id: record.id.clone(),
                    state,
                    expected: "a vm that is gone",
                });
            }
        }
        lock(&self.0.discarded_areas).push((record.id.clone(), isolation.clone()));
        StagingArea::new(&record.runtime_dir).remove().await
    }
}

#[cfg(test)]
mod tests;
