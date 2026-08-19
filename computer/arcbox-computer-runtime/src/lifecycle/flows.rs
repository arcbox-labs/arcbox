//! The flows one computer's actor spawns: the [`ComputerTasks`]
//! implementation over the real driver, network, record store and catalogs.
//!
//! The bodies themselves live in [`super::tasks`] — PR-F1 moved them there
//! one file at a time. What is here is the wiring the actor cannot have: the
//! services every computer shares, the one-shot inputs a launch consumes, and
//! the handle back to the mailbox that the readiness gate's initial `cmd`
//! claims its workload slot through.
//!
//! That handle is deliberately **weak**. A gate holding a live sender would
//! keep its own actor's mailbox open forever, and the actor stops when its
//! last sender drops — which is how a reservation that was never committed
//! shuts one down.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcbox_vm_driver::NicSpec;
use arcbox_vm_driver::VmDriver;
use arcbox_vm_driver::net::{GuestNetwork, NetworkLease};
use tokio::sync::broadcast;

use async_trait::async_trait;

use super::actor::{Mailbox, WeakMailbox};
use super::effect::ReleaseScope;
use super::event::RestoreOrigin;
use super::tasks::{CaptureSpec, ComputerTasks, Drain, TaskFailure, TaskResult};
use crate::agent::{GuestAgent, GuestAgentFactory};
use crate::config::RuntimeConfig;
use crate::error::{ComputerError, Result};
use crate::lifecycle::runtime::ComputerRuntime;
use crate::sandbox::pool::SlotPool;
use crate::sandbox::record::SandboxProvisionOutcome;
use crate::sandbox::record::SandboxRecordStore;
use crate::sandbox::warm::WarmPublishTicket;
use crate::sandbox::{CheckpointInfo, ComputerEvent, ComputerId, NetworkAttachment};
use crate::snapshot::{SnapshotCatalog, SnapshotMeta};
use crate::snapshot_cow::CowManager;

mod boot;
mod restore;
mod teardown;

pub use boot::ActorSlot;

/// What every computer's flows share with the manager. One `Arc`, cloned per
/// computer, so a new service reaches the flows without threading another
/// parameter through each of them.
pub struct ComputerServices {
    pub driver: Arc<dyn VmDriver>,
    pub network: Arc<dyn GuestNetwork>,
    pub agents: Arc<dyn GuestAgentFactory>,
    pub config: Arc<RuntimeConfig>,
    pub cow_manager: Arc<CowManager>,
    pub records: Arc<SandboxRecordStore>,
    pub snapshots: Arc<SnapshotCatalog>,
    pub events_tx: broadcast::Sender<ComputerEvent>,
    pub pool: Arc<SlotPool>,
}

/// How this computer comes up, and the inputs only its first flow consumes.
///
/// Resolved by the manager before the actor exists — the network reserve, the
/// warm-cache lookup and the checkpoint resolution are all things a caller
/// must be able to fail on — and consumed exactly once.
pub enum Launch {
    Boot(Box<BootLaunch>),
    Restore(Box<RestoreLaunch>),
    /// Nothing to launch: a computer the startup sweep reinstated, or one the
    /// manager parked at `Failed` when its own setup could not be unwound.
    Reinstated,
}

pub struct BootLaunch {
    /// The lease this create reserved and the interface it activated, which
    /// the boot hands to the VM spec and the guest's command line.
    pub attachment: Option<NetworkAttachment>,
    /// The warm-cache publish this boot owes, taken before READY.
    pub warm_publish: Option<WarmPublishTicket>,
}

pub struct RestoreLaunch {
    pub snapshot_id: String,
    pub snap_meta: SnapshotMeta,
    pub lease: Option<NetworkLease>,
    /// The interface activating that lease produced, if any.
    pub nic: Option<NicSpec>,
    /// When the caller's restore started, for the completion log's phase
    /// breakdown (CORE-75).
    pub started: std::time::Instant,
}

/// One computer's flows.
pub struct ComputerFlows {
    id: ComputerId,
    computer: Arc<Mutex<ComputerRuntime>>,
    services: Arc<ComputerServices>,
    mailbox: WeakMailbox,
    launch: Mutex<Launch>,
}

impl ComputerFlows {
    pub fn new(
        id: ComputerId,
        computer: Arc<Mutex<ComputerRuntime>>,
        services: Arc<ComputerServices>,
        mailbox: &Mailbox,
        launch: Launch,
    ) -> Self {
        Self {
            id,
            computer,
            services,
            mailbox: mailbox.downgrade(),
            launch: Mutex::new(launch),
        }
    }

    /// The agent reaching this computer's guest, built from the running VM's
    /// handle the way the manager's read path builds it — the flows and the
    /// exec path must describe the same guest.
    fn agent(&self) -> Result<Arc<dyn GuestAgent>> {
        let (handle, identity) = {
            let computer = self.computer.lock().unwrap();
            (computer.handle.clone(), computer.net_identity.clone())
        };
        let handle = handle.ok_or_else(|| {
            ComputerError::Vsock(format!("computer {} has no running vm to reach", self.id))
        })?;
        self.services.agents.connect(handle, identity.as_ref())
    }

    /// This computer's own mailbox, while its actor is still running.
    fn mailbox(&self) -> Result<Mailbox> {
        self.mailbox
            .upgrade()
            .ok_or_else(|| ComputerError::NotFound(self.id.clone()))
    }

    fn take_launch(&self) -> Launch {
        std::mem::replace(&mut *self.launch.lock().unwrap(), Launch::Reinstated)
    }

    /// The launch input a flow the machine only reaches through its own
    /// `Provision` is missing. Unreachable in practice; reported rather than
    /// panicked so a wiring mistake fails one computer, not the process.
    fn wrong_launch(&self, wanted: &str) -> TaskFailure {
        TaskFailure::recoverable(ComputerError::Other(format!(
            "computer {} was asked to {wanted} with no such launch",
            self.id
        )))
    }
}

/// Which restore this is, as the flows read it. The machine's own
/// [`RestoreOrigin`] decides the event contract; here it only labels the
/// completion log.
const fn warm_create(origin: RestoreOrigin) -> bool {
    matches!(origin, RestoreOrigin::WarmCreate)
}

#[async_trait]
impl ComputerTasks for ComputerFlows {
    async fn boot(
        &self,
        _warm: bool,
        handed_off: tokio::sync::oneshot::Sender<()>,
    ) -> TaskResult<Arc<dyn GuestAgent>> {
        self.boot_vm(handed_off).await
    }

    async fn gate(&self) -> TaskResult {
        self.run_gate().await
    }

    async fn restore(
        &self,
        origin: RestoreOrigin,
    ) -> TaskResult<(Arc<dyn GuestAgent>, SandboxProvisionOutcome)> {
        self.restore_vm(origin).await
    }

    async fn checkpoint(
        &self,
        hold: bool,
        spec: Option<CaptureSpec>,
    ) -> TaskResult<CheckpointInfo> {
        self.capture(hold, spec).await
    }

    async fn resume(&self) -> TaskResult<Arc<dyn GuestAgent>> {
        self.resume_vm().await
    }

    async fn stop(&self, budget: Duration, drain: Drain) -> TaskResult {
        self.stop_vm(budget, drain).await
    }

    async fn release(&self, scope: ReleaseScope) -> TaskResult {
        self.release_scope(scope).await
    }

    fn adopted_agent(&self) -> Option<Arc<dyn GuestAgent>> {
        self.agent().ok()
    }
}
