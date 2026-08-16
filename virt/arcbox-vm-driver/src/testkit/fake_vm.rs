//! The fake driver's VM: an in-memory state machine behind a real
//! [`VmHandle`].

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::broadcast;

use super::lock;
use crate::driver::{ExitStatus, ShutdownMode, VmEvent, VmHandle, VmRecord, VmState};
use crate::error::Result;
use crate::spec::{VmId, VmSpec};

/// What `shutdown(Kill)` and a killing `Drop` report.
const SIGKILL: i32 = 9;

/// The VM's shared state; the driver's registry and every handle to the VM
/// hold an `Arc` of it.
pub(super) struct VmInner {
    spec: VmSpec,
    record: VmRecord,
    state: Mutex<VmState>,
    events: broadcast::Sender<VmEvent>,
}

impl VmInner {
    pub(super) fn new(spec: VmSpec, record: VmRecord) -> Arc<Self> {
        let (events, _) = broadcast::channel(16);
        Arc::new(Self {
            spec,
            record,
            state: Mutex::new(VmState::Running),
            events,
        })
    }

    pub(super) fn id(&self) -> &VmId {
        &self.spec.id
    }

    pub(super) fn state(&self) -> VmState {
        *lock(&self.state)
    }

    /// Moves to `Exited(status)` and returns the status the VM ended with:
    /// `status`, or the earlier one if it had already exited.
    fn exit(&self, status: ExitStatus) -> ExitStatus {
        {
            let mut state = lock(&self.state);
            if let VmState::Exited(earlier) = *state {
                return earlier;
            }
            *state = VmState::Exited(status);
        }
        // A send error only means nobody is subscribed.
        let _ = self.events.send(VmEvent::Exited(status));
        status
    }
}

/// A [`VmHandle`] onto a fake VM.
///
/// Dropping it kills the VM; the driver's registry forgets exited VMs on
/// its next lookup.
pub struct FakeVm {
    vm: Arc<VmInner>,
}

impl FakeVm {
    pub(super) fn new(vm: Arc<VmInner>) -> Self {
        Self { vm }
    }
}

impl Drop for FakeVm {
    fn drop(&mut self) {
        self.vm.exit(ExitStatus::signaled(SIGKILL));
    }
}

#[async_trait]
impl VmHandle for FakeVm {
    fn id(&self) -> &VmId {
        self.vm.id()
    }

    fn record(&self) -> VmRecord {
        self.vm.record.clone()
    }

    fn state(&self) -> VmState {
        self.vm.state()
    }

    fn events(&self) -> broadcast::Receiver<VmEvent> {
        self.vm.events.subscribe()
    }

    async fn shutdown(&self, mode: ShutdownMode) -> Result<ExitStatus> {
        let status = match mode {
            ShutdownMode::Graceful { .. } => ExitStatus::exited(0),
            ShutdownMode::Kill => ExitStatus::signaled(SIGKILL),
        };
        Ok(self.vm.exit(status))
    }
}
