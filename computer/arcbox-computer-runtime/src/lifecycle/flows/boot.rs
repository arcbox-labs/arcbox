//! The cold-boot flows: bringing the VM up, and the readiness gate READY is
//! withheld for.
//!
//! `boot_sandbox`'s two halves, split where the machine splits them. What was
//! the tail's own bookkeeping — the generation re-checks, the `Ready` /
//! `Starting` assignment, the durable `Ready` write, the READY event and the
//! failure handling — belongs to the actor now; what is left is the work.

use std::sync::Arc;

use chrono::Utc;
use tracing::{info, warn};

use super::{ComputerFlows, Launch};
use crate::agent::{GuestAgent, StartCommand};
use crate::error::{Result, VmmError};
use crate::lifecycle::actor::{Command, Mailbox, WorkloadOutcome};
use crate::lifecycle::tasks::boot::{do_boot, wait_for_agent};
use crate::lifecycle::tasks::{TaskFailure, TaskResult};
use crate::sandbox::boot::run_ready_probe;
use crate::sandbox::warm::{WarmPublishTicket, publish_after_boot};
use crate::sandbox::workload::{WorkloadClaim, WorkloadSlot, start_run_workload};
use crate::sandbox::{SandboxId, SandboxSpec, SandboxState};

impl ComputerFlows {
    pub(super) async fn boot_vm(
        &self,
        handed_off: tokio::sync::oneshot::Sender<()>,
    ) -> TaskResult<Arc<dyn GuestAgent>> {
        let attachment = match self.take_attachment() {
            Some(attachment) => attachment,
            None => return Err(self.wrong_launch("boot")),
        };
        let attachment = attachment.into_inner();

        let (spec, vm_dir) = {
            let computer = self.computer.lock().unwrap();
            (computer.spec.clone(), computer.vm_dir.clone())
        };
        let services = &self.services;
        let outcome = do_boot(
            &self.id,
            &spec,
            attachment.as_ref(),
            &vm_dir,
            services.driver.as_ref(),
            services.agents.as_ref(),
            &services.config,
            &services.cow_manager,
            &self.computer,
            handed_off,
        )
        .await;

        let (handle, ready_gate) = match outcome {
            Ok(booted) => booted,
            // Whatever the boot had not yet handed over goes onto the
            // computer, so the release the failure spawns finds it. This is
            // `boot_sandbox`'s `updated_current` branch, reached without the
            // generation check the actor makes redundant.
            Err(failure) => {
                let mut computer = self.computer.lock().unwrap();
                if let Some(prepared) = failure.prepared {
                    computer.prepared = Some(prepared);
                }
                if let Some(cow_handle) = failure.cow_handle {
                    computer.cow_handle = Some(cow_handle);
                }
                return Err(TaskFailure::recoverable(failure.error));
            }
        };

        let agent = wait_for_agent(
            &self.id,
            &handle,
            attachment.as_ref(),
            ready_gate,
            services.agents.as_ref(),
        )
        .await
        .map_err(TaskFailure::recoverable)?;

        let mut computer = self.computer.lock().unwrap();
        computer.handle = Some(handle);
        computer.net_identity = attachment.map(|net| net.identity);
        computer.ready_at = Some(Utc::now());
        drop(computer);
        Ok(agent)
    }

    /// Everything READY is withheld for: the warm publish, the initial `cmd`,
    /// and the ready probe.
    pub(super) async fn run_gate(&self) -> TaskResult {
        let spec = self.computer.lock().unwrap().spec.clone();
        let agent = self.agent().map_err(TaskFailure::recoverable)?;

        // First eligible create of this boot shape (CORE-77): capture the
        // warm snapshot while the guest is still idle, before the initial cmd
        // dirties it. Synchronous on purpose — the cmd must not run before
        // the checkpoint — and failures only warn: cache population never
        // fails a healthy boot. The one that does is a guest left frozen,
        // which the machine degrades rather than announcing READY for.
        //
        // This whole gate is why READY is withheld: the checkpoint pauses the
        // guest, and a client acting on READY the moment it arrives would hit
        // that pause with an execution and hang.
        if let Some(ticket) = self.take_warm_ticket() {
            let services = &self.services;
            publish_after_boot(
                &self.id,
                &ticket,
                &self.computer,
                &services.cow_manager,
                // The gate holds `Starting` for its whole duration — the
                // reservation the boot's own `cmd` is owed — so the
                // checkpoint's precondition is what this pipeline set, not
                // what an API caller would see.
                SandboxState::Starting,
            )
            .await
            .map_err(TaskFailure::frozen)?;
        }

        // Initial cmd + ready probe (CORE-107). Every cmd-carrying boot
        // starts the cmd here, through the reserved Initial claim — the slot
        // could not have been taken by anyone else. A probed boot
        // additionally needs the cmd running before it probes: the cmd is the
        // only listener source in a computer (vm-agent is init; a docker
        // ENTRYPOINT never runs).
        let started = self.start_initial_cmd(&spec, agent.as_ref()).await;
        if let Some(probe) = spec.ready_probe.clone() {
            run_ready_probe(&probe, agent.as_ref()).await.map_err(|e| {
                TaskFailure::recoverable(VmmError::FailedPrecondition(format!(
                    "ready probe failed: {e}"
                )))
            })?;
        }
        // A failed initial start released the claim; give the cmd its one
        // ordinary second attempt. A second failure is final — warned, the
        // computer still reaches READY, and the caller can Run/Exec.
        if !started {
            self.start_initial_cmd(&spec, agent.as_ref()).await;
        }
        Ok(())
    }

    /// The boot's own `cmd`, launched through the reserved workload claim.
    /// `false` when there was nothing to start or the guest refused it.
    pub(super) async fn start_initial_cmd(
        &self,
        spec: &SandboxSpec,
        agent: &dyn GuestAgent,
    ) -> bool {
        if spec.cmd.is_empty() {
            return false;
        }
        let start = StartCommand {
            cmd: spec.cmd.clone(),
            env: spec.env.clone(),
            working_dir: spec.working_dir.clone(),
            user: spec.user.clone(),
            tty: false,
            tty_width: 80,
            tty_height: 24,
            timeout_seconds: 0,
        };
        let slot = match self.workload_slot() {
            Ok(slot) => slot,
            Err(error) => {
                warn!(sandbox_id = %self.id, %error, "the initial cmd found no computer to claim");
                return false;
            }
        };
        match start_run_workload(agent, start, slot, WorkloadClaim::Initial).await {
            Ok(mut rx) => {
                info!(sandbox_id = %self.id, "initial cmd started");
                // Nothing consumes an initial cmd's output; drain it so the
                // exit chunk still reaches the watcher.
                tokio::spawn(async move { while rx.recv().await.is_some() {} });
                true
            }
            Err(error) => {
                warn!(sandbox_id = %self.id, %error, "initial cmd failed to start");
                false
            }
        }
    }

    fn take_warm_ticket(&self) -> Option<WarmPublishTicket> {
        match &mut *self.launch.lock().unwrap() {
            Launch::Boot(launch) => launch.warm_publish.take(),
            _ => None,
        }
    }

    /// Takes the boot's network, leaving the gate's half of the launch in
    /// place. `None` when this computer was never launched as a cold boot.
    fn take_attachment(&self) -> Option<Attachment> {
        match &mut *self.launch.lock().unwrap() {
            Launch::Boot(launch) => Some(Attachment(launch.attachment.take())),
            _ => None,
        }
    }

    /// This computer's workload slot, taken and given back through its own
    /// mailbox.
    pub fn workload_slot(&self) -> Result<Arc<dyn WorkloadSlot>> {
        Ok(Arc::new(ActorSlot {
            id: self.id.clone(),
            mailbox: self.mailbox()?,
        }))
    }
}

/// A boot's network, distinguishing "this is not a boot" from "this boot has
/// no network" — the two `Option`s the take collapses otherwise.
struct Attachment(Option<crate::sandbox::NetworkAttachment>);

impl Attachment {
    fn into_inner(self) -> Option<crate::sandbox::NetworkAttachment> {
        self.0
    }
}

/// The single-workload slot as the actor owns it: the claim, its rollback and
/// the exit are all lifecycle transitions, so all three are mailbox verbs.
pub struct ActorSlot {
    pub id: SandboxId,
    pub mailbox: Mailbox,
}

#[async_trait::async_trait]
impl WorkloadSlot for ActorSlot {
    async fn claim(&self, claim: WorkloadClaim) -> Result<()> {
        self.mailbox
            .ask(&self.id, |reply| Command::ClaimWorkload { claim, reply })
            .await
    }

    fn release(&self) {
        self.mailbox.tell(Command::ReleaseWorkload);
    }

    fn exited(&self, outcome: WorkloadOutcome) {
        self.mailbox.tell(Command::WorkloadExited { outcome });
    }
}
