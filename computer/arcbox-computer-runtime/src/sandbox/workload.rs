use super::*;
use crate::lifecycle::actor::WorkloadOutcome;

/// Which caller is taking the single-workload slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadClaim {
    /// The public Run/Exec surface: claims from `Ready` only.
    Api,
    /// The boot/restore pipeline's own initial cmd: additionally claims
    /// from the readiness gate. A boot with an initial cmd holds the gate
    /// until this claim, so an Inspect-polling client cannot slip an exec
    /// into the boot tail (the warm-snapshot publish pause is a wide
    /// window) and silently steal the slot the template's default cmd was
    /// owed — the CORE-107 e2e caught exactly that.
    Initial,
}

/// A computer's single-workload slot.
///
/// Taking it, giving it back and reporting the exit are all lifecycle
/// transitions, so all three belong to the computer's actor rather than to
/// the code that dispatches the command. The seam keeps the dispatch itself
/// off the mailbox: [`start_run_workload`] talks to the guest directly, and
/// only the three edges are verbs.
#[async_trait::async_trait]
pub trait WorkloadSlot: Send + Sync {
    /// Take the slot. `WrongState` when a workload is already running, the
    /// computer is on its way out, or an `Api` claim reached one that has
    /// not announced READY.
    async fn claim(&self, claim: WorkloadClaim) -> Result<()>;
    /// Give the slot back after a dispatch the guest refused. Nothing ran,
    /// so nothing is announced.
    fn release(&self);
    /// The workload ended.
    fn exited(&self, outcome: WorkloadOutcome);
}

/// Spawn the watcher that mirrors a workload's output to the caller and drives
/// the exit-side state machine.
///
/// The watcher **always drains `inner_rx` to completion** so the `exit` chunk
/// is processed even after the caller drops its receiver. Coupling the state
/// update to a successful forward was the original defect: a consumer that
/// disconnected mid-workload broke the loop before the exit frame, stranding
/// the computer in `Running` forever. Now a gone consumer only stops the
/// forwarding; the drain (and the exit report) continues.
fn spawn_exit_watcher(
    inner_rx: tokio::sync::mpsc::Receiver<Result<OutputChunk>>,
    slot: Arc<dyn WorkloadSlot>,
) -> tokio::sync::mpsc::Receiver<Result<OutputChunk>> {
    let (wrapped_tx, wrapped_rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        let mut inner_rx = inner_rx;
        let mut consumer_gone = false;
        while let Some(result) = inner_rx.recv().await {
            // Handle the exit chunk regardless of the consumer's presence.
            if let Ok(OutputChunk::Exit(status)) = &result {
                slot.exited(WorkloadOutcome::Exited(*status));
            }
            // Forward until the consumer goes away, then keep draining so the
            // exit chunk above is still reached.
            if !consumer_gone && wrapped_tx.send(result).await.is_err() {
                consumer_gone = true;
            }
        }
    });
    wrapped_rx
}

/// Start a non-interactive workload through the computer's agent and wire up
/// the workload slot.
///
/// Shared by `Run` (`WorkloadClaim::Api`) and the initial `cmd` launched by
/// the boot/restore gates (`WorkloadClaim::Initial`): claims the slot
/// **before** connecting so a losing racer never dispatches a command,
/// launches the session, then spawns the exit watcher. A launch failure gives
/// the claim back.
pub async fn start_run_workload(
    agent: &dyn GuestAgent,
    start: StartCommand,
    slot: Arc<dyn WorkloadSlot>,
    claim: WorkloadClaim,
) -> Result<tokio::sync::mpsc::Receiver<Result<OutputChunk>>> {
    slot.claim(claim).await?;
    let inner_rx = match agent.run(start).await {
        Ok(rx) => rx,
        Err(error) => {
            slot.release();
            return Err(error);
        }
    };
    Ok(spawn_exit_watcher(inner_rx, slot))
}

impl ComputerManager {
    /// This computer's workload slot: its actor, behind the seam.
    pub(super) fn workload_slot(&self, id: &ComputerId) -> Result<Arc<dyn WorkloadSlot>> {
        Ok(Arc::new(crate::lifecycle::flows::ActorSlot {
            id: id.clone(),
            mailbox: self.mailbox(id)?,
        }))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "public API mirrors workload request"
    )]
    pub async fn run_in_computer(
        &self,
        id: &ComputerId,
        cmd: Vec<String>,
        env: HashMap<String, String>,
        working_dir: String,
        user: String,
        tty: bool,
        tty_size: Option<(u16, u16)>,
        timeout_seconds: u32,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<OutputChunk>>> {
        let agent = self.require_ready_agent(id)?;

        let start = StartCommand {
            cmd,
            env,
            working_dir,
            user,
            tty,
            tty_width: tty_size.map_or(80, |(w, _)| w),
            tty_height: tty_size.map_or(24, |(_, h)| h),
            timeout_seconds,
        };

        start_run_workload(
            agent.as_ref(),
            start,
            self.workload_slot(id)?,
            WorkloadClaim::Api,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what the watcher reported, standing in for the computer's
    /// actor: the state machine those reports drive is table-tested in
    /// `crate::lifecycle::tests`.
    #[derive(Default)]
    struct RecordingSlot {
        reports: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl WorkloadSlot for RecordingSlot {
        async fn claim(&self, _claim: WorkloadClaim) -> Result<()> {
            self.reports.lock().unwrap().push("claim".to_owned());
            Ok(())
        }

        fn release(&self) {
            self.reports.lock().unwrap().push("release".to_owned());
        }

        fn exited(&self, outcome: WorkloadOutcome) {
            self.reports.lock().unwrap().push(format!("{outcome:?}"));
        }
    }

    #[tokio::test]
    async fn the_watcher_reports_the_exit_even_when_the_consumer_disconnects() {
        // Regression for the strand-in-Running bug: drop the consumer before
        // the exit chunk; the watcher must still process the exit, or the
        // computer never leaves `Running`.
        let slot = Arc::new(RecordingSlot::default());
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel(8);

        let wrapped_rx = spawn_exit_watcher(inner_rx, Arc::clone(&slot) as Arc<dyn WorkloadSlot>);
        drop(wrapped_rx); // consumer gone immediately

        inner_tx
            .send(Ok(OutputChunk::Stdout(b"noise".to_vec())))
            .await
            .unwrap();
        inner_tx
            .send(Ok(OutputChunk::Exit(ExitStatus::Code(7))))
            .await
            .unwrap();
        drop(inner_tx); // guest side closes after exit

        for _ in 0..50 {
            if !slot.reports.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(slot.reports.lock().unwrap().as_slice(), ["Exited(Code(7))"]);
    }

    #[tokio::test]
    async fn the_watcher_forwards_then_reports_for_a_live_consumer() {
        let slot = Arc::new(RecordingSlot::default());
        let (inner_tx, inner_rx) = tokio::sync::mpsc::channel(8);

        let mut wrapped_rx =
            spawn_exit_watcher(inner_rx, Arc::clone(&slot) as Arc<dyn WorkloadSlot>);

        inner_tx
            .send(Ok(OutputChunk::Stdout(b"hello".to_vec())))
            .await
            .unwrap();
        let first = wrapped_rx.recv().await.unwrap().unwrap();
        assert!(matches!(first, OutputChunk::Stdout(data) if data == b"hello"));

        inner_tx
            .send(Ok(OutputChunk::Exit(ExitStatus::Code(0))))
            .await
            .unwrap();
        drop(inner_tx);

        // The forwarded exit chunk arrives, then the channel closes.
        let exit = wrapped_rx.recv().await.unwrap().unwrap();
        assert!(matches!(exit, OutputChunk::Exit(ExitStatus::Code(0))));
        assert!(wrapped_rx.recv().await.is_none());
        assert_eq!(slot.reports.lock().unwrap().as_slice(), ["Exited(Code(0))"]);
    }

    /// A guest that refuses the dispatch must give the slot back — and only
    /// the slot: nothing ran, so there is no exit to report.
    #[tokio::test]
    async fn a_refused_dispatch_gives_the_claim_back() {
        let slot = Arc::new(RecordingSlot::default());
        let agents = crate::testkit::agent::FakeAgentFactory::new();
        agents.on(
            &["/bin/nope"],
            crate::testkit::agent::Reply::Fails("no such file".into()),
        );

        start_run_workload(
            agents.agent().as_ref(),
            StartCommand {
                cmd: vec!["/bin/nope".into()],
                env: HashMap::new(),
                working_dir: String::new(),
                user: String::new(),
                tty: false,
                tty_width: 80,
                tty_height: 24,
                timeout_seconds: 0,
            },
            Arc::clone(&slot) as Arc<dyn WorkloadSlot>,
            WorkloadClaim::Api,
        )
        .await
        .expect_err("the guest refused the command");
        assert_eq!(
            slot.reports.lock().unwrap().as_slice(),
            ["claim", "release"]
        );
    }
}
