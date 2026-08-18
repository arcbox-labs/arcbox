//! The actor's own contract: what the machine's table cannot express.
//!
//! Preemption, the boot's resource handoff and its retry, the epoch that
//! makes a superseded task's completion inert, the deferred stop, the
//! deadline timers, and the guest agent riding the snapshot instead of the
//! mailbox. All of it runs with no VMM, no driver and no record store — which
//! is the point of the [`ComputerTasks`] seam.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcbox_vm_driver::testkit::FakeDriver;
use arcbox_vm_driver::{BootSpec, ConsoleSpec, IsolationSpec, VmDriver, VmId, VmSpec};
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::agent::{GuestAgent, GuestAgentFactory};
use crate::config::VmmConfig;
use crate::error::{Result, VmmError};
use crate::lifecycle::actor::{Command, ComputerActor, ComputerSeed, ComputerSnapshot, Deadlines};
use crate::lifecycle::effect::ReleaseScope;
use crate::lifecycle::event::{Provision, RestoreOrigin};
use crate::lifecycle::tasks::{ComputerTasks, TaskFailure, TaskResult};
use crate::sandbox::reconcile::{SandboxStateRecord, write_state_record};
use crate::sandbox::record::{SandboxProvisionOutcome, SandboxRecordStore};
use crate::sandbox::{IdleAction, SandboxEvent, SandboxState};
use crate::testkit::agent::FakeAgentFactory;

/// What the fake boot does with its resource handoff — the only sub-task the
/// actor treats specially.
#[derive(Clone, Copy)]
enum Boot {
    /// Hands off at once, then never returns: the abortable in-flight case.
    HandsOffThenHangs,
    /// Hands off only after `Duration`, so a teardown before then must stall
    /// and retry rather than strand what the task still owns.
    HandsOffAfter(Duration),
    /// Hands off and completes in the same poll, so its completion is already
    /// enqueued when the abort lands.
    HandsOffAndCompletes,
    /// Hands off, then panics: the join reports it, and a teardown must not
    /// swallow that.
    HandsOffThenPanics,
    /// Ends *without* signalling and then tears down what it never handed
    /// over, which a teardown must let finish rather than cut short.
    DropsHandoffThenCleansUp,
    /// Completes at once.
    Completes,
}

/// A scripted [`ComputerTasks`]: records every verb, answers as told.
struct Script {
    boot: Boot,
    agent: Arc<dyn GuestAgent>,
    calls: Mutex<Vec<&'static str>>,
    /// Every release fails, as a teardown that cannot finish does.
    release_fails: AtomicBool,
    /// The restore waits this long before returning, and records whether it
    /// was allowed to finish.
    restore_takes: Mutex<Option<Duration>>,
    restore_finished: AtomicBool,
    /// How long the gate holds READY back, which is how a test observes a
    /// computer while its launch is still in flight.
    gate_takes: Mutex<Option<Duration>>,
    /// Whether a boot that never handed off got to finish its own teardown.
    cleanup_finished: AtomicBool,
}

impl Script {
    fn new(boot: Boot, agent: Arc<dyn GuestAgent>) -> Arc<Self> {
        Arc::new(Self {
            boot,
            agent,
            calls: Mutex::new(Vec::new()),
            release_fails: AtomicBool::new(false),
            restore_takes: Mutex::new(None),
            restore_finished: AtomicBool::new(false),
            gate_takes: Mutex::new(None),
            cleanup_finished: AtomicBool::new(false),
        })
    }

    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl ComputerTasks for Script {
    async fn boot(
        &self,
        _warm: bool,
        handed_off: oneshot::Sender<()>,
    ) -> TaskResult<Arc<dyn GuestAgent>> {
        self.record("boot");
        match self.boot {
            Boot::HandsOffThenHangs => {
                let _ = handed_off.send(());
                std::future::pending::<()>().await;
                unreachable!("a hanging boot is only ever aborted")
            }
            Boot::HandsOffAfter(delay) => {
                tokio::time::sleep(delay).await;
                let _ = handed_off.send(());
                std::future::pending::<()>().await;
                unreachable!("a hanging boot is only ever aborted")
            }
            Boot::DropsHandoffThenCleansUp => {
                drop(handed_off);
                tokio::time::sleep(Duration::from_secs(2)).await;
                self.cleanup_finished.store(true, Ordering::SeqCst);
                Err(TaskFailure::recoverable(VmmError::Process(
                    "the vmm would not spawn".into(),
                )))
            }
            Boot::HandsOffThenPanics => {
                // Panics in the same poll as the signal, so the abort finds
                // a task that has already fallen over.
                let _ = handed_off.send(());
                panic!("the boot task fell over")
            }
            Boot::HandsOffAndCompletes | Boot::Completes => {
                let _ = handed_off.send(());
                Ok(Arc::clone(&self.agent))
            }
        }
    }

    async fn gate(&self) -> TaskResult {
        self.record("gate");
        let takes = *self.gate_takes.lock().unwrap();
        if let Some(takes) = takes {
            tokio::time::sleep(takes).await;
        }
        Ok(())
    }

    async fn restore(
        &self,
        _origin: RestoreOrigin,
    ) -> TaskResult<(Arc<dyn GuestAgent>, SandboxProvisionOutcome)> {
        self.record("restore");
        let takes = *self.restore_takes.lock().unwrap();
        if let Some(takes) = takes {
            tokio::time::sleep(takes).await;
        }
        self.restore_finished.store(true, Ordering::SeqCst);
        Ok((Arc::clone(&self.agent), SandboxProvisionOutcome::default()))
    }

    async fn checkpoint(&self, _hold: bool) -> TaskResult<String> {
        self.record("checkpoint");
        Ok("snap".to_owned())
    }

    async fn resume(&self) -> TaskResult<Arc<dyn GuestAgent>> {
        self.record("resume");
        Ok(Arc::clone(&self.agent))
    }

    async fn stop(&self, _budget: Duration) -> TaskResult {
        self.record("stop");
        Ok(())
    }

    async fn release(&self, _scope: ReleaseScope) -> TaskResult {
        self.record("release");
        if self.release_fails.load(Ordering::SeqCst) {
            return Err(TaskFailure::recoverable(VmmError::Process(
                "the vmm would not die".into(),
            )));
        }
        Ok(())
    }
}

/// One actor, its mailbox, its snapshot, and the events it publishes.
struct Harness {
    commands: mpsc::UnboundedSender<Command>,
    snapshot: watch::Receiver<ComputerSnapshot>,
    events: broadcast::Receiver<SandboxEvent>,
    script: Arc<Script>,
    actor: tokio::task::JoinHandle<()>,
    _timers: watch::Sender<bool>,
    dir: tempfile::TempDir,
}

impl Harness {
    async fn start(boot: Boot, deadlines: Deadlines) -> Self {
        Self::started(boot, deadlines, false).await
    }

    /// A harness whose computer has a crash journal on disk, so what the
    /// actor refuses to drop is observable.
    async fn journalled(boot: Boot, deadlines: Deadlines) -> Self {
        Self::started(boot, deadlines, true).await
    }

    async fn started(boot: Boot, deadlines: Deadlines, journal: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = Script::new(boot, agent().await);
        let (events_tx, events) = broadcast::channel(64);
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let (snapshot_tx, snapshot) = watch::channel(ComputerSnapshot::default());
        let (timers, timers_enabled) = watch::channel(true);
        if journal {
            let config = VmmConfig::default();
            let record = SandboxStateRecord::new("box", None, None, None, &config, None).unwrap();
            write_state_record(dir.path(), &record).unwrap();
        }
        let seed = ComputerSeed {
            id: "box".to_owned(),
            // No durable record: these tests exercise the actor, not the
            // store, so the record writes are no-ops. The crash journal is
            // not — it is a file beside them, and its ordering is the thing
            // under test above.
            generation: None,
            vm_dir: dir.path().to_path_buf(),
            records: Arc::new(SandboxRecordStore::new(dir.path()).unwrap()),
            events_tx,
            tasks: Arc::clone(&script) as Arc<dyn ComputerTasks>,
            deadlines,
            timers_enabled,
        };
        let actor = tokio::spawn(ComputerActor::new(seed, commands_rx, snapshot_tx).run());
        Self {
            commands,
            snapshot,
            events,
            script,
            actor,
            _timers: timers,
            dir,
        }
    }

    /// Sends a verb and returns its parked reply.
    fn send(&self, command: impl FnOnce(oneshot::Sender<Result<()>>) -> Command) -> Waiter {
        let (reply, waiter) = oneshot::channel();
        self.commands.send(command(reply)).unwrap();
        Waiter(waiter)
    }

    /// Drives a cold boot to `ready`, answering its create immediately.
    async fn boot_to_ready(&mut self) {
        self.send(|reply| Command::Provision {
            provision: Provision::Boot { warm: false },
            outcome: SandboxProvisionOutcome::default(),
            reply,
        })
        .ok()
        .await;
        self.settled(SandboxState::Ready).await;
    }

    /// Waits for the snapshot to reach `state`.
    async fn settled(&mut self, state: SandboxState) {
        self.snapshot
            .wait_for(|snapshot| snapshot.state == Some(state))
            .await
            .unwrap();
    }

    /// Waits for the actor to finish, which it does once the computer is
    /// gone.
    async fn joined(&mut self) {
        (&mut self.actor).await.unwrap();
    }

    /// Waits until the scripted tasks have recorded `call`.
    async fn awaited(&self, call: &str) {
        while !self.script.calls().contains(&call) {
            tokio::task::yield_now().await;
        }
    }

    /// Whether the crash journal is still on disk.
    fn has_journal(&self) -> bool {
        self.dir.path().join("state.json").exists()
    }

    /// The lifecycle actions published so far.
    fn actions(&mut self) -> Vec<String> {
        let mut actions = Vec::new();
        while let Ok(event) = self.events.try_recv() {
            actions.push(event.action);
        }
        actions
    }
}

/// A parked reply.
struct Waiter(oneshot::Receiver<Result<()>>);

impl Waiter {
    async fn ok(self) {
        self.0.await.unwrap().unwrap();
    }

    async fn error(self) -> VmmError {
        self.0.await.unwrap().unwrap_err()
    }
}

/// A guest agent to publish on the snapshot: the agent port's own fake, over
/// a fake VM's handle.
async fn agent() -> Arc<dyn GuestAgent> {
    let dir = tempfile::tempdir().unwrap();
    let driver = FakeDriver::new();
    let id = VmId::new("agent").unwrap();
    let prepared = driver
        .prepare()
        .unwrap()
        .prepare(&id, &IsolationSpec::None, dir.path())
        .await
        .unwrap();
    let handle = Arc::from(
        prepared
            .boot(VmSpec {
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
                vsock: None,
                shares: vec![],
                console: ConsoleSpec::Off,
                balloon: false,
                entropy: false,
                dirty_tracking: false,
                isolation: IsolationSpec::None,
            })
            .await
            .unwrap(),
    );
    FakeAgentFactory::new().connect(handle, None).unwrap()
}

fn no_deadlines() -> Deadlines {
    Deadlines::default()
}

#[tokio::test(start_paused = true)]
async fn a_force_remove_preempts_a_boot_that_has_handed_its_resources_over() {
    // The reason the slow work is in sub-tasks at all: today's cleanup lock
    // would make this Remove wait for the boot it is cancelling.
    let mut harness = Harness::start(Boot::HandsOffThenHangs, no_deadlines()).await;
    harness
        .send(|reply| Command::Provision {
            provision: Provision::Boot { warm: false },
            outcome: SandboxProvisionOutcome::default(),
            reply,
        })
        .ok()
        .await;

    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    harness.joined().await;

    assert_eq!(harness.script.calls(), vec!["boot", "release"]);
    assert!(harness.actions().contains(&"removed".to_owned()));
}

#[tokio::test(start_paused = true)]
async fn a_teardown_stalls_until_the_boot_hands_its_resources_over() {
    // Aborting before the handoff would strand whatever the task still owns,
    // so the teardown re-parks the task and retries — `expire_sandbox`'s
    // backoff loop, collapsed into the actor.
    let handoff_at = Duration::from_secs(25);
    let mut harness = Harness::start(Boot::HandsOffAfter(handoff_at), no_deadlines()).await;
    harness
        .send(|reply| Command::Provision {
            provision: Provision::Boot { warm: false },
            outcome: SandboxProvisionOutcome::default(),
            reply,
        })
        .ok()
        .await;

    let started = tokio::time::Instant::now();
    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    harness.joined().await;

    assert!(
        started.elapsed() >= handoff_at,
        "the teardown ran before the handoff landed"
    );
    assert_eq!(harness.script.calls(), vec!["boot", "release"]);
}

#[tokio::test(start_paused = true)]
async fn a_superseded_tasks_completion_cannot_drive_the_machine() {
    // The boot completes in the same poll as its handoff, so its completion
    // is already in the channel when the abort lands. Without the epoch it
    // would take the removing computer to `gating` and announce READY.
    let mut harness = Harness::start(Boot::HandsOffAndCompletes, no_deadlines()).await;
    // Both verbs before the boot task is ever polled, so the abort is waiting
    // on the handoff at the moment the task signals it and completes.
    let created = harness.send(|reply| Command::Provision {
        provision: Provision::Boot { warm: false },
        outcome: SandboxProvisionOutcome::default(),
        reply,
    });
    let removed = harness.send(|reply| Command::Remove { force: true, reply });
    created.ok().await;
    removed.ok().await;
    harness.joined().await;

    let actions = harness.actions();
    assert!(!actions.contains(&"ready".to_owned()), "{actions:?}");
    assert!(!harness.script.calls().contains(&"gate"));
}

#[tokio::test(start_paused = true)]
async fn a_stop_during_a_launch_is_served_once_the_launch_lands() {
    // Today's `stop_sandbox` answers WrongState here; the actor defers it,
    // which is what stops a stop from racing a boot mid-acquisition.
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    let created = harness.send(|reply| Command::Provision {
        provision: Provision::Boot { warm: false },
        outcome: SandboxProvisionOutcome::default(),
        reply,
    });
    let stopped = harness.send(|reply| Command::Stop {
        budget: Duration::from_secs(30),
        reply,
    });
    created.ok().await;
    stopped.ok().await;

    assert_eq!(harness.script.calls(), vec!["boot", "gate", "stop"]);
    // The agent rides the snapshot while the guest serves, and goes with it.
    assert!(harness.snapshot.borrow().agent.is_none());
    let actions = harness.actions();
    assert_eq!(
        actions,
        vec!["created", "ready", "stopping", "stopped"],
        "{actions:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_guest_agent_is_published_on_the_snapshot_the_moment_the_boot_reports() {
    // §B.6: the data plane reads the agent here rather than asking the actor
    // for it, so exec and the file verbs never queue behind a lifecycle verb.
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    assert!(harness.snapshot.borrow().agent.is_some());

    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    harness.joined().await;
    assert!(harness.snapshot.borrow().agent.is_none());
}

#[tokio::test(start_paused = true)]
async fn the_idle_window_is_the_actors_own_timer() {
    let mut harness = Harness::start(
        Boot::Completes,
        Deadlines {
            ttl: None,
            idle_timeout_seconds: 30,
            on_idle: IdleAction::Kill,
        },
    )
    .await;
    harness.boot_to_ready().await;

    // Nothing to do but wait: the actor's own `Sleep` fires the policy.
    harness.joined().await;
    assert_eq!(harness.script.calls(), vec!["boot", "gate", "release"]);
    assert!(harness.actions().contains(&"removed".to_owned()));
}

#[tokio::test(start_paused = true)]
async fn a_failure_keeps_its_crash_journal_when_the_release_fails() {
    // The journal names exactly the resources a restart would have to
    // reclaim, so it may only go once the release that frees them has
    // *finished* — `fail_live_sandbox` gates on the write being confirmed
    // AND the cleanup completing, and so must this.
    let mut harness = Harness::journalled(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    assert!(harness.has_journal());
    harness.script.release_fails.store(true, Ordering::SeqCst);

    harness.commands.send(Command::VmExited).unwrap();
    harness.settled(SandboxState::Failed).await;
    harness.awaited("release").await;
    tokio::task::yield_now().await;
    assert!(
        harness.has_journal(),
        "a failed release must leave the journal naming what it could not free"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failure_drops_its_crash_journal_once_the_release_is_done() {
    let mut harness = Harness::journalled(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    assert!(harness.has_journal());

    harness.commands.send(Command::VmExited).unwrap();
    harness.settled(SandboxState::Failed).await;
    while harness.has_journal() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_removal_whose_release_fails_answers_its_caller() {
    // `removing` coalesces the failure, so nothing else ever will — and
    // `remove_sandbox_impl` hands the release error straight back today.
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness.script.release_fails.store(true, Ordering::SeqCst);

    let error = harness
        .send(|reply| Command::Remove { force: true, reply })
        .error()
        .await;
    assert!(
        error.to_string().contains("the vmm would not die"),
        "{error}"
    );

    // And the retry re-drives a teardown that stopped rather than coalescing
    // onto it: `removing` swallows the event, so nothing else would answer.
    harness.script.release_fails.store(false, Ordering::SeqCst);
    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    harness.joined().await;
    assert!(harness.actions().contains(&"removed".to_owned()));
}

#[tokio::test(start_paused = true)]
async fn a_panicked_sub_task_is_reported_rather_than_swallowed() {
    // `cancel_and_join_boot` maps a join that is not a cancellation onto an
    // error that fails the removal; treating it as a clean join would hide
    // both the panic and whatever the task never transferred.
    let harness = Harness::start(Boot::HandsOffThenPanics, no_deadlines()).await;
    harness.send(|reply| Command::Provision {
        provision: Provision::Boot { warm: false },
        outcome: SandboxProvisionOutcome::default(),
        reply,
    });
    let error = harness
        .send(|reply| Command::Remove { force: true, reply })
        .error()
        .await;
    assert!(error.to_string().contains("panicked"), "{error}");
    // The teardown stopped where `remove_sandbox_impl` stops — no release —
    // so the record and its crash journal survive for the startup sweep.
    assert!(!harness.script.calls().contains(&"release"));

    // ...and the retry, whose join is clean, finishes it.
    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    assert!(harness.script.calls().contains(&"release"));
}

#[tokio::test(start_paused = true)]
async fn a_boot_that_never_handed_off_is_joined_so_its_own_cleanup_finishes() {
    // The middle arm of `cancel_and_join_boot`: a producer that ended
    // without declaring abort safety is tearing down what it never handed
    // over — the prepared VMM, a CoW handle — and aborting it there strands
    // exactly those.
    let harness = Harness::start(Boot::DropsHandoffThenCleansUp, no_deadlines()).await;
    harness.send(|reply| Command::Provision {
        provision: Provision::Boot { warm: false },
        outcome: SandboxProvisionOutcome::default(),
        reply,
    });
    // Let the actor observe the dropped signal before the teardown asks.
    harness.awaited("boot").await;
    tokio::task::yield_now().await;

    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    assert!(
        harness.script.cleanup_finished.load(Ordering::SeqCst),
        "the boot's own cleanup was cut short"
    );
}

#[tokio::test(start_paused = true)]
async fn a_restore_is_joined_rather_than_aborted() {
    // A restore keeps its lease and CoW handle in locals until it commits,
    // and unwinds them itself; aborting mid-flight would drop that unwind
    // with the resources still allocated, and the release that follows only
    // takes what the computer already owns.
    let harness = Harness::start(Boot::Completes, no_deadlines()).await;
    *harness.script.restore_takes.lock().unwrap() = Some(Duration::from_secs(3));
    harness.send(|reply| Command::Provision {
        provision: Provision::Restore {
            origin: RestoreOrigin::Restore,
        },
        outcome: SandboxProvisionOutcome::default(),
        reply,
    });
    tokio::task::yield_now().await;

    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    assert!(
        harness.script.restore_finished.load(Ordering::SeqCst),
        "the restore was aborted instead of joined"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stop_during_the_gates_own_cmd_is_still_deferred() {
    // The gate reads `Running` once the boot's own cmd has the slot, but its
    // launch is still in flight: keyed on the projection, the stop would be
    // refused instead of served when the gate lands.
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    *harness.script.gate_takes.lock().unwrap() = Some(Duration::from_secs(5));
    harness
        .send(|reply| Command::Provision {
            provision: Provision::Boot { warm: false },
            outcome: SandboxProvisionOutcome::default(),
            reply,
        })
        .ok()
        .await;
    harness.awaited("gate").await;

    // The boot's own cmd takes the slot the gate reserved: the computer now
    // reads `Running` with its launch still in flight.
    harness
        .send(|reply| Command::ClaimWorkload {
            claim: crate::sandbox::workload::WorkloadClaim::Initial,
            reply,
        })
        .ok()
        .await;
    harness.settled(SandboxState::Running).await;
    let stopped = harness.send(|reply| Command::Stop {
        budget: Duration::from_secs(30),
        reply,
    });
    stopped.ok().await;
    assert!(harness.script.calls().contains(&"stop"));
}

#[tokio::test(start_paused = true)]
async fn a_claim_the_machine_refuses_is_answered_wrong_state() {
    // `Handled` with no effects is the machine saying it has nothing to do;
    // what the caller is then told is the actor's decision.
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness
        .send(|reply| Command::ClaimWorkload {
            claim: crate::sandbox::workload::WorkloadClaim::Api,
            reply,
        })
        .ok()
        .await;

    let error = harness
        .send(|reply| Command::ClaimWorkload {
            claim: crate::sandbox::workload::WorkloadClaim::Api,
            reply,
        })
        .error()
        .await;
    assert!(matches!(error, VmmError::WrongState { .. }), "{error}");

    // ...and a non-forced remove is refused for the same reason.
    let error = harness
        .send(|reply| Command::Remove {
            force: false,
            reply,
        })
        .error()
        .await;
    assert!(matches!(error, VmmError::WrongState { .. }), "{error}");
}
