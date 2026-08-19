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
use crate::lifecycle::actor::{
    Command, ComputerActor, ComputerSeed, ComputerSnapshot, Deadlines, Seeded, WorkloadOutcome,
};
use crate::lifecycle::effect::ReleaseScope;
use crate::lifecycle::event::{PauseReason, Provision, RestoreOrigin};
use crate::lifecycle::runtime::ComputerRuntime;
use crate::lifecycle::tasks::{CaptureSpec, ComputerTasks, Drain, TaskFailure, TaskResult};
use crate::sandbox::reconcile::{SandboxStateRecord, write_state_record};
use crate::sandbox::record::{SandboxProvisionOutcome, SandboxRecordStore};
use crate::sandbox::workload::WorkloadClaim;
use crate::sandbox::{
    CheckpointInfo, IdleAction, LifecycleUpdate, SandboxEvent, SandboxSpec, SandboxState,
};
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
    restore_fails: AtomicBool,
    checkpoint_takes: Mutex<Option<Duration>>,
    release_takes: Mutex<Option<Duration>>,
    /// How long the gate holds READY back, which is how a test observes a
    /// computer while its launch is still in flight.
    gate_takes: Mutex<Option<Duration>>,
    /// Whether a boot that never handed off got to finish its own teardown.
    cleanup_finished: AtomicBool,
    /// The handover the driver refuses: the computer must stay where it was.
    detach_fails: AtomicBool,
    /// How long the stop holds the computer in `stopping`, which is how a test
    /// observes something arriving while a teardown is in flight.
    stop_takes: Mutex<Option<Duration>>,
    /// How long the handover's port call takes, which is how a test observes
    /// the snapshot during the one await that transfers ownership.
    detach_takes: Mutex<Option<Duration>>,
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
            restore_fails: AtomicBool::new(false),
            checkpoint_takes: Mutex::new(None),
            release_takes: Mutex::new(None),
            gate_takes: Mutex::new(None),
            cleanup_finished: AtomicBool::new(false),
            detach_fails: AtomicBool::new(false),
            stop_takes: Mutex::new(None),
            detach_takes: Mutex::new(None),
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
        if self.restore_fails.load(Ordering::SeqCst) {
            return Err(TaskFailure::recoverable(VmmError::Process(
                "the checkpoint would not load".into(),
            )));
        }
        Ok((Arc::clone(&self.agent), SandboxProvisionOutcome::default()))
    }

    async fn checkpoint(
        &self,
        _hold: bool,
        _spec: Option<CaptureSpec>,
    ) -> TaskResult<CheckpointInfo> {
        self.record("checkpoint");
        let takes = *self.checkpoint_takes.lock().unwrap();
        if let Some(takes) = takes {
            tokio::time::sleep(takes).await;
        }
        Ok(CheckpointInfo {
            snapshot_id: "snap".to_owned(),
            snapshot_dir: String::new(),
            created_at: String::new(),
        })
    }

    async fn resume(&self) -> TaskResult<Arc<dyn GuestAgent>> {
        self.record("resume");
        Ok(Arc::clone(&self.agent))
    }

    async fn stop(&self, _budget: Duration, _drain: Drain) -> TaskResult {
        self.record("stop");
        let takes = *self.stop_takes.lock().unwrap();
        if let Some(takes) = takes {
            tokio::time::sleep(takes).await;
        }
        Ok(())
    }

    async fn detach(&self) -> TaskResult {
        self.record("detach");
        let takes = *self.detach_takes.lock().unwrap();
        if let Some(takes) = takes {
            tokio::time::sleep(takes).await;
        }
        if self.detach_fails.load(Ordering::SeqCst) {
            return Err(TaskFailure::recoverable(VmmError::Process(
                "the vmm would not be handed over".into(),
            )));
        }
        Ok(())
    }

    fn adopted_agent(&self) -> Option<Arc<dyn GuestAgent>> {
        Some(Arc::clone(&self.agent))
    }

    async fn release(&self, _scope: ReleaseScope) -> TaskResult {
        self.record("release");
        let takes = *self.release_takes.lock().unwrap();
        if let Some(takes) = takes {
            tokio::time::sleep(takes).await;
        }
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
    /// Whether the computer is still in its manager's registry.
    registered: Arc<AtomicBool>,
    runtime: crate::lifecycle::runtime::Runtime,
    snapshot: watch::Receiver<ComputerSnapshot>,
    events: broadcast::Receiver<SandboxEvent>,
    script: Arc<Script>,
    actor: tokio::task::JoinHandle<()>,
    _timers: watch::Sender<bool>,
    dir: tempfile::TempDir,
}

impl Harness {
    async fn start(boot: Boot, deadlines: Deadlines) -> Self {
        Self::started(boot, deadlines, false, false).await
    }

    /// A harness whose computer owns a durable record, so what the actor
    /// does when that record refuses to move is observable.
    async fn recorded(boot: Boot, deadlines: Deadlines) -> Self {
        Self::started(boot, deadlines, false, true).await
    }

    /// A harness whose computer has a crash journal on disk, so what the
    /// actor refuses to drop is observable.
    async fn journalled(boot: Boot, deadlines: Deadlines) -> Self {
        Self::started(boot, deadlines, true, false).await
    }

    async fn started(boot: Boot, deadlines: Deadlines, journal: bool, record: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = Script::new(boot, agent().await);
        let (events_tx, events) = broadcast::channel(64);
        let (commands, commands_rx) = mpsc::unbounded_channel();
        let runtime = Arc::new(Mutex::new(ComputerRuntime::new(
            "box".to_owned(),
            SandboxSpec::default(),
            None,
            dir.path().to_path_buf(),
        )));
        let (snapshot_tx, snapshot) = watch::channel(ComputerSnapshot::project(
            &runtime.lock().unwrap(),
            SandboxState::Starting,
            deadlines,
        ));
        let (timers, timers_enabled) = watch::channel(true);
        if journal {
            let config = VmmConfig::default();
            let record = SandboxStateRecord::new("box", None, None, None, &config, None).unwrap();
            write_state_record(dir.path(), &record).unwrap();
        }
        let records = Arc::new(SandboxRecordStore::new(dir.path()).unwrap());
        // No durable record by default: these tests exercise the actor, not
        // the store, so the record writes are no-ops. The crash journal is
        // not — it is a file beside them, and its ordering is the thing
        // under test above.
        let generation = record.then(|| {
            match records
                .provision_intent(
                    "box",
                    "key",
                    SandboxSpec {
                        id: Some("box".to_owned()),
                        ..SandboxSpec::default()
                    },
                )
                .unwrap()
            {
                crate::sandbox::record::ProvisionIntent::Created(record) => record.generation,
                other => panic!("unexpected intent: {other:?}"),
            }
        });
        let registered = Arc::new(AtomicBool::new(true));
        let unregister = Arc::clone(&registered);
        let seed = ComputerSeed {
            id: "box".to_owned(),
            runtime: Arc::clone(&runtime),
            unregister: Arc::new(move || unregister.store(false, Ordering::SeqCst)),
            generation,
            vm_dir: dir.path().to_path_buf(),
            records,
            events_tx,
            tasks: Arc::clone(&script) as Arc<dyn ComputerTasks>,
            deadlines,
            timers_enabled,
            seeded: Seeded::Fresh,
        };
        let actor = tokio::spawn(ComputerActor::new(seed, commands_rx, snapshot_tx).run());
        Self {
            commands,
            registered,
            runtime,
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
            .wait_for(|snapshot| snapshot.state == state)
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

    /// The next event carrying `action`.
    async fn next_event(&mut self, action: &str) -> SandboxEvent {
        loop {
            let event = self.events.recv().await.expect("the event bus stays open");
            if event.action == action {
                return event;
            }
        }
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

/// A restore that fails is unwound by a force remove, and its caller must not
/// hear until that removal has finished.
///
/// The caller's next move is a cold boot **under the same id** — that is the
/// warm-create fallback — and until the record is forgotten and the registry
/// entry dropped, the id is still claimed. `rollback_restore` awaited the
/// whole teardown before handing its error back for exactly this reason; the
/// `sandbox` e2e's doomed-probe template create is what finds it when it
/// does not.
#[tokio::test(start_paused = true)]
async fn a_failed_restore_answers_only_once_its_teardown_has_freed_the_id() {
    let harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.script.restore_fails.store(true, Ordering::SeqCst);

    let restoring = harness.send(|reply| Command::Provision {
        provision: Provision::Restore {
            origin: RestoreOrigin::WarmCreate,
        },
        outcome: SandboxProvisionOutcome::default(),
        reply,
    });

    let error = restoring.error().await;
    assert!(
        error.to_string().contains("checkpoint would not load"),
        "the caller hears the restore's own failure: {error}"
    );
    // Answered *after* the release, which is what frees the id.
    assert_eq!(
        harness.script.calls(),
        vec!["restore", "release"],
        "the teardown ran before the caller was told"
    );
}

/// A paused computer records what it retained where its readers look.
///
/// `Inspect` and `List` size the checkpoint and the disk overlay from the
/// runtime, and a resume finds its checkpoint there — `pause_sandbox` wrote
/// both at the `Paused` commit, and nothing else does.
#[tokio::test(start_paused = true)]
async fn a_paused_computer_records_what_it_retained() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;

    let paused = harness.send(|reply| Command::Pause {
        reason: PauseReason::Requested,
        reply,
    });
    paused.ok().await;

    {
        let runtime = harness.runtime.lock().unwrap();
        assert_eq!(runtime.pause_snapshot_id.as_deref(), Some("snap"));
        assert!(
            runtime.paused_at.is_some(),
            "a paused computer reports when it went to sleep"
        );
    }
    // And on the read view *by the time the caller is answered*: `Inspect`
    // is the very next thing a client does, and the effects that write those
    // fields run after the transition published the snapshot.
    let snapshot = harness.snapshot.borrow();
    assert_eq!(snapshot.state, SandboxState::Paused);
    assert_eq!(snapshot.pause_snapshot_id.as_deref(), Some("snap"));
    assert!(snapshot.paused_at.is_some());
}

/// An idle pause reports itself as one.
///
/// The PAUSING event's `reason` is how a client tells the idle detector's
/// pause from a client's own, and only the expiry knows which this is —
/// `apply_idle_policy` passed `reason::IDLE_TIMEOUT` explicitly.
#[tokio::test(start_paused = true)]
async fn an_idle_pause_says_so_on_its_event() {
    let mut harness = Harness::start(
        Boot::Completes,
        Deadlines {
            ttl: None,
            idle_timeout_seconds: 2,
            on_idle: IdleAction::Pause,
        },
    )
    .await;
    harness.boot_to_ready().await;

    let pausing = harness
        .next_event(crate::sandbox::types::action::PAUSING)
        .await;
    assert_eq!(
        pausing.attributes.get("reason").map(String::as_str),
        Some(crate::sandbox::pause_reason::IDLE_TIMEOUT)
    );
}

/// A record that will not delete stalls the teardown instead of reporting it
/// done.
///
/// `remove_sandbox_impl` propagates a failed `finish_remove` *before* it drops
/// its map entry: the record still owns the id, and only a retry that re-runs
/// the deletion can free it. Unregistering and announcing REMOVED anyway
/// would leave that id un-creatable — `cancel_pending_or_missing` refuses
/// anything past `Creating` — until the next startup sweep.
#[tokio::test(start_paused = true)]
async fn a_record_that_will_not_move_stalls_the_teardown() {
    let mut harness = Harness::recorded(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;

    // A directory where the record file goes: every read of it fails, so
    // neither the `Removing` write nor the deletion can complete.
    let record_path = harness.dir.path().join("sandbox-records").join("box.json");
    let record = std::fs::read(&record_path).unwrap();
    std::fs::remove_file(&record_path).unwrap();
    std::fs::create_dir(&record_path).unwrap();

    let refused = harness
        .send(|reply| Command::Remove { force: true, reply })
        .error()
        .await;
    assert!(
        refused.to_string().contains("recording removing failed"),
        "the caller hears the write that was refused: {refused}"
    );
    assert!(
        harness.registered.load(Ordering::SeqCst),
        "the computer stays where a retry can reach it"
    );
    assert!(
        !harness
            .actions()
            .contains(&crate::sandbox::types::action::REMOVED.to_owned()),
        "nothing announces a removal that did not happen"
    );

    // Let the record through again; a retried removal finishes it, `Removing`
    // write and all.
    std::fs::remove_dir(&record_path).unwrap();
    std::fs::write(&record_path, record).unwrap();
    harness
        .send(|reply| Command::Remove { force: true, reply })
        .ok()
        .await;
    assert!(!harness.registered.load(Ordering::SeqCst));
    harness.joined().await;
}

/// A removal parked on a record that will not delete is not answered `Ok`
/// just because the machine reached `gone`.
///
/// The record — and with it the id — is exactly what the parked step is still
/// trying to release, so a second `Remove` waits for the retry rather than
/// being told the computer is gone.
#[tokio::test(start_paused = true)]
async fn a_removal_parked_on_its_record_is_not_answered_done() {
    let mut harness = Harness::recorded(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;

    let record_path = harness.dir.path().join("sandbox-records").join("box.json");
    // A slow release holds the teardown open between the `Removing` write and
    // the deletion, which is the window this needs: only the deletion is
    // refused.
    *harness.script.release_takes.lock().unwrap() = Some(Duration::from_secs(1));
    let removing = harness.send(|reply| Command::Remove { force: true, reply });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let record = std::fs::read(&record_path).unwrap();
    std::fs::remove_file(&record_path).unwrap();
    std::fs::create_dir(&record_path).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let second = harness.send(|reply| Command::Remove { force: true, reply });
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        harness.registered.load(Ordering::SeqCst),
        "the id is still owned by a record that would not delete"
    );

    std::fs::remove_dir(&record_path).unwrap();
    std::fs::write(&record_path, record).unwrap();
    tokio::time::sleep(Duration::from_secs(10)).await;
    removing.ok().await;
    second.ok().await;
    assert!(!harness.registered.load(Ordering::SeqCst));
}

/// A `Stop` (or a `Remove`) during a user checkpoint answers the checkpoint.
///
/// The stop supersedes the capture task, and the epoch then drops whatever it
/// would have reported — so without this its caller waits on a reply nobody
/// will send. A stop that succeeds leaves the actor alive, so not even its
/// exit answers.
#[tokio::test(start_paused = true)]
async fn a_preempted_checkpoint_answers_its_caller() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    *harness.script.checkpoint_takes.lock().unwrap() = Some(Duration::from_secs(30));

    let (reply, capture) = oneshot::channel();
    harness
        .commands
        .send(Command::Checkpoint {
            spec: CaptureSpec {
                name: "snap".to_owned(),
                labels: std::collections::HashMap::new(),
            },
            reply,
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    harness
        .send(|reply| Command::Stop {
            budget: Duration::from_secs(1),
            reply,
        })
        .ok()
        .await;

    let answered = tokio::time::timeout(Duration::from_secs(5), capture)
        .await
        .expect("the preempted checkpoint answers rather than hanging")
        .unwrap();
    let error = match answered {
        Ok(_) => panic!("a preempted checkpoint cannot report a snapshot"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("preempted"), "{error}");
}

/// A stop whose workload exits between the transition and the drain's first
/// poll does not wait the whole budget out.
///
/// The marker is read with the `Running -> Stopping` transition, so an exit
/// recorded before the task runs is already the change the drain is waiting
/// for. Sampling it inside the task compares against the exit that already
/// happened.
#[tokio::test(start_paused = true)]
async fn a_stop_drains_against_the_marker_its_transition_saw() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness
        .send(|reply| Command::ClaimWorkload {
            claim: WorkloadClaim::Api,
            reply,
        })
        .ok()
        .await;

    // The stop is ordered while the workload is running; its exit lands in
    // the same breath.
    let stopping = harness.send(|reply| Command::Stop {
        budget: Duration::from_secs(1),
        reply,
    });
    harness
        .commands
        .send(Command::WorkloadExited {
            outcome: WorkloadOutcome::Exited(crate::agent::ExitStatus::Code(0)),
        })
        .unwrap();

    stopping.ok().await;
    assert_eq!(harness.script.calls().last().copied(), Some("stop"));
}

/// Two concurrent partial `SetLifecycle` calls compose.
///
/// `None` means unchanged, and resolving the patch outside the actor made
/// that a lie: both callers would read the same policy, send a whole one, and
/// the second would restore what the first had just changed.
#[tokio::test(start_paused = true)]
async fn concurrent_partial_lifecycle_updates_compose() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;

    let ttl_only = harness.send(|reply| Command::SetLifecycle {
        update: LifecycleUpdate {
            ttl_seconds: Some(600),
            ..LifecycleUpdate::default()
        },
        reply,
    });
    let idle_only = harness.send(|reply| Command::SetLifecycle {
        update: LifecycleUpdate {
            idle_timeout_seconds: Some(30),
            ..LifecycleUpdate::default()
        },
        reply,
    });
    ttl_only.ok().await;
    idle_only.ok().await;

    let deadlines = harness.snapshot.borrow().deadlines;
    assert!(deadlines.ttl.is_some(), "the TTL-only update survived");
    assert_eq!(deadlines.idle_timeout_seconds, 30);
}

/// A required durable write that is refused abandons the rest of its
/// transition.
///
/// The `Resuming` write records that a resume is under way; the effects after
/// it *are* that resume. Letting them run against a record that never moved
/// leaves a live VM whose machine has already gone back to `Paused`, and a
/// caller parked on an answer nothing will send.
#[tokio::test(start_paused = true)]
async fn a_refused_resume_write_abandons_the_resume_it_was_recording() {
    let mut harness = Harness::recorded(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness
        .send(|reply| Command::Pause {
            reason: PauseReason::Requested,
            reply,
        })
        .ok()
        .await;

    // A directory where the record goes: the `Resuming` write is refused.
    let record_path = harness.dir.path().join("sandbox-records").join("box.json");
    std::fs::remove_file(&record_path).unwrap();
    std::fs::create_dir(&record_path).unwrap();

    let error = harness
        .send(|reply| Command::Resume {
            reason: "resume".to_owned(),
            reply,
        })
        .error()
        .await;
    assert!(error.to_string().contains("recording"), "{error}");
    assert!(
        !harness.script.calls().contains(&"resume"),
        "the resume the write was recording must not have run"
    );
}

/// A refused `Failed` write does not stop the release it records.
///
/// The other refusals abandon the rest of their transition, because the
/// effects after them are the work the write was recording. `Failed` is the
/// opposite: it records where the computer *ended up*, and
/// `persist_boot_failure` reports the refusal and lets the release run —
/// keeping the crash journal, which is what a restart would reclaim from.
#[tokio::test(start_paused = true)]
async fn a_refused_failure_write_still_releases_and_keeps_the_journal() {
    let mut harness = Harness::recorded(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    let journal =
        SandboxStateRecord::new("box", None, None, None, &VmmConfig::default(), None).unwrap();
    write_state_record(harness.dir.path(), &journal).unwrap();

    let record_path = harness.dir.path().join("sandbox-records").join("box.json");
    std::fs::remove_file(&record_path).unwrap();
    std::fs::create_dir(&record_path).unwrap();

    harness.commands.send(Command::VmExited).unwrap();
    harness.settled(SandboxState::Failed).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(
        harness.script.calls().contains(&"release"),
        "the release runs even though the failure was not recorded"
    );
    assert!(
        harness.has_journal(),
        "and the journal stays: nothing proved the failure durable"
    );
}

/// A handover ordered while a stop is in flight is refused (CORE-145).
///
/// This is the race the ticket is about: an in-flight `StopSandbox` is the
/// main reason a composer's drain budget expires, so the trigger for
/// `detach_all` and the concurrent writer it would race are the same event.
/// The stop wins because it was asked for first — the guest is meant to go
/// away — and the actor is what makes that a decision rather than a race.
#[tokio::test(start_paused = true)]
async fn a_handover_ordered_during_a_stop_is_refused() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    *harness.script.stop_takes.lock().unwrap() = Some(Duration::from_secs(30));

    let stopping = harness.send(|reply| Command::Stop {
        budget: Duration::from_secs(60),
        reply,
    });
    harness.settled(SandboxState::Stopping).await;

    let error = harness
        .send(|reply| Command::Detach { reply })
        .error()
        .await;
    assert!(
        matches!(error, VmmError::WrongState { .. }),
        "a handover during a teardown must be refused, not raced: {error}"
    );
    assert!(
        !harness.script.calls().contains(&"detach"),
        "the port was reached anyway: {:?}",
        harness.script.calls()
    );

    // And the stop it stood aside for still finishes.
    tokio::time::sleep(Duration::from_secs(31)).await;
    stopping.ok().await;
}

/// Nothing reaches a VM this process has handed over.
///
/// Without the terminal state a stop landing here would drive
/// `handle.shutdown` into a handle whose reaper has stood down, wait out the
/// whole budget for an exit that is never published, and then SIGKILL the VM
/// the successor is adopting.
#[tokio::test(start_paused = true)]
async fn a_teardown_after_a_handover_never_reaches_the_vm() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness.send(|reply| Command::Detach { reply }).ok().await;
    assert!(harness.script.calls().contains(&"detach"));

    let stop = harness
        .send(|reply| Command::Stop {
            budget: Duration::from_secs(1),
            reply,
        })
        .error()
        .await;
    assert!(
        matches!(stop, VmmError::WrongState { .. }),
        "a stop after a handover must be refused: {stop}"
    );
    let removed = harness
        .send(|reply| Command::Remove { force: true, reply })
        .error()
        .await;
    assert!(
        matches!(removed, VmmError::WrongState { .. }),
        "a forced remove after a handover must be refused: {removed}"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let calls = harness.script.calls();
    assert!(
        !calls.contains(&"stop") && !calls.contains(&"release"),
        "a handed-over vm was torn down anyway: {calls:?}"
    );
    // A second handover is a no-op rather than an error: `detach_all` fans out
    // over whatever is in the map, and reporting a failure for a computer that
    // is already the successor's would have a composer log a loss it did not
    // take.
    harness.send(|reply| Command::Detach { reply }).ok().await;
}

/// A handover the driver refuses leaves a computer that is still ours.
///
/// It dies with this process, which is what a failed handover has always
/// meant — but it must not be recorded `Failed` on the way out, because the
/// successor's sweep reads that record and would reinstate a perfectly good
/// guest as failed instead of adopting it.
#[tokio::test(start_paused = true)]
async fn a_refused_handover_leaves_the_computer_usable() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness.script.detach_fails.store(true, Ordering::SeqCst);

    let error = harness
        .send(|reply| Command::Detach { reply })
        .error()
        .await;
    assert!(
        error.to_string().contains("would not be handed over"),
        "{error}"
    );
    assert_eq!(
        harness.snapshot.borrow().state,
        SandboxState::Ready,
        "a refused handover moved the computer"
    );
    // Usable includes dialable. The agent comes off the snapshot before the
    // port call, so a handover that then fails has to put it back — nothing
    // changed hands, and the data plane must not lose a guest to a handover
    // that did not happen.
    assert!(
        harness.snapshot.borrow().agent.is_some(),
        "a refused handover left the computer undialable"
    );

    // Still this process's to stop, and the stop still runs.
    harness
        .send(|reply| Command::Stop {
            budget: Duration::from_secs(1),
            reply,
        })
        .ok()
        .await;
    assert!(harness.script.calls().contains(&"stop"));
}

/// A handover drops the guest agent, so the data plane stops reaching a VM
/// this process no longer owns.
///
/// The exec and file verbs read the agent straight off the snapshot and never
/// round-trip the mailbox — that is the whole point of the seam — so the
/// terminal state alone cannot stop them. `detached` projects `Ready`, which
/// is exactly what `require_alive_agent` admits, so without this an exec would
/// keep landing in a guest the successor had adopted. A stop and a release
/// forget the agent for the same reason.
#[tokio::test(start_paused = true)]
async fn a_handover_takes_the_guest_agent_off_the_snapshot() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    assert!(
        harness.snapshot.borrow().agent.is_some(),
        "a ready computer is dialable"
    );

    harness.send(|reply| Command::Detach { reply }).ok().await;
    assert!(
        harness.snapshot.borrow().agent.is_none(),
        "the data plane can still reach a handed-over guest"
    );
}

/// A handed-over computer refuses `SetLifecycle`.
///
/// It projects `Ready`, so the public-state gate lets it through, and what it
/// would reach is not a timer but the record: `persist_lifecycle` fsyncs into
/// the record the successor has already adopted, under the generation it
/// adopted with — so the write is accepted rather than fenced. The same race
/// this transition exists to close, moved from the guest to its record.
#[tokio::test(start_paused = true)]
async fn a_handed_over_computer_refuses_a_lifecycle_update() {
    let mut harness = Harness::recorded(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness.send(|reply| Command::Detach { reply }).ok().await;

    let error = harness
        .send(|reply| Command::SetLifecycle {
            update: LifecycleUpdate {
                ttl_seconds: Some(60),
                ..LifecycleUpdate::default()
            },
            reply,
        })
        .error()
        .await;
    assert!(
        matches!(error, VmmError::WrongState { .. }),
        "a handed-over record was written: {error}"
    );
}

/// A handover ordered while a capture is in flight is refused.
///
/// The capture sub-task cloned the handle before it started and the driver's
/// detach only stands the reaper down, so accepting would leave this process
/// freezing, snapshotting and resuming a guest the successor had adopted.
#[tokio::test(start_paused = true)]
async fn a_handover_during_a_capture_is_refused() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    *harness.script.checkpoint_takes.lock().unwrap() = Some(Duration::from_secs(30));

    let (reply, capture) = oneshot::channel();
    harness
        .commands
        .send(Command::Checkpoint {
            spec: CaptureSpec {
                name: "snap".to_owned(),
                labels: std::collections::HashMap::new(),
            },
            reply,
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let error = harness
        .send(|reply| Command::Detach { reply })
        .error()
        .await;
    assert!(
        matches!(error, VmmError::WrongState { .. }),
        "a handover during a capture must be refused: {error}"
    );
    assert!(
        !harness.script.calls().contains(&"detach"),
        "the port was reached while a capture held the handle: {:?}",
        harness.script.calls()
    );

    // The capture it stood aside for still owns the guest and still answers.
    tokio::time::sleep(Duration::from_secs(31)).await;
    capture.await.unwrap().unwrap();
}

/// The agent comes off the snapshot *before* the port call, not after.
///
/// Detach is the one flow whose ownership transfer happens inside an await, so
/// forgetting afterwards leaves the whole call open for a reader to take the
/// agent out of the snapshot and dial a VM that has already changed hands. It
/// does not close the race — a reader holding an `Arc` cloned a moment earlier
/// still has a working agent, and revoking that would mean routing the data
/// plane through the mailbox — but it bounds the exposure to callers already
/// in flight rather than every caller for the duration of the handover.
#[tokio::test(start_paused = true)]
async fn the_agent_is_gone_before_the_handover_reaches_the_driver() {
    let mut harness = Harness::start(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    *harness.script.detach_takes.lock().unwrap() = Some(Duration::from_secs(30));

    let detaching = harness.send(|reply| Command::Detach { reply });
    // Far enough in for the effect to have reached the port call and parked
    // there, and nowhere near its completion.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        harness.script.calls().last().copied(),
        Some("detach"),
        "the port call has not started yet"
    );
    assert!(
        harness.snapshot.borrow().agent.is_none(),
        "the data plane could still dial a vm that is changing hands"
    );

    tokio::time::sleep(Duration::from_secs(30)).await;
    detaching.ok().await;
}

/// A handed-over computer answers nothing but another handover.
///
/// The per-command version of this guard only ever covered the command whose
/// bug was noticed. `detached` projects `Ready` — the wire has no variant for
/// "the successor's" — so every gate reading the public state is blind to it:
/// `Resume` read `Ready`, matched its live-computer arm, and answered `Ok` for
/// a computer this process no longer owned. This walks the reply-bearing
/// surface so a command added later cannot quietly inherit that.
#[tokio::test(start_paused = true)]
async fn a_handed_over_computer_answers_nothing_but_another_handover() {
    async fn refused(waiter: Waiter, verb: &str) {
        let error = waiter.error().await;
        assert!(
            matches!(error, VmmError::WrongState { .. }),
            "{verb} was accepted by a handed-over computer: {error}"
        );
    }

    let mut harness = Harness::recorded(Boot::Completes, no_deadlines()).await;
    harness.boot_to_ready().await;
    harness.send(|reply| Command::Detach { reply }).ok().await;

    refused(
        harness.send(|reply| Command::Resume {
            reason: "test".to_owned(),
            reply,
        }),
        "resume",
    )
    .await;
    refused(
        harness.send(|reply| Command::Pause {
            reason: PauseReason::Requested,
            reply,
        }),
        "pause",
    )
    .await;
    refused(
        harness.send(|reply| Command::ClaimWorkload {
            claim: WorkloadClaim::Api,
            reply,
        }),
        "claim",
    )
    .await;
    refused(
        harness.send(|reply| Command::SetLifecycle {
            update: LifecycleUpdate {
                ttl_seconds: Some(60),
                ..LifecycleUpdate::default()
            },
            reply,
        }),
        "set-lifecycle",
    )
    .await;
    refused(
        harness.send(|reply| Command::Stop {
            budget: Duration::from_secs(1),
            reply,
        }),
        "stop",
    )
    .await;
    refused(
        harness.send(|reply| Command::Remove { force: true, reply }),
        "remove",
    )
    .await;

    // The capture surface too, which carries its own reply type.
    let (reply, capture) = oneshot::channel();
    harness
        .commands
        .send(Command::Checkpoint {
            spec: CaptureSpec {
                name: "snap".to_owned(),
                labels: std::collections::HashMap::new(),
            },
            reply,
        })
        .unwrap();
    assert!(matches!(
        capture.await.unwrap().unwrap_err(),
        VmmError::WrongState { .. }
    ));

    // Nothing reached the guest, and a second handover is still the idempotent
    // no-op `detach_all` needs it to be.
    let calls = harness.script.calls();
    assert!(
        !calls.contains(&"stop") && !calls.contains(&"release") && !calls.contains(&"checkpoint"),
        "a handed-over vm was driven anyway: {calls:?}"
    );
    harness.send(|reply| Command::Detach { reply }).ok().await;
}
