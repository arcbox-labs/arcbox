//! The lifecycle actor: sole owner of the statig machine.
//!
//! One actor task per [`super::VmLifecycleManager`]. Commands arrive on an
//! `mpsc` channel, boot/stop sub-tasks report completions on a second channel,
//! and the public state is published through a `watch` channel — so read paths
//! never contend with a boot in flight, and `ForceStop` preempts by aborting
//! the in-flight sub-task instead of racing a lock (the role the old
//! `transition_lock` bypass played).
//!
//! The actor never blocks: slow I/O (machine create/start, agent probing,
//! graceful stop) runs in spawned sub-tasks (see `boot.rs`) whose completions
//! come back as [`InternalEvent`]s. Every dispatch drains the machine's
//! [`Effect`]s and executes them here.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use statig::blocking::IntoStateMachineExt;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::boot_assets::BootAssetProvider;
use crate::error::{CoreError, Result};
use crate::event::{Event, EventBus};
use crate::machine::MachineManager;

use super::balloon;
use super::balloon::controller::{
    BalloonCommand, BalloonController, BalloonDeps, PressureWatch, WatchFrame,
};
use super::machine::{Effect, Effects, Notify, VmEvent, VmLifecycle};
use super::{
    BALLOON_SHRINK_DELAY_SECS, HealthMonitor, RecoveryPolicy, VmLifecycleConfig, VmLifecycleState,
};

/// A command sent from the facade to the lifecycle actor.
pub(super) enum Command {
    /// Ensure the VM is ready; reply with the agent CID.
    EnsureReady {
        /// Startup budget for a boot this command may initiate.
        timeout: Duration,
        /// Resolved with the CID once the agent is ready.
        reply: oneshot::Sender<Result<u32>>,
    },
    /// Gracefully stop the VM; reply when the stop completes.
    Shutdown {
        /// Resolved when the VM reached `Stopped` (or the stop failed).
        reply: oneshot::Sender<Result<()>>,
    },
    /// Force-terminate the VM, preempting any in-flight boot or stop.
    ForceStop {
        /// Resolved once the machine record is removed.
        reply: oneshot::Sender<Result<()>>,
    },
    /// Activity signal (a proxied Docker request, a Kubernetes hold):
    /// exit `Idle` if applicable.
    Activity,
}

/// A completion reported by a boot/stop sub-task.
pub(super) enum InternalEvent {
    /// The boot sub-task finished: the guest agent is ready.
    AgentReady,
    /// The boot sub-task failed terminally (retries exhausted or timeout).
    BootFailed(String),
    /// The stop sub-task finished: the machine stopped.
    Stopped,
    /// The stop sub-task failed.
    StopFailed(String),
}

/// An [`InternalEvent`] tagged with the epoch of the sub-task that sent it.
///
/// `JoinHandle::abort` is best-effort: a sub-task that already completed and
/// enqueued its outcome is unaffected, so after a `ForceStop` + reboot a stale
/// completion from the superseded task can still be sitting in the channel.
/// The actor bumps its epoch on every spawn/abort and drops completions whose
/// epoch doesn't match the live sub-task, so a stale `AgentReady`/`Stopped`
/// can neither clobber the new task's `inflight` handle nor drive the machine.
pub(super) struct Completion {
    /// Epoch of the sub-task that produced this outcome.
    pub(super) epoch: u64,
    /// The outcome itself.
    pub(super) outcome: InternalEvent,
}

/// State shared between the facade, the actor, and boot/stop sub-tasks.
///
/// Everything here is either immutable after construction or atomic, so the
/// facade can serve synchronous reads (`backend()`, `restart_generation()`)
/// without a round-trip through the actor.
pub(super) struct LifecycleShared {
    /// Machine name this lifecycle operates on.
    pub(super) machine_name: String,
    /// Filename of the persistent dockerd data image under `<data_dir>/data/`.
    pub(super) data_image_filename: String,
    /// Data directory.
    pub(super) data_dir: std::path::PathBuf,
    /// Machine manager for VM operations.
    pub(super) machine_manager: Arc<MachineManager>,
    /// Event bus for lifecycle notifications.
    pub(super) event_bus: EventBus,
    /// Boot asset provider.
    pub(super) boot_assets: Arc<BootAssetProvider>,
    /// Recovery policy (retry counter persists across boot attempts).
    pub(super) recovery: RecoveryPolicy,
    /// Health monitor.
    pub(super) health_monitor: Arc<HealthMonitor>,
    /// Configuration.
    pub(super) config: VmLifecycleConfig,
    /// Live hypervisor backend, encoded as `VmBackend as u8`. Seeded from the
    /// persisted machine; updated by `set_backend` for the next (re)boot.
    pub(super) backend: std::sync::atomic::AtomicU8,
    /// VM incarnation counter, bumped on every stop (see `restart_generation`).
    pub(super) restart_generation: std::sync::atomic::AtomicU64,
    /// Timestamp of last activity (epoch millis, for idle detection).
    pub(super) last_activity_ms: std::sync::atomic::AtomicU64,
    /// Live host-side operations (proxied Docker requests in flight). The
    /// idle gate never fires while this is non-zero — a VM serving a pull
    /// or build is not idle no matter how old the last activity stamp is.
    pub(super) active_ops: std::sync::atomic::AtomicUsize,
    /// Whether Kubernetes holds the VM in the active state.
    pub(super) kubernetes_hold: std::sync::atomic::AtomicBool,
}

impl LifecycleShared {
    /// Records activity, updating the last-activity timestamp.
    pub(super) fn record_activity(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_activity_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Returns seconds since last activity.
    fn idle_seconds(&self) -> u64 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last = self.last_activity_ms.load(Ordering::Relaxed);
        now_ms.saturating_sub(last) / 1000
    }

    /// Returns the System VM's current hypervisor backend.
    pub(super) fn backend(&self) -> arcbox_vmm::VmBackend {
        // Encoded as `VmBackend as u8` (Hv = 0, Vz = 1).
        match self.backend.load(Ordering::Acquire) {
            0 => arcbox_vmm::VmBackend::Hv,
            _ => arcbox_vmm::VmBackend::Vz,
        }
    }

    /// Gets the agent CID for this lifecycle's machine.
    fn get_cid(&self) -> Result<u32> {
        self.machine_manager
            .get_cid(&self.machine_name)
            .ok_or_else(|| CoreError::Machine("default machine has no CID".to_string()))
    }
}

/// Production [`BalloonDeps`]: agent RPCs for guest stats and the pressure
/// watch, the VM manager for balloon targets.
pub(super) struct RealBalloonDeps {
    pub(super) shared: Arc<LifecycleShared>,
}

impl RealBalloonDeps {
    fn connect_agent(&self) -> Result<crate::agent_client::AgentClient> {
        self.shared
            .machine_manager
            .connect_agent(&self.shared.machine_name)
    }
}

impl BalloonDeps for RealBalloonDeps {
    type Watch = AgentPressureWatch;

    fn full_memory_bytes(&self) -> Option<u64> {
        self.shared
            .machine_manager
            .get(&self.shared.machine_name)
            .map(|info| info.memory_mb * 1024 * 1024)
    }

    fn set_balloon_target(&self, bytes: u64) -> Result<()> {
        let info = self
            .shared
            .machine_manager
            .get(&self.shared.machine_name)
            .ok_or_else(|| CoreError::Machine("machine record missing".to_string()))?;
        self.shared
            .machine_manager
            .vm_manager()
            .set_balloon_target(&info.vm_id, bytes)
    }

    /// Any failure (connect, RPC, timeout) folds to `None`: the policy treats
    /// "unknown" as its own signal — never shrink on it, and fail open while
    /// shrunk, since a reclaim-thrashing guest is exactly one that cannot
    /// answer.
    async fn guest_stats(&self, budget: Duration) -> Option<balloon::GuestStats> {
        let mut agent = self.connect_agent().ok()?;
        let query = async move {
            let info = if agent.is_blocking() {
                tokio::task::spawn_blocking(move || agent.get_system_info_blocking())
                    .await
                    .ok()?
                    .ok()?
            } else {
                agent.get_system_info().await.ok()?
            };
            Some(balloon::GuestStats {
                total: info.total_memory,
                available: info.available_memory,
                loadavg1: info.load_average.first().copied().unwrap_or(0.0),
            })
        };
        tokio::time::timeout(budget, query).await.ok().flatten()
    }

    async fn open_pressure_watch(&self) -> Result<AgentPressureWatch> {
        use super::balloon::controller::{
            PRESSURE_MAX_REFAULT_RATE, PRESSURE_MIN_AVAILABLE, WATCH_KEEPALIVE, WATCH_WINDOW,
        };

        let mut agent = self.connect_agent()?;
        agent
            .watch_memory_pressure(arcbox_protocol::agent::WatchMemoryPressureRequest {
                timeout_ms: u32::try_from(WATCH_WINDOW.as_millis()).unwrap_or(u32::MAX),
                min_available_bytes: PRESSURE_MIN_AVAILABLE,
                max_refault_rate: PRESSURE_MAX_REFAULT_RATE,
                keepalive_ms: u32::try_from(WATCH_KEEPALIVE.as_millis()).unwrap_or(u32::MAX),
            })
            .await?;
        let mut watch = AgentPressureWatch { agent };
        // The agent acks with an immediate frame; anything else (an error
        // frame from an old agent, silence) means "unsupported" and the
        // controller degrades to stats polling.
        watch.next_frame(Duration::from_secs(5)).await?;
        Ok(watch)
    }
}

/// [`PressureWatch`] over the agent's `WatchMemoryPressure` event stream.
pub(super) struct AgentPressureWatch {
    agent: crate::agent_client::AgentClient,
}

impl PressureWatch for AgentPressureWatch {
    async fn next_frame(&mut self, max_wait: Duration) -> Result<WatchFrame> {
        use arcbox_protocol::agent::memory_pressure_event::Reason;

        let event = self.agent.next_memory_pressure_event(max_wait).await?;
        Ok(match event.reason() {
            Reason::Keepalive => WatchFrame::Keepalive,
            Reason::LowAvailable | Reason::RefaultSpike => WatchFrame::Pressure,
            Reason::Settled => WatchFrame::Settled,
            Reason::WindowElapsed => WatchFrame::WindowElapsed,
        })
    }
}

/// The lifecycle actor: owns the statig machine and executes its effects.
pub(super) struct LifecycleActor {
    shared: Arc<LifecycleShared>,
    /// Commands from the facade.
    commands: mpsc::UnboundedReceiver<Command>,
    /// Completions from boot/stop sub-tasks.
    events_rx: mpsc::UnboundedReceiver<Completion>,
    /// Cloned into every spawned sub-task so it can report back.
    events_tx: mpsc::UnboundedSender<Completion>,
    /// Publishes the public state after every dispatch.
    state_tx: watch::Sender<VmLifecycleState>,
    /// Effect sink passed to every dispatch as the statig context.
    effects: Effects,
    /// Parked `ensure_ready` callers, resolved on agent-ready or boot failure.
    waiters: Vec<oneshot::Sender<Result<u32>>>,
    /// Parked `shutdown` callers, resolved when the stop completes.
    stop_waiters: Vec<oneshot::Sender<Result<()>>>,
    /// Startup budget for a boot deferred until the current stop finishes.
    pending_timeout: Option<Duration>,
    /// A graceful stop requested while a boot was in flight, dispatched as
    /// soon as the boot resolves (the actor-model equivalent of the old
    /// `transition_lock` making `shutdown` wait for the boot).
    pending_stop: bool,
    /// The in-flight boot or stop sub-task, aborted on `ForceStop`.
    inflight: Option<JoinHandle<()>>,
    /// Epoch of the live sub-task; bumped on every spawn and abort so stale
    /// completions from superseded tasks are recognized and dropped.
    epoch: u64,
    /// The detached machine-removal task of a force stop, joined by the
    /// force-stop reply so callers still observe "removed" on return.
    removal: Option<JoinHandle<()>>,
    /// Command sender back into this actor, cloned into the balloon
    /// controller's activity callback so pressure exits ride the state
    /// machine like any other activity.
    cmd_tx: mpsc::UnboundedSender<Command>,
    /// Drives the balloon controller (EnterIdle / ExitIdle).
    balloon_tx: mpsc::UnboundedSender<BalloonCommand>,
    /// Controller receiver, consumed when `run` spawns the controller.
    balloon_seed: Option<mpsc::UnboundedReceiver<BalloonCommand>>,
}

impl LifecycleActor {
    /// Creates the actor half of a lifecycle channel pair.
    pub(super) fn new(
        shared: Arc<LifecycleShared>,
        commands: mpsc::UnboundedReceiver<Command>,
        cmd_tx: mpsc::UnboundedSender<Command>,
        state_tx: watch::Sender<VmLifecycleState>,
    ) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (balloon_tx, balloon_rx) = mpsc::unbounded_channel();
        Self {
            shared,
            commands,
            events_rx,
            events_tx,
            state_tx,
            effects: Effects::default(),
            waiters: Vec::new(),
            stop_waiters: Vec::new(),
            pending_timeout: None,
            pending_stop: false,
            inflight: None,
            epoch: 0,
            removal: None,
            cmd_tx,
            balloon_tx,
            balloon_seed: Some(balloon_rx),
        }
    }

    /// Runs the actor until the facade (all command senders) is dropped.
    pub(super) async fn run(mut self) {
        let mut machine = VmLifecycle
            .uninitialized_state_machine()
            .init_with_context(&mut self.effects);

        // The balloon controller lives exactly as long as the actor: its
        // command channel closes when the actor drops `balloon_tx`.
        if let Some(balloon_rx) = self.balloon_seed.take() {
            let deps = RealBalloonDeps {
                shared: Arc::clone(&self.shared),
            };
            let shared = Arc::clone(&self.shared);
            let cmd_tx = self.cmd_tx.clone();
            let activity = Arc::new(move || {
                shared.record_activity();
                let _ = cmd_tx.send(Command::Activity);
            });
            drop(tokio::spawn(
                BalloonController::new(balloon_rx, deps, activity).run(),
            ));
        }

        let mut idle_ticker = tokio::time::interval(Duration::from_secs(BALLOON_SHRINK_DELAY_SECS));
        idle_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Poll for a guest-initiated stop (PSCI SYSTEM_RESET) so a guest reboot
        // becomes an in-place VMM reboot. Coarse interval: reboot isn't
        // latency-critical and an idle daemon shouldn't wake often.
        const VM_LIVENESS_POLL_SECS: u64 = 2;
        let mut liveness_ticker = tokio::time::interval(Duration::from_secs(VM_LIVENESS_POLL_SECS));
        liveness_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            // Split-borrow the receivers away from `self` so the dispatch
            // helpers can borrow `self` mutably inside the match arms.
            tokio::select! {
                cmd = self.commands.recv() => {
                    let Some(cmd) = cmd else { break };
                    self.on_command(&mut machine, cmd);
                }
                Some(ev) = self.events_rx.recv() => {
                    self.on_internal(&mut machine, ev);
                }
                _ = idle_ticker.tick() => {
                    self.on_idle_tick(&mut machine);
                }
                _ = liveness_ticker.tick() => {
                    self.on_liveness_tick(&mut machine);
                }
            }
        }

        // Facade dropped: tear down any in-flight sub-task.
        if let Some(handle) = self.inflight.take() {
            handle.abort();
        }
    }

    /// Current public state.
    fn public(&self) -> VmLifecycleState {
        *self.state_tx.borrow()
    }

    /// Dispatches one event to the machine, publishes the new public state,
    /// and executes the effects the transition emitted.
    ///
    /// Synchronous by design: the machine is a pure decision core (its
    /// handlers never await), so dispatch uses statig's blocking engine —
    /// which also sidesteps the rustc higher-ranked `Send` inference
    /// limitation (rust#100013) the async engine runs into.
    fn dispatch(&mut self, machine: &mut Machine, event: VmEvent) {
        let before = machine.state().to_public();
        machine.handle_with_context(&event, &mut self.effects);
        let after = machine.state().to_public();

        if before != after {
            tracing::info!(
                machine = %self.shared.machine_name,
                from = before.as_str(),
                to = after.as_str(),
                "VM lifecycle transition"
            );
            self.state_tx.send_replace(after);

            // Balloon control derives from the Idle transitions themselves,
            // so every path out of idle (activity, stop, reboot, force-stop)
            // restores memory without each transition having to say so.
            if after == VmLifecycleState::Idle {
                let _ = self.balloon_tx.send(BalloonCommand::EnterIdle);
            } else if before == VmLifecycleState::Idle {
                let _ = self.balloon_tx.send(BalloonCommand::ExitIdle);
            }
        }

        for effect in self.effects.take() {
            self.apply(effect);
        }
    }

    /// Executes one effect emitted by a transition.
    fn apply(&mut self, effect: Effect) {
        match effect {
            Effect::SpawnBoot { create, timeout_ms } => {
                let epoch = self.abort_inflight();
                let shared = Arc::clone(&self.shared);
                let events = self.events_tx.clone();
                let timeout = Duration::from_millis(timeout_ms);
                self.inflight = Some(tokio::spawn(async move {
                    shared.run_boot(create, timeout, epoch, &events).await;
                }));
            }
            Effect::SpawnStop => {
                let epoch = self.abort_inflight();
                let shared = Arc::clone(&self.shared);
                let events = self.events_tx.clone();
                self.inflight = Some(tokio::spawn(async move {
                    shared.run_stop(epoch, &events).await;
                }));
            }
            Effect::SpawnReboot { timeout_ms } => {
                let epoch = self.abort_inflight();
                let shared = Arc::clone(&self.shared);
                let events = self.events_tx.clone();
                let timeout = Duration::from_millis(timeout_ms);
                self.inflight = Some(tokio::spawn(async move {
                    shared.run_reboot(timeout, epoch, &events).await;
                }));
            }
            Effect::AbortInflight => {
                self.abort_inflight();
            }
            Effect::RemoveMachine => {
                // `remove(force = true)` tears the VM down synchronously (a
                // hypervisor stop that can block for seconds); keep it off the
                // actor so the command loop stays responsive. The force-stop
                // reply joins `removal`, preserving the caller-visible
                // "returned ⇒ removed" contract.
                let shared = Arc::clone(&self.shared);
                self.removal = Some(tokio::task::spawn_blocking(move || {
                    let _ = shared.machine_manager.remove(&shared.machine_name, true);
                }));
            }
            Effect::BumpGeneration => {
                self.shared
                    .restart_generation
                    .fetch_add(1, Ordering::Release);
            }
            Effect::Publish(notify) => {
                let name = self.shared.machine_name.clone();
                self.shared.event_bus.publish(match notify {
                    Notify::Started => Event::MachineStarted { name },
                    Notify::Idle => Event::MachineIdle { name },
                    Notify::Stopped => Event::MachineStopped { name },
                });
            }
            Effect::ReadyWaiters => {
                for waiter in self.waiters.drain(..) {
                    let _ = waiter.send(self.shared.get_cid());
                }
            }
            Effect::FailWaiters(reason) => {
                for waiter in self.waiters.drain(..) {
                    let _ = waiter.send(Err(CoreError::Vm(reason.clone())));
                }
            }
        }
    }

    fn on_command(&mut self, machine: &mut Machine, cmd: Command) {
        match cmd {
            Command::EnsureReady { timeout, reply } => {
                self.on_ensure_ready(machine, timeout, reply);
            }
            Command::Shutdown { reply } => self.on_shutdown(machine, reply),
            Command::ForceStop { reply } => {
                // Match the old force_stop ordering: silence health checks
                // before tearing the machine down.
                self.shared.health_monitor.stop();
                self.dispatch(machine, VmEvent::ForceStop);
                // A graceful stop preempted mid-flight has reached its goal:
                // the VM is down.
                for waiter in self.stop_waiters.drain(..) {
                    let _ = waiter.send(Ok(()));
                }
                self.pending_timeout = None;
                self.pending_stop = false;
                // Reply once the detached removal finishes, so callers keep
                // the old "force_stop returned ⇒ machine removed" contract
                // without the removal blocking the actor.
                let removal = self.removal.take();
                drop(tokio::spawn(async move {
                    if let Some(handle) = removal {
                        let _ = handle.await;
                    }
                    let _ = reply.send(Ok(()));
                }));
            }
            Command::Activity => {
                self.dispatch(machine, VmEvent::Activity);
            }
        }
    }

    fn on_ensure_ready(
        &mut self,
        machine: &mut Machine,
        timeout: Duration,
        reply: oneshot::Sender<Result<u32>>,
    ) {
        self.shared.record_activity();
        let state = self.public();

        if state.is_ready() {
            // Exit idle (restoring the balloon) and answer immediately.
            self.dispatch(machine, VmEvent::Activity);
            let _ = reply.send(self.shared.get_cid());
            return;
        }

        self.waiters.push(reply);

        if state.needs_start() && self.inflight.is_none() {
            let create = self.decide_create(state);
            self.dispatch(
                machine,
                VmEvent::Start {
                    create,
                    timeout_ms: timeout.as_millis() as u64,
                },
            );
        } else {
            // Booting or stopping: park. A boot in flight resolves the waiter;
            // a stop in flight defers the boot until `Stopped` lands.
            self.pending_timeout.get_or_insert(timeout);
        }
    }

    fn on_shutdown(&mut self, machine: &mut Machine, reply: oneshot::Sender<Result<()>>) {
        let state = self.public();

        match state {
            VmLifecycleState::Stopping => {
                // A stop is already in flight; resolve when it lands.
                self.stop_waiters.push(reply);
            }
            VmLifecycleState::Creating | VmLifecycleState::Starting => {
                // A boot is in flight: stop right after it lands — the old
                // implementation reached the same outcome by making `shutdown`
                // wait on `transition_lock` until the boot finished. If the
                // boot fails instead, there is nothing to stop and the waiter
                // resolves Ok.
                self.stop_waiters.push(reply);
                self.pending_stop = true;
            }
            state if state.is_ready() => {
                self.stop_waiters.push(reply);
                self.dispatch(machine, VmEvent::Stop);
            }
            _ => {
                // Not running: nothing to do.
                let _ = reply.send(Ok(()));
            }
        }
    }

    /// Aborts the in-flight sub-task (if any) and bumps the epoch so any
    /// completion it already enqueued is recognized as stale. Returns the new
    /// epoch for the next sub-task to tag its completion with.
    fn abort_inflight(&mut self) -> u64 {
        if let Some(handle) = self.inflight.take() {
            handle.abort();
        }
        self.epoch += 1;
        self.epoch
    }

    fn on_internal(&mut self, machine: &mut Machine, completion: Completion) {
        if completion.epoch != self.epoch {
            // Completion from a superseded sub-task (aborted after it had
            // already finished): the machine has moved on; ignore it.
            tracing::debug!(
                machine = %self.shared.machine_name,
                stale_epoch = completion.epoch,
                current_epoch = self.epoch,
                "dropping stale lifecycle sub-task completion"
            );
            return;
        }
        self.inflight = None;
        match completion.outcome {
            InternalEvent::AgentReady => {
                self.dispatch(machine, VmEvent::AgentReady);
                // Serve a shutdown that arrived mid-boot now that the boot
                // (and its waiters) have resolved.
                if std::mem::take(&mut self.pending_stop) {
                    self.dispatch(machine, VmEvent::Stop);
                }
            }
            InternalEvent::BootFailed(reason) => {
                self.dispatch(machine, VmEvent::Failure);
                for waiter in self.waiters.drain(..) {
                    let _ = waiter.send(Err(CoreError::Vm(reason.clone())));
                }
                // A shutdown parked behind this boot has nothing left to stop.
                if std::mem::take(&mut self.pending_stop) {
                    for waiter in self.stop_waiters.drain(..) {
                        let _ = waiter.send(Ok(()));
                    }
                }
            }
            InternalEvent::Stopped => {
                self.dispatch(machine, VmEvent::Stopped);
                for waiter in self.stop_waiters.drain(..) {
                    let _ = waiter.send(Ok(()));
                }
            }
            InternalEvent::StopFailed(reason) => {
                self.dispatch(machine, VmEvent::Failure);
                for waiter in self.stop_waiters.drain(..) {
                    let _ = waiter.send(Err(CoreError::Vm(reason.clone())));
                }
            }
        }
        self.start_if_pending(machine);
    }

    /// Boots the VM for callers that parked while a stop (or failed stop) was
    /// in flight — the actor-model equivalent of the old `transition_lock`
    /// serialization, where a parked `ensure_ready` proceeded to boot as soon
    /// as the shutdown released the lock.
    fn start_if_pending(&mut self, machine: &mut Machine) {
        let state = self.public();
        if self.waiters.is_empty() || !state.needs_start() || self.inflight.is_some() {
            return;
        }
        let timeout = self
            .pending_timeout
            .take()
            .unwrap_or(self.shared.config.startup_timeout);
        let create = self.decide_create(state);
        self.dispatch(
            machine,
            VmEvent::Start {
                create,
                timeout_ms: timeout.as_millis() as u64,
            },
        );
    }

    fn on_idle_tick(&mut self, machine: &mut Machine) {
        if !self.shared.config.auto_stop
            || self.shared.kubernetes_hold.load(Ordering::Relaxed)
            || self.shared.active_ops.load(Ordering::Acquire) > 0
            || self.public() != VmLifecycleState::Running
        {
            return;
        }
        if self.shared.idle_seconds() >= self.shared.config.idle_timeout.as_secs() {
            tracing::info!(
                "VM entered idle state after {}s of inactivity",
                self.shared.idle_seconds()
            );
            self.dispatch(machine, VmEvent::IdleTimeout);
        }
    }

    /// Detects a guest-initiated VM stop and, when it was a PSCI SYSTEM_RESET,
    /// reboots the VM in place. Only meaningful while we believe the VM is up;
    /// a guest halt/crash (`Some(false)`) is left as-is for now.
    fn on_liveness_tick(&mut self, machine: &mut Machine) {
        if !matches!(
            self.public(),
            VmLifecycleState::Running | VmLifecycleState::Idle
        ) {
            return;
        }
        if self
            .shared
            .machine_manager
            .vm_self_stopped(&self.shared.machine_name)
            == Some(true)
        {
            tracing::info!("guest requested reboot (SYSTEM_RESET); rebooting VM in place");
            let timeout_ms =
                u64::try_from(self.shared.config.startup_timeout.as_millis()).unwrap_or(u64::MAX);
            self.dispatch(machine, VmEvent::GuestReset { timeout_ms });
        }
    }

    /// Whether a boot from `state` must (re)create the machine first: only
    /// when no machine record exists.
    ///
    /// The lifecycle state deliberately plays no part: the machine re-enters
    /// at `NotExist` on every daemon start, while the registry may well hold
    /// the persisted machine — which must be started, not recreated
    /// (`MachineManager::create` rejects duplicate names). Config drift
    /// against the resolved boot assets is re-checked inside the boot
    /// sub-task, where resolving assets (a potential download) cannot block
    /// the actor.
    fn decide_create(&self, state: VmLifecycleState) -> bool {
        let exists = self
            .shared
            .machine_manager
            .get(&self.shared.machine_name)
            .is_some();
        if !exists && state != VmLifecycleState::NotExist {
            tracing::warn!(
                state = state.as_str(),
                "machine record missing while lifecycle state indicates existing VM; recreating"
            );
        }
        !exists
    }
}

/// The initialized statig machine driven by the actor.
type Machine = statig::blocking::InitializedStateMachine<VmLifecycle>;
