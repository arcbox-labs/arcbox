//! The VM lifecycle as a `statig` hierarchical state machine.
//!
//! This is the **decision core**: handlers are pure transition logic that emit
//! [`Effect`]s into the externally-owned [`Effects`] context. They never touch
//! the hypervisor, spawn tasks, or block — all I/O is performed by the lifecycle
//! actor (see `actor.rs`), which owns the `Effects` buffer, reads it after every
//! `handle_with_context`, and applies the effects. The machine therefore holds
//! no `Arc<MachineManager>`, channels, or timers, so the whole transition table
//! is testable with nothing but an `Effects` scratch buffer.
//!
//! ## State hierarchy
//!
//! ```text
//! managed                                 ForceStop / Failure (anywhere)
//!  ├─ booting ── creating, starting       AgentReady → running
//!  ├─ active  ── running, idle            Stop → stopping; IdleTimeout ⇄ Activity
//!  ├─ stopping                            Stopped → stopped
//!  └─ resting ── not_exist, created,      Start → creating | starting
//!                stopped, failed
//! ```
//!
//! `Stop` during `booting` is not a machine transition: the actor defers it
//! until the boot resolves (see `actor.rs`).

use statig::prelude::*;

use super::types::VmLifecycleState;

/// `statig` outcome specialized to this machine's state enum.
type Outcome = statig::Outcome<State>;

/// A lifecycle event fed to the state machine.
///
/// Every variant is produced by the actor (commands) or by a boot/stop
/// sub-task (completions); none is dead vocabulary.
#[derive(Debug, Clone)]
pub(super) enum VmEvent {
    /// `ensure_ready` on a VM that needs starting. `create` is precomputed by
    /// the actor (`decide_create`: missing machine record) and selects
    /// `creating` vs `starting`; config drift is re-checked in the boot task.
    Start {
        /// Whether the machine must be (re)created before starting.
        create: bool,
        /// Startup budget in milliseconds, forwarded to the boot sub-task.
        timeout_ms: u64,
    },
    /// Activity observed on an already-ready VM (new request, Kubernetes hold).
    /// Exits `idle`.
    Activity,
    /// Boot sub-task: the guest agent reported ready.
    AgentReady,
    /// Boot or stop sub-task: terminal failure. The reason string stays on the
    /// actor side (`InternalEvent`), which delivers it to waiting callers.
    Failure,
    /// Idle ticker fired and the idle threshold was exceeded.
    IdleTimeout,
    /// Graceful shutdown request.
    Stop,
    /// Stop sub-task: the machine stopped.
    Stopped,
    /// Force-stop request (preempts any in-flight boot/stop).
    ForceStop,
}

/// Balloon target requested by a transition; the actor applies it idempotently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BalloonTarget {
    /// Shrink to the idle reservation to return memory to the host.
    Idle,
    /// Restore to the VM's full configured memory.
    Full,
}

/// Lifecycle notification a transition asks the actor to publish on the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Notify {
    /// VM reached `running` (`Event::MachineStarted`).
    Started,
    /// VM entered `idle` (`Event::MachineIdle`).
    Idle,
    /// VM stopped or was force-stopped (`Event::MachineStopped`).
    Stopped,
}

/// A side effect emitted by a transition, executed by the lifecycle actor.
///
/// The machine only *describes* what should happen; the actor owns the
/// hypervisor handle, the task join handles, the waiter list, and the event
/// bus, and is the sole executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Effect {
    /// Spawn the boot sub-task. `create` ⇒ (re)create the machine first.
    SpawnBoot {
        /// Whether to create the machine before starting it.
        create: bool,
        /// Startup budget in milliseconds.
        timeout_ms: u64,
    },
    /// Spawn the graceful-stop sub-task.
    SpawnStop,
    /// Abort the in-flight boot/stop sub-task (force path).
    AbortInflight,
    /// Remove the machine record (force path).
    RemoveMachine,
    /// Apply a balloon target.
    Balloon(BalloonTarget),
    /// Bump the VM incarnation counter (the Docker proxy watches it to detect
    /// restarts and reset cached readiness + pooled connections).
    BumpGeneration,
    /// Publish a lifecycle notification on the event bus.
    Publish(Notify),
    /// Resolve all parked `ensure_ready` callers with the agent CID.
    ReadyWaiters,
    /// Fail all parked `ensure_ready` callers with this reason.
    FailWaiters(String),
}

/// External context: the effect sink a dispatch writes into.
///
/// Owned by the actor and passed by `&mut` to every `handle_with_context`, so
/// the actor reads back the transition's effects without needing mutable access
/// to the (zero-sized) state-machine storage.
#[derive(Debug, Default)]
pub(super) struct Effects {
    items: Vec<Effect>,
}

impl Effects {
    /// Records an effect for the actor to execute.
    fn emit(&mut self, effect: Effect) {
        self.items.push(effect);
    }

    /// Drains the effects accumulated since the last call.
    pub(super) fn take(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.items)
    }

    /// Shared `ForceStop` handling: tear everything down and fail any waiters.
    fn force_stop(&mut self) -> Outcome {
        self.emit(Effect::AbortInflight);
        self.emit(Effect::RemoveMachine);
        self.emit(Effect::BumpGeneration);
        self.emit(Effect::Publish(Notify::Stopped));
        self.emit(Effect::FailWaiters("force stopped".to_owned()));
        Transition(State::not_exist())
    }
}

/// Zero-sized `statig` shared storage. All durable lifecycle data lives in the
/// actor; transition outputs flow through the [`Effects`] context.
#[derive(Debug, Default)]
pub(super) struct VmLifecycle;

#[state_machine(
    initial = "State::not_exist()",
    state(derive(Debug, Clone, Copy, PartialEq, Eq)),
    superstate(derive(Debug))
)]
impl VmLifecycle {
    // ----- managed (root): ForceStop / Failure, anywhere -----

    #[superstate]
    fn managed(event: &VmEvent, context: &mut Effects) -> Outcome {
        match event {
            VmEvent::ForceStop => context.force_stop(),
            VmEvent::Failure => Transition(State::failed()),
            _ => Handled,
        }
    }

    // ----- resting leaves: Start kicks off a boot -----

    #[superstate(superstate = "managed")]
    fn resting(event: &VmEvent, context: &mut Effects) -> Outcome {
        match event {
            VmEvent::Start { create, timeout_ms } => {
                context.emit(Effect::SpawnBoot {
                    create: *create,
                    timeout_ms: *timeout_ms,
                });
                Transition(if *create {
                    State::creating()
                } else {
                    State::starting()
                })
            }
            _ => Super,
        }
    }

    #[state(superstate = "resting")]
    fn not_exist() -> Outcome {
        Super
    }

    #[state(superstate = "resting")]
    fn created() -> Outcome {
        Super
    }

    #[state(superstate = "resting")]
    fn stopped() -> Outcome {
        Super
    }

    #[state(superstate = "resting")]
    fn failed() -> Outcome {
        Super
    }

    // ----- booting leaves: AgentReady promotes to running -----

    #[superstate(superstate = "managed")]
    fn booting(event: &VmEvent, context: &mut Effects) -> Outcome {
        match event {
            VmEvent::AgentReady => {
                context.emit(Effect::Publish(Notify::Started));
                context.emit(Effect::ReadyWaiters);
                Transition(State::running())
            }
            _ => Super,
        }
    }

    // `Stop` during a boot is deliberately not a transition here: the actor
    // parks it (`pending_stop`) and dispatches it once the boot resolves,
    // mirroring how the old `transition_lock` serialized shutdown behind an
    // in-flight boot.
    #[state(superstate = "booting")]
    fn creating() -> Outcome {
        Super
    }

    #[state(superstate = "booting")]
    fn starting() -> Outcome {
        Super
    }

    // ----- active leaves: running / idle -----

    #[superstate(superstate = "managed")]
    fn active(event: &VmEvent, context: &mut Effects) -> Outcome {
        match event {
            VmEvent::Stop => {
                context.emit(Effect::SpawnStop);
                Transition(State::stopping())
            }
            _ => Super,
        }
    }

    #[state(superstate = "active")]
    fn running(event: &VmEvent, context: &mut Effects) -> Outcome {
        match event {
            VmEvent::IdleTimeout => {
                context.emit(Effect::Balloon(BalloonTarget::Idle));
                context.emit(Effect::Publish(Notify::Idle));
                Transition(State::idle())
            }
            // Already ready; the actor replies to the caller directly.
            VmEvent::Activity | VmEvent::Start { .. } => Handled,
            _ => Super,
        }
    }

    #[state(superstate = "active")]
    fn idle(event: &VmEvent, context: &mut Effects) -> Outcome {
        match event {
            VmEvent::Activity | VmEvent::Start { .. } => {
                context.emit(Effect::Balloon(BalloonTarget::Full));
                Transition(State::running())
            }
            _ => Super,
        }
    }

    // ----- stopping leaf -----

    #[state(superstate = "managed")]
    fn stopping(event: &VmEvent, context: &mut Effects) -> Outcome {
        match event {
            VmEvent::Stopped => {
                context.emit(Effect::BumpGeneration);
                context.emit(Effect::Publish(Notify::Stopped));
                Transition(State::stopped())
            }
            _ => Super,
        }
    }
}

impl State {
    /// Projects the internal `statig` state onto the public lifecycle enum.
    pub(super) fn to_public(self) -> VmLifecycleState {
        match self {
            Self::NotExist {} => VmLifecycleState::NotExist,
            Self::Creating {} => VmLifecycleState::Creating,
            Self::Created {} => VmLifecycleState::Created,
            Self::Starting {} => VmLifecycleState::Starting,
            Self::Running {} => VmLifecycleState::Running,
            Self::Idle {} => VmLifecycleState::Idle,
            Self::Stopping {} => VmLifecycleState::Stopping,
            Self::Stopped {} => VmLifecycleState::Stopped,
            Self::Failed {} => VmLifecycleState::Failed,
        }
    }
}

#[cfg(test)]
mod machine_tests {
    use super::*;

    type Machine = statig::blocking::InitializedStateMachine<VmLifecycle>;

    /// Builds an initialized machine starting from `not_exist`.
    fn machine(fx: &mut Effects) -> Machine {
        VmLifecycle
            .uninitialized_state_machine()
            .init_with_context(fx)
    }

    /// Dispatches `event`, returning the resulting public state and the effects
    /// the transition emitted.
    fn step(sm: &mut Machine, fx: &mut Effects, event: VmEvent) -> (VmLifecycleState, Vec<Effect>) {
        sm.handle_with_context(&event, fx);
        (sm.state().to_public(), fx.take())
    }

    const T: u64 = 90_000;

    fn start(create: bool) -> VmEvent {
        VmEvent::Start {
            create,
            timeout_ms: T,
        }
    }

    #[test]
    fn start_from_not_exist_creates_then_boots_to_running() {
        let mut fx = Effects::default();
        let mut sm = machine(&mut fx);
        assert_eq!(sm.state().to_public(), VmLifecycleState::NotExist);

        let (state, effects) = step(&mut sm, &mut fx, start(true));
        assert_eq!(state, VmLifecycleState::Creating);
        assert_eq!(
            effects,
            vec![Effect::SpawnBoot {
                create: true,
                timeout_ms: T
            }]
        );

        let (state, effects) = step(&mut sm, &mut fx, VmEvent::AgentReady);
        assert_eq!(state, VmLifecycleState::Running);
        assert_eq!(
            effects,
            vec![Effect::Publish(Notify::Started), Effect::ReadyWaiters]
        );
    }

    #[test]
    fn start_without_create_goes_straight_to_starting() {
        let mut fx = Effects::default();
        let mut sm = machine(&mut fx);
        let (state, effects) = step(&mut sm, &mut fx, start(false));
        assert_eq!(state, VmLifecycleState::Starting);
        assert_eq!(
            effects,
            vec![Effect::SpawnBoot {
                create: false,
                timeout_ms: T
            }]
        );
    }

    #[test]
    fn boot_failure_lands_in_failed() {
        let mut fx = Effects::default();
        let mut sm = machine(&mut fx);
        step(&mut sm, &mut fx, start(true));
        let (state, effects) = step(&mut sm, &mut fx, VmEvent::Failure);
        assert_eq!(state, VmLifecycleState::Failed);
        assert!(effects.is_empty());
    }

    #[test]
    fn idle_round_trip_shrinks_then_restores_balloon() {
        let mut fx = Effects::default();
        let mut sm = running_machine(&mut fx);

        let (state, effects) = step(&mut sm, &mut fx, VmEvent::IdleTimeout);
        assert_eq!(state, VmLifecycleState::Idle);
        assert_eq!(
            effects,
            vec![
                Effect::Balloon(BalloonTarget::Idle),
                Effect::Publish(Notify::Idle)
            ]
        );

        let (state, effects) = step(&mut sm, &mut fx, VmEvent::Activity);
        assert_eq!(state, VmLifecycleState::Running);
        assert_eq!(effects, vec![Effect::Balloon(BalloonTarget::Full)]);
    }

    #[test]
    fn activity_while_running_is_a_noop() {
        let mut fx = Effects::default();
        let mut sm = running_machine(&mut fx);
        let (state, effects) = step(&mut sm, &mut fx, VmEvent::Activity);
        assert_eq!(state, VmLifecycleState::Running);
        assert!(effects.is_empty());
    }

    #[test]
    fn stop_from_running_drains_through_stopping() {
        let mut fx = Effects::default();
        let mut sm = running_machine(&mut fx);

        let (state, effects) = step(&mut sm, &mut fx, VmEvent::Stop);
        assert_eq!(state, VmLifecycleState::Stopping);
        assert_eq!(effects, vec![Effect::SpawnStop]);

        let (state, effects) = step(&mut sm, &mut fx, VmEvent::Stopped);
        assert_eq!(state, VmLifecycleState::Stopped);
        assert_eq!(
            effects,
            vec![Effect::BumpGeneration, Effect::Publish(Notify::Stopped)]
        );
    }

    #[test]
    fn stop_while_booting_is_swallowed_for_actor_deferral() {
        // The actor parks a mid-boot Stop (`pending_stop`) instead of the
        // machine transitioning; the machine must treat it as handled noise.
        let mut fx = Effects::default();
        let mut sm = machine(&mut fx);
        step(&mut sm, &mut fx, start(false));
        let (state, effects) = step(&mut sm, &mut fx, VmEvent::Stop);
        assert_eq!(state, VmLifecycleState::Starting);
        assert!(effects.is_empty());
    }

    #[test]
    fn force_stop_preempts_from_every_phase() {
        for reach in [
            ReachState::Creating,
            ReachState::Running,
            ReachState::Idle,
            ReachState::Stopping,
        ] {
            let mut fx = Effects::default();
            let mut sm = machine(&mut fx);
            reach.drive(&mut sm, &mut fx);

            let (state, effects) = step(&mut sm, &mut fx, VmEvent::ForceStop);
            assert_eq!(
                state,
                VmLifecycleState::NotExist,
                "force stop from {reach:?} must reach NotExist"
            );
            assert_eq!(
                effects,
                vec![
                    Effect::AbortInflight,
                    Effect::RemoveMachine,
                    Effect::BumpGeneration,
                    Effect::Publish(Notify::Stopped),
                    Effect::FailWaiters("force stopped".to_owned()),
                ]
            );
        }
    }

    fn running_machine(fx: &mut Effects) -> Machine {
        let mut sm = machine(fx);
        sm.handle_with_context(&start(true), fx);
        sm.handle_with_context(&VmEvent::AgentReady, fx);
        fx.take();
        sm
    }

    #[derive(Debug, Clone, Copy)]
    enum ReachState {
        Creating,
        Running,
        Idle,
        Stopping,
    }

    impl ReachState {
        fn drive(self, sm: &mut Machine, fx: &mut Effects) {
            sm.handle_with_context(&start(true), fx);
            match self {
                Self::Creating => {}
                Self::Running => {
                    sm.handle_with_context(&VmEvent::AgentReady, fx);
                }
                Self::Idle => {
                    sm.handle_with_context(&VmEvent::AgentReady, fx);
                    sm.handle_with_context(&VmEvent::IdleTimeout, fx);
                }
                Self::Stopping => {
                    sm.handle_with_context(&VmEvent::AgentReady, fx);
                    sm.handle_with_context(&VmEvent::Stop, fx);
                }
            }
            fx.take();
        }
    }
}
