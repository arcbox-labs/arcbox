//! The computer lifecycle: the decision core the per-computer actor will
//! drive (vm-stack-redesign R3).
//!
//! `machine` is a `statig` hierarchical state machine. Its handlers are pure
//! transition logic: they take an [`Event`] and emit [`Effect`]s into the
//! externally-owned [`Effects`] context, never touching a driver, a record
//! store, the network or a task. All I/O belongs to the actor (R3 PR-F), which
//! owns that buffer, reads it after every `handle_with_context`, and applies
//! the effects — so the machine holds no `Arc`s, channels or timers and the
//! whole table is testable with nothing but a scratch buffer. Same library and
//! same discipline as `arcbox-engine`'s `vm_lifecycle::machine`.
//!
//! ```text
//! computer                              Remove / TtlExpired / Failure, anywhere
//!  ├─ provisioning, staging             Provision → staging → booting|restoring
//!  ├─ launching ─ booting, restoring    AgentReady | Restored → gating
//!  ├─ gating                            Gated → ready (READY withheld until here)
//!  ├─ active ──── ready, running,       Stop → stopping; Pause → capturing
//!  │              checkpointing
//!  ├─ suspending ─ capturing, releasing CaptureDone → releasing → paused
//!  ├─ paused, resuming                  Resume → resuming; Restored → ready
//!  ├─ stopping                          StopDone → stopped
//!  ├─ resting ─── stopped, failed       terminal, still removable
//!  ├─ removing                          RemoveDone → gone
//!  └─ gone                              the record is forgotten
//! ```
//!
//! `Handled` with no effects means the machine has nothing to do; whether the
//! caller then gets `Ok` (an idempotent `Pause` of a paused computer) or
//! `WrongState` (a non-forced `Remove` of a busy one) is the actor's reply, as
//! `sandbox::cleanup::begin_removal` decides it today. The attributes today's
//! events carry (`reason` on PAUSING, `error` on FAILED, `exit_code` on IDLE)
//! likewise stay actor-side: [`Notify`] is 1:1 with `sandbox::types::action`
//! and the actor holds the context.
//!
//! `projection` answers the two questions the rest of the system asks about
//! a state — what a caller sees, and what a crash-restart reads back.
//!
//! Nothing consumes any of it yet: the machine lands with its transition table
//! pinned by tests so the flows can move onto an already-specified machine one
//! file at a time, rather than being rewritten and re-specified at once.
//!
//! [`Event`]: event::Event
//! [`Effect`]: effect::Effect
//! [`Effects`]: effect::Effects
//! [`Notify`]: effect::Notify

// R3 PR-F moves the flows onto this machine one file at a time; a machine
// specified only once it has a caller cannot be the specification those moves
// are reviewed against.
#![allow(
    dead_code,
    reason = "R3 PR-E lands the HSM with its tests; PR-F wires the actor"
)]

mod effect;
mod event;
mod machine;
