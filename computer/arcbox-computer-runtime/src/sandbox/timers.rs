//! Lifecycle deadlines: the hard TTL cap and idle detection (CORE-21/60).
//!
//! Two independent knobs, never conflated:
//!
//! - **TTL** (`ttl_deadline`) caps total lifetime regardless of activity and
//!   always destroys — pausing does not apply, and a paused computer still
//!   expires. `SetLifecycle` replaces the deadline from *now*.
//! - **Idle** (`idle_timeout_seconds` + `on_idle`) reacts to inactivity: the
//!   window is armed on every `Ready` edge (boot ready, workload exit,
//!   resume) and cancelled when a workload starts. Idle means "no running
//!   workload" — file activity does NOT re-arm.
//!
//! Both live in the computer's actor: they are two `Sleep`s in its select
//! loop, armed and cancelled by the same transitions that publish. What is
//! left here is the verb that replaces them, because it also has a durable
//! record to write — the timers are in memory, so the record is the only
//! thing a restart can re-arm them from.
//!
//! The apparatus this module used to hold — epoch-stamped timer slots, a
//! `Weak` back to the instance a detached expiry task was armed for, a
//! monitor driving all of it off the event stream, and a lag resync — existed
//! only to answer "is this detached task still talking about the current
//! generation?". A per-computer actor *is* the generation.

use super::*;

impl SandboxManager {
    /// Replace a computer's lifecycle deadlines (CORE-60).
    ///
    /// `ttl_seconds` re-arms the hard cap from *now* (0 removes it);
    /// `idle_timeout_seconds` replaces the idle window, re-arming any live
    /// timer; `on_idle` replaces the policy. `None` fields are unchanged.
    /// Allowed in any non-terminal state — a paused computer keeps honoring
    /// its (re-armed) TTL, and new idle knobs apply on the next `Ready`.
    pub async fn set_sandbox_lifecycle(
        &self,
        id: &ComputerId,
        update: LifecycleUpdate,
    ) -> Result<()> {
        self.await_reconcile().await?;
        let computer = self.computer(id)?;
        // The patch goes to the actor, which resolves it against what the
        // computer currently has. Resolving it here would let two concurrent
        // partial updates each read the same policy and send a whole one, so
        // the second would undo the first's field — which `None` means
        // unchanged promises it does not.
        computer
            .mailbox
            .ask(id, |reply| Command::SetLifecycle { update, reply })
            .await?;
        let deadlines = computer.snapshot.borrow().deadlines;
        info!(
            sandbox_id = %id,
            ttl_deadline = ?deadlines.ttl,
            idle_timeout_seconds = deadlines.idle_timeout_seconds,
            on_idle = ?deadlines.on_idle,
            "sandbox lifecycle updated"
        );
        Ok(())
    }
}
