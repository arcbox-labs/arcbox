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
        id: &SandboxId,
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

#[cfg(test)]
mod tests {
    use super::super::testing::{fake_manager_direct, plant_computer};
    use super::*;

    #[tokio::test]
    async fn set_lifecycle_rearms_ttl_from_now_and_replaces_idle_knobs() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) = fake_manager_direct(dir.path()).await;
        let manager = manager.into_shared();
        plant_computer(&manager, "box", SandboxState::Ready).await;

        let before = Utc::now();
        manager
            .set_sandbox_lifecycle(
                &"box".to_owned(),
                LifecycleUpdate {
                    ttl_seconds: Some(600),
                    idle_timeout_seconds: Some(30),
                    on_idle: Some(IdleAction::Pause),
                },
            )
            .await
            .unwrap();

        let info = manager.inspect_sandbox(&"box".to_owned()).unwrap();
        let deadline = info.ttl_deadline.expect("ttl deadline armed");
        assert!(deadline >= before + chrono::Duration::seconds(600));
        assert!(deadline <= Utc::now() + chrono::Duration::seconds(600));
        assert_eq!(info.idle_timeout_seconds, 30);
        assert_eq!(info.on_idle, IdleAction::Pause);

        // Absent fields are unchanged; ttl 0 removes the cap.
        manager
            .set_sandbox_lifecycle(
                &"box".to_owned(),
                LifecycleUpdate {
                    ttl_seconds: Some(0),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let info = manager.inspect_sandbox(&"box".to_owned()).unwrap();
        assert_eq!(info.ttl_deadline, None);
        assert_eq!(info.idle_timeout_seconds, 30);
        assert_eq!(info.on_idle, IdleAction::Pause);
    }

    #[tokio::test]
    async fn set_lifecycle_rejects_terminal_states_and_missing_ids() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) = fake_manager_direct(dir.path()).await;
        let manager = manager.into_shared();
        assert!(matches!(
            manager
                .set_sandbox_lifecycle(&"ghost".to_owned(), LifecycleUpdate::default())
                .await,
            Err(VmmError::NotFound(_))
        ));

        for state in [SandboxState::Stopped, SandboxState::Failed] {
            let id = format!("terminal-{state}");
            plant_computer(&manager, &id, state).await;
            assert!(
                matches!(
                    manager
                        .set_sandbox_lifecycle(&id, LifecycleUpdate::default())
                        .await,
                    Err(VmmError::WrongState { .. })
                ),
                "{state} must refuse a lifecycle update"
            );
        }

        // Paused computers accept updates: the TTL keeps applying to them.
        plant_computer(&manager, "asleep", SandboxState::Paused).await;
        manager
            .set_sandbox_lifecycle(
                &"asleep".to_owned(),
                LifecycleUpdate {
                    ttl_seconds: Some(120),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    /// The idle window opens on READY and the `Kill` policy destroys the
    /// computer when it elapses.
    ///
    /// The timer itself lives in the actor's select loop — `lifecycle::tests`
    /// covers its arming and cancelling — so what this pins is the wiring
    /// from `SetLifecycle` through to a computer that is really gone.
    #[tokio::test(start_paused = true)]
    async fn an_idle_computer_is_removed_when_its_policy_says_kill() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) = fake_manager_direct(dir.path()).await;
        let manager = manager.into_shared();
        std::fs::create_dir_all(dir.path().join("sandboxes/box")).unwrap();
        plant_computer(&manager, "box", SandboxState::Ready).await;
        manager
            .set_sandbox_lifecycle(
                &"box".to_owned(),
                LifecycleUpdate {
                    idle_timeout_seconds: Some(2),
                    on_idle: Some(IdleAction::Kill),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(3)).await;
        for _ in 0..100 {
            if manager.inspect_sandbox(&"box".to_owned()).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(matches!(
            manager.inspect_sandbox(&"box".to_owned()),
            Err(VmmError::NotFound(_))
        ));
    }

    /// The `Pause` policy never removes: an idle expiry it cannot serve —
    /// here, a direct-mode computer that could not resume — leaves it alone.
    #[tokio::test(start_paused = true)]
    async fn an_idle_computer_under_the_pause_policy_is_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, _driver, _probe) = fake_manager_direct(dir.path()).await;
        let manager = manager.into_shared();
        plant_computer(&manager, "box", SandboxState::Ready).await;
        manager
            .set_sandbox_lifecycle(
                &"box".to_owned(),
                LifecycleUpdate {
                    idle_timeout_seconds: Some(2),
                    on_idle: Some(IdleAction::Pause),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert!(
            manager.inspect_sandbox(&"box".to_owned()).is_ok(),
            "the PAUSE policy must never remove the computer"
        );
    }
}
