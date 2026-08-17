//! Lifecycle expiry timers: the hard TTL cap and idle detection (CORE-21/60).
//!
//! Two independent knobs, never conflated:
//!
//! - **TTL** (`ttl_deadline`) caps total lifetime regardless of activity and
//!   always destroys — pausing does not apply, and a paused sandbox still
//!   expires. `SetLifecycle` replaces the deadline from *now*.
//! - **Idle** (`spec.idle_timeout_seconds` + `spec.on_idle`) reacts to
//!   inactivity: the timer is armed on every `Ready` edge (boot ready,
//!   execution exit, resume) and cancelled when an execution starts. Idle
//!   means "no running execution" — file activity does NOT re-arm.
//!
//! The monitor task drives arming off the manager's own event stream, so the
//! transition sites (boot task, exit watchers, pause/resume) stay unaware of
//! timers. Every armed timer is epoch-stamped: re-arming or cancelling bumps
//! the slot epoch, and a woken task first *claims* its slot (removing it only
//! if the epoch still matches) so a stale timer can neither fire nor be
//! aborted mid-teardown.

use super::policy::deadlines;
use super::types::action;
use super::*;

/// Epoch-stamped timer registries for TTL and idle expiry.
#[derive(Default)]
pub(super) struct LifecycleTimers {
    ttl: TimerMap,
    idle: TimerMap,
}

#[derive(Default)]
struct TimerMap {
    slots: Mutex<HashMap<SandboxId, TimerSlot>>,
    next_epoch: std::sync::atomic::AtomicU64,
}

struct TimerSlot {
    epoch: u64,
    handle: tokio::task::JoinHandle<()>,
}

impl TimerMap {
    /// Replace the sandbox's timer: abort the old task (if any) and install
    /// the one produced by `spawn`, which receives the slot's epoch.
    fn arm(&self, id: &SandboxId, spawn: impl FnOnce(u64) -> tokio::task::JoinHandle<()>) {
        let epoch = self
            .next_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let handle = spawn(epoch);
        let mut slots = self.slots.lock().unwrap();
        if let Some(old) = slots.insert(id.clone(), TimerSlot { epoch, handle }) {
            old.handle.abort();
        }
    }

    /// Abort and drop the sandbox's timer, if one is armed.
    fn cancel(&self, id: &str) {
        let slot = self.slots.lock().unwrap().remove(id);
        if let Some(slot) = slot {
            slot.handle.abort();
        }
    }

    /// Claim the slot for a firing timer: remove it only when `epoch` still
    /// names the armed task. A `false` return means the timer was re-armed
    /// or cancelled while sleeping and must not act. After a successful
    /// claim the slot is gone, so a late `cancel` can no longer abort the
    /// task mid-action.
    fn try_claim(&self, id: &str, epoch: u64) -> bool {
        let mut slots = self.slots.lock().unwrap();
        if slots.get(id).is_some_and(|slot| slot.epoch == epoch) {
            slots.remove(id);
            true
        } else {
            false
        }
    }
}

/// Spawn the event-driven monitor that arms/cancels lifecycle timers.
///
/// Holds only a `Weak` on the manager: the task exits when the manager is
/// dropped (the event channel closes with it).
pub(super) fn spawn_lifecycle_monitor(manager: &Arc<SandboxManager>) {
    let weak = Arc::downgrade(manager);
    let mut events = manager.events_tx.subscribe();
    tokio::spawn(async move {
        // Reloaded (paused) sandboxes keep their TTL: re-arm after the
        // startup sweep has published the recovered instances.
        {
            let Some(manager) = weak.upgrade() else {
                return;
            };
            if manager.await_reconcile().await.is_ok() {
                manager.resync_lifecycle_timers();
            }
        }
        loop {
            match events.recv().await {
                Ok(event) => {
                    let Some(manager) = weak.upgrade() else {
                        return;
                    };
                    manager.on_lifecycle_event(&event);
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let Some(manager) = weak.upgrade() else {
                        return;
                    };
                    manager.resync_lifecycle_timers();
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    });
}

impl SandboxManager {
    /// Replace a sandbox's lifecycle deadlines (CORE-60).
    ///
    /// `ttl_seconds` re-arms the hard cap from *now* (0 removes it);
    /// `idle_timeout_seconds` replaces the idle window, re-arming any live
    /// timer; `on_idle` replaces the policy. `None` fields are unchanged.
    /// Allowed in any non-terminal state — a paused sandbox keeps honoring
    /// its (re-armed) TTL, and new idle knobs apply on the next `Ready`.
    pub async fn set_sandbox_lifecycle(
        &self,
        id: &SandboxId,
        update: LifecycleUpdate,
    ) -> Result<()> {
        self.await_reconcile().await?;
        let instance = self.get_instance(id)?;
        let (generation, ttl_deadline, idle_timeout_seconds, on_idle) = {
            let mut inst = instance.lock().unwrap();
            match inst.state {
                SandboxState::Stopping | SandboxState::Stopped | SandboxState::Failed => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "a live sandbox (not stopping, stopped, or failed)".into(),
                        actual: inst.state.to_string(),
                    });
                }
                _ => {}
            }
            if let Some(ttl) = update.ttl_seconds {
                inst.ttl_deadline =
                    (ttl > 0).then(|| Utc::now() + chrono::Duration::seconds(i64::from(ttl)));
            }
            if let Some(idle) = update.idle_timeout_seconds {
                inst.spec.idle_timeout_seconds = idle;
            }
            if let Some(policy) = update.on_idle {
                inst.spec.on_idle = policy;
            }
            (
                inst.record_generation,
                inst.ttl_deadline,
                inst.spec.idle_timeout_seconds,
                inst.spec.on_idle,
            )
        };
        let commit = generation
            .map(|generation| {
                self.records.update_lifecycle(
                    id,
                    generation,
                    ttl_deadline,
                    idle_timeout_seconds,
                    on_idle,
                )
            })
            .transpose()?;
        if update.ttl_seconds.is_some() {
            self.arm_ttl_timer(id);
        }
        if update.idle_timeout_seconds.is_some() || update.on_idle.is_some() {
            self.arm_idle_timer(id);
        }
        info!(
            sandbox_id = %id,
            ttl_deadline = ?ttl_deadline,
            idle_timeout_seconds,
            on_idle = ?on_idle,
            "sandbox lifecycle updated"
        );
        commit
            .map(|commit| commit.confirmed("sandbox lifecycle update"))
            .transpose()?;
        Ok(())
    }

    /// React to one lifecycle event: arm the idle timer on every `Ready`
    /// edge, cancel it while work is in flight, and drop both timers on
    /// teardown.
    fn on_lifecycle_event(&self, event: &SandboxEvent) {
        match event.action.as_str() {
            action::READY | action::IDLE | action::RESUMED => {
                self.arm_idle_timer(&event.sandbox_id);
            }
            action::RUNNING | action::PAUSING | action::STOPPING => {
                self.timers.idle.cancel(&event.sandbox_id);
            }
            action::STOPPED | action::FAILED | action::REMOVED => {
                self.timers.idle.cancel(&event.sandbox_id);
                self.timers.ttl.cancel(&event.sandbox_id);
            }
            _ => {}
        }
    }

    /// Rebuild every timer from current instance state (startup, or after
    /// the monitor lagged behind the event stream).
    fn resync_lifecycle_timers(&self) {
        let instances: Vec<_> = self
            .instances
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for id in instances {
            self.arm_ttl_timer(&id);
            self.arm_idle_timer(&id);
        }
    }

    /// Arm (or clear) the TTL timer from the instance's current deadline.
    ///
    /// The armed task holds only `Weak`s plus the resource set the expiry
    /// needs, so it never keeps the manager alive; a `SetLifecycle` re-arm
    /// replaces the slot and aborts the sleeping task.
    ///
    /// No-op without a shared handle ([`SandboxManager::into_shared`]), like
    /// [`Self::arm_idle_timer`]: the fired task claims its timer slot through
    /// the manager, and a task that cannot claim one must not act — reading
    /// the two functions opposite ways on the same condition is how a stale
    /// timer would slip past both staleness guards below.
    pub(super) fn arm_ttl_timer(&self, id: &SandboxId) {
        let Some(self_handle) = self.self_handle.get().cloned() else {
            return;
        };
        let Ok(instance) = self.get_instance(id) else {
            self.timers.ttl.cancel(id);
            return;
        };
        let (deadline, generation, state) = {
            let inst = instance.lock().unwrap();
            (inst.ttl_deadline, inst.record_generation, inst.state)
        };
        let Some(deadline) = deadlines::ttl_due(state, deadline) else {
            self.timers.ttl.cancel(id);
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let armed_for = Arc::downgrade(&instance);
        let instances = Arc::clone(&self.instances);
        let network = Arc::clone(&self.network);
        let events_tx = self.events_tx.clone();
        let config = Arc::clone(&self.config);
        let cow_manager = Arc::clone(&self.cow_manager);
        let records = Arc::clone(&self.records);
        let snapshots = Arc::clone(&self.snapshots);
        let id = id.clone();
        self.timers.ttl.arm(&id.clone(), move |epoch| {
            tokio::spawn(async move {
                sleep_until_utc(deadline).await;
                // Claim the slot so a late cancel cannot abort mid-removal.
                // A gone manager means the whole sandbox layer is being torn
                // down: there is nothing to claim the slot against and no one
                // left to expire for, so bail rather than fall through.
                let Some(manager) = self_handle.upgrade() else {
                    return;
                };
                if !manager.timers.ttl.try_claim(&id, epoch) {
                    return;
                }
                // Re-armed deadlines replace the task; a moved deadline
                // observed here means the claim raced one — bail.
                let still_due = armed_for
                    .upgrade()
                    .is_some_and(|inst| inst.lock().unwrap().ttl_deadline == Some(deadline));
                if !still_due {
                    return;
                }
                info!(sandbox_id = %id, "sandbox TTL expired; removing");
                super::cleanup::expire_sandbox(
                    &id,
                    generation,
                    &armed_for,
                    &instances,
                    &network,
                    &events_tx,
                    &config,
                    &cow_manager,
                    &records,
                    &snapshots,
                    true,
                    "TTL",
                )
                .await;
            })
        });
    }

    /// Arm (or clear) the idle timer for a `Ready` sandbox.
    ///
    /// No-op without a shared handle ([`SandboxManager::into_shared`]): the
    /// expiry action needs the manager's pause/remove flows.
    pub(super) fn arm_idle_timer(&self, id: &SandboxId) {
        let Some(weak_manager) = self.self_handle.get().cloned() else {
            return;
        };
        let Ok(instance) = self.get_instance(id) else {
            self.timers.idle.cancel(id);
            return;
        };
        let idle_after = {
            let inst = instance.lock().unwrap();
            deadlines::idle_due(inst.state, inst.spec.idle_timeout_seconds)
        };
        let Some(idle_after) = idle_after else {
            self.timers.idle.cancel(id);
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let armed_for = Arc::downgrade(&instance);
        let id = id.clone();
        self.timers.idle.arm(&id.clone(), move |epoch| {
            tokio::spawn(async move {
                tokio::time::sleep(idle_after).await;
                let Some(manager) = weak_manager.upgrade() else {
                    return;
                };
                if !manager.timers.idle.try_claim(&id, epoch) {
                    return;
                }
                manager.apply_idle_policy(&id, &armed_for).await;
            })
        });
    }

    /// Apply the sandbox's `on_idle` policy after its idle timeout fired.
    ///
    /// Re-verifies the armed generation and the `Ready` state first; both
    /// the pause flow (atomic `Ready → Pausing` claim) and the non-forced
    /// remove reject a sandbox that turned busy in the remaining window, so
    /// a race at worst logs and leaves the sandbox untouched.
    async fn apply_idle_policy(
        &self,
        id: &SandboxId,
        armed_for: &std::sync::Weak<Mutex<SandboxInstance>>,
    ) {
        let current = self.instances.read().unwrap().get(id).cloned();
        let Some(instance) = armed_for.upgrade() else {
            return;
        };
        if !current.is_some_and(|current| Arc::ptr_eq(&current, &instance)) {
            return;
        }
        let (policy, generation) = {
            let inst = instance.lock().unwrap();
            if inst.state != SandboxState::Ready {
                return;
            }
            (inst.spec.on_idle, inst.record_generation)
        };
        match policy {
            IdleAction::Pause => {
                match self
                    .pause_sandbox_with_reason(id, super::pause::reason::IDLE_TIMEOUT)
                    .await
                {
                    Ok(()) => info!(sandbox_id = %id, "idle timeout: sandbox paused"),
                    Err(VmmError::WrongState { .. }) => {
                        debug!(sandbox_id = %id, "sandbox became busy before the idle pause");
                    }
                    Err(error) => {
                        warn!(sandbox_id = %id, error = %error, "idle pause failed");
                    }
                }
            }
            IdleAction::Kill => {
                info!(sandbox_id = %id, "idle timeout: removing sandbox");
                super::cleanup::expire_sandbox(
                    id,
                    generation,
                    armed_for,
                    &self.instances,
                    &self.network,
                    &self.events_tx,
                    &self.config,
                    &self.cow_manager,
                    &self.records,
                    &self.snapshots,
                    false,
                    "idle",
                )
                .await;
            }
        }
    }
}

/// Sleep until a wall-clock deadline (already-past deadlines return at once).
async fn sleep_until_utc(deadline: DateTime<Utc>) {
    tokio::time::sleep(deadlines::remaining(deadline, Utc::now())).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn shared_manager(data_dir: &Path) -> Arc<SandboxManager> {
        let mut config = VmmConfig::default();
        config.firecracker.data_dir = data_dir.to_string_lossy().into_owned();
        let manager = SandboxManager::new(config).unwrap().into_shared();
        manager.await_reconcile().await.unwrap();
        manager
    }

    fn insert_instance(
        manager: &SandboxManager,
        id: &str,
        state: SandboxState,
        spec: SandboxSpec,
    ) -> Arc<Mutex<SandboxInstance>> {
        let vm_dir = PathBuf::from(&manager.config.firecracker.data_dir)
            .join("sandboxes")
            .join(id);
        let mut inst = SandboxInstance::new(
            id.to_owned(),
            SandboxSpec {
                id: Some(id.to_owned()),
                ..spec
            },
            None,
            vm_dir,
        );
        inst.state = state;
        let arc = Arc::new(Mutex::new(inst));
        manager
            .instances
            .write()
            .unwrap()
            .insert(id.to_owned(), Arc::clone(&arc));
        arc
    }

    #[tokio::test]
    async fn set_lifecycle_rearms_ttl_from_now_and_replaces_idle_knobs() {
        let dir = tempfile::tempdir().unwrap();
        let manager = shared_manager(dir.path()).await;
        insert_instance(&manager, "box", SandboxState::Ready, SandboxSpec::default());

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
        let manager = shared_manager(dir.path()).await;
        assert!(matches!(
            manager
                .set_sandbox_lifecycle(&"ghost".to_owned(), LifecycleUpdate::default())
                .await,
            Err(VmmError::NotFound(_))
        ));

        for state in [
            SandboxState::Stopping,
            SandboxState::Stopped,
            SandboxState::Failed,
        ] {
            let id = format!("terminal-{state}");
            insert_instance(&manager, &id, state, SandboxSpec::default());
            assert!(matches!(
                manager
                    .set_sandbox_lifecycle(&id, LifecycleUpdate::default())
                    .await,
                Err(VmmError::WrongState { .. })
            ));
        }

        // Paused sandboxes accept updates: the TTL keeps applying to them.
        insert_instance(
            &manager,
            "asleep",
            SandboxState::Paused,
            SandboxSpec::default(),
        );
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

    #[tokio::test(start_paused = true)]
    async fn idle_timer_arms_on_ready_and_cancels_on_running() {
        let dir = tempfile::tempdir().unwrap();
        let manager = shared_manager(dir.path()).await;
        let spec = SandboxSpec {
            idle_timeout_seconds: 5,
            on_idle: IdleAction::Pause,
            ..Default::default()
        };
        insert_instance(&manager, "box", SandboxState::Ready, spec);

        manager.arm_idle_timer(&"box".to_owned());
        assert!(
            manager
                .timers
                .idle
                .slots
                .lock()
                .unwrap()
                .contains_key("box")
        );

        // An execution start cancels the timer.
        manager.on_lifecycle_event(&SandboxEvent::new("box", action::RUNNING));
        assert!(
            !manager
                .timers
                .idle
                .slots
                .lock()
                .unwrap()
                .contains_key("box")
        );

        // A non-Ready sandbox or a zero timeout never arms.
        manager.instances.read().unwrap()["box"]
            .lock()
            .unwrap()
            .state = SandboxState::Running;
        manager.on_lifecycle_event(&SandboxEvent::new("box", action::IDLE));
        assert!(
            !manager
                .timers
                .idle
                .slots
                .lock()
                .unwrap()
                .contains_key("box")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_expiry_pause_policy_pauses_instead_of_removing() {
        let dir = tempfile::tempdir().unwrap();
        let manager = shared_manager(dir.path()).await;
        let spec = SandboxSpec {
            idle_timeout_seconds: 2,
            on_idle: IdleAction::Pause,
            ..Default::default()
        };
        insert_instance(&manager, "box", SandboxState::Ready, spec);

        manager.arm_idle_timer(&"box".to_owned());
        tokio::time::sleep(Duration::from_secs(3)).await;
        // The fired timer claims its slot, then routes to the pause flow
        // (which fails fast here — no jailer/VM — leaving the sandbox
        // intact). The full reason=idle_timeout pause is e2e-covered.
        for _ in 0..50 {
            if !manager
                .timers
                .idle
                .slots
                .lock()
                .unwrap()
                .contains_key("box")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !manager
                .timers
                .idle
                .slots
                .lock()
                .unwrap()
                .contains_key("box"),
            "the idle timer must have fired and claimed its slot"
        );
        assert!(
            manager.instances.read().unwrap().contains_key("box"),
            "the PAUSE policy must never remove the sandbox"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_expiry_kill_removes_the_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let manager = shared_manager(dir.path()).await;
        std::fs::create_dir_all(dir.path().join("sandboxes/box")).unwrap();
        let spec = SandboxSpec {
            idle_timeout_seconds: 2,
            on_idle: IdleAction::Kill,
            ..Default::default()
        };
        insert_instance(&manager, "box", SandboxState::Ready, spec);

        manager.arm_idle_timer(&"box".to_owned());
        tokio::time::sleep(Duration::from_secs(3)).await;
        // The removal runs on a detached task; poll briefly for the map drop.
        for _ in 0..50 {
            if !manager.instances.read().unwrap().contains_key("box") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!manager.instances.read().unwrap().contains_key("box"));
    }

    #[tokio::test(start_paused = true)]
    async fn stale_idle_timer_does_not_fire_after_rearm() {
        let dir = tempfile::tempdir().unwrap();
        let manager = shared_manager(dir.path()).await;
        let spec = SandboxSpec {
            idle_timeout_seconds: 2,
            on_idle: IdleAction::Kill,
            ..Default::default()
        };
        insert_instance(&manager, "box", SandboxState::Ready, spec);

        manager.arm_idle_timer(&"box".to_owned());
        // Re-arm with a longer window; the first timer's epoch is stale.
        manager.instances.read().unwrap()["box"]
            .lock()
            .unwrap()
            .spec
            .idle_timeout_seconds = 3600;
        manager.arm_idle_timer(&"box".to_owned());

        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(
            manager.instances.read().unwrap().contains_key("box"),
            "stale timer must not remove the re-armed sandbox"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_timer_honors_a_rearmed_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let manager = shared_manager(dir.path()).await;
        std::fs::create_dir_all(dir.path().join("sandboxes/box")).unwrap();
        insert_instance(&manager, "box", SandboxState::Ready, SandboxSpec::default());
        manager.instances.read().unwrap()["box"]
            .lock()
            .unwrap()
            .ttl_deadline = Some(Utc::now() + chrono::Duration::seconds(2));
        manager.arm_ttl_timer(&"box".to_owned());

        // Re-arm far into the future before the first deadline hits.
        manager
            .set_sandbox_lifecycle(
                &"box".to_owned(),
                LifecycleUpdate {
                    ttl_seconds: Some(3600),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(
            manager.instances.read().unwrap().contains_key("box"),
            "re-armed TTL must outlive the original deadline"
        );

        // The re-armed deadline still fires.
        tokio::time::sleep(Duration::from_secs(3600)).await;
        for _ in 0..50 {
            if !manager.instances.read().unwrap().contains_key("box") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!manager.instances.read().unwrap().contains_key("box"));
    }

    /// A terminal sandbox recovered by the restart sweep carries a
    /// `ttl_deadline` (`inactive_instance` restores it unconditionally), but
    /// the live path cancels TTL on the STOPPED/FAILED edge. Arming one
    /// anyway would make reaping a stopped record depend on whether the
    /// agent happened to bounce.
    #[tokio::test(start_paused = true)]
    async fn ttl_timer_is_not_armed_for_a_terminal_sandbox() {
        for state in [SandboxState::Stopped, SandboxState::Failed] {
            let dir = tempfile::tempdir().unwrap();
            let manager = shared_manager(dir.path()).await;
            std::fs::create_dir_all(dir.path().join("sandboxes/box")).unwrap();
            insert_instance(&manager, "box", state, SandboxSpec::default());
            manager.instances.read().unwrap()["box"]
                .lock()
                .unwrap()
                .ttl_deadline = Some(Utc::now() + chrono::Duration::seconds(2));

            manager.arm_ttl_timer(&"box".to_owned());

            tokio::time::sleep(Duration::from_secs(10)).await;
            assert!(
                manager.instances.read().unwrap().contains_key("box"),
                "a {state} sandbox must not be expired by a re-armed TTL"
            );
        }
    }
}
