//! The balloon controller: single owner of the idle balloon.
//!
//! A message-driven task, commanded by the lifecycle actor on state
//! transitions (`EnterIdle` on entering `Idle`, `ExitIdle` on leaving it
//! for any reason). Every hypervisor balloon call happens here, serially —
//! no shared balloon state, no cross-task races.
//!
//! Modes:
//!
//! ```text
//! Active ──EnterIdle──▶ probe guest (entry_decision)
//!    ▲                     ├─ NotIdle ──activity()──▶ Active
//!    │                     ├─ Keep ────────────────▶ IdleUnshrunk (retry 30s)
//!    │                     └─ Shrink ─▶ step target ─▶ Watching ◀─┐
//!    │                                                  │  Settled + more to
//!    │                                                  │  shrink: next step,
//!    │        pressure / watch error / silence ≥ 25s    │  fresh watch ──────┘
//!    └────── restore full + activity() ◀───────────┬────▼
//!                                                  └─ Polling (30s stats,
//!                                                     step on healthy poll,
//!                                                     fail open on silence)
//! ```
//!
//! The descent is staged ([`super::SHRINK_STEP`] per move) because inflation
//! speed is not under host control and each step's scarcity window should be
//! short; the guest's `SETTLED` frame gates each further step.
//!
//! Exits always ride the lifecycle state machine: pressure and fail-open
//! paths restore full memory immediately, then note activity, which exits
//! `Idle` and resets the 5-minute idle clock — so a re-shrink requires a
//! fresh quiet period plus a fresh entry probe. Oscillation is structurally
//! impossible.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::error::Result;

use super::{EntryDecision, GuestStats, entry_decision};

/// Command from the lifecycle actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::vm_lifecycle) enum BalloonCommand {
    /// The VM entered `Idle`: probe guest usage and shrink if worthwhile.
    EnterIdle,
    /// The VM left `Idle` (activity, stop, reboot): restore full memory.
    ExitIdle,
}

/// One frame observed on a pressure watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::vm_lifecycle) enum WatchFrame {
    /// Agent alive, no pressure.
    Keepalive,
    /// Guest memory pressure detected.
    Pressure,
    /// The guest settled at the current balloon target (detector armed).
    Settled,
    /// The watch window elapsed; re-open to keep watching.
    WindowElapsed,
}

/// An open guest pressure watch.
pub(in crate::vm_lifecycle) trait PressureWatch: Send {
    /// Waits for the next frame, at most `max_wait`. An error is either
    /// transport failure or silence past the keepalive budget — both mean
    /// the guest cannot be trusted to report pressure anymore.
    fn next_frame(&mut self, max_wait: Duration)
    -> impl Future<Output = Result<WatchFrame>> + Send;
}

/// What the controller needs from the world, narrow enough to fake in tests.
pub(in crate::vm_lifecycle) trait BalloonDeps:
    Send + Sync + 'static
{
    /// The watch type produced by [`Self::open_pressure_watch`].
    type Watch: PressureWatch;

    /// Configured full memory of the machine, if the machine record exists.
    fn full_memory_bytes(&self) -> Option<u64>;

    /// Applies a balloon target on the hypervisor device.
    fn set_balloon_target(&self, bytes: u64) -> Result<()>;

    /// Guest memory + load snapshot within `budget`; `None` = unreachable.
    fn guest_stats(&self, budget: Duration) -> impl Future<Output = Option<GuestStats>> + Send;

    /// Opens a guest pressure watch. An error means the watch mechanism is
    /// unavailable (old agent, transport limits) — the controller degrades
    /// to polling.
    fn open_pressure_watch(&self) -> impl Future<Output = Result<Self::Watch>> + Send;
}

/// Retry cadence while idle but not (yet) shrunk.
const IDLE_ENTRY_RETRY: Duration = Duration::from_secs(30);

/// Minimum dwell at each descent step before taking the next one.
///
/// The guest's `SETTLED` frame proves the guest is healthy at the current
/// *memory level*, not that inflation caught up with the target — inflation
/// lags and its speed is not under host control. Hardware-validated: without
/// a dwell the descent outran inflation by many GiB and the deferred squeeze
/// OOM-killed the workload faster than the 1s sampler could see. The dwell
/// keeps the un-inflated lag bounded to roughly one step.
const STEP_DWELL: Duration = Duration::from_secs(15);

/// Maximum silence on an open watch before failing open. Must exceed the
/// agent keepalive cadence (10s) with margin.
const WATCH_SILENCE_DEADLINE: Duration = Duration::from_secs(25);

/// Poll cadence in degraded (no-watch) mode.
const DEGRADED_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// `MemAvailable` floor for pressure, both as the watch request threshold
/// and the degraded-poll check. Safely below the entry headroom (256 MiB).
pub(in crate::vm_lifecycle) const PRESSURE_MIN_AVAILABLE: u64 = 128 * 1024 * 1024;

/// Refault-rate threshold (pages/second) for the watch request. Disabled:
/// hardware validation showed the post-shrink page-cache rewarm produces
/// refault bursts that outlive any warm-up, and refaulting with healthy
/// `MemAvailable` is cache warming, not pressure — the floor plus the
/// silence fail-open cover the thrash class. The plumbing stays host-
/// tunable for a future smarter signal (e.g. PSI).
pub(in crate::vm_lifecycle) const PRESSURE_MAX_REFAULT_RATE: u64 = 0;

/// Watch window requested from the agent; the watch is re-opened when it
/// elapses.
pub(in crate::vm_lifecycle) const WATCH_WINDOW: Duration = Duration::from_secs(300);

/// Keepalive cadence requested from the agent.
pub(in crate::vm_lifecycle) const WATCH_KEEPALIVE: Duration = Duration::from_secs(10);

/// Budget for the entry-time guest stats probe.
const GUEST_STATS_TIMEOUT: Duration = Duration::from_secs(super::GUEST_STATS_TIMEOUT_SECS);

/// The controller task. Owns all balloon state; communicates with the world
/// only through [`BalloonDeps`] (in) and the activity callback (out).
pub(in crate::vm_lifecycle) struct BalloonController<D: BalloonDeps> {
    commands: mpsc::UnboundedReceiver<BalloonCommand>,
    deps: D,
    /// Notes lifecycle activity: resets the idle clock and exits `Idle`.
    activity: Arc<dyn Fn() + Send + Sync>,
    /// Currently applied balloon target while shrunk.
    applied: Option<u64>,
    /// Final descent target; `applied > final` means more steps pending.
    final_target: Option<u64>,
    /// When the current step was applied (dwell pacing).
    step_applied_at: Option<tokio::time::Instant>,
}

/// Controller mode; holds the open watch so drops cancel it naturally.
enum Mode<W> {
    /// VM not idle; balloon at full memory.
    Active,
    /// VM idle, balloon not shrunk (no stats yet / nothing to reclaim);
    /// entry is retried on a timer.
    IdleUnshrunk,
    /// Balloon shrunk; guest pressure watch open.
    Watching(W),
    /// Guest settled before the step dwell elapsed: keep watching for
    /// pressure, take the next step when the dwell timer fires.
    Dwelling {
        /// The open watch (pressure still exits during the dwell).
        watch: W,
        /// When the dwell completes.
        until: tokio::time::Instant,
    },
    /// Balloon shrunk; watch unavailable — polling stats instead.
    Polling,
}

impl<D: BalloonDeps> BalloonController<D> {
    pub(in crate::vm_lifecycle) fn new(
        commands: mpsc::UnboundedReceiver<BalloonCommand>,
        deps: D,
        activity: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            commands,
            deps,
            activity,
            applied: None,
            final_target: None,
            step_applied_at: None,
        }
    }

    /// Runs until the command channel closes (actor drop).
    pub(in crate::vm_lifecycle) async fn run(mut self) {
        let mut mode = Mode::Active;
        loop {
            mode = match mode {
                Mode::Active => match self.commands.recv().await {
                    Some(BalloonCommand::EnterIdle) => self.enter_idle().await,
                    Some(BalloonCommand::ExitIdle) => Mode::Active,
                    None => return,
                },
                Mode::IdleUnshrunk => {
                    tokio::select! {
                        cmd = self.commands.recv() => match cmd {
                            // Nothing was shrunk; nothing to restore.
                            Some(BalloonCommand::ExitIdle) => Mode::Active,
                            Some(BalloonCommand::EnterIdle) => Mode::IdleUnshrunk,
                            None => return,
                        },
                        () = tokio::time::sleep(IDLE_ENTRY_RETRY) => self.enter_idle().await,
                    }
                }
                Mode::Watching(mut watch) => {
                    tokio::select! {
                        cmd = self.commands.recv() => match cmd {
                            Some(BalloonCommand::ExitIdle) => {
                                self.restore("idle exit");
                                Mode::Active
                            }
                            Some(BalloonCommand::EnterIdle) => Mode::Watching(watch),
                            None => return,
                        },
                        frame = watch.next_frame(WATCH_SILENCE_DEADLINE) => match frame {
                            Ok(WatchFrame::Keepalive) => Mode::Watching(watch),
                            Ok(WatchFrame::Settled) => {
                                if self.next_pending_step().is_none() {
                                    // Final target reached; keep watching.
                                    Mode::Watching(watch)
                                } else {
                                    // The guest settled at this memory level,
                                    // but inflation lags the target: hold the
                                    // remaining dwell (still watching for
                                    // pressure) before the next step.
                                    let applied_at = self
                                        .step_applied_at
                                        .unwrap_or_else(tokio::time::Instant::now);
                                    Mode::Dwelling {
                                        watch,
                                        until: applied_at + STEP_DWELL,
                                    }
                                }
                            }
                            Ok(WatchFrame::WindowElapsed) => self.open_watch().await,
                            Ok(WatchFrame::Pressure) => self.fail_open("guest memory pressure"),
                            Err(e) => self.fail_open(&format!(
                                "pressure watch lost ({e}); guest may be too starved to answer"
                            )),
                        },
                    }
                }
                Mode::Dwelling { mut watch, until } => {
                    tokio::select! {
                        cmd = self.commands.recv() => match cmd {
                            Some(BalloonCommand::ExitIdle) => {
                                self.restore("idle exit");
                                Mode::Active
                            }
                            Some(BalloonCommand::EnterIdle) => Mode::Dwelling { watch, until },
                            None => return,
                        },
                        () = tokio::time::sleep_until(until) => {
                            // Each further step needs a fresh settling
                            // detector: drop this watch before moving.
                            drop(watch);
                            self.continue_descent().await
                        }
                        frame = watch.next_frame(WATCH_SILENCE_DEADLINE) => match frame {
                            Ok(WatchFrame::Keepalive | WatchFrame::Settled) => {
                                Mode::Dwelling { watch, until }
                            }
                            Ok(WatchFrame::WindowElapsed) => match self.open_watch().await {
                                Mode::Watching(watch) => Mode::Dwelling { watch, until },
                                other => other,
                            },
                            Ok(WatchFrame::Pressure) => self.fail_open("guest memory pressure"),
                            Err(e) => self.fail_open(&format!(
                                "pressure watch lost ({e}); guest may be too starved to answer"
                            )),
                        },
                    }
                }
                Mode::Polling => {
                    tokio::select! {
                        cmd = self.commands.recv() => match cmd {
                            Some(BalloonCommand::ExitIdle) => {
                                self.restore("idle exit");
                                Mode::Active
                            }
                            Some(BalloonCommand::EnterIdle) => Mode::Polling,
                            None => return,
                        },
                        () = tokio::time::sleep(DEGRADED_POLL_INTERVAL) => {
                            match self.deps.guest_stats(GUEST_STATS_TIMEOUT).await {
                                None => self.fail_open("agent unreachable while shrunk"),
                                Some(s) if s.available < PRESSURE_MIN_AVAILABLE => {
                                    self.fail_open("guest available memory below floor")
                                }
                                // A healthy poll is the degraded mode's
                                // settle signal: take the next step.
                                Some(_) => match self.next_pending_step() {
                                    Some(next) => {
                                        self.apply_step(next);
                                        Mode::Polling
                                    }
                                    None => Mode::Polling,
                                },
                            }
                        }
                    }
                }
            };
        }
    }

    /// Entry probe: size the balloon from clean (balloon-empty) stats.
    async fn enter_idle(&mut self) -> Mode<D::Watch> {
        let Some(full) = self.deps.full_memory_bytes() else {
            return Mode::IdleUnshrunk;
        };
        let stats = self.deps.guest_stats(GUEST_STATS_TIMEOUT).await;
        match entry_decision(stats, full) {
            EntryDecision::NotIdle => {
                tracing::info!("guest is busy; exiting idle instead of shrinking");
                (self.activity)();
                Mode::Active
            }
            EntryDecision::Keep => Mode::IdleUnshrunk,
            EntryDecision::Shrink(final_target) => {
                let first = super::next_step(full, final_target);
                if let Err(e) = self.deps.set_balloon_target(first) {
                    tracing::warn!("failed to shrink idle balloon: {e}");
                    return Mode::IdleUnshrunk;
                }
                self.applied = Some(first);
                self.final_target = Some(final_target);
                self.step_applied_at = Some(tokio::time::Instant::now());
                tracing::info!(
                    target_mb = first / (1024 * 1024),
                    final_mb = final_target / (1024 * 1024),
                    "idle balloon shrunk to guest usage + headroom"
                );
                self.open_watch().await
            }
        }
    }

    /// The next descent step, if the applied target is above the final one.
    fn next_pending_step(&self) -> Option<u64> {
        let (applied, final_target) = (self.applied?, self.final_target?);
        (applied > final_target).then(|| super::next_step(applied, final_target))
    }

    /// Applies one descent step (best effort — a failed step leaves the
    /// current, already-settled target in place).
    fn apply_step(&mut self, next: u64) {
        match self.deps.set_balloon_target(next) {
            Ok(()) => {
                self.applied = Some(next);
                self.step_applied_at = Some(tokio::time::Instant::now());
                tracing::info!(target_mb = next / (1024 * 1024), "idle balloon step");
            }
            Err(e) => tracing::warn!("failed to step idle balloon: {e}"),
        }
    }

    /// Continues the staged descent after the guest settled, or keeps
    /// watching at the final target.
    async fn continue_descent(&mut self) -> Mode<D::Watch> {
        if let Some(next) = self.next_pending_step() {
            self.apply_step(next);
        }
        self.open_watch().await
    }

    /// Opens (or re-opens) the pressure watch, degrading to polling when
    /// the agent doesn't support it.
    async fn open_watch(&self) -> Mode<D::Watch> {
        match self.deps.open_pressure_watch().await {
            Ok(watch) => Mode::Watching(watch),
            Err(e) => {
                tracing::info!("pressure watch unavailable ({e}); polling guest stats instead");
                Mode::Polling
            }
        }
    }

    /// Restores full memory and exits idle via the state machine.
    fn fail_open(&mut self, reason: &str) -> Mode<D::Watch> {
        tracing::info!(reason, "restoring full memory");
        self.restore(reason);
        (self.activity)();
        Mode::Active
    }

    /// Restores the balloon to the machine's full configured memory.
    fn restore(&mut self, reason: &str) {
        self.applied = None;
        self.final_target = None;
        self.step_applied_at = None;
        let Some(full) = self.deps.full_memory_bytes() else {
            return;
        };
        match self.deps.set_balloon_target(full) {
            Ok(()) => tracing::info!(
                full_mb = full / (1024 * 1024),
                reason,
                "balloon restored to full memory"
            ),
            Err(e) => tracing::debug!("failed to restore balloon ({reason}): {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    const FULL: u64 = 16 * GIB;

    /// Scripted watch: yields frames from a channel; `None` (closed) is a
    /// transport error.
    struct FakeWatch {
        frames: mpsc::UnboundedReceiver<WatchFrame>,
    }

    impl PressureWatch for FakeWatch {
        async fn next_frame(&mut self, max_wait: Duration) -> Result<WatchFrame> {
            match tokio::time::timeout(max_wait, self.frames.recv()).await {
                Ok(Some(frame)) => Ok(frame),
                Ok(None) => Err(CoreError::Machine("watch transport closed".into())),
                Err(_) => Err(CoreError::Machine("watch silence deadline".into())),
            }
        }
    }

    /// Test double with scripted stats/watch behavior and recorded targets.
    struct FakeDeps {
        full: Option<u64>,
        stats: Mutex<Vec<Option<GuestStats>>>,
        targets: Arc<Mutex<Vec<u64>>>,
        watch_supported: bool,
        watch_frames: Mutex<Vec<mpsc::UnboundedReceiver<WatchFrame>>>,
        watch_senders: Mutex<Vec<mpsc::UnboundedSender<WatchFrame>>>,
        watches_opened: Arc<AtomicUsize>,
    }

    impl FakeDeps {
        fn new(full: Option<u64>) -> Self {
            Self {
                full,
                stats: Mutex::new(Vec::new()),
                targets: Arc::new(Mutex::new(Vec::new())),
                watch_supported: true,
                watch_frames: Mutex::new(Vec::new()),
                watch_senders: Mutex::new(Vec::new()),
                watches_opened: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// Queues the reply for the next `guest_stats` call (LIFO-safe: we
        /// only ever queue in test order and pop front).
        fn push_stats(&self, stats: Option<GuestStats>) {
            self.stats.lock().unwrap().push(stats);
        }

        /// Queues frames for the next opened watch and returns the sender.
        fn push_watch(&self) -> mpsc::UnboundedSender<WatchFrame> {
            let (tx, rx) = mpsc::unbounded_channel();
            self.watch_frames.lock().unwrap().push(rx);
            self.watch_senders.lock().unwrap().push(tx.clone());
            tx
        }
    }

    impl BalloonDeps for Arc<FakeDeps> {
        type Watch = FakeWatch;

        fn full_memory_bytes(&self) -> Option<u64> {
            self.full
        }

        fn set_balloon_target(&self, bytes: u64) -> Result<()> {
            self.targets.lock().unwrap().push(bytes);
            Ok(())
        }

        async fn guest_stats(&self, _budget: Duration) -> Option<GuestStats> {
            let mut stats = self.stats.lock().unwrap();
            if stats.is_empty() {
                None
            } else {
                stats.remove(0)
            }
        }

        async fn open_pressure_watch(&self) -> Result<FakeWatch> {
            self.watches_opened.fetch_add(1, Ordering::SeqCst);
            if !self.watch_supported {
                return Err(CoreError::Agent {
                    code: 400,
                    message: "invalid request: unexpected message type".into(),
                });
            }
            let mut queued = self.watch_frames.lock().unwrap();
            if queued.is_empty() {
                // A watch with no scripted frames: stays silent (the sender
                // is leaked so the channel never reports closed).
                let (tx, rx) = mpsc::unbounded_channel();
                std::mem::forget(tx);
                Ok(FakeWatch { frames: rx })
            } else {
                Ok(FakeWatch {
                    frames: queued.remove(0),
                })
            }
        }
    }

    impl Harness {
        fn watch_senders(&self) -> Vec<mpsc::UnboundedSender<WatchFrame>> {
            self.deps.watch_senders.lock().unwrap().clone()
        }
    }

    struct Harness {
        deps: Arc<FakeDeps>,
        commands: mpsc::UnboundedSender<BalloonCommand>,
        activity: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Harness {
        fn spawn(deps: FakeDeps) -> Self {
            let deps = Arc::new(deps);
            let (tx, rx) = mpsc::unbounded_channel();
            let activity = Arc::new(AtomicUsize::new(0));
            let activity_probe = Arc::clone(&activity);
            let controller = BalloonController::new(
                rx,
                Arc::clone(&deps),
                Arc::new(move || {
                    activity_probe.fetch_add(1, Ordering::SeqCst);
                }),
            );
            let task = tokio::spawn(controller.run());
            Self {
                deps,
                commands: tx,
                activity,
                task,
            }
        }

        fn targets(&self) -> Vec<u64> {
            self.deps.targets.lock().unwrap().clone()
        }

        fn activity_count(&self) -> usize {
            self.activity.load(Ordering::SeqCst)
        }

        /// Lets the paused-clock runtime drive the controller until quiescent.
        async fn settle(&self) {
            for _ in 0..50 {
                tokio::task::yield_now().await;
            }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn idle_stats() -> GuestStats {
        // 4 GiB used, quiet guest.
        GuestStats {
            total: FULL,
            available: 12 * GIB,
            loadavg1: 0.1,
        }
    }

    /// Final descent target for `idle_stats` (usage + headroom).
    const FINAL_TARGET: u64 = 4 * GIB + super::super::IDLE_BALLOON_HEADROOM;
    /// First staged step from 16 GiB full memory.
    const FIRST_STEP: u64 = FULL - super::super::SHRINK_STEP;

    #[tokio::test(start_paused = true)]
    async fn enter_idle_takes_first_staged_step_and_watches() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let _watch = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;

        // Usage-aware final, but only one SHRINK_STEP applied up front.
        assert_eq!(h.targets(), vec![FIRST_STEP]);
        assert_eq!(h.deps.watches_opened.load(Ordering::SeqCst), 1);
        assert_eq!(h.activity_count(), 0);
    }

    /// Each guest `Settled` frame gates the next step; every step gets a
    /// fresh watch (fresh settling detector).
    #[tokio::test(start_paused = true)]
    async fn staged_descent_steps_on_settled_frames() {
        const STEP: u64 = super::super::SHRINK_STEP;
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let watches: Vec<_> = (0..6).map(|_| deps.push_watch()).collect();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;

        let expected = [
            FULL - STEP,     // 14 GiB
            FULL - 2 * STEP, // 12 GiB
            FULL - 3 * STEP, // 10 GiB
            FULL - 4 * STEP, // 8 GiB
            FULL - 5 * STEP, // 6 GiB
            FINAL_TARGET,    // clamp
        ];
        for (i, watch) in watches.iter().enumerate().take(expected.len() - 1) {
            watch.send(WatchFrame::Settled).unwrap();
            h.settle().await;
            assert_eq!(
                h.targets(),
                expected[..=i].to_vec(),
                "settling alone must not step — the dwell paces the descent"
            );
            tokio::time::advance(STEP_DWELL).await;
            h.settle().await;
            assert_eq!(h.targets(), expected[..i + 2].to_vec());
        }
        assert_eq!(
            h.deps.watches_opened.load(Ordering::SeqCst),
            expected.len(),
            "each step must get a fresh watch"
        );
        assert_eq!(h.activity_count(), 0, "descent is not activity");

        // At the final target, further Settled frames change nothing.
        watches[5].send(WatchFrame::Settled).unwrap();
        h.settle().await;
        assert_eq!(h.targets(), expected.to_vec());
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_mid_descent_restores_full() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let first = deps.push_watch();
        let _second = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;
        first.send(WatchFrame::Settled).unwrap();
        h.settle().await;
        tokio::time::advance(STEP_DWELL).await;
        h.settle().await;

        // Pressure during the second step: full restore, not a re-step.
        h.watch_senders()[1].send(WatchFrame::Pressure).unwrap();
        h.settle().await;
        assert_eq!(
            h.targets(),
            vec![FIRST_STEP, FULL - 2 * super::super::SHRINK_STEP, FULL]
        );
        assert_eq!(h.activity_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn enter_idle_busy_guest_notes_activity_without_shrinking() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(GuestStats {
            loadavg1: 3.0,
            ..idle_stats()
        }));
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;

        assert!(h.targets().is_empty(), "busy guest must not be shrunk");
        assert_eq!(h.activity_count(), 1, "controller must exit idle");
    }

    /// Incident guard: no stats ⇒ no shrink; the entry probe retries later
    /// instead of squeezing an unknown guest.
    #[tokio::test(start_paused = true)]
    async fn enter_idle_without_stats_retries_later() {
        let deps = FakeDeps::new(Some(FULL));
        // First probe: unreachable. Retry: reachable.
        deps.push_stats(None);
        deps.push_stats(Some(idle_stats()));
        let _watch = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;
        assert!(h.targets().is_empty(), "no stats ⇒ no shrink");

        tokio::time::advance(IDLE_ENTRY_RETRY).await;
        h.settle().await;
        assert_eq!(h.targets(), vec![FIRST_STEP], "retry must re-probe");
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_event_restores_full_and_notes_activity() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let watch = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;

        watch.send(WatchFrame::Pressure).unwrap();
        h.settle().await;

        assert_eq!(h.targets(), vec![FIRST_STEP, FULL]);
        assert_eq!(h.activity_count(), 1);
    }

    /// Incident guard: a guest too starved to answer is exactly the one that
    /// needs its memory back — silence past the keepalive budget fails open.
    #[tokio::test(start_paused = true)]
    async fn watch_silence_fails_open() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let watch = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;
        assert_eq!(h.targets(), vec![FIRST_STEP]);

        // No frames at all: silence past the deadline.
        tokio::time::advance(WATCH_SILENCE_DEADLINE + Duration::from_secs(1)).await;
        h.settle().await;

        assert_eq!(h.targets(), vec![FIRST_STEP, FULL]);
        assert_eq!(h.activity_count(), 1);
        drop(watch);
    }

    #[tokio::test(start_paused = true)]
    async fn watch_transport_error_fails_open() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let watch = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;

        // Close the channel from every end (the deps keep a clone of each
        // sender for mid-descent scripting) → transport error.
        drop(watch);
        h.deps.watch_senders.lock().unwrap().clear();
        h.settle().await;

        assert_eq!(h.targets(), vec![FIRST_STEP, FULL]);
        assert_eq!(h.activity_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn window_elapsed_reopens_watch() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let first = deps.push_watch();
        let _second = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;

        first.send(WatchFrame::WindowElapsed).unwrap();
        h.settle().await;

        assert_eq!(h.deps.watches_opened.load(Ordering::SeqCst), 2);
        assert_eq!(
            h.targets(),
            vec![FIRST_STEP],
            "no spurious restore, no step"
        );
        assert_eq!(h.activity_count(), 0);
    }

    /// Old agents don't implement the watch RPC: the controller must degrade
    /// to stats polling and still fail open on unreachability.
    #[tokio::test(start_paused = true)]
    async fn watch_unsupported_degrades_to_polling_and_fails_open() {
        let mut deps = FakeDeps::new(Some(FULL));
        deps.watch_supported = false;
        deps.push_stats(Some(idle_stats())); // entry probe
        // First poll: healthy. Second poll: unreachable (no queued stats).
        deps.push_stats(Some(idle_stats()));
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;
        assert_eq!(h.targets(), vec![FIRST_STEP]);

        tokio::time::advance(DEGRADED_POLL_INTERVAL).await;
        h.settle().await;
        assert_eq!(h.activity_count(), 0, "healthy poll must not fail open");
        assert_eq!(
            h.targets(),
            vec![FIRST_STEP, FULL - 2 * super::super::SHRINK_STEP],
            "a healthy poll is the degraded mode's settle signal"
        );

        tokio::time::advance(DEGRADED_POLL_INTERVAL).await;
        h.settle().await;
        assert_eq!(
            h.targets(),
            vec![FIRST_STEP, FULL - 2 * super::super::SHRINK_STEP, FULL]
        );
        assert_eq!(h.activity_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn polling_low_available_fails_open() {
        let mut deps = FakeDeps::new(Some(FULL));
        deps.watch_supported = false;
        deps.push_stats(Some(idle_stats())); // entry probe
        deps.push_stats(Some(GuestStats {
            available: PRESSURE_MIN_AVAILABLE / 2,
            ..idle_stats()
        }));
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;

        tokio::time::advance(DEGRADED_POLL_INTERVAL).await;
        h.settle().await;

        assert_eq!(h.targets(), vec![FIRST_STEP, FULL]);
        assert_eq!(h.activity_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn exit_idle_restores_full() {
        let deps = FakeDeps::new(Some(FULL));
        deps.push_stats(Some(idle_stats()));
        let _watch = deps.push_watch();
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;
        h.commands.send(BalloonCommand::ExitIdle).unwrap();
        h.settle().await;

        assert_eq!(h.targets(), vec![FIRST_STEP, FULL]);
        assert_eq!(h.activity_count(), 0, "plain exit is not new activity");
    }

    #[tokio::test(start_paused = true)]
    async fn exit_idle_without_shrink_touches_nothing() {
        let deps = FakeDeps::new(Some(FULL));
        // Entry probe fails → IdleUnshrunk.
        let h = Harness::spawn(deps);

        h.commands.send(BalloonCommand::EnterIdle).unwrap();
        h.settle().await;
        h.commands.send(BalloonCommand::ExitIdle).unwrap();
        h.settle().await;

        assert!(h.targets().is_empty());
        assert_eq!(h.activity_count(), 0);
    }
}
