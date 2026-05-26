//! EnsureRuntime state machine (platform-independent, testable).
//!
//! Non-blocking semantics: the RPC never awaits the start sequence inline.
//! The first caller transitions `NotStarted`/`Failed` → `Starting`, spawns
//! the actual start work as a background task, and returns `STATUS_STARTING`
//! immediately. Subsequent callers see `Starting` and also return
//! `STATUS_STARTING`. Once the background task publishes its result:
//! - `Ready` → callers get cached endpoint/message with `STATUS_REUSED`.
//! - `Failed` → the *next* caller with `start_if_needed=true` transitions
//!   back to `Starting` and spawns a fresh start; callers don't observe a
//!   cached failed response because the expected recovery mode is "ask the
//!   agent to try again." Probe-only (`start_if_needed=false`) callers
//!   bypass the state machine and re-run `probe_fn`.
//!
//! Why non-blocking: the host-side vsock transport uses a short per-RPC
//! deadline (~5s). Blocking the RPC for the full cold-boot window (up to
//! ~90s waiting on containerd + dockerd) causes the daemon to close the
//! socketpair mid-call, and the agent's eventual response write fails with
//! EPIPE. Returning immediately keeps the RPC well under the deadline and
//! lets the daemon poll with its own backoff.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::OnceLock;

// STATUS_STARTED is still a valid terminal status the start task can report
// internally (persisted via `RuntimeState::Ready`'s message); callers see
// STATUS_REUSED once state is settled.
#[allow(unused_imports)]
pub use arcbox_constants::status::{
    RUNTIME_FAILED as STATUS_FAILED, RUNTIME_REUSED as STATUS_REUSED,
    RUNTIME_STARTED as STATUS_STARTED, RUNTIME_STARTING as STATUS_STARTING,
};
use arcbox_protocol::agent::RuntimeEnsureResponse;
use futures::FutureExt;
use tokio::sync::Mutex;

/// Runtime lifecycle state.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RuntimeState {
    /// No ensure has been attempted yet.
    NotStarted,
    /// A background start task is running.
    Starting,
    /// Runtime is confirmed ready.
    Ready { endpoint: String, message: String },
    /// Last start attempt failed; a new `start_if_needed=true` call will retry.
    Failed { message: String },
}

/// Global guard that serializes start attempts and caches the outcome.
#[allow(dead_code)]
pub struct RuntimeGuard {
    pub state: Mutex<RuntimeState>,
}

impl RuntimeGuard {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RuntimeState::NotStarted),
        }
    }
}

impl Default for RuntimeGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the global `RuntimeGuard` singleton as an `Arc`.
///
/// `Arc` (rather than `&'static RuntimeGuard`) lets callers cheaply clone the
/// guard and move an owned handle into the background start task — the
/// singleton state stays shared, but the spawn doesn't require borrowing
/// from a `'static` reference.
#[allow(dead_code)]
pub fn runtime_guard() -> Arc<RuntimeGuard> {
    static GUARD: OnceLock<Arc<RuntimeGuard>> = OnceLock::new();
    GUARD.get_or_init(|| Arc::new(RuntimeGuard::new())).clone()
}

/// Non-blocking EnsureRuntime handler.
///
/// - If state is `Ready`: returns the cached endpoint/message with `STATUS_REUSED`.
/// - If `start_if_needed == false`: invokes `probe_fn` and returns its result.
/// - If state is `Starting`: returns `STATUS_STARTING` immediately (daemon polls).
/// - Otherwise (`NotStarted` or `Failed`): transitions state to `Starting`,
///   spawns `make_start()` as a background task, and returns `STATUS_STARTING`.
///
/// The background task awaits the start future and publishes the outcome to
/// `guard.state` (transitioning to `Ready` or `Failed`). If the start future
/// panics, the task catches the unwind and publishes a `Failed` state so the
/// state machine always settles and the daemon's poll loop can make progress.
///
/// Both `make_start` and `probe_fn` are `FnOnce() -> Fut` (not bare futures)
/// so the caller does not construct a future on hot `Ready`/`Starting`
/// polling paths where neither will be invoked.
#[allow(dead_code)]
pub async fn ensure_runtime<F, Fut, P, PFut>(
    guard: Arc<RuntimeGuard>,
    start_if_needed: bool,
    make_start: F,
    probe_fn: P,
) -> RuntimeEnsureResponse
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = RuntimeEnsureResponse> + Send + 'static,
    P: FnOnce() -> PFut,
    PFut: Future<Output = RuntimeEnsureResponse>,
{
    // Fast path: Ready → return cached state.
    {
        let state = guard.state.lock().await;
        if let RuntimeState::Ready { endpoint, message } = &*state {
            return RuntimeEnsureResponse {
                ready: true,
                endpoint: endpoint.clone(),
                message: message.clone(),
                status: STATUS_REUSED.to_string(),
            };
        }
    }

    if !start_if_needed {
        return probe_fn().await;
    }

    // Decide whether to become the driver (spawn the background task).
    let become_driver = {
        let mut state = guard.state.lock().await;
        match &*state {
            RuntimeState::Ready { endpoint, message } => {
                // Another call finished while we waited for the lock.
                return RuntimeEnsureResponse {
                    ready: true,
                    endpoint: endpoint.clone(),
                    message: message.clone(),
                    status: STATUS_REUSED.to_string(),
                };
            }
            RuntimeState::Starting => false,
            RuntimeState::NotStarted | RuntimeState::Failed { .. } => {
                *state = RuntimeState::Starting;
                true
            }
        }
    };

    if become_driver {
        let fut = make_start();
        let guard_for_task = Arc::clone(&guard);
        tokio::spawn(async move {
            // Catch panics from the start future so a bug there can't leave
            // state stuck at `Starting` forever. `AssertUnwindSafe` is sound
            // here: we discard the inner future on panic and publish a
            // fresh `Failed` state directly.
            let response = match AssertUnwindSafe(fut).catch_unwind().await {
                Ok(resp) => resp,
                Err(panic_payload) => {
                    let message = panic_message(&panic_payload);
                    tracing::error!(
                        "ensure_runtime start task panicked: {}; marking runtime Failed",
                        message
                    );
                    RuntimeEnsureResponse {
                        ready: false,
                        endpoint: String::new(),
                        message: format!("runtime start panicked: {message}"),
                        status: STATUS_FAILED.to_string(),
                    }
                }
            };
            let mut state = guard_for_task.state.lock().await;
            *state = if response.ready {
                RuntimeState::Ready {
                    endpoint: response.endpoint.clone(),
                    message: response.message.clone(),
                }
            } else {
                RuntimeState::Failed {
                    message: response.message.clone(),
                }
            };
        });
    }

    // Either we just spawned, or another caller is already driving. Return
    // the pending marker so the daemon polls with backoff.
    RuntimeEnsureResponse {
        ready: false,
        endpoint: String::new(),
        message: "runtime start in progress".to_string(),
        status: STATUS_STARTING.to_string(),
    }
}

/// Best-effort extraction of a human-readable message from a panic payload.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic payload was not a string".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn make_ready_response() -> RuntimeEnsureResponse {
        RuntimeEnsureResponse {
            ready: true,
            endpoint: "vsock:2375".to_string(),
            message: "docker socket ready".to_string(),
            status: STATUS_STARTED.to_string(),
        }
    }

    fn make_failed_response() -> RuntimeEnsureResponse {
        RuntimeEnsureResponse {
            ready: false,
            endpoint: String::new(),
            message: "docker socket missing".to_string(),
            status: STATUS_FAILED.to_string(),
        }
    }

    /// Waits for the background task to settle state into Ready or Failed.
    async fn wait_settled(guard: &RuntimeGuard, deadline_ms: u64) -> RuntimeState {
        let deadline = std::time::Instant::now() + Duration::from_millis(deadline_ms);
        loop {
            {
                let state = guard.state.lock().await;
                match &*state {
                    RuntimeState::Ready { .. } | RuntimeState::Failed { .. } => {
                        return state.clone();
                    }
                    _ => {}
                }
            }
            if std::time::Instant::now() >= deadline {
                let state = guard.state.lock().await;
                return state.clone();
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn first_call_returns_starting_and_state_becomes_ready() {
        let guard = Arc::new(RuntimeGuard::new());

        let r = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { make_ready_response() },
            || async { unreachable!("probe should not be called when start_if_needed=true") },
        )
        .await;

        assert!(!r.ready);
        assert_eq!(r.status, STATUS_STARTING);

        let settled = wait_settled(&guard, 500).await;
        assert!(
            matches!(&settled, RuntimeState::Ready { .. }),
            "expected Ready, got {:?}",
            settled
        );
    }

    #[tokio::test]
    async fn second_call_after_ready_returns_reused() {
        let guard = Arc::new(RuntimeGuard::new());

        // Drive start + wait for Ready.
        let _ = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { make_ready_response() },
            || async { unreachable!() },
        )
        .await;
        let _ = wait_settled(&guard, 500).await;

        // Subsequent call hits fast path.
        let r = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { panic!("start_fn should not be called after Ready") },
            || async { unreachable!() },
        )
        .await;

        assert!(r.ready);
        assert_eq!(r.status, STATUS_REUSED);
        assert_eq!(r.endpoint, "vsock:2375");
    }

    #[tokio::test]
    async fn call_while_starting_returns_starting() {
        let guard = Arc::new(RuntimeGuard::new());
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_for_start = Arc::clone(&gate);

        // First call spawns start that blocks on `gate` — state stays Starting.
        let r1 = ensure_runtime(
            Arc::clone(&guard),
            true,
            move || {
                let gate = gate_for_start;
                async move {
                    gate.notified().await;
                    make_ready_response()
                }
            },
            || async { unreachable!() },
        )
        .await;
        assert_eq!(r1.status, STATUS_STARTING);

        // Second call while Starting returns immediately with Starting.
        let r2 = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { panic!("start_fn must not re-run while Starting") },
            || async { unreachable!() },
        )
        .await;
        assert!(!r2.ready);
        assert_eq!(r2.status, STATUS_STARTING);

        // Release the start task and wait for settlement.
        gate.notify_one();
        let settled = wait_settled(&guard, 500).await;
        assert!(matches!(settled, RuntimeState::Ready { .. }));
    }

    #[tokio::test]
    async fn failed_start_transitions_to_failed_and_retry_can_succeed() {
        let guard = Arc::new(RuntimeGuard::new());

        let _ = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { make_failed_response() },
            || async { unreachable!() },
        )
        .await;
        let settled = wait_settled(&guard, 500).await;
        assert!(matches!(settled, RuntimeState::Failed { .. }));

        // Retry: new start is spawned.
        let r = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { make_ready_response() },
            || async { unreachable!() },
        )
        .await;
        assert_eq!(r.status, STATUS_STARTING);
        let settled = wait_settled(&guard, 500).await;
        assert!(matches!(settled, RuntimeState::Ready { .. }));
    }

    #[tokio::test]
    async fn probe_only_does_not_spawn_start() {
        let guard = Arc::new(RuntimeGuard::new());

        let r = ensure_runtime(
            Arc::clone(&guard),
            false,
            || async { panic!("start_fn must not run when start_if_needed=false") },
            || async { make_failed_response() },
        )
        .await;

        assert!(!r.ready);
        assert_eq!(r.status, STATUS_FAILED);

        // State untouched.
        let state = guard.state.lock().await;
        assert!(matches!(&*state, RuntimeState::NotStarted));
    }

    #[tokio::test]
    async fn concurrent_callers_spawn_start_exactly_once() {
        let guard = Arc::new(RuntimeGuard::new());
        let start_count = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(5));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let guard = Arc::clone(&guard);
            let start_count = Arc::clone(&start_count);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                ensure_runtime(
                    guard,
                    true,
                    move || {
                        let start_count = Arc::clone(&start_count);
                        async move {
                            start_count.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            make_ready_response()
                        }
                    },
                    || async { unreachable!() },
                )
                .await
            }));
        }

        for h in handles {
            let r = h.await.unwrap();
            assert_eq!(r.status, STATUS_STARTING);
        }

        let settled = wait_settled(&guard, 500).await;
        assert!(matches!(settled, RuntimeState::Ready { .. }));
        assert_eq!(start_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn panic_in_start_task_transitions_to_failed() {
        let guard = Arc::new(RuntimeGuard::new());

        let r = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { panic!("boom from start_fn") },
            || async { unreachable!() },
        )
        .await;
        assert_eq!(r.status, STATUS_STARTING);

        // Without the catch_unwind guard, state would stay Starting forever.
        // With it, the panic is converted into Failed so the daemon's poll
        // loop has a terminal state to observe.
        let settled = wait_settled(&guard, 500).await;
        assert!(
            matches!(&settled, RuntimeState::Failed { .. }),
            "expected Failed after panic, got {:?}",
            settled
        );

        // A subsequent start_if_needed=true call retries cleanly.
        let r = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { make_ready_response() },
            || async { unreachable!() },
        )
        .await;
        assert_eq!(r.status, STATUS_STARTING);
        let settled = wait_settled(&guard, 500).await;
        assert!(matches!(settled, RuntimeState::Ready { .. }));
    }

    #[tokio::test]
    async fn probe_after_ready_returns_reused_without_running_probe() {
        let guard = Arc::new(RuntimeGuard::new());

        // Start + settle.
        let _ = ensure_runtime(
            Arc::clone(&guard),
            true,
            || async { make_ready_response() },
            || async { unreachable!() },
        )
        .await;
        let _ = wait_settled(&guard, 500).await;

        // Probe-only: fast path hits Ready before probe_fn is awaited.
        let r = ensure_runtime(
            Arc::clone(&guard),
            false,
            || async { panic!("start_fn must not run") },
            || async { panic!("probe_fn must not run when state is already Ready") },
        )
        .await;

        assert!(r.ready);
        assert_eq!(r.status, STATUS_REUSED);
    }
}
