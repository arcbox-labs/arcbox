//! Host sleep/wake observation (macOS).
//!
//! Neither macOS backend steps the guest wall clock across a host sleep: the
//! guest's vCPUs stop, and on wake the guest is behind by the accumulated
//! sleep time. Containers then write timestamps hours in the past and TLS
//! certificate validation fails on `docker pull` (ABX-518, GH #574).
//!
//! The daemon therefore watches IOKit's system power notifications and
//! re-pushes the host clock on every wake. `IORegisterForSystemPower`
//! delivers on a CFRunLoop, which is why this owns a dedicated thread rather
//! than living in the tokio reactor.
//!
//! **Acknowledging sleep is mandatory**: `kIOMessageCanSystemSleep` and
//! `kIOMessageSystemWillSleep` each hold the system's sleep transition until
//! every registered client answers or a ~30 s timeout expires. Dropping the
//! ack would make the daemon delay every sleep on the machine.

use std::ffi::c_void;
use std::future::Future;
use std::sync::Arc;

use arcbox_core::Runtime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Retry budget for the post-wake sync. Network-independent (vsock), but the
/// guest needs a moment to schedule the agent after a long sleep.
const WAKE_SYNC_ATTEMPTS: usize = 3;
const WAKE_SYNC_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Spawns the host power observer and the task that re-syncs the guest clock
/// on wake. No-op off macOS, where the host clock reaches the guest through
/// the platform's own mechanisms.
pub fn spawn_wake_clock_sync(runtime: &Arc<Runtime>, shutdown: &CancellationToken) {
    #[cfg(target_os = "macos")]
    {
        let (tx, rx) = mpsc::channel(1);
        if let Err(error) = imp::spawn_observer(tx, shutdown.clone()) {
            warn!(%error, "host wake observer unavailable; guest clock will not re-sync after sleep");
            return;
        }
        let runtime = Arc::clone(runtime);
        let shutdown = shutdown.clone();
        drop(tokio::spawn(async move {
            wake_sync_loop(rx, runtime, shutdown).await;
        }));
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (runtime, shutdown);
    }
}

/// Re-syncs the guest clock for every wake event until shutdown.
///
/// Best effort by design: the VM may legitimately be down (`Ok(false)`), and
/// a failed ping must not take the daemon with it — the boot path syncs the
/// clock again on the next readiness.
async fn wake_sync_loop(
    mut wakes: mpsc::Receiver<()>,
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            wake = wakes.recv() => {
                if wake.is_none() {
                    break;
                }
                let runtime = Arc::clone(&runtime);
                sync_after_wake(
                    || {
                        let runtime = Arc::clone(&runtime);
                        async move { runtime.sync_system_vm_clock().await }
                    },
                    &shutdown,
                )
                .await;
            }
        }
    }
}

/// Runs one post-wake sync, retrying a transient failure.
///
/// `sync` reports `Ok(true)` when the clock was pushed, `Ok(false)` when
/// there was no ready VM to push it to (not an error, and not worth
/// retrying — the boot path will sync on the next readiness).
async fn sync_after_wake<F, Fut>(sync: F, shutdown: &CancellationToken)
where
    F: Fn() -> Fut,
    Fut: Future<Output = arcbox_core::Result<bool>>,
{
    for attempt in 1..=WAKE_SYNC_ATTEMPTS {
        match sync().await {
            Ok(true) => {
                info!("guest wall clock re-synced after host wake");
                return;
            }
            Ok(false) => {
                debug!("host wake: System VM not ready, nothing to re-sync");
                return;
            }
            Err(error) if attempt == WAKE_SYNC_ATTEMPTS => {
                warn!(%error, "guest clock re-sync after host wake failed");
                return;
            }
            Err(error) => {
                debug!(%error, attempt, "guest clock re-sync failed; retrying");
            }
        }
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(WAKE_SYNC_RETRY_DELAY) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{WAKE_SYNC_ATTEMPTS, sync_after_wake};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    fn transient_error() -> arcbox_core::CoreError {
        arcbox_core::CoreError::Vm("agent not reachable yet".to_owned())
    }

    /// The guest needs a moment to schedule its agent after a long sleep, so
    /// a first-attempt failure must not lose the wake — that would leave the
    /// clock hours behind until the next boot.
    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_is_retried_until_the_clock_lands() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        sync_after_wake(
            || {
                let seen = Arc::clone(&seen);
                async move {
                    if seen.fetch_add(1, Ordering::Relaxed) == 0 {
                        Err(transient_error())
                    } else {
                        Ok(true)
                    }
                }
            },
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(calls.load(Ordering::Relaxed), 2, "the retry must have run");
    }

    /// A wake with no VM up is a normal outcome, not a failure to retry:
    /// retrying would burn the budget waiting for a VM nobody started.
    #[tokio::test(start_paused = true)]
    async fn a_vm_that_is_not_ready_ends_the_attempt_immediately() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        sync_after_wake(
            || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::Relaxed);
                    Ok(false)
                }
            },
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_persistent_failure_gives_up_after_the_budget() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        sync_after_wake(
            || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::Relaxed);
                    Err(transient_error())
                }
            },
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(calls.load(Ordering::Relaxed), WAKE_SYNC_ATTEMPTS);
    }

    /// Shutdown must preempt the retry backoff; otherwise a daemon stopping
    /// right after a wake waits out the full budget before exiting.
    #[tokio::test(start_paused = true)]
    async fn shutdown_preempts_the_retry_backoff() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let elapsed = tokio::time::Instant::now();
        sync_after_wake(
            || {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::Relaxed);
                    Err(transient_error())
                }
            },
            &shutdown,
        )
        .await;
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(elapsed.elapsed() < Duration::from_secs(1));
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{CancellationToken, c_void, debug, mpsc};

    /// IOKit power-message values, expanded from `IOMessage.h`'s
    /// `iokit_common_msg(x)` = `sys_iokit | sub_iokit_common | x`, where
    /// `sys_iokit = err_system(0x38) = 0xE000_0000` and
    /// `sub_iokit_common = err_sub(0) = 0`.
    const K_IO_MESSAGE_CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
    const K_IO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;
    const K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON: u32 = 0xE000_0300;

    type IoConnectT = u32;
    type IoObjectT = u32;
    type IoServiceT = u32;
    type IoReturnT = i32;
    type IoNotificationPortRef = *mut c_void;
    type CfRunLoopSourceRef = *mut c_void;
    type CfRunLoopRef = *mut c_void;
    type CfStringRef = *const c_void;

    type IoServiceInterestCallback =
        unsafe extern "C" fn(refcon: *mut c_void, service: IoServiceT, msg: u32, arg: *mut c_void);

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IORegisterForSystemPower(
            refcon: *mut c_void,
            port: *mut IoNotificationPortRef,
            callback: IoServiceInterestCallback,
            notifier: *mut IoObjectT,
        ) -> IoConnectT;
        fn IODeregisterForSystemPower(notifier: *mut IoObjectT) -> IoReturnT;
        fn IONotificationPortGetRunLoopSource(port: IoNotificationPortRef) -> CfRunLoopSourceRef;
        fn IONotificationPortDestroy(port: IoNotificationPortRef);
        fn IOAllowPowerChange(connect: IoConnectT, arg: isize) -> IoReturnT;
        fn IOServiceClose(connect: IoConnectT) -> IoReturnT;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopDefaultMode: CfStringRef;
        fn CFRunLoopGetCurrent() -> CfRunLoopRef;
        fn CFRunLoopAddSource(rl: CfRunLoopRef, source: CfRunLoopSourceRef, mode: CfStringRef);
        fn CFRunLoopRemoveSource(rl: CfRunLoopRef, source: CfRunLoopSourceRef, mode: CfStringRef);
        fn CFRunLoopRunInMode(mode: CfStringRef, seconds: f64, return_after_source: u8) -> i32;
    }

    /// How long the run loop blocks between shutdown checks. The callback
    /// fires from inside `CFRunLoopRunInMode`, so this only bounds how long
    /// teardown waits, not notification latency.
    const RUN_LOOP_TICK_SECS: f64 = 1.0;

    /// State the IOKit callback needs. Lives for the observer thread's whole
    /// life and is only touched from that thread's run loop.
    struct Observer {
        root_port: IoConnectT,
        wakes: mpsc::Sender<()>,
    }

    /// IOKit power-notification callback. Runs on the observer thread's run
    /// loop.
    ///
    /// # Safety
    ///
    /// `refcon` must be the `Observer` pointer passed to
    /// `IORegisterForSystemPower`, valid for the run loop's lifetime.
    unsafe extern "C" fn on_power_message(
        refcon: *mut c_void,
        _service: IoServiceT,
        msg: u32,
        arg: *mut c_void,
    ) {
        // SAFETY: refcon is the Observer we registered; it outlives the run
        // loop, and only this thread's run loop dereferences it.
        let observer = unsafe { &*refcon.cast::<Observer>() };
        match msg {
            // Both sleep messages must be acknowledged or the system's sleep
            // transition stalls on this process for ~30 s. We never veto.
            K_IO_MESSAGE_CAN_SYSTEM_SLEEP | K_IO_MESSAGE_SYSTEM_WILL_SLEEP => {
                // SAFETY: root_port is the live connection from registration;
                // `arg` is the notification token IOKit expects back.
                unsafe { IOAllowPowerChange(observer.root_port, arg as isize) };
            }
            K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON => {
                // A full-capacity channel already has a wake pending — the
                // sync reads the clock when it runs, so coalescing is exact.
                // DarkWake delivers this too; a redundant sync is harmless.
                if observer.wakes.try_send(()).is_err() {
                    debug!("host wake: sync already pending");
                }
            }
            _ => {}
        }
    }

    /// Registers for system power notifications on a dedicated run-loop
    /// thread, sending `()` on every wake.
    ///
    /// # Errors
    /// Returns an error if IOKit registration fails.
    pub(super) fn spawn_observer(
        wakes: mpsc::Sender<()>,
        shutdown: CancellationToken,
    ) -> std::io::Result<()> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("arcbox-power".to_owned())
            .spawn(move || run_observer(&wakes, &shutdown, &ready_tx))?;
        // Registration happens on that thread; surface its outcome here so a
        // failure is reported by the caller rather than only logged.
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::other(
                "power observer thread exited before registering",
            )),
        }
    }

    fn run_observer(
        wakes: &mpsc::Sender<()>,
        shutdown: &CancellationToken,
        ready: &std::sync::mpsc::Sender<std::io::Result<()>>,
    ) {
        let mut port: IoNotificationPortRef = std::ptr::null_mut();
        let mut notifier: IoObjectT = 0;
        // Boxed so the address stays valid while IOKit holds it; the box is
        // dropped only after deregistration below.
        let mut observer = Box::new(Observer {
            root_port: 0,
            wakes: wakes.clone(),
        });
        let refcon = (&raw mut *observer).cast::<c_void>();

        // SAFETY: out-params are valid locals; `refcon` outlives the
        // registration (dropped after IODeregisterForSystemPower below).
        let root_port = unsafe {
            IORegisterForSystemPower(refcon, &raw mut port, on_power_message, &raw mut notifier)
        };
        if root_port == 0 || port.is_null() {
            let _ = ready.send(Err(std::io::Error::other(
                "IORegisterForSystemPower failed",
            )));
            return;
        }
        // The callback acks sleep through this connection, so it must be set
        // before the source joins the run loop.
        observer.root_port = root_port;

        // SAFETY: `port` is the live notification port from registration.
        let source = unsafe { IONotificationPortGetRunLoopSource(port) };
        // SAFETY: attaching a valid source to this thread's run loop.
        let run_loop = unsafe { CFRunLoopGetCurrent() };
        // SAFETY: all three handles are valid and belong to this thread.
        unsafe { CFRunLoopAddSource(run_loop, source, kCFRunLoopDefaultMode) };
        let _ = ready.send(Ok(()));

        while !shutdown.is_cancelled() {
            // SAFETY: running this thread's own run loop; the callback fires
            // from inside and only touches `observer`.
            unsafe { CFRunLoopRunInMode(kCFRunLoopDefaultMode, RUN_LOOP_TICK_SECS, 0) };
        }

        // Teardown order is load-bearing: stop delivery (deregister + detach
        // the source) before the port and the callback's context go away, or
        // IOKit can call into freed memory.
        // SAFETY: every handle below is live and released exactly once.
        unsafe {
            IODeregisterForSystemPower(&raw mut notifier);
            CFRunLoopRemoveSource(run_loop, source, kCFRunLoopDefaultMode);
            IONotificationPortDestroy(port);
            IOServiceClose(root_port);
        }
        drop(observer);
    }
}
