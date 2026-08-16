//! The VMM process guard: one owner of the child, an exit everyone can
//! observe, and kill / wait / detach that never race the reaper.
//!
//! A spawned process is handed to one waiter task that owns the `fc-sdk`
//! handle and reaps the child the moment it exits, publishing the status on
//! a `watch` (state) and a `broadcast` (the port's `Exited` event, once).
//! Everyone else — the prepared VM, the handle, the driver — holds an
//! [`FcProcess`] and only ever reads the exit, signals the pid, or waits
//! on the watch. Because the waiter reaps eagerly, "alive" is answered
//! from the watch, never from the pid: a reaped pid is never probed or
//! signalled again. An adopted process (no child to wait on) is the one
//! exception, tracked by probing `/proc` until it is seen gone.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arcbox_vm_driver::{ExitStatus, VmEvent};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::sync::{broadcast, oneshot, watch};

use crate::error::{FcError, Result};

/// How long `kill` waits for the reaper after `SIGKILL` before giving up
/// and reporting [`FcError::ReapTimeout`] — the caller keeps its handle and
/// may retry.
pub const REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// How often an adopted process is probed while waiting for it to exit.
const PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// The exit status recorded for a process whose real status was never
/// observed: an adopted VMM that vanished, or a `wait` that failed.
pub const UNKNOWN_EXIT: ExitStatus = ExitStatus {
    code: None,
    signal: None,
};

/// A spawned VMM child the waiter task can own: `fc-sdk`'s process handle
/// in production, a plain `tokio` child in tests.
pub trait Vmm: Send + 'static {
    /// The child's pid, when the spawn reported one.
    fn pid(&self) -> Option<u32>;
    /// Wait for the child to exit and reap it.
    fn wait(&mut self) -> impl std::future::Future<Output = ExitStatus> + Send;
    /// Give the child up without killing it.
    fn release(self);
}

impl Vmm for fc_sdk::FirecrackerProcess {
    fn pid(&self) -> Option<u32> {
        Self::pid(self)
    }

    async fn wait(&mut self) -> ExitStatus {
        match Self::wait(self).await {
            Ok(Some(status)) => status.into(),
            Ok(None) | Err(_) => UNKNOWN_EXIT,
        }
    }

    fn release(self) {
        // The detached handle keeps nothing that would kill on drop.
        drop(self.detach());
    }
}

/// A live VMM process shared by everything that refers to it.
pub struct FcProcess {
    pid: u32,
    api_socket: PathBuf,
    exit: watch::Sender<Option<ExitStatus>>,
    events: broadcast::Sender<VmEvent>,
    ownership: Ownership,
}

enum Ownership {
    /// A waiter task owns the child; `detach` tells it to release.
    Owned {
        detach: Mutex<Option<oneshot::Sender<()>>>,
        detached: AtomicBool,
    },
    /// Found running; nobody here can reap it, so its exit is inferred by
    /// probing the pid.
    Adopted,
}

impl FcProcess {
    /// Take ownership of a spawned child: a waiter task reaps it and
    /// publishes its exit.
    ///
    /// Fails when the spawn reported no pid — the caller has nothing to
    /// signal and must not keep the process.
    pub fn spawn<C: Vmm>(child: C, api_socket: PathBuf) -> Result<Self> {
        let pid = child.pid().ok_or(FcError::NoPid)?;
        let (exit, _) = watch::channel(None);
        let (events, _) = broadcast::channel(16);
        let (detach_tx, detach_rx) = oneshot::channel();
        let process = Self {
            pid,
            api_socket,
            exit: exit.clone(),
            events: events.clone(),
            ownership: Ownership::Owned {
                detach: Mutex::new(Some(detach_tx)),
                detached: AtomicBool::new(false),
            },
        };
        tokio::spawn(waiter(child, exit, events, detach_rx));
        Ok(process)
    }

    /// Track a process this crate did not spawn.
    pub fn adopt(pid: u32, api_socket: PathBuf) -> Self {
        let (exit, _) = watch::channel(None);
        let (events, _) = broadcast::channel(16);
        Self {
            pid,
            api_socket,
            exit,
            events,
            ownership: Ownership::Adopted,
        }
    }

    /// The VMM's pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The Firecracker API socket, as the host connects to it.
    pub fn api_socket(&self) -> &Path {
        &self.api_socket
    }

    /// How the process ended, once it has. An adopted process is probed
    /// here; the first probe that finds it gone records [`UNKNOWN_EXIT`].
    pub fn exit_status(&self) -> Option<ExitStatus> {
        let recorded = *self.exit.borrow();
        if let Some(status) = recorded {
            return Some(status);
        }
        if matches!(self.ownership, Ownership::Adopted) && !probe_alive(self.pid) {
            return Some(publish(&self.exit, &self.events, UNKNOWN_EXIT));
        }
        None
    }

    /// `true` until the exit has been observed; never flips back.
    pub fn alive(&self) -> bool {
        self.exit_status().is_none()
    }

    /// The port's event stream: `Exited` once, when the process ends.
    pub fn events(&self) -> broadcast::Receiver<VmEvent> {
        self.events.subscribe()
    }

    /// A watch that flips to `Some` when the process exits.
    pub fn subscribe(&self) -> watch::Receiver<Option<ExitStatus>> {
        self.exit.subscribe()
    }

    /// Wait up to `timeout` for the exit; `None` if it did not come.
    pub async fn wait(&self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut rx = self.exit.subscribe();
        loop {
            if let Some(status) = self.exit_status() {
                return Some(status);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.ownership {
                Ownership::Owned { .. } => {
                    if tokio::time::timeout(remaining, rx.changed()).await.is_err() {
                        return None;
                    }
                }
                Ownership::Adopted => {
                    tokio::time::sleep(remaining.min(PROBE_INTERVAL)).await;
                }
            }
        }
    }

    /// `SIGKILL` the process unless it already exited, then wait for the
    /// reaper up to [`REAP_TIMEOUT`]. Idempotent: an exited process just
    /// reports its status.
    pub async fn kill(&self) -> Result<ExitStatus> {
        if let Some(status) = self.exit_status() {
            return Ok(status);
        }
        self.signal(Signal::SIGKILL)?;
        self.wait(REAP_TIMEOUT)
            .await
            .ok_or(FcError::ReapTimeout { pid: self.pid })
    }

    /// Best-effort `SIGKILL` for drop paths: no wait, no error.
    pub fn kill_now(&self) {
        if self.exit_status().is_none() {
            let _ = self.signal(Signal::SIGKILL);
        }
    }

    /// Release the child: nothing here kills it any more, and the waiter
    /// stops reaping. `Exited` is never reported for a detached process.
    pub fn detach(&self) {
        if let Ownership::Owned { detach, detached } = &self.ownership {
            detached.store(true, Ordering::Release);
            let tx = detach.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(tx) = tx {
                let _ = tx.send(());
            }
        }
    }

    /// `true` after [`detach`](Self::detach) (always `false` for an
    /// adopted process, which was never owned).
    pub fn is_detached(&self) -> bool {
        match &self.ownership {
            Ownership::Owned { detached, .. } => detached.load(Ordering::Acquire),
            Ownership::Adopted => false,
        }
    }

    fn signal(&self, signal: Signal) -> Result<()> {
        #[allow(
            clippy::cast_possible_wrap,
            reason = "Firecracker pid fits platform pid_t"
        )]
        match kill(Pid::from_raw(self.pid as i32), signal) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
            Err(source) => Err(FcError::Kill {
                pid: self.pid,
                source,
            }),
        }
    }
}

/// Records `status` unless an exit was already recorded, and returns the
/// one that stands; the `Exited` event is sent for the first only.
fn publish(
    exit: &watch::Sender<Option<ExitStatus>>,
    events: &broadcast::Sender<VmEvent>,
    status: ExitStatus,
) -> ExitStatus {
    let mut first = None;
    exit.send_if_modified(|slot| {
        if slot.is_some() {
            return false;
        }
        *slot = Some(status);
        first = Some(status);
        true
    });
    match first {
        Some(status) => {
            // A send error only means nobody is subscribed.
            let _ = events.send(VmEvent::Exited(status));
            status
        }
        None => exit.borrow().unwrap_or(UNKNOWN_EXIT),
    }
}

/// The child, held so a task dropped mid-wait releases a detached child
/// instead of letting the handle's own drop kill it.
struct Held<C: Vmm> {
    child: Option<C>,
    detached: bool,
}

impl<C: Vmm> Drop for Held<C> {
    fn drop(&mut self) {
        if self.detached
            && let Some(child) = self.child.take()
        {
            child.release();
        }
    }
}

async fn waiter<C: Vmm>(
    child: C,
    exit: watch::Sender<Option<ExitStatus>>,
    events: broadcast::Sender<VmEvent>,
    mut detach: oneshot::Receiver<()>,
) {
    let mut held = Held {
        child: Some(child),
        detached: false,
    };
    let outcome = {
        let child = held.child.as_mut().expect("held until the task ends");
        let wait = child.wait();
        tokio::pin!(wait);
        tokio::select! {
            status = &mut wait => Some(status),
            _ = &mut detach => None,
        }
    };
    match outcome {
        Some(status) => {
            publish(&exit, &events, status);
        }
        None => {
            held.detached = true;
        }
    }
}

/// `true` while `pid` names a live, unreaped process (a zombie counts as
/// gone on Linux, where its state is readable).
fn probe_alive(pid: u32) -> bool {
    #[allow(
        clippy::cast_possible_wrap,
        reason = "Firecracker pid fits platform pid_t"
    )]
    if kill(Pid::from_raw(pid as i32), None).is_err() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        // The state letter is the field after the parenthesized comm; comm
        // may itself contain spaces or parens, so split at the LAST ')'.
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .is_some_and(|state| state != "Z" && state != "X"),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// Plain `tokio` children standing in for Firecracker in this crate's
/// tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A plain `tokio` child stands in for Firecracker.
    pub struct Child(pub tokio::process::Child);

    impl Vmm for Child {
        fn pid(&self) -> Option<u32> {
            self.0.id()
        }

        async fn wait(&mut self) -> ExitStatus {
            self.0.wait().await.map_or(UNKNOWN_EXIT, Into::into)
        }

        fn release(self) {
            drop(self.0);
        }
    }

    /// An owned [`FcProcess`] over `program args`.
    pub fn spawn(program: &str, args: &[&str]) -> FcProcess {
        let child = tokio::process::Command::new(program)
            .args(args)
            .spawn()
            .expect("spawn test child");
        FcProcess::spawn(Child(child), PathBuf::from("/tmp/api.sock")).unwrap()
    }

    /// `true` while `pid` can be signalled.
    pub fn pid_exists(pid: u32) -> bool {
        #[allow(clippy::cast_possible_wrap, reason = "test pid")]
        kill(Pid::from_raw(pid as i32), None).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{pid_exists, spawn};
    use super::*;

    #[tokio::test]
    async fn exit_is_published_once_and_alive_flips_for_good() {
        let process = spawn("sh", &["-c", "exit 3"]);
        let mut events = process.events();
        let status = process
            .wait(Duration::from_secs(10))
            .await
            .expect("the child exits");
        assert_eq!(status, ExitStatus::exited(3));
        assert!(!process.alive());
        assert_eq!(process.exit_status(), Some(status));
        assert_eq!(events.recv().await.unwrap(), VmEvent::Exited(status));
        assert!(events.try_recv().is_err(), "Exited is delivered once");
        // Killing an exited process just reports the recorded status.
        assert_eq!(process.kill().await.unwrap(), status);
    }

    #[tokio::test]
    async fn kill_reaps_and_reports_the_signal() {
        let process = spawn("sleep", &["30"]);
        assert!(process.alive());
        let status = process.kill().await.unwrap();
        assert_eq!(status, ExitStatus::signaled(9));
        assert!(!process.alive());
        assert_eq!(process.kill().await.unwrap(), status);
        assert!(!pid_exists(process.pid()), "the child was reaped");
    }

    #[tokio::test]
    async fn detach_releases_the_child_without_killing_it() {
        let process = spawn("sleep", &["30"]);
        let pid = process.pid();
        process.detach();
        assert!(process.is_detached());
        // Give the waiter a chance to release.
        tokio::task::yield_now().await;
        drop(process);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(pid_exists(pid), "a detached child keeps running");
        #[allow(clippy::cast_possible_wrap, reason = "test pid")]
        kill(Pid::from_raw(pid as i32), Signal::SIGKILL).unwrap();
    }

    #[tokio::test]
    async fn an_adopted_process_is_tracked_by_probing() {
        let mut child = tokio::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let process = FcProcess::adopt(child.id().unwrap(), PathBuf::from("/tmp/api.sock"));
        assert!(process.alive());
        assert!(!process.is_detached());
        // Killed out from under us and reaped by its real parent, the probe
        // sees it gone and records an unknown exit — once.
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        let mut events = process.events();
        assert_eq!(process.exit_status(), Some(UNKNOWN_EXIT));
        assert!(!process.alive());
        assert_eq!(events.try_recv().unwrap(), VmEvent::Exited(UNKNOWN_EXIT));
        assert_eq!(process.exit_status(), Some(UNKNOWN_EXIT));
        assert!(events.try_recv().is_err(), "the exit is recorded once");
        assert_eq!(process.kill().await.unwrap(), UNKNOWN_EXIT);
    }

    #[tokio::test]
    async fn adopted_kill_signals_and_waits_for_the_pid_to_vanish() {
        let mut child = tokio::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let process = FcProcess::adopt(child.id().unwrap(), PathBuf::from("/tmp/api.sock"));
        // The real parent reaps once the signal lands.
        let reaper = tokio::spawn(async move { child.wait().await.unwrap() });
        assert_eq!(process.kill().await.unwrap(), UNKNOWN_EXIT);
        assert!(!process.alive());
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(reaper.await.unwrap().signal(), Some(9));
    }
}
