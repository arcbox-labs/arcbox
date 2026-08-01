//! Daemon ownership lifecycle: the `flock` contract (ABX-293).
//!
//! `startup::lock::DaemonLock` is the mechanism that keeps two daemons from
//! driving the same data dir. Nothing tested it. These checks pin the
//! contract as implemented — which is **not** what ABX-293's description
//! assumed.
//!
//! **The lock is takeover, not exclusion.** The description expects a second
//! daemon to "exit with error". It does not. `DaemonLock::acquire` reads the
//! holder's PID, `SIGTERM`s it if it is an arcbox daemon, then takes a
//! *blocking* `LOCK_EX` and waits for the release. So the second daemon wins
//! and the first one leaves. `displaced_stale_daemon()` exists precisely to
//! report that a takeover happened. Asserting the description's behavior
//! would encode a defect that isn't there.
//!
//! **Why these are cheap.** The lock is taken in `acquire_daemon_lease`,
//! stage 2 of the startup pipeline — before assets and long before the
//! System VM. Every assertion here lands as soon as the lock changes hands,
//! so no test waits for READY. Boot assets are still staged so the daemons
//! behave normally rather than dying early on a missing asset.
//!
//! **Exit status is deliberately not asserted.** ABX-415 is a known teardown
//! bug where the daemon can exit on a signal *after* doing its work
//! correctly. Requiring exit code 0 would make these tests fail for a
//! defect they are not about. The lock and the socket are the observable
//! contract; the exit code is not yet trustworthy.

use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};

/// Ceiling for a daemon to reach `acquire_daemon_lease` (pipeline stage 2).
/// Generous: it covers process start and the host-prep stage before it.
const LOCK_TIMEOUT: Duration = Duration::from_secs(60);
/// Ceiling for a displaced daemon to release, or a killed one's lock to be
/// reclaimed by the kernel.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(100);

static BUILD: Once = Once::new();

// ---------------------------------------------------------------------------
// Lock probing
// ---------------------------------------------------------------------------

/// Whether the daemon lock at `path` is currently held by some process.
///
/// Mirrors what a starting daemon does — a non-blocking `LOCK_EX` — and
/// releases immediately on success, so the probe never becomes the blocker
/// the next daemon trips over.
fn lock_is_held(path: &Path) -> Result<bool> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;

    // SAFETY: `file` owns a valid fd for the duration of both calls.
    let acquired = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if acquired {
        // SAFETY: same fd, still owned.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return Ok(false);
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Ok(true);
    }
    bail!("unexpected flock error probing {}: {err}", path.display())
}

/// PID recorded in the lock file. Diagnostics only in the daemon, but a
/// useful identity check here: it tells us *which* daemon holds the lock.
fn lock_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Polls `condition` until it holds or `timeout` elapses.
fn wait_until(
    what: &str,
    timeout: Duration,
    mut condition: impl FnMut() -> Result<bool>,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if condition()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out after {timeout:?} waiting for {what}");
        }
        std::thread::sleep(POLL);
    }
}

/// True once the process has gone away (or become a zombie we can't signal).
fn process_gone(pid: u32) -> bool {
    // SAFETY: signal 0 performs error checking without delivering a signal.
    unsafe { libc::kill(pid.cast_signed(), 0) != 0 }
}

// ---------------------------------------------------------------------------
// Daemon scaffolding
// ---------------------------------------------------------------------------

/// Two daemons in one test need their own spawn path — `run_vz_scenario`
/// owns a single handle and a scenario closure.
struct Fixture {
    root: PathBuf,
    version: String,
    data_dir: tempfile::TempDir,
}

impl Fixture {
    fn new(name: &str) -> Result<Self> {
        let root = arcbox_e2e::repo_root();
        if !arcbox_e2e::env_flag("SKIP_BUILD") {
            let mut built = Ok(());
            BUILD.call_once(|| {
                built = (|| {
                    let shell = xshell::Shell::new()?;
                    shell.change_dir(&root);
                    xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
                    anyhow::Ok(())
                })();
            });
            built?;
        }
        let version = resolve_boot_version(&root)?;
        let data_dir = tempfile::Builder::new()
            .prefix(&format!("arcbox-{name}-"))
            .tempdir()?;
        // Staged so a daemon behaves normally instead of failing out at the
        // asset stage, which would release the lock mid-assertion.
        stage_dev_boot_assets(&root, data_dir.path(), &version)?;
        Ok(Self {
            root,
            version,
            data_dir,
        })
    }

    fn lock_file(&self) -> PathBuf {
        self.data_dir.path().join("run/daemon.lock")
    }

    /// Spawns a daemon against the fixture's shared data dir.
    fn spawn(&self) -> Result<DaemonHandle> {
        let dns_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .context("probing a free DNS port")?
            .port();
        DaemonHandle::spawn(DaemonConfig {
            binary: self.root.join("target/release/arcbox-daemon"),
            data_dir: self.data_dir.path().to_owned(),
            args: vec![],
            env: vec![
                ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), self.version.clone()),
                ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
                ("ARCBOX_DNS_PORT".to_owned(), dns_port.to_string()),
                ("RUST_LOG".to_owned(), "info".to_owned()),
            ],
        })
    }

    /// Blocks until some daemon holds the lock.
    fn wait_lock_held(&self) -> Result<()> {
        let lock = self.lock_file();
        wait_until("the daemon lock to be held", LOCK_TIMEOUT, || {
            lock_is_held(&lock)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A running daemon holds the lock and records its own PID in it.
#[test]
#[ignore = "spawns a signed daemon; run on the e2e runner"]
fn running_daemon_holds_the_lock() -> Result<()> {
    let fixture = Fixture::new("lock-held")?;
    let daemon = fixture.spawn()?;
    fixture.wait_lock_held()?;

    let pid = lock_pid(&fixture.lock_file());
    if pid != Some(daemon.pid()) {
        bail!(
            "lock file records PID {pid:?} but the daemon we spawned is {}",
            daemon.pid()
        );
    }
    Ok(())
}

/// A SIGKILLed daemon's lock is reclaimed by the kernel, and the next daemon
/// starts on the same data dir without a leftover socket blocking it.
///
/// This is the crash-recovery case: no cooperative cleanup runs, so anything
/// that has to be released must be released by the kernel.
#[test]
#[ignore = "spawns a signed daemon; run on the e2e runner"]
fn killed_daemon_releases_the_lock_for_the_next_one() -> Result<()> {
    let fixture = Fixture::new("lock-crash")?;

    let first = fixture.spawn()?;
    fixture.wait_lock_held()?;
    let first_pid = first.pid();

    // SIGKILL: no destructor, no cleanup — exactly the crash shape.
    // SAFETY: `first_pid` is a child we spawned and have not reaped.
    unsafe { libc::kill(first_pid.cast_signed(), libc::SIGKILL) };
    drop(first); // reaps the zombie

    let lock = fixture.lock_file();
    wait_until(
        "the kernel to release a killed daemon's lock",
        RELEASE_TIMEOUT,
        || Ok(!lock_is_held(&lock)?),
    )?;

    let second = fixture.spawn()?;
    fixture.wait_lock_held()?;
    let pid = lock_pid(&lock);
    if pid != Some(second.pid()) {
        bail!(
            "after a crash the replacement daemon should own the lock; file says {pid:?}, \
             replacement is {}",
            second.pid()
        );
    }
    Ok(())
}

/// A second daemon displaces a live one: it signals the holder, waits for
/// the release, and takes ownership.
///
/// Note this asserts *takeover*, not the "second daemon errors out" behavior
/// ABX-293's description assumed — see the module docs.
#[test]
#[ignore = "spawns two signed daemons; run on the e2e runner"]
fn second_daemon_displaces_the_first() -> Result<()> {
    let fixture = Fixture::new("lock-takeover")?;

    let first = fixture.spawn()?;
    fixture.wait_lock_held()?;
    let first_pid = first.pid();

    // The displaced daemon is terminated by the newcomer, not by us.
    let second = fixture.spawn()?;

    wait_until("the displaced daemon to exit", RELEASE_TIMEOUT, || {
        Ok(process_gone(first_pid))
    })?;

    let lock = fixture.lock_file();
    wait_until("the newcomer to own the lock", RELEASE_TIMEOUT, || {
        Ok(lock_is_held(&lock)? && lock_pid(&lock) == Some(second.pid()))
    })?;

    // Keep `first` alive as a handle so its Drop reaps the process.
    drop(first);
    Ok(())
}

/// A graceful shutdown releases the lock and removes the gRPC socket.
///
/// Exit status is not asserted — see the module docs on ABX-415.
#[test]
#[ignore = "spawns a signed daemon; run on the e2e runner"]
fn graceful_shutdown_releases_lock_and_socket() -> Result<()> {
    let fixture = Fixture::new("lock-shutdown")?;
    let daemon = fixture.spawn()?;
    fixture.wait_lock_held()?;

    // The gRPC socket appears in stage 3, right after the lock.
    let socket = daemon.grpc_socket();
    wait_until("the gRPC socket to appear", LOCK_TIMEOUT, || {
        Ok(socket.exists())
    })?;

    let status = daemon.shutdown().context("SIGTERM shutdown")?;
    tracing::info!(%status, "daemon stopped");

    let lock = fixture.lock_file();
    wait_until(
        "the lock to be released after SIGTERM",
        RELEASE_TIMEOUT,
        || Ok(!lock_is_held(&lock)?),
    )?;
    wait_until("the gRPC socket to be removed", RELEASE_TIMEOUT, || {
        Ok(!socket.exists())
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Probe self-check (no daemon, no VM)
// ---------------------------------------------------------------------------

/// The probe itself must distinguish held from free, and must not leave the
/// lock held — otherwise every assertion above would read "held" forever.
///
/// `flock` is per open-file-description, so a second open in this same
/// process is a faithful stand-in for another process.
#[test]
fn lock_probe_detects_held_and_frees_what_it_takes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("daemon.lock");

    assert!(!lock_is_held(&path)?, "a fresh lock file is not held");
    // Probing must not leave it held.
    assert!(!lock_is_held(&path)?, "the probe released what it acquired");

    let holder = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    // SAFETY: `holder` owns a valid fd for the duration of the call.
    assert_eq!(
        unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test could not take the lock it means to hold"
    );
    assert!(lock_is_held(&path)?, "a held lock must probe as held");

    drop(holder);
    assert!(
        !lock_is_held(&path)?,
        "closing the holder releases the lock"
    );
    Ok(())
}

#[test]
fn lock_pid_reads_what_the_daemon_writes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("daemon.lock");
    // The daemon writes `writeln!(file, "{pid}")` — trailing newline included.
    std::fs::write(&path, "4242\n")?;
    assert_eq!(lock_pid(&path), Some(4242));

    std::fs::write(&path, "")?;
    assert_eq!(lock_pid(&path), None, "an empty lock file has no PID");
    Ok(())
}
