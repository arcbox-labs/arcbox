//! Idle-balloon regression e2e (2026-07-15 incident → 2026-07-29 verdict).
//!
//! History: the 2026-07-15 incident (an unconditional shrink to 128 MB
//! starved a running compose stack for 18 hours) led to the usage-aware
//! staged-descent redesign this test originally exercised. The 2026-07-29
//! measurements then showed no macOS backend actually reclaims ballooned
//! memory (VZ: Apple applies no madvise at all; HV: `MADV_DONTNEED` is a
//! Darwin deactivation hint) — shrinking was guest starvation with zero
//! host benefit, so the idle balloon is disabled on macOS entirely. See
//! `app/arcbox-core/src/vm_lifecycle/balloon/mod.rs` for the evidence.
//!
//! This scenario pins the new contract on a real VZ daemon with a short
//! idle timeout, while a container runs in the guest and a persistent
//! `docker events` subscription is held open (the desktop-UI shape that
//! once pinned `active_ops` and disabled idle handling outright):
//!
//! - idle must still ENGAGE (the disabled-balloon line is the witness);
//! - the balloon must never shrink or restore — no descent, no
//!   `Out of puff` reclaim storm, no 8.5-minute shrink/restore cycle;
//! - Docker must be responsive afterwards.
//!
//! Balloon moves have no RPC surface; the daemon log is the only oracle
//! for them. That is an explicit exception to the "readiness only via
//! `WatchSetupStatus`" rule — readiness itself still uses `wait_ready`.

use std::path::Path;
use std::sync::Once;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::{docker_output, docker_stream, ensure_image};
use arcbox_e2e::metrics::RunMetrics;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Idle timeout under test (knob). The actor's idle ticker runs every 10s,
/// so idle entry lands within ~30s of the last docker call.
const IDLE_TIMEOUT_SECS: u64 = 20;
/// Budget for observing the disabled-balloon line in the daemon log.
const IDLE_BUDGET: Duration = Duration::from_secs(120);
/// Quiet window after idle entry in which no shrink may appear. Longer
/// than `IDLE_ENTRY_RETRY` (30s), so a regression that arms the retry
/// timer instead of staying inert is caught too.
const QUIET_WINDOW: Duration = Duration::from_secs(90);
/// Ceiling for one docker CLI invocation.
const DOCKER_ATTEMPT: Duration = Duration::from_secs(30);

fn init_tracing() {
    TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

#[test]
#[ignore = "boots a VZ System VM through a real daemon and verifies idle entry never shrinks the balloon"]
fn idle_entry_never_shrinks_on_macos() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-idle-balloon-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            (
                "ARCBOX_IDLE_TIMEOUT_SECS".to_owned(),
                IDLE_TIMEOUT_SECS.to_string(),
            ),
        ],
    })?;

    let mut metrics = RunMetrics::new("idle_balloon", Some("vz"));
    let result = scenario(&mut daemon, data_dir.path(), &mut metrics);
    metrics.passed = result.is_ok();
    if let Err(error) = metrics.write(Some(data_dir.path())) {
        tracing::warn!("writing run metrics failed: {error:#}");
    }
    if result.is_err() {
        let kept = data_dir.keep();
        tracing::warn!(path = %kept.display(), "preserving test directory");
    }
    result
}

fn scenario(daemon: &mut DaemonHandle, data_dir: &Path, metrics: &mut RunMetrics) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;

    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
    metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

    // Persistent observer, held open for the whole cycle: idle entry below
    // must engage despite this live `/events` subscription.
    let mut events = docker_stream(data_dir, &["events"]).context("subscribing to events")?;

    // An in-guest workload: container load never counts as host activity
    // (the incident shape), so it must not block idle entry either.
    metrics.time("workload_start", || {
        docker_output(
            data_dir,
            &["run", "-d", "--name", "workload", &image, "sleep", "900"],
            DOCKER_ATTEMPT,
        )
        .context("starting workload container")
    })?;

    // Phase 1 — idle must engage, and the balloon gate must answer it with
    // the disabled line (not a shrink).
    let disabled = metrics.time("idle_disabled", || {
        wait_for_log(data_dir, "idle balloon disabled", IDLE_BUDGET)
    })?;
    tracing::info!(line = %disabled, "idle entry answered by the disabled gate");

    // Phase 2 — the quiet window: nothing balloon-shaped may happen. This
    // is the anti-regression for both the descent (would log a shrink) and
    // the thrash cycle (would log a restore + Out-of-puff storm).
    metrics.time("quiet_window", || -> Result<()> {
        let deadline = Instant::now() + QUIET_WINDOW;
        while Instant::now() < deadline {
            for forbidden in ["idle balloon shrunk", "balloon restored to full memory"] {
                if log_contains(data_dir, forbidden)? {
                    bail!("daemon log contains {forbidden:?} — the reclaim gate did not hold");
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    })?;
    let storm_lines = count_log_matches(data_dir, "Out of puff")?;
    if storm_lines > 0 {
        bail!("guest logged {storm_lines} 'Out of puff' lines with the balloon disabled");
    }

    // Phase 3 — Docker responsive after the idle window (this call also
    // exits idle, which must work without any balloon bookkeeping).
    metrics.time("docker_after_idle", || {
        docker_output(data_dir, &["ps"], Duration::from_secs(10)).context("docker ps after idle")
    })?;

    // The whole cycle ran under a live events subscription — prove the
    // observer survived, so idle entry above really engaged despite it.
    events
        .assert_alive()
        .context("events subscription died mid-scenario")?;

    docker_output(data_dir, &["rm", "-f", "workload"], DOCKER_ATTEMPT).ok();
    Ok(())
}

/// The daemon's own rotating log (structured JSON lines).
fn daemon_log_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("log/daemon.log")
}

fn read_log(data_dir: &Path) -> Result<String> {
    let path = daemon_log_path(data_dir);
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

fn log_contains(data_dir: &Path, needle: &str) -> Result<bool> {
    Ok(read_log(data_dir)?.contains(needle))
}

fn count_log_matches(data_dir: &Path, needle: &str) -> Result<usize> {
    Ok(read_log(data_dir)?.matches(needle).count())
}

/// Polls the daemon log for a line containing `needle`, returning that line.
fn wait_for_log(data_dir: &Path, needle: &str, budget: Duration) -> Result<String> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(line) = read_log(data_dir)?.lines().find(|l| l.contains(needle)) {
            return Ok(line.to_owned());
        }
        if Instant::now() >= deadline {
            bail!("daemon log never contained {needle:?} within budget");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
