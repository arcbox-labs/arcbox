//! Idle-balloon regression e2e (2026-07-15 incident).
//!
//! The incident: a VM running containers idled after 5 quiet minutes, the
//! balloon was shrunk to an unconditional 128 MB, and nothing could ever
//! restore it — 18 hours of reclaim thrash with dockerd and the agent
//! starved unresponsive.
//!
//! This scenario replays the shape on a real VZ daemon with a short idle
//! timeout: hold a memory workload, let the VM idle-shrink, then grow the
//! workload *inside the guest* (no host API traffic, exactly like the
//! incident) and require the guest-driven pressure exit: balloon restored,
//! Docker responsive, no reclaim storm.
//!
//! The whole cycle runs under a persistent `docker events` subscription —
//! the desktop UI holds one for its entire lifetime, and counting that
//! passive stream as VM activity once pinned `active_ops` and disabled
//! idle reclaim outright on desktop installs.
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
use arcbox_e2e::docker::{docker_output, docker_stream};
use arcbox_e2e::metrics::RunMetrics;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Idle timeout under test (knob). The actor's idle ticker runs every 10s,
/// so the shrink lands within ~30s of the last docker call.
const IDLE_TIMEOUT_SECS: u64 = 20;
/// Budget for observing the idle shrink in the daemon log.
const SHRINK_BUDGET: Duration = Duration::from_secs(120);
/// Budget from ballast growth until the balloon must be restored. Covers
/// the slow path where growth lands while the guest is still settling and
/// the agent's never-settled cap (180 samples) has to fire.
const RESTORE_BUDGET: Duration = Duration::from_secs(150);
/// Ceiling for one docker CLI invocation.
const DOCKER_ATTEMPT: Duration = Duration::from_secs(30);
/// Delay inside the ballast container before it grows its memory. Sized
/// past the idle timeout (~20s) + ticker (10s) + the full staged descent
/// (~7 steps × 15s dwell) + the final step's settle, so growth hits a
/// shrunk, settled, armed guest and exercises the fast pressure path.
const BALLAST_GROW_DELAY_SECS: u64 = 180;

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
#[ignore = "boots a VZ System VM through a real daemon and drives an idle-shrink/pressure-restore cycle"]
fn idle_shrink_is_usage_aware_and_pressure_restores() -> Result<()> {
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

    // Persistent observer, held open for the whole cycle: the idle shrink
    // below must engage despite this live `/events` subscription.
    let mut events = docker_stream(data_dir, &["events"]).context("subscribing to events")?;

    // The ballast: hold ~256 MB immediately (tmpfs pages persist regardless
    // of process lifetime), then grow by 2 GiB after the VM has idled and
    // shrunk. The growth happens entirely inside the guest — no host API
    // traffic — exactly the incident shape. `--shm-size` matters: Docker's
    // default /dev/shm is 64 MB, which silently neuters the ballast.
    let ballast_script = format!(
        "dd if=/dev/zero of=/dev/shm/hold bs=1M count=256 && sleep {BALLAST_GROW_DELAY_SECS} && \
         dd if=/dev/zero of=/dev/shm/grow bs=1M count=2048; sleep 900"
    );
    metrics.time("ballast_start", || {
        docker_output(
            data_dir,
            &[
                "run",
                "-d",
                "--shm-size=3g",
                "--name",
                "ballast",
                &image,
                "sh",
                "-c",
                &ballast_script,
            ],
            DOCKER_ATTEMPT,
        )
        .context("starting ballast container")
    })?;
    let ballast_started = Instant::now();

    // Phase 1 — the idle shrink must be usage-aware.
    let shrink = metrics.time("idle_shrink", || {
        wait_for_log(
            data_dir,
            "idle balloon shrunk to guest usage + headroom",
            SHRINK_BUDGET,
        )
    })?;
    let target_mb =
        extract_u64_field(&shrink, "target_mb").context("shrink log line carries no target_mb")?;
    let final_mb =
        extract_u64_field(&shrink, "final_mb").context("shrink log line carries no final_mb")?;
    tracing::info!(target_mb, final_mb, "idle balloon descent started");
    if final_mb < 384 {
        bail!("final target {final_mb}MB below the 384MB floor (incident-style blind shrink?)");
    }
    if final_mb >= 16384 {
        bail!("final target {final_mb}MB is not usage-aware (no reclaim planned)");
    }

    // The staged dev agent must support the pressure watch; a fallback to
    // polling means a stale agent and would validate the wrong path.
    if log_contains(data_dir, "pressure watch unavailable")? {
        bail!("controller degraded to polling — staged agent lacks WatchMemoryPressure");
    }

    // Phase 2 — the shrink must survive the post-inflation transient.
    // Hardware regression guard: inflating the balloon evicts the page
    // cache, and the resulting refault burst once tripped a restore one
    // second after the shrink.
    let grow_at = ballast_started + Duration::from_secs(BALLAST_GROW_DELAY_SECS);
    let quiet_until = grow_at
        .checked_sub(Duration::from_secs(5))
        .unwrap_or(grow_at);
    metrics.time("shrink_survives_transient", || -> Result<()> {
        while Instant::now() < quiet_until {
            if log_contains(data_dir, "balloon restored to full memory")? {
                bail!("balloon restored before the in-guest growth");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    })?;

    // Phase 3 — in-guest growth must be answered by a guest-driven restore.
    let restore_deadline = grow_at + RESTORE_BUDGET;
    let restored = wait_for_log_until(
        data_dir,
        "balloon restored to full memory",
        restore_deadline,
    )?;
    let restore_latency = Instant::now().saturating_duration_since(grow_at);
    tracing::info!(line = %restored, latency_secs = restore_latency.as_secs(), "balloon restored");
    metrics.record("pressure_restore_latency", restore_latency.as_secs_f64());

    // The fast (armed) pressure path must have answered — not the bounded
    // never-settled cap. The staged descent exists precisely so the guest
    // settles and arms before real pressure can arrive.
    if !agent_log_contains(data_dir, "memory pressure detector armed")? {
        bail!("guest never armed — staged descent did not settle before growth");
    }
    if restore_latency > Duration::from_secs(30) {
        bail!(
            "restore took {}s — cap path, not the armed fast path",
            restore_latency.as_secs()
        );
    }

    // Phase 4 — the incident signature must be absent and Docker must be
    // responsive right after the restore.
    let storm_lines = count_log_matches(data_dir, "Out of puff")?;
    if storm_lines > 20 {
        bail!("guest logged {storm_lines} 'Out of puff' lines — reclaim storm not prevented");
    }
    metrics.time("docker_after_restore", || {
        docker_output(data_dir, &["ps"], Duration::from_secs(10)).context("docker ps after restore")
    })?;

    // The exit must have gone through the state machine (idle → running).
    if !log_contains(data_dir, r#""from":"idle","to":"running""#)? {
        bail!("balloon restore did not ride the lifecycle state machine");
    }

    // The whole cycle ran under a live events subscription — prove the
    // observer survived, so the shrink above really happened despite it.
    events
        .assert_alive()
        .context("events subscription died mid-scenario")?;

    docker_output(data_dir, &["rm", "-f", "ballast"], DOCKER_ATTEMPT).ok();
    Ok(())
}

/// Makes `image` available in the daemon under test, without depending on
/// registry reachability more than once per machine: the first successful
/// pull is cached as a tarball under `target/`, and later runs `docker load`
/// it (guest registry access is environment-dependent; pulls here have been
/// observed to black-hole intermittently).
fn ensure_image(data_dir: &Path, image: &str) -> Result<()> {
    let cache_dir = arcbox_e2e::repo_root().join("target/e2e-image-cache");
    let tar = cache_dir.join(format!(
        "{}.tar",
        image.replace(['/', ':'], "_").replace('.', "-")
    ));
    if tar.exists() {
        docker_output(
            data_dir,
            &["load", "-i", &tar.display().to_string()],
            Duration::from_secs(60),
        )
        .context("docker load from cache")?;
        return Ok(());
    }

    let mut last_err = None;
    for attempt in 1..=3 {
        match docker_output(data_dir, &["pull", image], Duration::from_secs(90)) {
            Ok(_) => {
                std::fs::create_dir_all(&cache_dir)?;
                docker_output(
                    data_dir,
                    &["save", "-o", &tar.display().to_string(), image],
                    Duration::from_secs(60),
                )
                .context("docker save to cache")?;
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(attempt, "docker pull failed: {e:#}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap()).context("docker pull (3 attempts)")
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

/// The guest agent's log, exported to the host via VirtioFS.
fn agent_log_contains(data_dir: &Path, needle: &str) -> Result<bool> {
    let path = data_dir.join("log/agent.log");
    if !path.exists() {
        return Ok(false);
    }
    Ok(std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .contains(needle))
}

fn count_log_matches(data_dir: &Path, needle: &str) -> Result<usize> {
    Ok(read_log(data_dir)?.matches(needle).count())
}

/// Polls the daemon log for a line containing `needle`, returning that line.
fn wait_for_log(data_dir: &Path, needle: &str, budget: Duration) -> Result<String> {
    wait_for_log_until(data_dir, needle, Instant::now() + budget)
}

fn wait_for_log_until(data_dir: &Path, needle: &str, deadline: Instant) -> Result<String> {
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

/// Extracts a numeric field (`"name":123`) from a structured log line.
fn extract_u64_field(line: &str, name: &str) -> Option<u64> {
    let key = format!("\"{name}\":");
    let rest = &line[line.find(&key)? + key.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}
