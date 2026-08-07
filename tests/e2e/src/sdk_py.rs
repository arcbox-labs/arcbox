//! Runs the Python SDK's gated hello-world e2e
//! (`sdk/python/tests/test_e2e.py`) against an isolated daemon.
//!
//! The daemon side mirrors the sandbox smoke: release host binaries plus
//! musl guest agents, staged dev boot assets, an isolated data dir, and
//! readiness observed via `WatchSetupStatus`. The SDK side is
//! `uv run pytest tests/test_e2e.py` with `ARCBOX_SDK_E2E=1` and
//! `ARCBOX_SOCKET` pointing at the isolated daemon's gRPC socket.

use std::env;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use crate::daemon::{DaemonConfig, DaemonHandle};
use crate::metrics::RunMetrics;
use crate::{env_flag, repo_root};

/// Generous ceiling for daemon startup: asset staging, the cold
/// ~255 MiB runtime-binary download into the isolated data dir, VM boot,
/// and the agent — the same budget as the sandbox smoke (measured
/// 2026-08-07, where the sibling sdk_ts harness reached READY in 214 s).
const READY_TIMEOUT: Duration = Duration::from_secs(360);
/// Ceiling for the whole pytest run: two sandbox boots (sync + async
/// flavors) plus a handful of executions each. This only catches a
/// wedged runner.
const PYTEST_TIMEOUT: Duration = Duration::from_secs(600);

pub struct SdkPyConfig {
    pub skip_build: bool,
    pub keep_test_dir: bool,
    pub version: Option<String>,
}

impl SdkPyConfig {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            skip_build: env_flag("SKIP_BUILD"),
            keep_test_dir: env_flag("KEEP_TEST_DIR"),
            version: env::var("ARCBOX_BOOT_ASSET_VERSION").ok(),
        }
    }
}

pub fn run(config: SdkPyConfig) -> Result<()> {
    info!("starting Python SDK e2e");

    if !config.skip_build {
        // Same binary set as the sandbox smoke: the SDK drives the same
        // sandbox surface, so it needs vm-agent staged just the same.
        crate::sandbox::build_binaries()?;
    }

    let root = repo_root();
    let version = match config.version {
        Some(v) => v,
        None => crate::boot_assets::boot_version(&root.join("assets.lock"))?,
    };

    let temp_dir = tempfile::Builder::new()
        .prefix("arcbox-sdk-py-e2e-")
        .tempdir()
        .context("creating SDK e2e test directory")?;
    let data_dir = temp_dir.path().to_owned();

    crate::boot_assets::stage_dev_boot_assets(&root, &data_dir, &version)?;

    let mut metrics = RunMetrics::new("sdk_py", Some("vz"));
    let result = run_scenario(&root, &data_dir, &version, &mut metrics);
    metrics.passed = result.is_ok();
    match metrics.write(Some(&data_dir)) {
        Ok(paths) => {
            for path in paths {
                info!(path = %path.display(), "run metrics written");
            }
        }
        Err(error) => warn!("writing run metrics failed: {error:#}"),
    }

    if result.is_err() || config.keep_test_dir {
        let path = temp_dir.keep();
        warn!(path = %path.display(), "preserving test directory");
    }
    result
}

fn run_scenario(
    root: &Path,
    data_dir: &Path,
    version: &str,
    metrics: &mut RunMetrics,
) -> Result<()> {
    let sdk_dir = root.join("sdk/python");
    ensure_venv(&sdk_dir)?;

    // The sandbox surface needs nested virtualization, which VZ provides.
    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version.to_owned()),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
        ],
    })?;

    let ready_started = Instant::now();
    daemon.wait_ready_blocking(READY_TIMEOUT)?;
    metrics.record("daemon_ready", ready_started.elapsed().as_secs_f64());
    info!(
        elapsed_seconds = ready_started.elapsed().as_secs(),
        "daemon ready"
    );

    let scenario = metrics.time("sdk_pytest", || pytest(&sdk_dir, &daemon.grpc_socket()));

    // Always shut the daemon down; a teardown failure must not mask the
    // scenario result.
    match daemon.shutdown() {
        Ok(status) => info!(%status, "daemon stopped"),
        Err(error) => warn!("daemon shutdown failed: {error:#}"),
    }

    scenario
}

/// Syncs the SDK's virtualenv from the committed lockfile (a no-op when
/// it is already up to date).
fn ensure_venv(sdk_dir: &Path) -> Result<()> {
    let status = Command::new("uv")
        .args(["sync", "--frozen"])
        .current_dir(sdk_dir)
        .status()
        .context("running uv sync (is uv installed?)")?;
    if !status.success() {
        bail!("uv sync failed with {status}");
    }
    Ok(())
}

/// Runs the gated SDK e2e against the isolated daemon socket, streaming
/// pytest output to the test's stdout/stderr.
fn pytest(sdk_dir: &Path, socket: &Path) -> Result<()> {
    info!(socket = %socket.display(), "running uv run pytest tests/test_e2e.py");
    let mut child = Command::new("uv")
        .args(["run", "--frozen", "pytest", "tests/test_e2e.py", "-v"])
        .current_dir(sdk_dir)
        .env("ARCBOX_SDK_E2E", "1")
        .env("ARCBOX_SOCKET", socket)
        // The SDK resolves ARCBOX_API_URL over the socket, and
        // ARCBOX_DATA_DIR would re-derive a default socket path; neither
        // may leak in from the caller's environment.
        .env_remove("ARCBOX_API_URL")
        .env_remove("ARCBOX_DATA_DIR")
        .stdin(Stdio::null())
        .spawn()
        .context("spawning uv run pytest (is uv installed?)")?;

    let deadline = Instant::now() + PYTEST_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("polling pytest")? {
            if status.success() {
                info!("SDK e2e passed");
                return Ok(());
            }
            bail!("pytest failed with {status}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("pytest did not finish within {PYTEST_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
