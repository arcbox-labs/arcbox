//! Runs the TypeScript SDK's gated hello-world e2e
//! (`sdk/typescript/test/e2e.test.ts`) against an isolated daemon.
//!
//! The daemon side mirrors the sandbox smoke: release host binaries plus
//! musl guest agents, staged dev boot assets, an isolated data dir, and
//! readiness observed via `WatchSetupStatus`. The SDK side is
//! `npm test -- test/e2e.test.ts` with `ARCBOX_SDK_E2E=1` and
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
/// 2026-08-06).
const READY_TIMEOUT: Duration = Duration::from_secs(360);
/// Ceiling for the whole vitest run: one sandbox boot (which may include
/// the first in-guest rootfs build) plus a handful of executions. Vitest's
/// own per-test timeout is 300s; this only catches a wedged runner.
const NPM_TIMEOUT: Duration = Duration::from_secs(420);

pub struct SdkTsConfig {
    pub skip_build: bool,
    pub keep_test_dir: bool,
    pub version: Option<String>,
}

impl SdkTsConfig {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            skip_build: env_flag("SKIP_BUILD"),
            keep_test_dir: env_flag("KEEP_TEST_DIR"),
            version: env::var("ARCBOX_BOOT_ASSET_VERSION").ok(),
        }
    }
}

pub fn run(config: SdkTsConfig) -> Result<()> {
    info!("starting TypeScript SDK e2e");

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
        .prefix("arcbox-sdk-ts-e2e-")
        .tempdir()
        .context("creating SDK e2e test directory")?;
    let data_dir = temp_dir.path().to_owned();

    crate::boot_assets::stage_dev_boot_assets(&root, &data_dir, &version)?;

    let mut metrics = RunMetrics::new("sdk_ts", Some("vz"));
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
    let sdk_dir = root.join("sdk/typescript");
    ensure_node_modules(&sdk_dir)?;

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

    let scenario = metrics.time("sdk_npm_test", || npm_test(&sdk_dir, &daemon.grpc_socket()));

    // Always shut the daemon down; a teardown failure must not mask the
    // scenario result.
    match daemon.shutdown() {
        Ok(status) => info!(%status, "daemon stopped"),
        Err(error) => warn!("daemon shutdown failed: {error:#}"),
    }

    scenario
}

/// Installs the SDK's dependencies when they are missing (fresh checkout /
/// CI); a populated `node_modules` is used as-is.
fn ensure_node_modules(sdk_dir: &Path) -> Result<()> {
    if sdk_dir.join("node_modules").is_dir() {
        return Ok(());
    }
    info!("node_modules missing; running npm ci");
    let status = Command::new("npm")
        .arg("ci")
        .current_dir(sdk_dir)
        .status()
        .context("running npm ci (is npm installed?)")?;
    if !status.success() {
        bail!("npm ci failed with {status}");
    }
    Ok(())
}

/// Runs the gated SDK e2e against the isolated daemon socket, streaming
/// vitest output to the test's stdout/stderr.
fn npm_test(sdk_dir: &Path, socket: &Path) -> Result<()> {
    info!(socket = %socket.display(), "running npm test -- test/e2e.test.ts");
    let mut child = Command::new("npm")
        .args(["test", "--", "test/e2e.test.ts"])
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
        .context("spawning npm test (is npm installed?)")?;

    let deadline = Instant::now() + NPM_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("polling npm test")? {
            if status.success() {
                info!("SDK e2e passed");
                return Ok(());
            }
            bail!("npm test failed with {status}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("npm test did not finish within {NPM_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
