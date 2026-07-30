//! VirtioFS file-I/O baseline (perf-target table: File I/O > 90% of native).
//!
//! Boots an isolated VZ daemon, copies the musl bench binary into the
//! daemon's data dir (guest-visible under the `/arcbox` VirtioFS share),
//! runs the suite inside the guest against that share, then runs the same
//! suite natively on the host against a directory on the same volume.
//! Both JSON reports land in `target/bench-virtiofs/` for comparison —
//! this test measures and records; it does not assert a ratio (there is
//! no baseline yet to regress against).
//!
//! Prerequisites (bailed on, not built here — keep the run's timing
//! honest): both bench binaries must exist:
//!
//! ```sh
//! cargo build --manifest-path tests/bench-virtiofs/Cargo.toml --release
//! cargo build --manifest-path tests/bench-virtiofs/Cargo.toml --release \
//!     --target aarch64-unknown-linux-musl
//! ```

use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::{docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Ceiling for the full in-guest suite (dozens of benchmarks, files up to
/// 256 MB, over VirtioFS).
const BENCH_BUDGET: Duration = Duration::from_secs(1800);
/// First-baseline iteration counts: bounded runtime beats tight variance
/// until a committed baseline exists.
const WARMUP: &str = "1";
const ITERATIONS: &str = "3";

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
#[ignore = "boots a VZ System VM through a real daemon and runs the VirtioFS benchmark suite"]
fn virtiofs_guest_vs_native_baseline() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    let bench_dir = root.join("tests/bench-virtiofs/target");
    let guest_bin = bench_dir.join("aarch64-unknown-linux-musl/release/arcbox-bench-virtiofs");
    let host_bin = bench_dir.join("release/arcbox-bench-virtiofs");
    for (bin, what) in [(&guest_bin, "musl guest"), (&host_bin, "host native")] {
        if !bin.exists() {
            bail!(
                "{what} bench binary missing at {} — build it first (see module docs)",
                bin.display()
            );
        }
    }

    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-bench-virtiofs-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
        ],
    })?;

    let mut metrics = RunMetrics::new("bench_virtiofs", Some("vz"));
    let result = scenario(
        &mut daemon,
        data_dir.path(),
        &root,
        &guest_bin,
        &host_bin,
        &mut metrics,
    );
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

fn scenario(
    daemon: &mut DaemonHandle,
    data_dir: &Path,
    root: &Path,
    guest_bin: &Path,
    host_bin: &Path,
    metrics: &mut RunMetrics,
) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;

    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
    metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

    // Stage the guest binary inside the share so the guest sees it at
    // /arcbox/bench without any image plumbing.
    let stage = data_dir.join("bench");
    // The bench refuses a missing --target; both scratch dirs are created
    // host-side (the guest sees them through the share).
    std::fs::create_dir_all(stage.join("scratch"))?;
    std::fs::copy(guest_bin, stage.join("arcbox-bench-virtiofs"))
        .context("staging guest bench binary into the share")?;

    // In-guest run against the VirtioFS share (scratch inside the share).
    let guest_json = metrics.time("guest_bench", || {
        docker_output(
            data_dir,
            &[
                "run",
                "--rm",
                "-v",
                "/arcbox/bench:/b",
                &image,
                "/b/arcbox-bench-virtiofs",
                "--all",
                "--format",
                "json",
                "--target",
                "/b/scratch",
                "--platform",
                "arcbox-vz",
                "--warmup",
                WARMUP,
                "--iterations",
                ITERATIONS,
            ],
            BENCH_BUDGET,
        )
        .context("running guest bench suite")
    })?;

    // Native baseline on the host, same volume as the data dir.
    let native_scratch = data_dir.join("bench/native-scratch");
    std::fs::create_dir_all(&native_scratch)?;
    let native_json = metrics.time("native_bench", || -> Result<String> {
        let out = std::process::Command::new(host_bin)
            .args([
                "--all",
                "--format",
                "json",
                "--target",
                native_scratch.to_str().context("non-UTF8 scratch path")?,
                "--platform",
                "native",
                "--warmup",
                WARMUP,
                "--iterations",
                ITERATIONS,
            ])
            .output()
            .context("running native bench suite")?;
        if !out.status.success() {
            bail!(
                "native bench failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        String::from_utf8(out.stdout).context("native bench emitted non-UTF8")
    })?;

    // Persist both reports outside the (deleted-on-success) data dir.
    let results = root.join("target/bench-virtiofs");
    std::fs::create_dir_all(&results)?;
    std::fs::write(
        results.join("guest-vz.json"),
        extract_json_object(&guest_json)?,
    )?;
    std::fs::write(
        results.join("native.json"),
        extract_json_object(&native_json)?,
    )?;
    tracing::info!(dir = %results.display(), "bench reports written");
    Ok(())
}

/// Cuts a bench report down to its top-level JSON object and validates it.
///
/// `docker_output` merges the container's stdout and stderr, and the bench
/// prints progress text to stderr even in JSON mode — so the guest capture
/// is a pretty-printed JSON object followed by loose text. The object's
/// closing brace is the only column-0 `}` (nested closes are indented).
fn extract_json_object(raw: &str) -> Result<String> {
    let start = raw.find('{').context("no JSON object in bench output")?;
    let end = raw[start..]
        .find("\n}")
        .map(|i| start + i + 2)
        .context("no top-level closing brace in bench output")?;
    let json = &raw[start..end];
    serde_json::from_str::<serde_json::Value>(json)
        .context("extracted bench report is not valid JSON")?;
    Ok(json.to_owned())
}
