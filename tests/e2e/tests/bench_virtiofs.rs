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
//! The network-dependent macro benchmarks (`npm_install`, `git_clone`) are
//! skipped on both sides: they need npm/git in the guest image (absent
//! from the minimal bench image, where they fail instantly and report
//! nonsense) and would hit the real registry/GitHub from the native run.
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
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::daemon::DaemonHandle;
use arcbox_e2e::docker::{docker_output, ensure_image, run_with_timeout};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::scenario::run_vz_scenario_with_log;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Ceiling for one full suite run (dozens of benchmarks, files up to
/// 256 MB); applied to the guest and the native phase alike.
const BENCH_BUDGET: Duration = Duration::from_secs(1800);
/// First-baseline iteration counts: bounded runtime beats tight variance
/// until a committed baseline exists.
const WARMUP: &str = "1";
const ITERATIONS: &str = "3";
/// Network-dependent macro benchmarks, excluded on both sides (see the
/// module docs).
const SKIP_BENCHES: &str = "npm_install,git_clone";

#[test]
#[ignore = "boots a VZ System VM through a real daemon and runs the VirtioFS benchmark suite"]
fn virtiofs_guest_vs_native_baseline() -> Result<()> {
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

    run_vz_scenario_with_log("bench_virtiofs", "info", |daemon, data_dir, metrics| {
        scenario(daemon, data_dir, &root, &guest_bin, &host_bin, metrics)
    })
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
    let guest_output = metrics.time("guest_bench", || {
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
                "--skip",
                SKIP_BENCHES,
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
    let native_output = metrics.time("native_bench", || -> Result<String> {
        let mut command = std::process::Command::new(host_bin);
        command.args([
            "--all",
            "--skip",
            SKIP_BENCHES,
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
        ]);
        let out =
            run_with_timeout(&mut command, BENCH_BUDGET).context("running native bench suite")?;
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
    persist_report(&results, "guest-vz", &guest_output)?;
    persist_report(&results, "native", &native_output)?;
    tracing::info!(dir = %results.display(), "bench reports written");
    Ok(())
}

/// Writes `<name>.json` with the report extracted from a raw capture; on
/// extraction failure the raw capture is preserved as `<name>.raw` so a
/// failed 100+-second run never evaporates.
fn persist_report(results: &Path, name: &str, raw: &str) -> Result<()> {
    match extract_json_object(raw) {
        Ok(json) => std::fs::write(results.join(format!("{name}.json")), json)
            .with_context(|| format!("writing {name}.json")),
        Err(error) => {
            let raw_path = results.join(format!("{name}.raw"));
            if let Err(write_error) = std::fs::write(&raw_path, raw) {
                tracing::warn!("preserving raw {name} capture failed: {write_error:#}");
            }
            Err(error.context(format!(
                "extracting the {name} report (raw capture preserved at {})",
                raw_path.display()
            )))
        }
    }
}

/// Extracts the first JSON value from a bench capture and re-serializes it.
///
/// `docker_output` merges the container's stdout and stderr, and the bench
/// prints progress text to stderr even in JSON mode — so the capture is
/// one JSON object surrounded by loose text. The streaming deserializer
/// consumes exactly one value wherever it ends, with no assumptions about
/// the report's formatting.
fn extract_json_object(raw: &str) -> Result<String> {
    let excerpt: String = raw.chars().take(200).collect();
    let start = raw
        .find('{')
        .with_context(|| format!("no JSON object in bench output: {excerpt:?}"))?;
    let value = serde_json::Deserializer::from_str(&raw[start..])
        .into_iter::<serde_json::Value>()
        .next()
        .with_context(|| format!("empty JSON stream in bench output: {excerpt:?}"))?
        .with_context(|| format!("bench output is not valid JSON: {excerpt:?}"))?;
    Ok(serde_json::to_string_pretty(&value)?)
}
