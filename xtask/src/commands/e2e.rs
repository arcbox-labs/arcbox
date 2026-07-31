//! Repeated e2e runs with artifact capture.
//!
//! Race-class bugs demand a cheap red: `cargo xtask e2e --backend hv
//! --repeat 200` runs the selected arcbox-e2e integration test over and
//! over, writing each run's full output to an artifacts directory and
//! recording the preserved test dir of every failure (the harness keeps
//! a failing run's data dir — daemon log, guest logs, virtio-debug
//! snapshot — alive for inspection).

use std::fs;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use xtask_kit::repo;

use crate::{E2eArgs, E2eBackend};

/// Whether `test` drives its daemon through `scenario::run_vz_scenario*`,
/// which hardcodes `ARCBOX_VM_BACKEND=vz` (`tests/e2e/src/scenario.rs`) and
/// stamps `"vz"` into the metrics. The runner's `--backend` cannot move such
/// a target, so honoring an HV request would archive a VZ run under an HV
/// label and corrupt any backend comparison read from it.
///
/// Read from the target's source rather than kept as a list here: the set
/// grows whenever someone writes a scenario-based test, and a list would
/// silently go stale exactly when a new target needs the guard most. A
/// target with no source file (an unknown name) is not pinned — cargo
/// reports that better than we can.
fn is_vz_pinned(root: &std::path::Path, test: &str) -> Result<bool> {
    let path = root.join("tests/e2e/tests").join(format!("{test}.rs"));
    match fs::read_to_string(&path) {
        Ok(source) => Ok(source.contains("run_vz_scenario")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// One test-run outcome for the final summary.
struct RunOutcome {
    label: String,
    passed: bool,
    seconds: f64,
    /// Data dir preserved by the harness on failure, if it advertised one.
    preserved_dir: Option<String>,
}

pub fn run(args: E2eArgs) -> Result<()> {
    let root = repo::root_from_xtask_manifest(env!("CARGO_MANIFEST_DIR"))?;
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(|| {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        root.join("target/e2e-artifacts").join(stamp.to_string())
    });
    fs::create_dir_all(&artifacts_dir)
        .with_context(|| format!("creating {}", artifacts_dir.display()))?;

    let backends: &[Option<&str>] = match args.backend {
        E2eBackend::Vz => &[Some("vz")],
        E2eBackend::Hv => &[Some("hv")],
        E2eBackend::Both => &[Some("vz"), Some("hv")],
    };
    if !matches!(args.backend, E2eBackend::Vz) && is_vz_pinned(&root, &args.test)? {
        bail!(
            "test `{}` pins ARCBOX_VM_BACKEND=vz in its scenario harness, so the \
             requested backend cannot take effect — the run would be VZ while the \
             label, metrics, and archive said HV. Re-run with `--backend vz`, or \
             move the target off scenario::run_vz_scenario first.",
            args.test,
        );
    }

    // Build what the selected test would build, once, so every repeat
    // runs with SKIP_BUILD=1 instead of re-invoking cargo.
    let prebuilt = prebuild(&root, &args.test)?;

    println!(
        "[e2e] test={} backends={:?} repeat={} artifacts={}",
        args.test,
        backends.iter().flatten().collect::<Vec<_>>(),
        args.repeat,
        artifacts_dir.display()
    );

    let mut outcomes: Vec<RunOutcome> = Vec::new();
    'runs: for iteration in 1..=args.repeat {
        for backend in backends {
            let backend_label = backend.unwrap_or("default");
            let label = format!("run-{iteration:04}-{backend_label}");
            let log_path = artifacts_dir.join(format!("{label}.log"));

            let mut command = Command::new("cargo");
            command
                .current_dir(&root)
                .args([
                    "test",
                    "-p",
                    "arcbox-e2e",
                    "--test",
                    &args.test,
                    "--",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ARCBOX_E2E_METRICS_DIR", &artifacts_dir)
                .env("ARCBOX_E2E_RUN_LABEL", &label);
            if prebuilt {
                command.env("SKIP_BUILD", "1");
            }
            if let Some(backend) = backend {
                command.env("ARCBOX_VM_BACKEND", backend);
            }

            let started = Instant::now();
            let output = command
                .output()
                .with_context(|| format!("running e2e test {}", args.test))?;
            let seconds = started.elapsed().as_secs_f64();

            let mut log = output.stdout;
            log.extend_from_slice(&output.stderr);
            fs::write(&log_path, &log)
                .with_context(|| format!("writing {}", log_path.display()))?;

            let text = String::from_utf8_lossy(&log);
            let preserved_dir = preserved_dir_from_log(&text);
            let passed = output.status.success();
            println!(
                "[e2e] {label}: {} in {seconds:.1}s{}",
                if passed { "PASS" } else { "FAIL" },
                preserved_dir
                    .as_deref()
                    .map(|d| format!(" (test dir preserved: {d})"))
                    .unwrap_or_default()
            );

            let failed = !passed;
            outcomes.push(RunOutcome {
                label,
                passed,
                seconds,
                preserved_dir,
            });
            if failed && args.fail_fast {
                break 'runs;
            }
        }
    }

    summarize(&outcomes, &artifacts_dir)
}

/// Pre-builds the binaries the selected test spawns. Returns whether a
/// recipe matched — if not, the runs go without `SKIP_BUILD` so the
/// test performs its own build.
fn prebuild(root: &std::path::Path, test: &str) -> Result<bool> {
    let shell = xtask_kit::process::shell()?;
    shell.change_dir(root);
    match test {
        "boot_assets" | "backend_matrix" => {
            xshell::cmd!(
                shell,
                "cargo build --release -p arcbox-cli -p arcbox-daemon"
            )
            .run()?;
            Ok(true)
        }
        "hv_vmm" => {
            xshell::cmd!(shell, "cargo build --release -p arcbox-e2e --bin hv_e2e").run()?;
            Ok(true)
        }
        // Must match tests/e2e/tests/stats_watch.rs's own build: the daemon
        // plus the musl guest agent (the scenario needs WatchStats support).
        "stats_watch" => {
            xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
            xshell::cmd!(
                shell,
                "cargo build --release -p arcbox-agent --target aarch64-unknown-linux-musl"
            )
            .run()?;
            Ok(true)
        }
        // Must match tests/e2e/src/scenario.rs's self-build (the shared
        // daemon-boot scaffolding these targets run through).
        "egress_throughput" | "docker_build" | "docker_build_external" => {
            xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
            Ok(true)
        }
        // Must match tests/e2e/src/sandbox.rs::build_binaries exactly
        // (packages AND profiles), or SKIP_BUILD runs stale binaries.
        "sandbox" => {
            xshell::cmd!(
                shell,
                "cargo build --release -p arcbox-cli -p arcbox-daemon"
            )
            .run()?;
            xshell::cmd!(
                shell,
                "cargo build --release -p arcbox-agent -p arcbox-vm --bins --target aarch64-unknown-linux-musl"
            )
            .run()?;
            Ok(true)
        }
        other => {
            println!("[e2e] no prebuild recipe for test '{other}'; every run builds for itself");
            Ok(false)
        }
    }
}

/// Extracts the preserved test dir path from harness log output
/// (`preserving test directory path=/…`).
fn preserved_dir_from_log(log: &str) -> Option<String> {
    log.lines()
        .filter(|line| line.contains("preserving test directory"))
        .find_map(|line| {
            line.split_whitespace()
                .find_map(|word| word.strip_prefix("path="))
                .map(str::to_owned)
        })
}

/// Prints the per-run table and pass/fail counts; errors if any run failed.
fn summarize(outcomes: &[RunOutcome], artifacts_dir: &std::path::Path) -> Result<()> {
    let passed = outcomes.iter().filter(|o| o.passed).count();
    let failed = outcomes.len() - passed;

    println!("\n[e2e] ── summary ──");
    for outcome in outcomes {
        println!(
            "[e2e] {} {} {:.1}s{}",
            outcome.label,
            if outcome.passed { "PASS" } else { "FAIL" },
            outcome.seconds,
            outcome
                .preserved_dir
                .as_deref()
                .map(|d| format!(" preserved={d}"))
                .unwrap_or_default()
        );
    }
    println!(
        "[e2e] {passed} passed, {failed} failed; logs in {}",
        artifacts_dir.display()
    );

    if failed > 0 {
        bail!("{failed} of {} e2e runs failed", outcomes.len());
    }
    Ok(())
}
