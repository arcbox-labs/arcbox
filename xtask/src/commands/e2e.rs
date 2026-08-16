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

/// The backend `test` hardcodes, if any — `--backend` cannot move it.
///
/// Targets fall into three groups. A few read `ARCBOX_VM_BACKEND` from the
/// environment and genuinely honor `--backend` (`boot_assets`,
/// `backend_matrix`). Most pin one backend outright, either in their own
/// source (`virtio_debug` and `hv_reboot` pin **hv**; `machine`,
/// `idle_balloon`, `stats_watch`, `nfs_restart_probe` pin vz) or through a
/// shared harness in `tests/e2e/src` (`scenario::run_vz_scenario*`,
/// `sandbox`). For a pinned target the runner's env has no effect, so a
/// mismatched request archives a run under the wrong backend's label and
/// corrupts any comparison read from it — the same ghost-debugging class as
/// a mismatched `SKIP_BUILD` recipe. Note this cuts both ways: `--backend
/// vz` on an hv-pinned target is just as wrong as `--backend hv` on a
/// vz-pinned one.
///
/// Derived from the sources rather than kept as a list here: the set changes
/// whenever someone adds a target, and a list goes stale exactly when a new
/// target needs the guard most. An unreadable or absent target is treated as
/// unpinned — cargo reports an unknown test better than we can.
fn pinned_backend(root: &std::path::Path, test: &str) -> Result<Option<String>> {
    let path = root.join("tests/e2e/tests").join(format!("{test}.rs"));
    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };

    // The target's own source first, then the `arcbox_e2e` modules it pulls
    // in — that one level of indirection is where `run_vz_scenario` and the
    // sandbox harness hide their pin.
    if let Some(backend) = literal_backend_pin(&source) {
        return Ok(Some(backend));
    }
    for module in imported_e2e_modules(&source) {
        let path = root.join("tests/e2e/src").join(format!("{module}.rs"));
        if let Ok(helper) = fs::read_to_string(&path)
            && let Some(backend) = literal_backend_pin(&helper)
        {
            return Ok(Some(backend));
        }
    }
    Ok(None)
}

/// Finds a hardcoded `ARCBOX_VM_BACKEND` value in `source`.
///
/// A pin names the variable and carries a `"vz"` or `"hv"` literal just
/// after it. The scan deliberately is NOT line-based: rustfmt is free to
/// split a tuple across lines, and then no single line holds both halves —
/// a line-by-line search would report "not pinned" and the guard would
/// silently stop applying to a target that is still pinned. Instead each
/// occurrence of the variable gets a bounded lookahead, wide enough for a
/// split tuple and narrow enough that an unrelated literal further down
/// cannot be mistaken for the pin. Code that merely *reads* the variable
/// (`env::var("ARCBOX_VM_BACKEND")`) or forwards an already-computed value
/// carries no literal in that window and is correctly ignored.
fn literal_backend_pin(source: &str) -> Option<String> {
    const LOOKAHEAD_BYTES: usize = 80;

    source
        .match_indices("ARCBOX_VM_BACKEND")
        .find_map(|(at, name)| {
            let from = at + name.len();
            let mut to = source.len().min(from + LOOKAHEAD_BYTES);
            while to > from && !source.is_char_boundary(to) {
                to -= 1;
            }
            let window = &source[from..to];
            ["vz", "hv"]
                .into_iter()
                .find(|backend| window.contains(&format!("\"{backend}\"")))
                .map(str::to_owned)
        })
}

/// Module names from every `arcbox_e2e::<module>` path in `source`.
fn imported_e2e_modules(source: &str) -> Vec<String> {
    const PREFIX: &str = "arcbox_e2e::";
    let mut modules = Vec::new();
    for (index, _) in source.match_indices(PREFIX) {
        let module: String = source[index + PREFIX.len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !module.is_empty() && !modules.contains(&module) {
            modules.push(module);
        }
    }
    modules
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

    let pinned = pinned_backend(&root, &args.test)?;
    // An unset `--backend` is not a request for vz. clap cannot distinguish a
    // default from a typed value, so defaulting the flag would make
    // `cargo xtask e2e --test virtio_debug` — hv-pinned, and previously fine —
    // bail on a conflict with a backend nobody asked for. Unset adopts the
    // target's pin instead, and only an explicit request can conflict.
    let backend = match (args.backend, pinned.as_deref()) {
        (Some(requested), _) => requested,
        (None, Some("hv")) => E2eBackend::Hv,
        (None, _) => E2eBackend::Vz,
    };
    let backends: &[Option<&str>] = match backend {
        E2eBackend::Vz => &[Some("vz")],
        E2eBackend::Hv => &[Some("hv")],
        E2eBackend::Both => &[Some("vz"), Some("hv")],
    };
    if let Some(pinned) = pinned.as_deref()
        && backends.iter().flatten().any(|wanted| *wanted != pinned)
    {
        bail!(
            "test `{}` hardcodes ARCBOX_VM_BACKEND={pinned}, so the requested \
             backend cannot take effect — the run would be {pinned} while the \
             label, metrics, and archive said otherwise. Re-run with \
             `--backend {pinned}`, or make the target read the env first.",
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
        // sandbox_coldstart reuses that same build_binaries().
        "sandbox" | "sandbox_coldstart" => {
            xshell::cmd!(
                shell,
                "cargo build --release -p arcbox-cli -p arcbox-daemon"
            )
            .run()?;
            xshell::cmd!(
                shell,
                "cargo build --release -p arcbox-agent -p arcbox-vm-agent --bins --target aarch64-unknown-linux-musl"
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the pins out of the actual tree, not out of shapes transcribed
    /// into this file. A transcription only proves the scanner handles what
    /// the author remembered writing; these three assert what it answers for
    /// the targets as they exist — a direct hv pin, a vz pin reached through
    /// `arcbox_e2e::scenario`, and a target that honors `--backend` and must
    /// not be mistaken for pinned.
    #[test]
    fn the_pins_in_the_tree_resolve() {
        let root = repo::root_from_xtask_manifest(env!("CARGO_MANIFEST_DIR")).unwrap();
        assert_eq!(
            pinned_backend(&root, "virtio_debug").unwrap().as_deref(),
            Some("hv")
        );
        assert_eq!(
            pinned_backend(&root, "docker_build").unwrap().as_deref(),
            Some("vz"),
            "docker_build inherits scenario's vz pin one level away"
        );
        assert_eq!(pinned_backend(&root, "boot_assets").unwrap(), None);
    }

    /// rustfmt is free to split a pin across lines, and the scan must
    /// survive it: a line-based search finds neither half and silently
    /// reports "not pinned", which turns the `--backend` guard off for a
    /// target that is still pinned.
    #[test]
    fn a_pin_split_across_lines_is_still_a_pin() {
        let split =
            "env: vec![(\n    \"ARCBOX_VM_BACKEND\".to_owned(),\n    \"hv\".to_owned(),\n)],";
        assert_eq!(literal_backend_pin(split).as_deref(), Some("hv"));
    }

    /// The shapes every pin in `tests/e2e` is actually written in — a
    /// tuple entry, `.into()` instead of `.to_owned()`, and an hv pin.
    #[test]
    fn literal_pins_are_recognized_in_the_shapes_used() {
        let vz = r#"("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),"#;
        let vz_into = r#"("ARCBOX_VM_BACKEND".into(), "vz".into()),"#;
        let hv = r#"("ARCBOX_VM_BACKEND".to_owned(), "hv".to_owned()),"#;
        assert_eq!(literal_backend_pin(vz).as_deref(), Some("vz"));
        assert_eq!(literal_backend_pin(vz_into).as_deref(), Some("vz"));
        assert_eq!(literal_backend_pin(hv).as_deref(), Some("hv"));
    }

    /// A target that *reads* the env honors `--backend` and must not be
    /// mistaken for a pinned one — `boot_assets` and `backend_matrix` are
    /// the whole reason the runner has a `--backend` flag.
    #[test]
    fn reading_the_env_is_not_a_pin() {
        let reads = r#"let backend = match env::var("ARCBOX_VM_BACKEND") {"#;
        let forwards =
            r#"env.push(("ARCBOX_VM_BACKEND".to_owned(), backend.as_str().to_owned()));"#;
        assert!(literal_backend_pin(reads).is_none());
        assert!(literal_backend_pin(forwards).is_none());
    }

    /// The pin a scenario-based target inherits lives one level away, in
    /// the `arcbox_e2e` module it imports — that indirection is what a
    /// naive scan of the target's own source misses.
    #[test]
    fn imported_modules_are_collected_for_the_indirect_pin() {
        let source = "use arcbox_e2e::scenario::run_vz_scenario_with_log;\n\
                      use arcbox_e2e::metrics::RunMetrics;\n\
                      let root = arcbox_e2e::repo_root();\n";
        let modules = imported_e2e_modules(source);
        assert!(modules.contains(&"scenario".to_owned()));
        assert!(modules.contains(&"metrics".to_owned()));
        assert!(modules.contains(&"repo_root".to_owned()));
    }
}
