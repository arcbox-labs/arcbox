//! docker build e2e — Tier X of
//! internal-docs/plans/docker-build-e2e-matrix.md: real-project builds at
//! pinned upstream commits, with real registry/package-manager/keyserver
//! traffic through the datapath.
//!
//! Env-gated behind `ARCBOX_E2E_EXTERNAL=1` (the network-workload plan's
//! external-phase convention): results depend on upstream availability by
//! nature, so this suite is run manually when touching the proxy or
//! datapath — it gates nothing.
//!
//! - **X1 postgres** (`docker-library/postgres` `17/bookworm`): the classic
//!   official-image shape — tiny context, real `apt` + `wget` + **gpg
//!   keyserver** traffic.
//! - **X2 next.js** (`vercel/next.js` `examples/with-docker`): the single
//!   most common user Dockerfile shape — multi-stage standalone build with
//!   a real `pnpm install --frozen-lockfile`.
//! - **X3 caddy builder** (`caddyserver/caddy-docker` `2.11/builder`):
//!   apk + checksum-verified release-binary fetch (xcaddy).
//!
//! X4 (mastodon/immich-scale heavyweights) stays manual-only — see the
//! plan.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::docker::{docker_ignore, docker_output, run_with_timeout};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::scenario::run_vz_scenario_with_log;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Real builds pull base images and run package managers; give each one a
/// generous ceiling — the assertion is "completes", not "fast".
const BUILD_DEADLINE: Duration = Duration::from_secs(900);
const FETCH_TIMEOUT: Duration = Duration::from_secs(180);

/// Pinned upstream commits (2026-07-22). Bump deliberately: a pin move can
/// change what the build exercises.
const POSTGRES_PIN: (&str, &str, &str) = (
    "https://github.com/docker-library/postgres.git",
    "62a714f93cc32220de46fd12235c9d509e3b1ad6",
    "17/bookworm",
);
const NEXTJS_PIN: (&str, &str, &str) = (
    "https://github.com/vercel/next.js.git",
    "1d3bf10cde7b19093222305c4ded5f5948928419",
    "examples/with-docker",
);
const CADDY_PIN: (&str, &str, &str) = (
    "https://github.com/caddyserver/caddy-docker.git",
    "70350320b11d6cb04586bb869b798273180aa6d1",
    "2.11/builder",
);

#[test]
#[ignore = "real upstream builds over the internet; set ARCBOX_E2E_EXTERNAL=1 and run manually"]
fn docker_build_external_suite() -> Result<()> {
    if !arcbox_e2e::env_flag("ARCBOX_E2E_EXTERNAL") {
        eprintln!("skipping: ARCBOX_E2E_EXTERNAL is not set");
        return Ok(());
    }
    run_vz_scenario_with_log(
        "docker_build_external",
        "info",
        |daemon, data_dir, metrics| {
            metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;

            let scenarios: [(&str, ScenarioFn); 3] = [
                ("x3_caddy_builder", x3_caddy_builder),
                ("x1_postgres", x1_postgres),
                ("x2_nextjs", x2_nextjs),
            ];
            let only = std::env::var("ARCBOX_E2E_BUILD_ONLY").ok();
            let mut failures = Vec::new();
            for (name, scenario) in scenarios {
                if let Some(ref only) = only
                    && only != name
                {
                    continue;
                }
                tracing::info!(scenario = name, "starting");
                match scenario(data_dir, metrics) {
                    Ok(()) => tracing::info!(scenario = name, "passed"),
                    Err(error) => {
                        tracing::warn!(scenario = name, "failed: {error:#}");
                        failures.push(format!("{name}: {error:#}"));
                    }
                }
            }
            if failures.is_empty() {
                Ok(())
            } else {
                bail!(
                    "{} of {} external builds failed:\n{}",
                    failures.len(),
                    scenarios.len(),
                    failures.join("\n---\n")
                )
            }
        },
    )
}

type ScenarioFn = fn(&Path, &mut RunMetrics) -> Result<()>;

/// Sparse-fetches `subdir` of `repo` at the pinned `sha` (GitHub allows
/// arbitrary-SHA fetches) and returns the materialized subdir path.
fn fetch_pinned_subdir(
    data_dir: &Path,
    label: &str,
    (repo, sha, subdir): (&str, &str, &str),
) -> Result<PathBuf> {
    let dest = data_dir.join(format!("src-{label}"));
    std::fs::create_dir_all(&dest)?;
    let git = |args: &[&str]| -> Result<()> {
        let output = run_with_timeout(
            Command::new("git").arg("-C").arg(&dest).args(args),
            FETCH_TIMEOUT,
        )
        .with_context(|| format!("git {args:?}"))?;
        if !output.status.success() {
            bail!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    };
    git(&["init", "-q"])?;
    git(&["remote", "add", "origin", repo])?;
    git(&["sparse-checkout", "init", "--cone"])?;
    git(&["sparse-checkout", "set", subdir])?;
    git(&[
        "fetch",
        "-q",
        "--depth",
        "1",
        "--filter=blob:none",
        "origin",
        sha,
    ])?;
    git(&[
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "-q",
        "FETCH_HEAD",
    ])?;
    let ctx = dest.join(subdir);
    if !ctx.join("Dockerfile").is_file() {
        bail!("{label}: no Dockerfile at {}", ctx.display());
    }
    Ok(ctx)
}

fn build_and_time(
    data_dir: &Path,
    metrics: &mut RunMetrics,
    key: &str,
    ctx: &Path,
    tag: &str,
) -> Result<()> {
    let ctx_arg = ctx.display().to_string();
    let started = std::time::Instant::now();
    let result = docker_output(
        data_dir,
        &["build", "--progress=plain", "-t", tag, &ctx_arg],
        BUILD_DEADLINE,
    );
    metrics.record(key, started.elapsed().as_secs_f64());
    result.with_context(|| format!("{key}: docker build"))?;
    Ok(())
}

/// X1: the official postgres image — apt, wget'd gosu, gpg keyserver
/// verification, locale generation. The smoke check runs the built binary.
fn x1_postgres(data_dir: &Path, metrics: &mut RunMetrics) -> Result<()> {
    let ctx = fetch_pinned_subdir(data_dir, "postgres", POSTGRES_PIN)?;
    let tag = "arcbox-e2e-external:postgres";
    let result = (|| {
        build_and_time(data_dir, metrics, "x1_postgres_build_wall", &ctx, tag)?;
        let version = docker_output(
            data_dir,
            &["run", "--rm", tag, "postgres", "--version"],
            Duration::from_secs(60),
        )?;
        if !version.contains("PostgreSQL") {
            bail!("postgres smoke: unexpected version output {version:?}");
        }
        Ok(())
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), tag.into()]);
    result
}

/// X2: the canonical Next.js standalone build — multi-stage, corepack +
/// `pnpm install --frozen-lockfile`, `next build`. Smoke: the runtime
/// stage carries a working node.
fn x2_nextjs(data_dir: &Path, metrics: &mut RunMetrics) -> Result<()> {
    let ctx = fetch_pinned_subdir(data_dir, "nextjs", NEXTJS_PIN)?;
    // Upstream ships no `packageManager` pin, so corepack pulls the latest
    // pnpm at build time, whose supply-chain default refuses sharp's build
    // scripts (ERR_PNPM_IGNORED_BUILDS) — the verbatim build fails on ANY
    // engine. Apply pnpm's documented escape hatch and keep everything
    // else verbatim; bail loudly if a pin bump makes the patch stale.
    let dockerfile = ctx.join("Dockerfile");
    let content = std::fs::read_to_string(&dockerfile)?;
    let patched = content.replace(
        "pnpm install --frozen-lockfile",
        "pnpm install --frozen-lockfile --dangerously-allow-all-builds",
    );
    if patched == content {
        bail!("nextjs: pnpm install line not found — re-check the accommodation against the pin");
    }
    std::fs::write(&dockerfile, patched)?;
    let tag = "arcbox-e2e-external:nextjs";
    let result = (|| {
        build_and_time(data_dir, metrics, "x2_nextjs_build_wall", &ctx, tag)?;
        let version = docker_output(
            data_dir,
            &["run", "--rm", "--entrypoint", "node", tag, "--version"],
            Duration::from_secs(60),
        )?;
        if !version.trim().starts_with('v') {
            bail!("nextjs smoke: unexpected node version {version:?}");
        }
        Ok(())
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), tag.into()]);
    result
}

/// X3: the caddy builder image — apk + checksum-verified xcaddy release
/// fetch. Cheapest of the three; runs first to fail fast on a broken
/// external environment.
fn x3_caddy_builder(data_dir: &Path, metrics: &mut RunMetrics) -> Result<()> {
    let ctx = fetch_pinned_subdir(data_dir, "caddy", CADDY_PIN)?;
    let tag = "arcbox-e2e-external:caddy-builder";
    let result = (|| {
        build_and_time(data_dir, metrics, "x3_caddy_build_wall", &ctx, tag)?;
        let version = docker_output(
            data_dir,
            &["run", "--rm", "--entrypoint", "xcaddy", tag, "version"],
            Duration::from_secs(60),
        )?;
        if !version.contains("v0.4") {
            bail!("caddy smoke: unexpected xcaddy version {version:?}");
        }
        Ok(())
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), tag.into()]);
    result
}
