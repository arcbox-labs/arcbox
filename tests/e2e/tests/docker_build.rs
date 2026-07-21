//! docker build e2e — Phase 1 (D1–D3) of
//! internal-docs/plans/docker-build-e2e-matrix.md.
//!
//! Where `network_workload` W14 drives *one* build to prove the datapath,
//! this suite tests the build surface itself, with scenarios modeled on the
//! real-world Dockerfile corpus in the plan:
//!
//! - **D2 stage graph** (grafana / buildkit shape): a 12-stage diamond —
//!   `FROM scratch AS scripts` carrier (airflow pattern), four independent
//!   branches, `COPY --from` joins, a heredoc RUN, `COPY --link`, and a
//!   `FROM scratch AS export` tail, under `# syntax=docker/dockerfile:1`
//!   (the external frontend 12 of 25 corpus files declare). Asserts the
//!   final image carries exactly the export-stage artifact and none of the
//!   builder-stage residue.
//! - **D3 cache semantics** (mastodon / next.js shape): a
//!   `RUN --mount=type=cache,sharing=locked` step plus a leaf step, then
//!   three rebuilds — unchanged (full cache hit: identical image ID, warm
//!   wall bounded), leaf-only change (upstream stamp stable, downstream
//!   re-runs), base change (both re-run, and the cache mount's content
//!   demonstrably survives across builds).
//!
//! All scenarios share one booted daemon; failures aggregate. The workload
//! suite's quiet-log rule applies: builds must leave no proxy-layer ERROR.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::docker::{docker_ignore, docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::net_fixtures::daemon_log_cursor;
use arcbox_e2e::scenario::run_vz_scenario_with_log;

const READY_TIMEOUT: Duration = Duration::from_secs(180);

/// External dockerfile frontend used by D2's `# syntax=` directive,
/// pre-loaded so the build does not depend on registry reachability.
const FRONTEND_IMAGE: &str = "docker/dockerfile:1";

/// D2: stage-graph build deadline.
const STAGE_GRAPH_DEADLINE: Duration = Duration::from_secs(120);
const STAGE_GRAPH_TAG: &str = "arcbox-e2e-build:stage-graph";
const STAGE_GRAPH_PROBE: &str = "arcbox-e2e-build-d2-probe";

/// D3: per-build deadline, the sleep that gives the cold build measurable
/// duration (two sleeping steps ⇒ cold ≥ 2× this), and the warm bound —
/// `max(cold / 10, WARM_FLOOR)`, the suite's usual CI-slack floor so a
/// fast cold build isn't judged on noise.
const CACHE_BUILD_DEADLINE: Duration = Duration::from_secs(120);
const CACHE_STEP_SLEEP_SECS: u64 = 4;
const CACHE_WARM_FLOOR: Duration = Duration::from_secs(3);

#[test]
#[ignore = "boots a VZ System VM through a real daemon; run on the e2e runner"]
fn docker_build_suite() -> Result<()> {
    run_vz_scenario_with_log("docker_build", "info", |daemon, data_dir, metrics| {
        metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
        let image =
            std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
        metrics.time("docker_pull", || ensure_image(data_dir, &image))?;
        metrics.time("frontend_pull", || ensure_image(data_dir, FRONTEND_IMAGE))?;

        // Taken after setup so image-pull noise is out of scope; covers
        // every build below.
        let log = daemon_log_cursor(data_dir);

        let scenarios: [(&str, ScenarioFn); 2] = [
            ("stage_graph", stage_graph),
            ("cache_semantics", cache_semantics),
        ];
        // Diagnostic filter: run only the named scenario, e.g.
        // ARCBOX_E2E_BUILD_ONLY=cache_semantics.
        let only = std::env::var("ARCBOX_E2E_BUILD_ONLY").ok();
        let mut failures = Vec::new();
        for (name, scenario) in scenarios {
            if let Some(ref only) = only
                && only != name
            {
                continue;
            }
            tracing::info!(scenario = name, "starting");
            match scenario(data_dir, metrics, &image) {
                Ok(()) => tracing::info!(scenario = name, "passed"),
                Err(error) => {
                    tracing::warn!(scenario = name, "failed: {error:#}");
                    failures.push(format!("{name}: {error:#}"));
                }
            }
        }

        match log.proxy_errors() {
            Ok(errors) if !errors.is_empty() => failures.push(format!(
                "quiet-log: {} proxy-layer ERROR line(s) during builds:\n{}",
                errors.len(),
                errors.join("\n")
            )),
            Ok(_) => {}
            Err(error) => failures.push(format!("quiet-log: unreadable: {error:#}")),
        }

        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "{} of {} build checks failed:\n{}",
                failures.len(),
                scenarios.len() + 1,
                failures.join("\n---\n")
            )
        }
    })
}

type ScenarioFn = fn(&Path, &mut RunMetrics, &str) -> Result<()>;

/// Runs `docker build --progress=plain -t tag ctx`, recording the wall
/// under `key` (also for failed builds — a slow failure is still trend
/// data) and failing past `deadline`.
fn timed_build(
    data_dir: &Path,
    metrics: &mut RunMetrics,
    key: &str,
    ctx: &Path,
    tag: &str,
    deadline: Duration,
) -> Result<(String, Duration)> {
    let ctx_arg = ctx.display().to_string();
    let started = Instant::now();
    let build = docker_output(
        data_dir,
        &["build", "--progress=plain", "-t", tag, &ctx_arg],
        deadline + Duration::from_secs(60),
    );
    let elapsed = started.elapsed();
    metrics.record(key, elapsed.as_secs_f64());
    let output = build.with_context(|| format!("{key}: docker build"))?;
    if elapsed >= deadline {
        bail!("{key}: build took {elapsed:?} (>= {deadline:?})");
    }
    Ok((output, elapsed))
}

/// `cat`s one file out of a built image via a throwaway container.
fn image_file(data_dir: &Path, tag: &str, path: &str) -> Result<String> {
    docker_output(
        data_dir,
        &["run", "--rm", tag, "cat", path],
        Duration::from_secs(60),
    )
    .map(|out| out.trim().to_owned())
    .with_context(|| format!("reading {path} from {tag}"))
}

/// D2: 12-stage diamond under the external `docker/dockerfile:1` frontend.
/// Four independent branches (one fed from a `FROM scratch` script-carrier
/// stage, one built through a heredoc RUN) join into an aggregate, and a
/// `FROM scratch AS export` tail carries exactly one artifact. The final
/// image must contain that artifact byte-exact and none of the builder
/// residue (`/sentinel.txt`, parts, intermediates).
fn stage_graph(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d2-ctx");
    std::fs::create_dir_all(&ctx).context("creating d2 context dir")?;
    std::fs::write(ctx.join("make-part.sh"), "echo \"part-$1\"\n")?;
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r"# syntax=docker/dockerfile:1
FROM scratch AS scripts
COPY make-part.sh /make-part.sh

FROM {image} AS base
RUN echo shared > /shared.txt

FROM base AS branch-a
COPY --from=scripts /make-part.sh /make-part.sh
RUN sh /make-part.sh a > /part.txt && echo builder-only > /sentinel.txt

FROM base AS branch-a-out
COPY --from=branch-a /part.txt /part.txt
RUN cat /shared.txt /part.txt > /out.txt

FROM base AS branch-b
RUN <<EOT
set -e
echo part-b > /part.txt
echo b-extra >> /part.txt
EOT

FROM base AS branch-b-out
COPY --from=branch-b /part.txt /part.txt
RUN cat /shared.txt /part.txt > /out.txt

FROM base AS branch-c
RUN echo part-c > /part.txt

FROM base AS branch-c-out
COPY --from=branch-c /part.txt /part.txt
RUN cat /shared.txt /part.txt > /out.txt

FROM base AS branch-d
RUN echo part-d > /part.txt

FROM base AS branch-d-out
COPY --from=branch-d /part.txt /part.txt
RUN cat /shared.txt /part.txt > /out.txt

FROM base AS join
COPY --from=branch-a-out /out.txt /join/out-a.txt
COPY --from=branch-b-out /out.txt /join/out-b.txt
COPY --from=branch-c-out /out.txt /join/out-c.txt
COPY --from=branch-d-out /out.txt /join/out-d.txt
RUN cat /join/out-a.txt /join/out-b.txt /join/out-c.txt /join/out-d.txt > /artifact.txt

FROM scratch AS export
COPY --link --from=join /artifact.txt /artifact.txt
"
        ),
    )
    .context("writing d2 Dockerfile")?;
    let expected_artifact =
        "shared\npart-a\nshared\npart-b\nb-extra\nshared\npart-c\nshared\npart-d\n";

    let result = (|| {
        timed_build(
            data_dir,
            metrics,
            "stage_graph_build_wall",
            &ctx,
            STAGE_GRAPH_TAG,
            STAGE_GRAPH_DEADLINE,
        )?;

        // A scratch image cannot run; probe it via a created (never
        // started) container.
        docker_output(
            data_dir,
            &[
                "create",
                "--name",
                STAGE_GRAPH_PROBE,
                STAGE_GRAPH_TAG,
                "/noop",
            ],
            Duration::from_secs(60),
        )
        .context("creating probe container")?;

        let artifact_host = data_dir.join("d2-artifact.txt");
        let artifact_arg = artifact_host.display().to_string();
        docker_output(
            data_dir,
            &[
                "cp",
                &format!("{STAGE_GRAPH_PROBE}:/artifact.txt"),
                &artifact_arg,
            ],
            Duration::from_secs(60),
        )
        .context("copying artifact out of the built image")?;
        let artifact = std::fs::read_to_string(&artifact_host)?;
        if artifact != expected_artifact {
            bail!(
                "stage_graph: artifact mismatch:\n{artifact:?}\nexpected:\n{expected_artifact:?}"
            );
        }

        // Full-rootfs sweep for builder residue: the export listing may
        // carry init-layer entries (/dev, /etc/hosts, …) but must not
        // carry anything from the builder stages.
        let export_tar = data_dir.join("d2-export.tar");
        let export_arg = export_tar.display().to_string();
        docker_output(
            data_dir,
            &["export", "-o", &export_arg, STAGE_GRAPH_PROBE],
            Duration::from_secs(120),
        )
        .context("exporting probe container")?;
        let listing = std::process::Command::new("tar")
            .args(["-tf", &export_arg])
            .output()
            .context("listing export tar")?;
        if !listing.status.success() {
            bail!(
                "stage_graph: tar -tf failed: {}",
                String::from_utf8_lossy(&listing.stderr)
            );
        }
        let names = String::from_utf8_lossy(&listing.stdout);
        if !names.lines().any(|l| l.ends_with("artifact.txt")) {
            bail!("stage_graph: artifact.txt missing from export listing:\n{names}");
        }
        for residue in ["sentinel", "part", "shared", "out-", "make-"] {
            if let Some(hit) = names.lines().find(|l| l.contains(residue)) {
                bail!("stage_graph: builder-stage residue {hit:?} leaked into the final image");
            }
        }
        Ok(())
    })();

    docker_ignore(
        data_dir,
        &["rm".into(), "-f".into(), STAGE_GRAPH_PROBE.into()],
    );
    docker_ignore(
        data_dir,
        &["rmi".into(), "-f".into(), STAGE_GRAPH_TAG.into()],
    );
    result
}

/// D3: cache semantics across four builds of one Dockerfile. Each RUN step
/// writes a per-execution random stamp, so "was this step re-executed?" is
/// read from the image itself rather than parsed out of progress output.
/// The cached step's `--mount=type=cache` also round-trips a token, proving
/// the cache mount's content survives across builds.
fn cache_semantics(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d3-ctx");
    std::fs::create_dir_all(&ctx).context("creating d3 context dir")?;
    std::fs::write(ctx.join("base.txt"), "base-v1\n")?;
    std::fs::write(ctx.join("leaf.txt"), "leaf-v1\n")?;
    let sleep = CACHE_STEP_SLEEP_SECS;
    let stamp = "head -c 16 /dev/urandom | sha256sum | cut -d' ' -f1";
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r"FROM {image}
COPY base.txt /base.txt
RUN --mount=type=cache,target=/build-cache,sharing=locked (cp /build-cache/token /cache-prev 2>/dev/null || : > /cache-prev) && cp /base.txt /build-cache/token && sleep {sleep} && {stamp} > /stamp-base
COPY leaf.txt /leaf.txt
RUN sleep {sleep} && {stamp} > /stamp-leaf
"
        ),
    )
    .context("writing d3 Dockerfile")?;

    let tags = ["cold", "warm", "leaf", "base"].map(|t| format!("arcbox-e2e-build:cache-{t}"));
    let [cold_tag, warm_tag, leaf_tag, base_tag] = &tags;

    let result = (|| {
        // Build 1 — cold: everything executes, the cache mount is seeded.
        let (_, cold_wall) = timed_build(
            data_dir,
            metrics,
            "cache_cold_wall",
            &ctx,
            cold_tag,
            CACHE_BUILD_DEADLINE,
        )?;
        let cold_stamp_base = image_file(data_dir, cold_tag, "/stamp-base")?;
        let cold_stamp_leaf = image_file(data_dir, cold_tag, "/stamp-leaf")?;
        let cold_cache_prev = image_file(data_dir, cold_tag, "/cache-prev")?;
        if cold_stamp_base.is_empty() || cold_stamp_leaf.is_empty() {
            bail!("cache: cold build produced empty stamps");
        }
        if !cold_cache_prev.is_empty() {
            bail!(
                "cache: cold build saw a pre-existing cache token {cold_cache_prev:?} — \
                 the fresh daemon's build cache was not empty"
            );
        }

        // Build 2 — unchanged: a full cache hit, so the same image ID and a
        // wall bounded far below cold (with the usual CI-slack floor).
        let (_, warm_wall) = timed_build(
            data_dir,
            metrics,
            "cache_warm_wall",
            &ctx,
            warm_tag,
            CACHE_BUILD_DEADLINE,
        )?;
        let id = |tag: &str| {
            docker_output(
                data_dir,
                &["image", "inspect", "-f", "{{.Id}}", tag],
                Duration::from_secs(30),
            )
            .map(|out| out.trim().to_owned())
        };
        let (cold_id, warm_id) = (id(cold_tag)?, id(warm_tag)?);
        if warm_id != cold_id {
            bail!("cache: unchanged rebuild produced a different image ({cold_id} vs {warm_id})");
        }
        let warm_bound = cold_wall.div_f64(10.0).max(CACHE_WARM_FLOOR);
        if warm_wall > warm_bound {
            bail!(
                "cache: unchanged rebuild took {warm_wall:?} (bound {warm_bound:?}, \
                 cold {cold_wall:?}) — cache hit not engaging"
            );
        }

        // Build 3 — leaf change: the step above the change stays cached,
        // the steps at and below it re-execute.
        std::fs::write(ctx.join("leaf.txt"), "leaf-v2\n")?;
        timed_build(
            data_dir,
            metrics,
            "cache_leaf_wall",
            &ctx,
            leaf_tag,
            CACHE_BUILD_DEADLINE,
        )?;
        let leaf_stamp_base = image_file(data_dir, leaf_tag, "/stamp-base")?;
        let leaf_stamp_leaf = image_file(data_dir, leaf_tag, "/stamp-leaf")?;
        if leaf_stamp_base != cold_stamp_base {
            bail!("cache: leaf-only change re-executed the upstream cached step");
        }
        if leaf_stamp_leaf == cold_stamp_leaf {
            bail!("cache: leaf change did not re-execute the downstream step");
        }

        // Build 4 — base change: both steps re-execute, and the re-run
        // cached step reads back the token build 1 wrote — the cache mount
        // persisted across builds.
        std::fs::write(ctx.join("base.txt"), "base-v2\n")?;
        timed_build(
            data_dir,
            metrics,
            "cache_base_wall",
            &ctx,
            base_tag,
            CACHE_BUILD_DEADLINE,
        )?;
        let base_stamp_base = image_file(data_dir, base_tag, "/stamp-base")?;
        let base_stamp_leaf = image_file(data_dir, base_tag, "/stamp-leaf")?;
        let base_cache_prev = image_file(data_dir, base_tag, "/cache-prev")?;
        if base_stamp_base == cold_stamp_base {
            bail!("cache: base change did not re-execute the cached step");
        }
        if base_stamp_leaf == leaf_stamp_leaf {
            bail!("cache: base change did not invalidate the downstream step");
        }
        if base_cache_prev != "base-v1" {
            bail!(
                "cache: cache-mount token did not survive across builds \
                 (read {base_cache_prev:?}, expected \"base-v1\")"
            );
        }
        Ok(())
    })();

    for tag in &tags {
        docker_ignore(data_dir, &["rmi".into(), "-f".into(), tag.clone()]);
    }
    result
}
