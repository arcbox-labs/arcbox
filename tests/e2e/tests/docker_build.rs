//! docker build e2e — Phases 1–3 (D1–D10) of
//! internal-docs/plans/docker-build-e2e-matrix.md.
//!
//! Where `network_workload` W14 drives *one* build to prove the datapath,
//! this suite tests the build surface itself, with scenarios modeled on the
//! real-world Dockerfile corpus in the plan:
//!
//! - **D1 large context** (immich / node_modules shape): 512 MiB
//!   incompressible payload + 100k small files through the context upload,
//!   with `.dockerignore` exclusion. Byte-exactness asserted *inside* the
//!   build (payload sha + whole-tree sha), so truncation or corruption
//!   anywhere in the transfer fails the build.
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
//! - **D4 session channel** (authentik shape): `--secret` readable inside
//!   its RUN, gone from the next layer, and absent from every byte of the
//!   saved image; `--ssh` forwards a live host agent socket. Both ride the
//!   `/session` upgrade proxy, previously covered by unit tests only.
//! - **D5 bind-mount lockfiles** (authentik / immich pnpm shape):
//!   `RUN --mount=type=bind` consumes a context file without a COPY layer.
//! - **D6 cross-platform** (vaultwarden / moby shape): `BUILDPLATFORM` /
//!   `TARGETARCH` expansion on a native build, and a `--platform
//!   linux/amd64` build whose RUN executes through the binfmt translator
//!   (asserted in-build via `uname -m`).
//! - **D7 concurrent builds** (CI shape): four distinct builds plus two
//!   racing on one shared context, all in flight at once; unique markers
//!   prove no cross-talk.
//! - **D8 cancellation** (production reality): the client is SIGKILLed
//!   mid-RUN and mid-context-upload; the guest must reap the build
//!   container, the daemon must stay quiet, and the next build must
//!   succeed promptly.
//! - **D9 output streaming**: a chatty RUN streamed un-clipped through the
//!   proxy, and `-q` mode reduced to the bare image ID.
//! - **D10 exporters**: `--output type=local` and `type=tar` — build
//!   artifacts streaming host-ward through the session (reverse direction).
//!
//! All scenarios share one booted daemon; failures aggregate. The workload
//! suite's quiet-log rule applies: builds must leave no proxy-layer ERROR.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use arcbox_e2e::docker::{docker_host, docker_ignore, docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::net_fixtures::daemon_log_cursor;
use arcbox_e2e::scenario::run_vz_scenario_with_log;
use sha2::Digest;

const READY_TIMEOUT: Duration = Duration::from_secs(180);

/// External dockerfile frontend used by D2's `# syntax=` directive,
/// pre-loaded so the build does not depend on registry reachability.
const FRONTEND_IMAGE: &str = "docker/dockerfile:1";

/// D1: payload size and small-file tree shape (100 dirs × 1000 files).
const LARGE_CTX_PAYLOAD: usize = 512 * 1024 * 1024;
const LARGE_CTX_TREE_DIRS: usize = 100;
const LARGE_CTX_FILES_PER_DIR: usize = 1000;
const LARGE_CTX_DEADLINE: Duration = Duration::from_secs(300);
const LARGE_CTX_TAG: &str = "arcbox-e2e-build:large-ctx";

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

/// D4: the secret value asserted inside the build and swept for outside it.
/// Alphanumeric+dash so it can be inlined into shell fragments verbatim.
const SECRET_VALUE: &str = "s3cret-build-token-abx494";
const SESSION_DEADLINE: Duration = Duration::from_secs(120);
const SECRET_TAG: &str = "arcbox-e2e-build:secret";
const SSH_TAG: &str = "arcbox-e2e-build:ssh";

/// D5: bind-mount lockfile scenario.
const BIND_DEADLINE: Duration = Duration::from_secs(120);
const BIND_TAG: &str = "arcbox-e2e-build:bind";

/// D9: chatty-RUN shape. BuildKit rate-limits step logs (the embedded
/// builder clips at 200 KiB/s — measured, the marker names the limit), so
/// the emitter is PACED: `STREAM_CHUNKS` bursts of `STREAM_CHUNK_LINES`
/// lines with a 1 s sleep between (~68 KiB/s). Under the limit, "no clip
/// marker + tail lines present" is a fair streaming-integrity assertion;
/// a bulk `seq` would be clipped by design and prove nothing.
const STREAM_CHUNKS: usize = 5;
const STREAM_CHUNK_LINES: usize = 10_000;
const STREAM_DEADLINE: Duration = Duration::from_secs(120);
const STREAM_TAG: &str = "arcbox-e2e-build:stream";
const QUIET_TAG: &str = "arcbox-e2e-build:quiet";

/// D10: exporter scenario — artifacts stream host-ward through the session.
const EXPORT_DEADLINE: Duration = Duration::from_secs(120);
const EXPORT_PAYLOAD: &str = "exporter-proof-payload\n";

/// D6: cross-platform args + the amd64 binfmt translator. FEX ships in
/// every bundle ≥ 0.6.6, so only the provisioned direction is asserted;
/// the fail-closed unprovisioned direction awaits an e2e knob (see the
/// plan's phasing note).
const XPLAT_DEADLINE: Duration = Duration::from_secs(180);
const XPLAT_ARGS_TAG: &str = "arcbox-e2e-build:xplat-args";
const XPLAT_AMD64_TAG: &str = "arcbox-e2e-build:xplat-amd64";

/// D7: concurrent builds — distinct contexts plus two racing on one shared
/// context.
const CONCURRENT_DISTINCT: usize = 4;
const CONCURRENT_SHARED: usize = 2;
const CONCURRENT_DEADLINE: Duration = Duration::from_secs(180);

/// D8: cancellation probes — the mid-upload kill needs a payload big
/// enough that the transfer is still in flight when the client dies.
const CANCEL_UPLOAD_PAYLOAD: usize = 256 * 1024 * 1024;
const CANCEL_DEADLINE: Duration = Duration::from_secs(120);

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

        let scenarios: [(&str, ScenarioFn); 10] = [
            ("stage_graph", stage_graph),
            ("cache_semantics", cache_semantics),
            ("session_secret_ssh", session_secret_ssh),
            ("bind_mounts", bind_mounts),
            ("output_streaming", output_streaming),
            ("exporters", exporters),
            ("cross_platform", cross_platform),
            ("concurrent_builds", concurrent_builds),
            ("cancellation", cancellation),
            ("large_context", large_context),
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

/// Runs `docker build --progress=plain -t tag <extra_args> ctx`, recording
/// the wall under `key` (also for failed builds — a slow failure is still
/// trend data) and failing past `deadline`.
fn timed_build(
    data_dir: &Path,
    metrics: &mut RunMetrics,
    key: &str,
    ctx: &Path,
    tag: &str,
    extra_args: &[&str],
    deadline: Duration,
) -> Result<(String, Duration)> {
    let ctx_arg = ctx.display().to_string();
    let mut args = vec!["build", "--progress=plain", "-t", tag];
    args.extend_from_slice(extra_args);
    args.push(&ctx_arg);
    let started = Instant::now();
    let build = docker_output(data_dir, &args, deadline + Duration::from_secs(60));
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

/// Extracts BuildKit's own context-transfer timing from `--progress=plain`
/// output (`#N transferring context: <bytes> <secs>s done`). Best-effort:
/// the line format is BuildKit's, not ours, so a miss records nothing.
fn context_transfer_seconds(output: &str) -> Option<f64> {
    output
        .lines()
        .rfind(|line| line.contains("transferring context:") && line.trim_end().ends_with("done"))
        .and_then(|line| {
            line.split_whitespace()
                .rev()
                .filter(|token| token.len() > 1 && token.ends_with('s'))
                .find_map(|token| token.trim_end_matches('s').parse::<f64>().ok())
        })
}

/// Fills `buf` with xorshift output — incompressible, so context transfer
/// and layer commits move real bytes.
fn fill_incompressible(buf: &mut [u8]) {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for chunk in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
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
            &[],
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
            &[],
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

        // Build 2 — unchanged: a full cache hit. Image IDs are NOT compared:
        // BuildKit stamps a fresh `created` timestamp into the config on
        // every build, so even a fully-cached rebuild gets a new ID. The
        // per-execution stamps are the execution truth — both must match
        // the cold build's — plus a wall bound far below cold (with the
        // usual CI-slack floor).
        let (_, warm_wall) = timed_build(
            data_dir,
            metrics,
            "cache_warm_wall",
            &ctx,
            warm_tag,
            &[],
            CACHE_BUILD_DEADLINE,
        )?;
        let warm_stamp_base = image_file(data_dir, warm_tag, "/stamp-base")?;
        let warm_stamp_leaf = image_file(data_dir, warm_tag, "/stamp-leaf")?;
        if warm_stamp_base != cold_stamp_base || warm_stamp_leaf != cold_stamp_leaf {
            bail!("cache: unchanged rebuild re-executed a step (stamps changed)");
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
            &[],
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
            &[],
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

/// D1: 512 MiB incompressible payload plus a 100k-file tree through the
/// context upload, `.dockerignore` honored. All integrity assertions run
/// *inside* the build: the payload sha, the file count, and a whole-tree
/// sha computed in deterministic path order, so a single lost, truncated,
/// or corrupted entry anywhere in the transfer fails the build.
fn large_context(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d1-ctx");
    std::fs::create_dir_all(&ctx).context("creating d1 context dir")?;

    let generated = Instant::now();
    let mut payload = vec![0u8; LARGE_CTX_PAYLOAD];
    fill_incompressible(&mut payload);
    std::fs::write(ctx.join("payload.bin"), &payload).context("writing payload")?;
    let payload_sha = format!("{:x}", sha2::Sha256::digest(&payload));
    drop(payload);

    // Zero-padded names make guest-side `find . | sort` order equal this
    // generation order, so one incremental host hash matches the in-build
    // whole-tree hash.
    let mut tree_hasher = sha2::Sha256::new();
    for dir in 0..LARGE_CTX_TREE_DIRS {
        let dir_name = format!("d{dir:03}");
        let dir_path = ctx.join("tree").join(&dir_name);
        std::fs::create_dir_all(&dir_path)?;
        for file in 0..LARGE_CTX_FILES_PER_DIR {
            let content = format!("{dir_name}/f{file:03}\n");
            std::fs::write(dir_path.join(format!("f{file:03}")), &content)?;
            tree_hasher.update(content.as_bytes());
        }
    }
    let tree_sha = format!("{:x}", tree_hasher.finalize());
    let file_count = LARGE_CTX_TREE_DIRS * LARGE_CTX_FILES_PER_DIR;

    std::fs::write(ctx.join(".dockerignore"), "excluded/\n")?;
    std::fs::create_dir_all(ctx.join("excluded"))?;
    std::fs::write(ctx.join("excluded/marker.txt"), "must-not-transfer\n")?;
    tracing::info!(
        elapsed = ?generated.elapsed(),
        payload_mib = LARGE_CTX_PAYLOAD / (1024 * 1024),
        file_count,
        "large_context: context generated"
    );

    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r#"FROM {image}
COPY . /ctx
RUN echo "{payload_sha}  /ctx/payload.bin" | sha256sum -c -
RUN test "$(find /ctx/tree -type f | wc -l)" -eq {file_count}
RUN cd /ctx/tree && test "$(find . -type f | sort | xargs cat | sha256sum | cut -d' ' -f1)" = "{tree_sha}"
RUN test ! -e /ctx/excluded
"#
        ),
    )
    .context("writing d1 Dockerfile")?;

    let result = (|| {
        let (output, elapsed) = timed_build(
            data_dir,
            metrics,
            "large_context_build_wall",
            &ctx,
            LARGE_CTX_TAG,
            &[],
            LARGE_CTX_DEADLINE,
        )?;
        match context_transfer_seconds(&output) {
            Some(seconds) => metrics.record("large_context_transfer", seconds),
            None => tracing::info!("large_context: no transfer timing in build output"),
        }
        tracing::info!(?elapsed, "large_context: build done");
        Ok(())
    })();

    docker_ignore(data_dir, &["rmi".into(), "-f".into(), LARGE_CTX_TAG.into()]);
    result
}

/// A throwaway host `ssh-agent` on a private socket, killed on drop. The
/// agent carries one fresh ed25519 key so the forwarded socket is a
/// realistic one, not an empty stub.
struct ThrowawaySshAgent {
    pid: String,
    sock: std::path::PathBuf,
}

impl ThrowawaySshAgent {
    fn spawn(dir: &Path) -> Result<Self> {
        let sock = dir.join("d4-agent.sock");
        let output = std::process::Command::new("ssh-agent")
            .args(["-a", &sock.display().to_string()])
            .output()
            .context("spawning ssh-agent")?;
        if !output.status.success() {
            bail!(
                "ssh-agent failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pid = stdout
            .split("SSH_AGENT_PID=")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("no SSH_AGENT_PID in ssh-agent output: {stdout}"))?;
        let agent = Self { pid, sock };

        let key = dir.join("d4-ssh-key");
        let keygen = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .context("generating throwaway ssh key")?;
        if !keygen.status.success() {
            bail!(
                "ssh-keygen failed: {}",
                String::from_utf8_lossy(&keygen.stderr)
            );
        }
        let add = std::process::Command::new("ssh-add")
            .arg(&key)
            .env("SSH_AUTH_SOCK", &agent.sock)
            .output()
            .context("loading key into ssh-agent")?;
        if !add.status.success() {
            bail!("ssh-add failed: {}", String::from_utf8_lossy(&add.stderr));
        }
        Ok(agent)
    }
}

impl Drop for ThrowawaySshAgent {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill").arg(&self.pid).status();
    }
}

/// Sweeps every byte of `docker save <tag>` for `needle` — including inside
/// gzip'd layer blobs (the containerd image store compresses them). A hit
/// anywhere fails: build secrets must never persist into image content.
fn assert_absent_from_saved_image(
    data_dir: &Path,
    tag: &str,
    needle: &str,
    label: &str,
) -> Result<()> {
    let tar = data_dir.join(format!("{label}-save.tar"));
    let tar_arg = tar.display().to_string();
    docker_output(
        data_dir,
        &["save", "-o", &tar_arg, tag],
        Duration::from_secs(120),
    )
    .context("docker save for secret sweep")?;

    // No `X && echo LEAK` shorthand under `set -e`: a non-matching grep
    // returns 1, fails the AND-list, and aborts the sweep before
    // SWEEP-DONE — every clean image would read as an incomplete sweep.
    let script = format!(
        r#"set -e
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
tar -xf "{tar_arg}" -C "$d"
find "$d" -type f | while read -r f; do
  if [ "$(head -c 2 "$f" | od -An -tx1 | tr -d ' \n')" = "1f8b" ]; then
    if gunzip -c "$f" 2>/dev/null | grep -aq -- "{needle}"; then echo "LEAK:$f"; fi
  elif grep -aq -- "{needle}" "$f"; then
    echo "LEAK:$f"
  fi
done
echo SWEEP-DONE"#
    );
    let sweep = std::process::Command::new("sh")
        .args(["-c", &script])
        .output()
        .context("running secret sweep")?;
    let stdout = String::from_utf8_lossy(&sweep.stdout);
    if !stdout.contains("SWEEP-DONE") {
        bail!(
            "{label}: secret sweep did not complete: {stdout}{}",
            String::from_utf8_lossy(&sweep.stderr)
        );
    }
    if stdout.contains("LEAK:") {
        bail!("{label}: secret bytes leaked into the saved image:\n{stdout}");
    }
    Ok(())
}

/// D4: the BuildKit session channel — `--secret` and `--ssh` both ride the
/// `/session` HTTP upgrade through the proxy. The secret must be readable
/// inside its mounting RUN, gone from the next layer, and absent from every
/// byte of the exported image; the ssh mount must expose a live forwarded
/// agent socket.
fn session_secret_ssh(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d4-secret-ctx");
    std::fs::create_dir_all(&ctx).context("creating d4 secret context dir")?;
    std::fs::write(ctx.join("token.txt"), SECRET_VALUE)?;
    // The Dockerfile must carry only the HASH of the secret: RUN command
    // lines persist verbatim into the image config's history, so inlining
    // the value would plant exactly the leak the sweep below hunts for.
    let secret_sha = format!("{:x}", sha2::Sha256::digest(SECRET_VALUE.as_bytes()));
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r#"FROM {image}
RUN --mount=type=secret,id=build_token echo "{secret_sha}  /run/secrets/build_token" | sha256sum -c - && echo secret-visible > /probe
RUN test ! -e /run/secrets/build_token
"#
        ),
    )
    .context("writing d4 secret Dockerfile")?;

    // Absolute path: BuildKit resolves a relative `src` against the CLI's
    // working directory, not the build context.
    let secret_src = format!("id=build_token,src={}", ctx.join("token.txt").display());
    let secret_result = (|| {
        timed_build(
            data_dir,
            metrics,
            "session_secret_build_wall",
            &ctx,
            SECRET_TAG,
            &["--secret", &secret_src],
            SESSION_DEADLINE,
        )?;
        if image_file(data_dir, SECRET_TAG, "/probe")? != "secret-visible" {
            bail!("secret: probe layer missing");
        }
        assert_absent_from_saved_image(data_dir, SECRET_TAG, SECRET_VALUE, "session_secret")
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), SECRET_TAG.into()]);
    secret_result?;

    let agent = ThrowawaySshAgent::spawn(data_dir)?;
    let ctx = data_dir.join("d4-ssh-ctx");
    std::fs::create_dir_all(&ctx).context("creating d4 ssh context dir")?;
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r#"FROM {image}
RUN --mount=type=ssh test -S "$SSH_AUTH_SOCK" && echo ssh-forwarded > /probe
"#
        ),
    )
    .context("writing d4 ssh Dockerfile")?;

    let ssh_arg = format!("default={}", agent.sock.display());
    let ssh_result = (|| {
        timed_build(
            data_dir,
            metrics,
            "session_ssh_build_wall",
            &ctx,
            SSH_TAG,
            &["--ssh", &ssh_arg],
            SESSION_DEADLINE,
        )?;
        if image_file(data_dir, SSH_TAG, "/probe")? != "ssh-forwarded" {
            bail!("ssh: probe layer missing");
        }
        Ok(())
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), SSH_TAG.into()]);
    ssh_result
}

/// D5: `RUN --mount=type=bind` consumes a context file with no COPY layer —
/// the pnpm-lockfile shape. The mounted file must be readable in its RUN,
/// derived content must land in the image, and the mount itself must leave
/// no trace in the final filesystem.
fn bind_mounts(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d5-ctx");
    std::fs::create_dir_all(&ctx).context("creating d5 context dir")?;
    let lockfile = "lockfile-v1\n";
    std::fs::write(ctx.join("lockfile.txt"), lockfile)?;
    let lockfile_sha = format!("{:x}", sha2::Sha256::digest(lockfile.as_bytes()));
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r"FROM {image}
RUN --mount=type=bind,source=lockfile.txt,target=/lockfile.txt sha256sum /lockfile.txt | cut -d' ' -f1 > /derived
RUN test ! -e /lockfile.txt
"
        ),
    )
    .context("writing d5 Dockerfile")?;

    let result = (|| {
        timed_build(
            data_dir,
            metrics,
            "bind_mounts_build_wall",
            &ctx,
            BIND_TAG,
            &[],
            BIND_DEADLINE,
        )?;
        let derived = image_file(data_dir, BIND_TAG, "/derived")?;
        if derived != lockfile_sha {
            bail!("bind_mounts: derived hash {derived} != host hash {lockfile_sha}");
        }
        Ok(())
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), BIND_TAG.into()]);
    result
}

/// D6: cross-platform builds. (a) A native build expands
/// `--platform=$BUILDPLATFORM` and `TARGETARCH` correctly. (b) A
/// `--platform linux/amd64` build executes its RUN step through the binfmt
/// translator — asserted in-build via `uname -m`, plus the image's
/// recorded architecture. This is the surface ABX-494 wedged: the arch
/// probe behind it now runs on every ListWorkers.
fn cross_platform(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d6-args-ctx");
    std::fs::create_dir_all(&ctx).context("creating d6 args context dir")?;
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r#"FROM --platform=$BUILDPLATFORM {image} AS build
ARG BUILDPLATFORM
ARG TARGETARCH
RUN echo "$BUILDPLATFORM:$TARGETARCH" > /args.txt
FROM {image}
COPY --from=build /args.txt /args.txt
"#
        ),
    )
    .context("writing d6 args Dockerfile")?;

    let args_result = (|| {
        timed_build(
            data_dir,
            metrics,
            "xplat_args_build_wall",
            &ctx,
            XPLAT_ARGS_TAG,
            &[],
            XPLAT_DEADLINE,
        )?;
        let args = image_file(data_dir, XPLAT_ARGS_TAG, "/args.txt")?;
        if args != "linux/arm64:arm64" {
            bail!("cross_platform: platform args expanded to {args:?}, expected linux/arm64:arm64");
        }
        Ok(())
    })();
    docker_ignore(
        data_dir,
        &["rmi".into(), "-f".into(), XPLAT_ARGS_TAG.into()],
    );
    args_result?;

    // The amd64 base variant is not in the arm64 tar cache; pull it with
    // the same retry discipline as `ensure_image`.
    let mut last_err = None;
    for attempt in 1..=3 {
        match docker_output(
            data_dir,
            &["pull", "--platform", "linux/amd64", image],
            Duration::from_secs(90),
        ) {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                tracing::warn!(attempt, "amd64 variant pull failed: {e:#}");
                last_err = Some(e);
            }
        }
    }
    if let Some(e) = last_err {
        return Err(e).context("pulling amd64 base variant (3 attempts)");
    }

    let ctx = data_dir.join("d6-amd64-ctx");
    std::fs::create_dir_all(&ctx).context("creating d6 amd64 context dir")?;
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r#"FROM {image}
RUN uname -m > /arch && test "$(cat /arch)" = "x86_64"
"#
        ),
    )
    .context("writing d6 amd64 Dockerfile")?;

    let amd64_result = (|| {
        timed_build(
            data_dir,
            metrics,
            "xplat_amd64_build_wall",
            &ctx,
            XPLAT_AMD64_TAG,
            &["--platform", "linux/amd64"],
            XPLAT_DEADLINE,
        )?;
        let arch = docker_output(
            data_dir,
            &[
                "image",
                "inspect",
                "-f",
                "{{.Architecture}}",
                XPLAT_AMD64_TAG,
            ],
            Duration::from_secs(30),
        )?;
        if arch.trim() != "amd64" {
            bail!(
                "cross_platform: built image records architecture {:?}, expected amd64",
                arch.trim()
            );
        }
        Ok(())
    })();
    docker_ignore(
        data_dir,
        &["rmi".into(), "-f".into(), XPLAT_AMD64_TAG.into()],
    );
    amd64_result
}

/// D7: concurrent builds — the CI shape. Four builds with distinct
/// contexts plus two racing on one shared context all run at once; each
/// image must carry exactly its own marker (no cross-talk between build
/// sessions sharing the daemon and builder).
fn concurrent_builds(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let mut jobs: Vec<(String, std::path::PathBuf, String)> = Vec::new();
    for i in 0..CONCURRENT_DISTINCT {
        let ctx = data_dir.join(format!("d7-ctx-{i}"));
        std::fs::create_dir_all(&ctx)?;
        let marker = format!("marker-{i}");
        std::fs::write(
            ctx.join("Dockerfile"),
            format!("FROM {image}\nRUN sleep 2 && echo {marker} > /marker\n"),
        )?;
        jobs.push((format!("arcbox-e2e-build:conc-{i}"), ctx, marker));
    }
    let shared = data_dir.join("d7-ctx-shared");
    std::fs::create_dir_all(&shared)?;
    std::fs::write(
        shared.join("Dockerfile"),
        format!("FROM {image}\nRUN sleep 2 && echo marker-shared > /marker\n"),
    )?;
    for j in 0..CONCURRENT_SHARED {
        jobs.push((
            format!("arcbox-e2e-build:conc-shared-{j}"),
            shared.clone(),
            "marker-shared".to_owned(),
        ));
    }

    let started = Instant::now();
    let results: Vec<(String, Result<String>)> = std::thread::scope(|scope| {
        #[expect(
            clippy::needless_collect,
            reason = "collect forces every spawn before the first join; a lazy chain would run the builds serially"
        )]
        let handles: Vec<_> = jobs
            .iter()
            .map(|(tag, ctx, _)| {
                scope.spawn(move || {
                    let ctx_arg = ctx.display().to_string();
                    docker_output(
                        data_dir,
                        &["build", "-t", tag, &ctx_arg],
                        CONCURRENT_DEADLINE,
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .zip(&jobs)
            .map(|(handle, (tag, _, _))| {
                (
                    tag.clone(),
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(anyhow!("build thread panicked"))),
                )
            })
            .collect()
    });
    let elapsed = started.elapsed();
    metrics.record("concurrent_builds_wall", elapsed.as_secs_f64());

    let result = (|| {
        for (tag, result) in &results {
            if let Err(error) = result {
                bail!("concurrent: {tag} failed: {error:#}");
            }
        }
        if elapsed >= CONCURRENT_DEADLINE {
            bail!("concurrent: builds took {elapsed:?} (>= {CONCURRENT_DEADLINE:?})");
        }
        for (tag, _, marker) in &jobs {
            let got = image_file(data_dir, tag, "/marker")?;
            if got != *marker {
                bail!("concurrent: {tag} carries marker {got:?}, expected {marker:?} — cross-talk");
            }
        }
        Ok(())
    })();
    for (tag, _, _) in &jobs {
        docker_ignore(data_dir, &["rmi".into(), "-f".into(), tag.clone()]);
    }
    result
}

/// Spawns a `docker build` that the caller intends to kill — output goes
/// to /dev/null since nothing will ever collect it.
fn spawn_build(data_dir: &Path, ctx: &Path, tag: &str) -> Result<std::process::Child> {
    std::process::Command::new("docker")
        .env("DOCKER_HOST", docker_host(data_dir))
        .args(["build", "-t", tag])
        .arg(ctx)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawning cancellable docker build")
}

/// D8: cancellation — the client is SIGKILLed mid-RUN and mid-context-
/// upload. The guest must reap the cancelled RUN's process, and the next
/// build must succeed promptly. The suite-level quiet-log check asserts
/// the daemon rode both kills without proxy ERRORs.
fn cancellation(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    // (1) Kill mid-RUN: the sleep marker is uniquely greppable guest-side.
    let ctx = data_dir.join("d8-run-ctx");
    std::fs::create_dir_all(&ctx).context("creating d8 run context dir")?;
    std::fs::write(
        ctx.join("Dockerfile"),
        format!("FROM {image}\nRUN sleep 6543\n"),
    )?;
    let mut child = spawn_build(data_dir, &ctx, "arcbox-e2e-build:cancel-run")?;
    std::thread::sleep(Duration::from_secs(8));
    let _ = child.kill();
    let _ = child.wait();

    let mut reaped = false;
    for _ in 0..15 {
        let count = docker_output(
            data_dir,
            &[
                "run",
                "--rm",
                "--pid=host",
                image,
                "sh",
                "-c",
                "ps | grep 'sleep [6]543' | wc -l",
            ],
            Duration::from_secs(60),
        )
        .context("guest process sweep")?;
        if count.trim() == "0" {
            reaped = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    if !reaped {
        bail!("cancellation: the cancelled RUN's process is still alive in the guest");
    }

    // (2) Kill mid-context-upload: 256 MiB is several seconds of transfer.
    let ctx = data_dir.join("d8-upload-ctx");
    std::fs::create_dir_all(&ctx).context("creating d8 upload context dir")?;
    let mut payload = vec![0u8; CANCEL_UPLOAD_PAYLOAD];
    fill_incompressible(&mut payload);
    std::fs::write(ctx.join("payload.bin"), &payload).context("writing d8 payload")?;
    drop(payload);
    std::fs::write(
        ctx.join("Dockerfile"),
        format!("FROM {image}\nCOPY payload.bin /payload.bin\n"),
    )?;
    let mut child = spawn_build(data_dir, &ctx, "arcbox-e2e-build:cancel-upload")?;
    std::thread::sleep(Duration::from_millis(1500));
    let _ = child.kill();
    let _ = child.wait();

    // (3) The daemon must build normally right after both kills.
    let ctx = data_dir.join("d8-followup-ctx");
    std::fs::create_dir_all(&ctx).context("creating d8 followup context dir")?;
    std::fs::write(
        ctx.join("Dockerfile"),
        format!("FROM {image}\nRUN echo recovered > /marker\n"),
    )?;
    let result = (|| {
        timed_build(
            data_dir,
            metrics,
            "cancel_followup_wall",
            &ctx,
            "arcbox-e2e-build:cancel-followup",
            &[],
            CANCEL_DEADLINE,
        )?;
        if image_file(data_dir, "arcbox-e2e-build:cancel-followup", "/marker")? != "recovered" {
            bail!("cancellation: follow-up build produced a wrong image");
        }
        Ok(())
    })();
    for tag in ["cancel-run", "cancel-upload", "cancel-followup"] {
        docker_ignore(
            data_dir,
            &["rmi".into(), "-f".into(), format!("arcbox-e2e-build:{tag}")],
        );
    }
    result
}

/// D9: build-output streaming. A RUN step emitting ordered lines, paced
/// under BuildKit's step-log rate clip, must arrive complete through the
/// proxy (a wedge shows up as the deadline, truncation as the clip marker
/// or a missing tail), and `-q` mode must reduce to one image-ID line.
fn output_streaming(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d9-ctx");
    std::fs::create_dir_all(&ctx).context("creating d9 context dir")?;
    let total_lines = STREAM_CHUNKS * STREAM_CHUNK_LINES;
    let chunk_indices = (1..=STREAM_CHUNKS)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r"FROM {image}
RUN for i in {chunk_indices}; do seq $(( (i-1)*{STREAM_CHUNK_LINES} + 1 )) $(( i*{STREAM_CHUNK_LINES} )); sleep 1; done
RUN echo streamed > /marker
"
        ),
    )
    .context("writing d9 Dockerfile")?;

    let result = (|| {
        let (output, _) = timed_build(
            data_dir,
            metrics,
            "streaming_build_wall",
            &ctx,
            STREAM_TAG,
            &["--no-cache"],
            STREAM_DEADLINE,
        )?;
        if output.contains("output clipped") {
            bail!("streaming: BuildKit clipped the step log (proxy delivered a truncated stream)");
        }
        let tail_marker = total_lines.to_string();
        let near_tail_marker = (total_lines - 1).to_string();
        if !output.contains(&tail_marker) || !output.contains(&near_tail_marker) {
            bail!("streaming: tail of the step log missing ({near_tail_marker}/{tail_marker})");
        }

        // Quiet mode: exactly one image-ID line on stdout.
        let ctx_arg = ctx.display().to_string();
        let quiet = docker_output(
            data_dir,
            &["build", "-q", "-t", QUIET_TAG, &ctx_arg],
            STREAM_DEADLINE,
        )
        .context("quiet build")?;
        let quiet = quiet.trim();
        if !quiet.starts_with("sha256:") || quiet.lines().count() != 1 {
            bail!("streaming: -q output is not a single image ID: {quiet:?}");
        }
        Ok(())
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), STREAM_TAG.into()]);
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), QUIET_TAG.into()]);
    result
}

/// D10: exporters — `--output type=local` and `type=tar` stream the build
/// artifact back to the client through the session, the reverse of the
/// context-upload direction. Content must arrive byte-exact.
fn exporters(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let ctx = data_dir.join("d10-ctx");
    std::fs::create_dir_all(&ctx).context("creating d10 context dir")?;
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            r"FROM {image} AS build
RUN mkdir /out && printf '{}' > /out/artifact.txt
FROM scratch AS export
COPY --from=build /out/ /
",
            EXPORT_PAYLOAD.trim_end_matches('\n'),
        ),
    )
    .context("writing d10 Dockerfile")?;
    // printf without a trailing newline directive: the payload constant's
    // newline is added back by comparing against the trimmed form.
    let expected = EXPORT_PAYLOAD.trim_end_matches('\n');
    let ctx_arg = ctx.display().to_string();

    let local_dest = data_dir.join("d10-local-out");
    let local_arg = format!("type=local,dest={}", local_dest.display());
    let started = Instant::now();
    let local = docker_output(
        data_dir,
        &["build", "--progress=plain", "-o", &local_arg, &ctx_arg],
        EXPORT_DEADLINE,
    );
    metrics.record("exporter_local_wall", started.elapsed().as_secs_f64());
    local.context("local exporter build")?;
    let exported = std::fs::read_to_string(local_dest.join("artifact.txt"))
        .context("reading locally-exported artifact")?;
    if exported != expected {
        bail!("exporters: local export mismatch: {exported:?} != {expected:?}");
    }

    let tar_dest = data_dir.join("d10-export.tar");
    let tar_arg = format!("type=tar,dest={}", tar_dest.display());
    let started = Instant::now();
    let tar_build = docker_output(
        data_dir,
        &["build", "--progress=plain", "-o", &tar_arg, &ctx_arg],
        EXPORT_DEADLINE,
    );
    metrics.record("exporter_tar_wall", started.elapsed().as_secs_f64());
    tar_build.context("tar exporter build")?;
    let extract_dir = data_dir.join("d10-tar-out");
    std::fs::create_dir_all(&extract_dir)?;
    let extract = std::process::Command::new("tar")
        .args(["-xf", &tar_dest.display().to_string(), "-C"])
        .arg(&extract_dir)
        .output()
        .context("extracting tar export")?;
    if !extract.status.success() {
        bail!(
            "exporters: tar extract failed: {}",
            String::from_utf8_lossy(&extract.stderr)
        );
    }
    let exported = std::fs::read_to_string(extract_dir.join("artifact.txt"))
        .context("reading tar-exported artifact")?;
    if exported != expected {
        bail!("exporters: tar export mismatch: {exported:?} != {expected:?}");
    }
    Ok(())
}
