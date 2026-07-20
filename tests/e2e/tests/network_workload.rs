//! Network-workload e2e — Phase 1 (W2–W4) of
//! internal-docs/plans/network-workload-e2e.md.
//!
//! Where `network_fault` injects faults, this suite drives the datapath with
//! the traffic shapes a developer generates daily and asserts they behave:
//!
//! - **W2 upload** (push/POST shape): 256 MiB guest→host, against a
//!   normal reader and against one that pauses mid-stream. The upload
//!   direction has *no* backpressure queue — a host-socket `WouldBlock`
//!   silently drops the payload and recovery is the guest kernel's RTO
//!   retransmit (`splicetcp/src/tcp_bridge/fast_path.rs`). The paused-reader
//!   variant pins that behavior: slower is acceptable, wedged is a bug.
//! - **W3 burst** (npm/cargo-install shape): 64 concurrent downloads, in one
//!   container and spread across 8, with a straggler bound — one stalled
//!   flow among many is exactly what per-flow zombie bugs look like.
//! - **W4 churn** (apk/git-HTTP shape): 500 sequential fresh-connection
//!   requests with a latency-flatness bound — per-flow state leaks show up
//!   as monotonic slowdown.
//! - **W13 parallel large downloads** (multi-image-pull shape): 8 × 64 MiB
//!   concurrently — sustained windowing and retransmission under volume
//!   rather than connection count.
//! - **W14 docker build**: context upload over vsock, RUN-step networking
//!   through the datapath, layer commits; byte-exactness asserted inside
//!   the build via `RUN test $(wc -c ...)` steps.
//! - **W15/W16 integrity**: content, not just completion — a known-pattern
//!   download and a urandom upload are SHA-256'd end to end and compared,
//!   catching corruption/reorder/truncation that byte-count checks miss
//!   (the shape the silent-upload-loss bug produced).
//!
//! All scenarios share one booted daemon (boot dominates the runtime) and
//! run inside a long-lived workbench container whose netns the zombie sweep
//! inspects afterwards. Two cross-cutting assertions close each run: no
//! `ESTABLISHED` flow to a fixture outlives its workload, and the daemon
//! log stays free of proxy-layer ERRORs — workloads must be quiet, the
//! observability inverse of the fault suite.
//!
//! Known issue: the VZ virtio-net freeze (ABX-420) intermittently stalls
//! egress flows for ~60-75 s and can fail the burst/churn scenarios here,
//! exactly as it does `egress_throughput`.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::docker::{docker_ignore, docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::net_fixtures::{
    GUEST_GATEWAY_IP, SinkPause, assert_no_established_flows, daemon_log_cursor, spawn_blob_server,
    spawn_hashing_sink, spawn_pattern_server, spawn_slow_sink,
};
use arcbox_e2e::scenario::run_vz_scenario_with_log;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Long-lived workbench container: scenarios `docker exec` into it (vsock,
/// off-datapath), and its netns is where the zombie sweep looks.
const BENCH: &str = "net-workload-bench";

/// W2: upload volume. Large enough that buffers are a rounding error and the
/// transfer is genuinely sustained.
const UPLOAD_BYTES: usize = 256 * 1024 * 1024;
const UPLOAD_MIB: usize = UPLOAD_BYTES / (1024 * 1024);
/// W2 steady-reader deadline. Loopback-backed, so this is generous.
const UPLOAD_DEADLINE: Duration = Duration::from_secs(180);
/// W2 paused-reader deadline: steady bound + pause + RTO-backoff recovery
/// slack (the guest's retransmit backoff can idle several seconds past the
/// reader's resume).
const UPLOAD_PAUSED_DEADLINE: Duration = Duration::from_secs(300);
/// W2 paused variant: reader stops for this long once `PAUSE_AFTER_BYTES`
/// have arrived, forcing the host socket buffers full and the daemon's
/// upload write into `WouldBlock` while the client still pushes.
const PAUSE_AFTER_BYTES: usize = 16 * 1024 * 1024;
const PAUSE_DURATION: Duration = Duration::from_secs(5);

/// W3: flows per burst and blob size per flow.
const BURST_FLOWS: usize = 64;
const BURST_BLOB_BYTES: usize = 4 * 1024 * 1024;
const BURST_DEADLINE: Duration = Duration::from_secs(120);
/// W3 multi-container variant: 8 containers × 8 flows = the same 64.
const BURST_CONTAINERS: usize = 8;

/// W4: request count and body size (dependency-index shape: small, many).
const CHURN_REQUESTS: usize = 500;
const CHURN_BLOB_BYTES: usize = 64 * 1024;
const CHURN_DEADLINE: Duration = Duration::from_secs(180);

/// W13: concurrent LARGE downloads (multi-image-pull shape) — few flows,
/// each moving real volume. Where the burst stresses flow setup and
/// per-flow fairness, this stresses sustained windowing, the retransmit
/// buffers, and the delivery queue at full throughput.
const PARALLEL_LARGE_FLOWS: usize = 8;
const PARALLEL_LARGE_BLOB_BYTES: usize = 64 * 1024 * 1024;
const PARALLEL_LARGE_DEADLINE: Duration = Duration::from_secs(240);
/// Straggler floor for large flows. Observed medians are a few seconds
/// (2.4 s at ~131 MiB/s aggregate), so this floor — not 4×median — is
/// usually the operative bound: it tolerates CI slowness on multi-second
/// transfers while still failing a flow that wedges outright (a wedged
/// flow costs its client timeout, far beyond 10 s).
const PARALLEL_LARGE_FLOOR: Duration = Duration::from_secs(10);

/// W14: docker build — context upload (vsock), RUN-step networking
/// through the datapath, and layer commits, in one compound daily flow.
const BUILD_CONTEXT_PAYLOAD: usize = 8 * 1024 * 1024;
const BUILD_FETCH_BYTES: usize = 4 * 1024 * 1024;
const BUILD_DEADLINE: Duration = Duration::from_secs(240);
const BUILD_TAG: &str = "net-workload-build:latest";

/// Teardown grace for the zombie sweep: in-flight FIN handling passes, a
/// frozen flow (the 2026-07-19 incident shape) fails.
const SWEEP_GRACE: Duration = Duration::from_secs(10);

/// Integrity payload size: large enough to span many segments/retransmits
/// so a reordering/truncation/duplication bug actually shows up in the
/// SHA-256, small enough to stay quick.
const INTEGRITY_BYTES: usize = 32 * 1024 * 1024;
const INTEGRITY_DEADLINE: Duration = Duration::from_secs(120);

#[test]
#[ignore = "boots a VZ System VM through a real daemon; run on the e2e runner"]
fn net_workload_egress_suite() -> Result<()> {
    // No splicetcp=debug: it logs every classified frame, and a dup-ACK
    // storm turns that into ~6k lines/s of hot-path logging that distorts
    // the very throughput under test.
    run_vz_scenario_with_log(
        "network_workload",
        "info,arcbox_net=debug",
        |daemon, data_dir, metrics| {
            metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
            let image =
                std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
            metrics.time("docker_pull", || ensure_image(data_dir, &image))?;
            docker_output(
                data_dir,
                &["run", "-d", "--name", BENCH, &image, "sleep", "2147483647"],
                Duration::from_secs(60),
            )
            .context("starting workbench container")?;

            // Taken after setup so image-pull noise is out of scope; covers
            // every workload below.
            let log = daemon_log_cursor(data_dir);

            let scenarios: [(&str, ScenarioFn); 9] = [
                ("upload_steady", upload_steady),
                ("upload_paused_reader", upload_paused_reader),
                ("burst_single_container", burst_single_container),
                ("burst_multi_container", burst_multi_container),
                ("churn_sequential", churn_sequential),
                ("parallel_large_downloads", parallel_large_downloads),
                ("docker_build_network", docker_build_network),
                ("download_integrity", download_integrity),
                ("upload_integrity", upload_integrity),
            ];
            // Diagnostic filter: run only the named scenario, e.g.
            // ARCBOX_E2E_WORKLOAD_ONLY=burst_single_container.
            let only = std::env::var("ARCBOX_E2E_WORKLOAD_ONLY").ok();
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
                    "quiet-log: {} proxy-layer ERROR line(s) during workloads:\n{}",
                    errors.len(),
                    errors.join("\n")
                )),
                Ok(_) => {}
                Err(error) => failures.push(format!("quiet-log: unreadable: {error:#}")),
            }

            docker_ignore(data_dir, &["rm".into(), "-f".into(), BENCH.into()]);
            if failures.is_empty() {
                Ok(())
            } else {
                bail!(
                    "{} of {} workload checks failed:\n{}",
                    failures.len(),
                    scenarios.len() + 1,
                    failures.join("\n---\n")
                )
            }
        },
    )
}

type ScenarioFn = fn(&Path, &mut RunMetrics, &str) -> Result<()>;

fn upload_steady(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    upload(
        data_dir,
        metrics,
        image,
        "upload_steady",
        None,
        UPLOAD_DEADLINE,
    )
}

fn upload_paused_reader(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    upload(
        data_dir,
        metrics,
        image,
        "upload_paused",
        Some(SinkPause {
            after_bytes: PAUSE_AFTER_BYTES,
            duration: PAUSE_DURATION,
        }),
        UPLOAD_PAUSED_DEADLINE,
    )
}

/// W2: the workbench pipes `UPLOAD_BYTES` of zeroes into a raw TCP sink.
/// The sink closing after the exact byte count is what ends the client, so
/// the assertion surface is sink-side and immune to busybox `nc`'s
/// stdin-EOF quirks. The kernel keeps delivering after a client-side close,
/// so the sink count is authoritative either way.
fn upload(
    data_dir: &Path,
    metrics: &mut RunMetrics,
    _image: &str,
    label: &str,
    pause: Option<SinkPause>,
    deadline: Duration,
) -> Result<()> {
    let sink = spawn_slow_sink(UPLOAD_BYTES, pause)?;
    let command = format!(
        "dd if=/dev/zero bs=1M count={UPLOAD_MIB} 2>/dev/null | nc {GUEST_GATEWAY_IP} {}",
        sink.port()
    );
    let started = Instant::now();
    docker_output(
        data_dir,
        &["exec", BENCH, "sh", "-c", &command],
        deadline + Duration::from_secs(60),
    )
    .with_context(|| format!("{label}: in-container upload command"))?;
    let report = sink.wait_complete(deadline.saturating_sub(started.elapsed()))?;
    let elapsed = started.elapsed();
    metrics.record(&format!("{label}_wall"), elapsed.as_secs_f64());
    metrics.record(
        &format!("{label}_sink_transfer"),
        report.transfer.as_secs_f64(),
    );
    tracing::info!(
        ?elapsed,
        sink_transfer = ?report.transfer,
        mib = UPLOAD_MIB,
        "{label}: upload done"
    );

    if report.received != UPLOAD_BYTES {
        bail!(
            "{label}: sink received {} of {UPLOAD_BYTES} bytes",
            report.received
        );
    }
    if elapsed >= deadline {
        bail!("{label}: upload took {elapsed:?} (>= {deadline:?})");
    }
    assert_no_established_flows(data_dir, BENCH, sink.port(), SWEEP_GRACE)
}

/// Burst worker script: `flows` parallel downloads, each failing the script
/// if any flow fails. The per-flow `-T 60` turns a stalled flow into a
/// clean nonzero exit instead of an opaque outer timeout.
fn burst_script(url: &str, flows: usize) -> String {
    format!(
        r#"pids=""
i=0
while [ $i -lt {flows} ]; do
  wget -q -O /dev/null -T 60 "{url}" &
  pids="$pids $!"
  i=$((i+1))
done
rc=0
for p in $pids; do wait $p || rc=1; done
exit $rc"#
    )
}

/// W3a: 64 concurrent flows from one container. Server-side per-flow
/// completion timings (accept → client close) feed the straggler bound.
fn burst_single_container(data_dir: &Path, metrics: &mut RunMetrics, _image: &str) -> Result<()> {
    let server = spawn_blob_server(BURST_BLOB_BYTES)?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{}/blob", server.port());
    let script = burst_script(&url, BURST_FLOWS);

    let started = Instant::now();
    if let Err(error) = docker_output(
        data_dir,
        &["exec", BENCH, "sh", "-c", &script],
        BURST_DEADLINE + Duration::from_secs(60),
    ) {
        bail!(
            "burst_single: in-container burst failed ({} of {BURST_FLOWS} flows completed \
             server-side): {error:#}",
            server.timings().len()
        );
    }
    let elapsed = started.elapsed();
    metrics.record("burst_single_wall", elapsed.as_secs_f64());
    if elapsed >= BURST_DEADLINE {
        bail!("burst_single: took {elapsed:?} (>= {BURST_DEADLINE:?})");
    }
    check_stragglers(
        &server.wait_for_timings(BURST_FLOWS, SWEEP_GRACE),
        BURST_FLOWS,
        "burst_single",
        Duration::from_secs(2),
        metrics,
    )?;
    assert_no_established_flows(data_dir, BENCH, server.port(), SWEEP_GRACE)
}

/// W3b: the same 64 flows spread across 8 containers — the multi-project
/// shape, and container-count scaling for the daemon's flow table.
fn burst_multi_container(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let server = spawn_blob_server(BURST_BLOB_BYTES)?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{}/blob", server.port());
    let flows_each = BURST_FLOWS / BURST_CONTAINERS;
    let script = burst_script(&url, flows_each);

    let names: Vec<String> = (0..BURST_CONTAINERS)
        .map(|i| format!("net-workload-burst-{i}"))
        .collect();
    let started = Instant::now();
    let result = (|| {
        for name in &names {
            docker_output(
                data_dir,
                &["run", "-d", "--name", name, image, "sh", "-c", &script],
                Duration::from_secs(60),
            )
            .with_context(|| format!("burst_multi: starting {name}"))?;
        }
        for name in &names {
            let code = docker_output(
                data_dir,
                &["wait", name],
                BURST_DEADLINE + Duration::from_secs(60),
            )
            .with_context(|| format!("burst_multi: waiting for {name}"))?;
            if code.trim() != "0" {
                bail!("burst_multi: {name} exited {}", code.trim());
            }
        }
        Ok(())
    })();
    for name in &names {
        docker_ignore(data_dir, &["rm".into(), "-f".into(), name.clone()]);
    }
    if let Err(error) = result {
        bail!(
            "burst_multi failed ({} of {BURST_FLOWS} flows completed server-side): {error:#}",
            server.timings().len()
        );
    }
    let elapsed = started.elapsed();
    metrics.record("burst_multi_wall", elapsed.as_secs_f64());
    if elapsed >= BURST_DEADLINE {
        bail!("burst_multi: took {elapsed:?} (>= {BURST_DEADLINE:?})");
    }
    // No netns sweep: the burst containers are gone, and with them their
    // guest-side flows; the quiet-log check still covers the daemon side.
    check_stragglers(
        &server.wait_for_timings(BURST_FLOWS, SWEEP_GRACE),
        BURST_FLOWS,
        "burst_multi",
        Duration::from_secs(2),
        metrics,
    )
}

/// W4: 500 sequential fresh-connection requests. Flatness bound: the mean of
/// the last 50 server-side timings must stay within 3× the first 50 (with an
/// absolute floor so a fast path isn't judged on noise) — per-flow state
/// leaks show up as monotonic slowdown long before anything hard-fails.
fn churn_sequential(data_dir: &Path, metrics: &mut RunMetrics, _image: &str) -> Result<()> {
    let server = spawn_blob_server(CHURN_BLOB_BYTES)?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{}/blob", server.port());
    let script = format!(
        r#"i=0
while [ $i -lt {CHURN_REQUESTS} ]; do
  wget -q -O /dev/null -T 30 "{url}" || {{ echo "request $i failed" >&2; exit 1; }}
  i=$((i+1))
done"#
    );

    let started = Instant::now();
    if let Err(error) = docker_output(
        data_dir,
        &["exec", BENCH, "sh", "-c", &script],
        CHURN_DEADLINE + Duration::from_secs(60),
    ) {
        bail!(
            "churn: request loop failed ({} of {CHURN_REQUESTS} requests completed \
             server-side): {error:#}",
            server.timings().len()
        );
    }
    let elapsed = started.elapsed();
    metrics.record("churn_wall", elapsed.as_secs_f64());
    if elapsed >= CHURN_DEADLINE {
        bail!("churn: took {elapsed:?} (>= {CHURN_DEADLINE:?})");
    }

    let timings = server.wait_for_timings(CHURN_REQUESTS, SWEEP_GRACE);
    if timings.len() != CHURN_REQUESTS {
        bail!(
            "churn: expected {CHURN_REQUESTS} completed requests, server saw {}",
            timings.len()
        );
    }
    let decile = CHURN_REQUESTS / 10;
    let mean =
        |window: &[Duration]| -> Duration { window.iter().sum::<Duration>() / window.len() as u32 };
    let first = mean(&timings[..decile]);
    let last = mean(&timings[CHURN_REQUESTS - decile..]);
    metrics.record("churn_first_decile_mean", first.as_secs_f64());
    metrics.record("churn_last_decile_mean", last.as_secs_f64());
    tracing::info!(?first, ?last, "churn decile means");
    let bound = (first * 3).max(Duration::from_millis(500));
    if last > bound {
        bail!(
            "churn: last-decile mean {last:?} exceeds flatness bound {bound:?} \
             (first-decile mean {first:?}) — per-connection slowdown"
        );
    }
    assert_no_established_flows(data_dir, BENCH, server.port(), SWEEP_GRACE)
}

/// Straggler bound: slowest flow ≤ max(4× median, `floor`). The absolute
/// floor keeps small medians from turning scheduler noise into a failure.
fn check_stragglers(
    timings: &[Duration],
    expected: usize,
    label: &str,
    floor: Duration,
    metrics: &mut RunMetrics,
) -> Result<()> {
    if timings.len() != expected {
        bail!(
            "{label}: expected {expected} completed flows, server saw {}",
            timings.len()
        );
    }
    let mut sorted = timings.to_vec();
    sorted.sort();
    let median = sorted[sorted.len() / 2];
    let slowest = *sorted.last().expect("non-empty by the length check");
    metrics.record(&format!("{label}_flow_median"), median.as_secs_f64());
    metrics.record(&format!("{label}_flow_slowest"), slowest.as_secs_f64());
    tracing::info!(?median, ?slowest, "{label} flow timings");
    let bound = (median * 4).max(floor);
    if slowest > bound {
        bail!(
            "{label}: slowest flow {slowest:?} exceeds straggler bound {bound:?} \
             (median {median:?}) — a flow stalled while its peers completed"
        );
    }
    Ok(())
}

/// W13: eight concurrent 64 MiB downloads — the multi-image-pull shape.
/// Sustained full-throughput windowing across parallel flows; the straggler
/// bound catches a flow whose retransmission or window accounting wedges
/// under volume rather than under connection count.
fn parallel_large_downloads(data_dir: &Path, metrics: &mut RunMetrics, _image: &str) -> Result<()> {
    let server = spawn_blob_server(PARALLEL_LARGE_BLOB_BYTES)?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{}/blob", server.port());
    let script = burst_script(&url, PARALLEL_LARGE_FLOWS);

    let started = Instant::now();
    if let Err(error) = docker_output(
        data_dir,
        &["exec", BENCH, "sh", "-c", &script],
        PARALLEL_LARGE_DEADLINE + Duration::from_secs(60),
    ) {
        bail!(
            "parallel_large: downloads failed ({} of {PARALLEL_LARGE_FLOWS} flows completed \
             server-side): {error:#}",
            server.timings().len()
        );
    }
    let elapsed = started.elapsed();
    metrics.record("parallel_large_wall", elapsed.as_secs_f64());
    let total_mib = (PARALLEL_LARGE_FLOWS * PARALLEL_LARGE_BLOB_BYTES) / (1024 * 1024);
    metrics.record(
        "parallel_large_mib_per_s",
        total_mib as f64 / elapsed.as_secs_f64(),
    );
    tracing::info!(?elapsed, total_mib, "parallel large downloads done");
    if elapsed >= PARALLEL_LARGE_DEADLINE {
        bail!("parallel_large: took {elapsed:?} (>= {PARALLEL_LARGE_DEADLINE:?})");
    }
    check_stragglers(
        &server.wait_for_timings(PARALLEL_LARGE_FLOWS, SWEEP_GRACE),
        PARALLEL_LARGE_FLOWS,
        "parallel_large",
        PARALLEL_LARGE_FLOOR,
        metrics,
    )?;
    assert_no_established_flows(data_dir, BENCH, server.port(), SWEEP_GRACE)
}

/// W14: docker build — the compound daily flow. Exercises the build-context
/// upload (Docker API over vsock), RUN-step networking through the full
/// datapath, and layer commits. Byte-exactness is asserted *inside* the
/// build: `RUN test $(wc -c ...)` steps fail the build on any truncation,
/// of the COPY'd context payload or of the in-RUN download.
fn docker_build_network(data_dir: &Path, metrics: &mut RunMetrics, image: &str) -> Result<()> {
    let server = spawn_blob_server(BUILD_FETCH_BYTES)?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{}/blob", server.port());

    // Build context: a Dockerfile plus an incompressible payload so the
    // context transfer moves real bytes.
    let ctx = data_dir.join("build-ctx");
    std::fs::create_dir_all(&ctx).context("creating build context dir")?;
    let mut payload = vec![0u8; BUILD_CONTEXT_PAYLOAD];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for chunk in payload.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    std::fs::write(ctx.join("payload.bin"), &payload).context("writing context payload")?;
    // Content hashes, not just lengths: a corrupted-but-length-preserving
    // transfer (the pre-fix upload path could reorder/hole-fill) must fail
    // the build, for both the vsock context upload and the RUN download.
    use sha2::Digest;
    let payload_sha = format!("{:x}", sha2::Sha256::digest(&payload));
    let blob_sha = format!("{:x}", sha2::Sha256::digest(vec![0u8; BUILD_FETCH_BYTES]));
    std::fs::write(
        ctx.join("Dockerfile"),
        format!(
            "FROM {image}\n\
             COPY payload.bin /payload.bin\n\
             RUN echo \"{payload_sha}  /payload.bin\" | sha256sum -c -\n\
             RUN wget -q -O /blob {url} && echo \"{blob_sha}  /blob\" | sha256sum -c -\n\
             RUN echo built-ok > /marker\n"
        ),
    )
    .context("writing Dockerfile")?;

    let started = Instant::now();
    let ctx_arg = ctx.display().to_string();
    let build = docker_output(
        data_dir,
        &["build", "-t", BUILD_TAG, &ctx_arg],
        BUILD_DEADLINE + Duration::from_secs(60),
    );
    let elapsed = started.elapsed();
    metrics.record("docker_build_wall", elapsed.as_secs_f64());
    let result = (|| {
        build.context("docker build")?;
        if elapsed >= BUILD_DEADLINE {
            bail!("docker_build: took {elapsed:?} (>= {BUILD_DEADLINE:?})");
        }
        // The image must actually run and carry the final layer.
        let marker = docker_output(
            data_dir,
            &["run", "--rm", BUILD_TAG, "cat", "/marker"],
            Duration::from_secs(60),
        )
        .context("running built image")?;
        if !marker.contains("built-ok") {
            bail!("docker_build: marker layer missing from built image: {marker:?}");
        }
        Ok(())
    })();
    docker_ignore(data_dir, &["rmi".into(), "-f".into(), BUILD_TAG.into()]);
    result
}

/// W15: download **integrity** — content, not just completion. The
/// byte-count checks elsewhere would pass on a stream that arrived the
/// right length but reordered/duplicated/corrupted (the shape the
/// silent-upload-loss bug produced on the other direction). The container
/// pipes a known-pattern download straight through `sha256sum` and we
/// compare to the server's hash of the exact bytes it served — end to end
/// through the download retransmission + reassembly path.
fn download_integrity(data_dir: &Path, _metrics: &mut RunMetrics, _image: &str) -> Result<()> {
    let server = spawn_pattern_server(INTEGRITY_BYTES, 0xABCD_1234)?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{}/blob", server.port());
    let script = format!("wget -q -O - '{url}' | sha256sum | cut -d' ' -f1");
    let out = docker_output(
        data_dir,
        &["exec", BENCH, "sh", "-c", &script],
        INTEGRITY_DEADLINE + Duration::from_secs(60),
    )
    .context("download_integrity: in-container hashed download")?;
    let got = out.trim();
    if got != server.sha256() {
        bail!(
            "download_integrity: sha256 mismatch — served {}, guest received {got} \
             (content corrupted in transit despite completing)",
            server.sha256()
        );
    }
    assert_no_established_flows(data_dir, BENCH, server.port(), SWEEP_GRACE)
}

/// W16: upload **integrity** — the direction the silent-data-loss bug hit.
/// The container hashes exactly what it sends (a urandom payload → temp
/// file → sha256sum → nc), and the host sink hashes exactly what it
/// receives; the two must match. A source-file hash + sink hash computed
/// independently at runtime catches any corruption without a predetermined
/// pattern.
fn upload_integrity(data_dir: &Path, _metrics: &mut RunMetrics, _image: &str) -> Result<()> {
    let sink = spawn_hashing_sink(INTEGRITY_BYTES)?;
    let mib = INTEGRITY_BYTES / (1024 * 1024);
    // Materialize the payload once, hash it, then stream it — so the
    // client-side hash is of the exact bytes handed to nc.
    let script = format!(
        "dd if=/dev/urandom of=/tmp/up.bin bs=1M count={mib} 2>/dev/null; \
         sha256sum /tmp/up.bin | cut -d' ' -f1; \
         nc {GUEST_GATEWAY_IP} {} < /tmp/up.bin; rm -f /tmp/up.bin",
        sink.port()
    );
    let started = Instant::now();
    let out = docker_output(
        data_dir,
        &["exec", BENCH, "sh", "-c", &script],
        INTEGRITY_DEADLINE + Duration::from_secs(60),
    )
    .context("upload_integrity: in-container hashed upload")?;
    let sent_sha = out
        .lines()
        .next()
        .map(str::trim)
        .filter(|h| h.len() == 64)
        .with_context(|| format!("upload_integrity: no client sha in output {out:?}"))?;
    let report = sink.wait_complete(INTEGRITY_DEADLINE.saturating_sub(started.elapsed()))?;
    if report.received != INTEGRITY_BYTES {
        bail!(
            "upload_integrity: sink received {} of {INTEGRITY_BYTES} bytes",
            report.received
        );
    }
    if report.sha256 != sent_sha {
        bail!(
            "upload_integrity: sha256 mismatch — client sent {sent_sha}, sink received {} \
             (upload corrupted in transit despite arriving full-length)",
            report.sha256
        );
    }
    assert_no_established_flows(data_dir, BENCH, sink.port(), SWEEP_GRACE)
}
