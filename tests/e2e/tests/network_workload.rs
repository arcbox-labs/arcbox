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
    spawn_slow_sink,
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

/// Teardown grace for the zombie sweep: in-flight FIN handling passes, a
/// frozen flow (the 2026-07-19 incident shape) fails.
const SWEEP_GRACE: Duration = Duration::from_secs(10);

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

            let scenarios: [(&str, ScenarioFn); 5] = [
                ("upload_steady", upload_steady),
                ("upload_paused_reader", upload_paused_reader),
                ("burst_single_container", burst_single_container),
                ("burst_multi_container", burst_multi_container),
                ("churn_sequential", churn_sequential),
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

/// Straggler bound: slowest flow ≤ max(4× median, 2 s). The absolute floor
/// keeps sub-second medians from turning scheduler noise into a failure.
fn check_stragglers(
    timings: &[Duration],
    expected: usize,
    label: &str,
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
    let bound = (median * 4).max(Duration::from_secs(2));
    if slowest > bound {
        bail!(
            "{label}: slowest flow {slowest:?} exceeds straggler bound {bound:?} \
             (median {median:?}) — a flow stalled while its peers completed"
        );
    }
    Ok(())
}
