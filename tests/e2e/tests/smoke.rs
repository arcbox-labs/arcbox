//! Smoke suite — the "does the product basically work" checks (ABX-291).
//!
//! These are the assertions a release should never ship without: a container
//! runs and the CLI returns, a published port reaches it from the host, and a
//! container resolves a sibling by name. Everything else in `tests/e2e`
//! targets a specific defect class; this file targets the happy path itself,
//! which until now had no automated coverage at all.
//!
//! **One VM, sequential phases.** Each phase costs a full System VM boot if
//! split across `#[test]` functions, so this follows `boot_assets`: one boot,
//! phases named for the issue they close, recorded into `metrics.json`. A
//! failing phase masks later ones — acceptable here, since a broken
//! `docker run` makes the rest meaningless anyway.
//!
//! **Isolation.** No fixed host ports: the published-port phase asks Docker
//! for an ephemeral one on `127.0.0.1` and reads it back with `docker port`,
//! per the parallel-safety contract in AGENTS.md.
//!
//! Covers ABX-305 (run & exit), ABX-306 (published port), ABX-308 (name
//! resolution), ABX-309 (boot budget), CORE-67 (setup phase progression).
//!
//! Deliberately **not** covered: **ABX-307** (L3 direct routing to a
//! container IP via bridge100). The host route is installed by the
//! privileged helper (`route_add` in `app/arcbox-helper`), which the harness
//! does not run and AGENTS.md forbids touching. A test here would silently
//! depend on the developer's installed ArcBox having placed the route — host
//! state, not product behavior. It needs a helper-aware harness first.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::daemon::PhaseMarks;
use arcbox_e2e::docker::{docker_ignore, docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::scenario::run_vz_scenario;
use arcbox_protocol::v1::setup_status::Phase;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);
/// Body the in-container httpd serves; distinctive enough that a stray proxy
/// or a wrong-port connection cannot produce it by accident.
const MARKER: &str = "arcbox-smoke-ok";
/// How long to wait for busybox httpd to bind inside the container. The
/// container is already running by then — this only covers process start.
const HTTPD_READY: Duration = Duration::from_secs(30);
/// Per-attempt budget for a host→container HTTP request.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Default ceiling for the `VmStarting → VmReady` span (ABX-309).
///
/// **A regression backstop, not the performance target.** The span is the
/// guest boot on its own — guest binaries are staged before `VmStarting` and
/// the agent has answered by `VmReady` (CORE-67) — so it is directly
/// comparable to the ~1.5 s cold-boot target, unlike the `AssetsReady →
/// Ready` window it replaced. Measured 1.55 s and 2.29 s on an M-series
/// developer machine under VZ (2026-08-01); the ceiling leaves roughly 4×
/// for a loaded CI runner, because a bound tight enough to double as the
/// target would buy flakes rather than signal. Tighten via
/// `ARCBOX_E2E_BOOT_BUDGET_SECS` as `metrics.json` accumulates a
/// distribution to argue from.
const BOOT_BUDGET_DEFAULT_SECS: f64 = 10.0;

/// Phases a healthy cold start publishes, in order.
///
/// `AssetsReady` may be missed — the harness subscribes only once the gRPC
/// socket exists, and a fast startup can already be past it. Everything from
/// `VmStarting` on is published well after that point, so a missing one is a
/// real defect, not a fast run.
const EXPECTED_PROGRESSION: [Phase; 5] = [
    Phase::AssetsReady,
    Phase::VmStarting,
    Phase::VmReady,
    Phase::NetworkReady,
    Phase::Ready,
];

#[test]
#[ignore = "boots a VZ System VM through a real daemon; run on the e2e runner"]
fn smoke_suite() -> Result<()> {
    run_vz_scenario("smoke", |daemon, data_dir, metrics| {
        // Measured directly rather than via `metrics.time` because ABX-309
        // wants the number, not just the recording.
        let started = Instant::now();
        daemon.wait_ready_blocking(READY_TIMEOUT)?;
        let ready_elapsed = started.elapsed();
        metrics.record("daemon_ready", ready_elapsed.as_secs_f64());
        tracing::info!(?ready_elapsed, "daemon ready");

        // Every observed phase lands in metrics.json so a baseline can be
        // built from passing runs, not just from failures.
        for (name, at) in daemon.phase_marks().timeline() {
            metrics.record(
                &format!("phase_{}", name.to_ascii_lowercase()),
                at.as_secs_f64(),
            );
        }
        check_phase_progression(daemon.phase_marks())?;
        check_boot_budget(daemon.phase_marks(), metrics)?;

        let image =
            std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
        metrics.time("image_pull", || ensure_image(data_dir, &image))?;

        // Unique per run so parallel harnesses cannot collide on names.
        let suffix = std::process::id();
        let server_name = format!("arcbox-smoke-httpd-{suffix}");
        let guard = ContainerGuard::new(data_dir, &server_name);

        metrics.time("container_run", || run_and_exit(data_dir, &image))?;
        let host_port = metrics.time("published_port", || {
            published_port_reaches_container(data_dir, &image, &server_name)
        })?;
        tracing::info!(host_port, "published port verified");
        metrics.time("name_resolution", || {
            name_resolves_from_sibling(data_dir, &image, &server_name)
        })?;

        drop(guard);
        Ok(())
    })
}

/// CORE-67 — the setup stream reports the whole progression, in order.
///
/// An unpublished phase is not observable as a gap: it never arrives, so a
/// client waits forever or reports a plausible zero. This asserts the phases
/// actually show up, and that their sighting order matches the declared
/// progression, so a reordering of the startup pipeline cannot silently
/// start lying to clients.
fn check_phase_progression(marks: &PhaseMarks) -> Result<()> {
    let observed: Vec<Phase> = EXPECTED_PROGRESSION
        .into_iter()
        .filter(|phase| marks.at(*phase).is_some())
        .collect();

    for phase in EXPECTED_PROGRESSION {
        // AssetsReady is genuinely missable on a fast start; the rest are
        // published long after the harness subscribes.
        if phase != Phase::AssetsReady && !observed.contains(&phase) {
            bail!(
                "daemon never published {} — observed {:?}. A declared-but-unpublished phase \
                 leaves clients blind to that stage (CORE-67).",
                phase.as_str_name(),
                observed
            );
        }
    }

    // Sorting by sighting time is a stable no-op when the order is right;
    // ties (two phases in the same instant) keep declaration order.
    let mut by_sighting = observed.clone();
    by_sighting.sort_by_key(|phase| marks.at(*phase).expect("filtered to observed phases"));
    if by_sighting != observed {
        bail!("setup phases arrived out of order: {by_sighting:?}, expected {observed:?}");
    }
    Ok(())
}

/// ABX-309 — the boot span stays within budget.
///
/// Measures `VmStarting → VmReady`: the guest boot alone. Guest binaries are
/// staged before `VmStarting`, and `VmReady` means the guest agent answered,
/// so runtime construction, asset preparation, the dockerd wait, and host
/// service startup all fall outside it (CORE-67).
///
/// Both marks are required, not skipped when absent: they are published long
/// after the harness subscribes, so a missing one means the daemon never sent
/// it — which is unobservable as a gap and would otherwise pass as a silent
/// skip (CORE-67).
fn check_boot_budget(marks: &PhaseMarks, metrics: &mut RunMetrics) -> Result<()> {
    let Some(span) = marks.span(Phase::VmStarting, Phase::VmReady) else {
        bail!(
            "no VmStarting → VmReady pair on the setup stream, so the guest boot cannot be \
             measured at all"
        );
    };
    metrics.record("boot_span", span.as_secs_f64());

    let budget = std::env::var("ARCBOX_E2E_BOOT_BUDGET_SECS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(BOOT_BUDGET_DEFAULT_SECS);

    if span.as_secs_f64() > budget {
        bail!(
            "guest boot took {:.1}s, over the {budget:.1}s budget (VmStarting → VmReady: System \
             VM boot through agent readiness). Either this is a boot regression, or the machine \
             is legitimately slower — raise ARCBOX_E2E_BOOT_BUDGET_SECS.",
            span.as_secs_f64()
        );
    }
    tracing::info!(?span, budget, "guest boot within budget");
    Ok(())
}

/// ABX-305 — `docker run --rm <image> echo hello` exits 0 with "hello".
///
/// The assertion is as much about *returning* as about the output: ABX-372
/// reports foreground `docker run` hanging after the container exits, in
/// which case `docker_output` trips its timeout and this fails loudly.
fn run_and_exit(data_dir: &std::path::Path, image: &str) -> Result<()> {
    let out = docker_output(
        data_dir,
        &["run", "--rm", image, "echo", MARKER],
        DOCKER_TIMEOUT,
    )
    .context("docker run --rm did not return (see ABX-372 for the known hang)")?;

    if !out.contains(MARKER) {
        bail!("container ran but stdout lacked {MARKER:?}; got: {out:?}");
    }
    Ok(())
}

/// ABX-306 — a published port on the host reaches the container.
///
/// Publishes to `127.0.0.1` on an *ephemeral* host port (`-p 127.0.0.1::80`)
/// rather than the fixed `18080` the original issue suggested: a fixed host
/// port is one of the globals a data dir does not isolate, so it would break
/// parallel runs and collide with an installed ArcBox. Returns the assigned
/// port so the caller can record it.
fn published_port_reaches_container(
    data_dir: &std::path::Path,
    image: &str,
    name: &str,
) -> Result<u16> {
    docker_output(
        data_dir,
        &[
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::80",
            image,
            "sh",
            "-c",
            &httpd_command(),
        ],
        DOCKER_TIMEOUT,
    )
    .context("starting the httpd container")?;

    let mapping = docker_output(data_dir, &["port", name, "80/tcp"], DOCKER_TIMEOUT)
        .context("reading the assigned host port")?;
    let host_port = parse_host_port(&mapping)
        .with_context(|| format!("parsing `docker port` output: {mapping:?}"))?;

    let addr = format!("127.0.0.1:{host_port}");
    let body = http_get_with_retry(&addr, HTTPD_READY)
        .with_context(|| format!("host could not reach the published port at {addr}"))?;
    if !body.contains(MARKER) {
        bail!("published port answered but body lacked {MARKER:?}; got: {body:?}");
    }
    Ok(host_port)
}

/// ABX-308 — a container resolves a sibling by name and can reach it.
///
/// Runs guest-side on purpose. The original issue framed this as
/// `curl http://name.arcbox.local/` from the *host*, which needs
/// `/etc/resolver/arcbox.local` — written by the privileged helper, outside
/// what this harness may touch. Container→container resolution exercises the
/// same registration path (`dns_server::register_container`, driven by the
/// agent's docker event stream) without any host-global state.
fn name_resolves_from_sibling(data_dir: &std::path::Path, image: &str, target: &str) -> Result<()> {
    let url = format!("http://{target}/");
    let out = docker_output(
        data_dir,
        &[
            "run", "--rm", image, "wget", "-q", "-T", "20", "-O", "-", &url,
        ],
        DOCKER_TIMEOUT,
    )
    .with_context(|| {
        format!(
            "a sibling container could not resolve/reach {target:?} — the agent registers \
             container names for DNS in dns_server::register_container"
        )
    })?;

    if !out.contains(MARKER) {
        bail!("resolved {target:?} but body lacked {MARKER:?}; got: {out:?}");
    }
    Ok(())
}

/// busybox httpd serving a single file containing [`MARKER`].
///
/// Uses what alpine already ships rather than pulling nginx, so the suite
/// needs exactly one image.
fn httpd_command() -> String {
    format!("mkdir -p /www && printf '%s' '{MARKER}' > /www/index.html && httpd -f -p 80 -h /www")
}

/// Extracts the host port from `docker port <c> 80/tcp` output, e.g.
/// `127.0.0.1:54321` (possibly several lines for multiple bindings).
fn parse_host_port(mapping: &str) -> Option<u16> {
    mapping
        .lines()
        .filter_map(|line| line.trim().rsplit_once(':'))
        .find_map(|(_, port)| port.trim().parse::<u16>().ok())
}

/// Retries [`http_get`] until `deadline` elapses — the container is running
/// before httpd has necessarily bound.
fn http_get_with_retry(addr: &str, grace: Duration) -> Result<String> {
    let started = Instant::now();
    let mut last: Option<anyhow::Error> = None;
    while started.elapsed() < grace {
        match http_get(addr) {
            Ok(body) => return Ok(body),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no attempt was made")))
        .with_context(|| format!("no successful response within {grace:?}"))
}

/// Minimal HTTP/1.0 GET — avoids depending on `curl` being installed on the
/// runner, and keeps the host side dependency-free like `net_fixtures`.
fn http_get(addr: &str) -> Result<String> {
    let mut stream = TcpStream::connect(addr).context("connect")?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT))?;
    stream.set_write_timeout(Some(HTTP_TIMEOUT))?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .context("write request")?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("read response")?;
    Ok(response)
}

/// Removes a container on drop so a failed assertion cannot leak it into the
/// next run. The data dir is per-run, but a preserved dir (`KEEP_TEST_DIR`)
/// keeps its daemon's state around.
struct ContainerGuard<'a> {
    data_dir: &'a std::path::Path,
    name: String,
}

impl<'a> ContainerGuard<'a> {
    fn new(data_dir: &'a std::path::Path, name: &str) -> Self {
        Self {
            data_dir,
            name: name.to_owned(),
        }
    }
}

impl Drop for ContainerGuard<'_> {
    fn drop(&mut self) {
        docker_ignore(
            self.data_dir,
            &["rm".to_owned(), "-f".to_owned(), self.name.clone()],
        );
    }
}
