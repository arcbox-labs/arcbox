//! iperf3 throughput matrix e2e — the programmatic counterpart to the
//! manual `docs/net-perf-limits.md` reproducer.
//!
//! `tests/e2e/AGENTS.md` states the boot ladder proves liveness, not
//! throughput, and that RX/TX regressions are proven by hand. This test
//! turns that manual procedure into one command with structured output.
//! It deliberately does NOT gate on an absolute Gbps figure (throughput is
//! host-dependent and the project's stance is "no automated throughput
//! target", and VZ throughput is wildly run-to-run variable — an idle-VM
//! freeze can drop a 5 Gbps path to 0.4 Gbps with no code change). By
//! default the only hard assertion is **liveness**: a gated cell must not
//! error/hang or deliver literally zero. Every rate is recorded to
//! `RunMetrics` as a trend line, and `ARCBOX_E2E_IPERF_MIN_GBPS` turns the
//! gate into a real per-host throughput floor on a quiet machine.
//!
//! Matrix (all against a host-local iperf3 server the guest reaches at
//! `10.0.2.1`, the gateway→loopback egress datapath):
//!
//! - **netns**: default docker bridge (container datapath: eth0 → bridge →
//!   veth → container netns) vs `--net=host` (bare-guest datapath: the
//!   container shares the guest root netns, no veth hop). The bridge/host
//!   ratio quantifies the veth hop — the exact place the lossless-delivery
//!   contract ends and the download retransmission path earns its keep.
//! - **direction**: forward (client→server = guest→host **upload**) vs
//!   `-R` (server→client = host→guest **download**, which exercises the
//!   window-flow-control + retransmission path in `splicetcp`).
//! - **parallelism**: single stream vs `-P 4`.
//!
//! Plus one **inbound** cell: an iperf3 server in a container with a
//! published port, driven by a host-side iperf3 client — the reverse
//! topology, exercising `InboundListenerManager`.
//!
//! Requires a host `iperf3` binary (Homebrew: `brew install iperf3`) and,
//! in the guest, an iperf3 image (`networkstatic/iperf3` by default,
//! override with `ARCBOX_E2E_IPERF_IMAGE`); pulling it needs working guest
//! egress, which a real e2e boot has.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::docker::{docker_ignore, docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::net_fixtures::GUEST_GATEWAY_IP;
use arcbox_e2e::scenario::run_vz_scenario_with_log;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Per-stream transfer duration. Long enough to leave iperf3's slow-start
/// and reach steady state, short enough to keep the matrix under a couple
/// of minutes.
const STREAM_SECS: u32 = 5;
/// Parallel-variant stream count.
const PARALLEL_STREAMS: u32 = 4;
/// Hard ceiling on any single iperf3 invocation: its own `-t` plus generous
/// slack for the ~2 s control handshake and docker start.
fn cell_timeout() -> Duration {
    Duration::from_secs(u64::from(STREAM_SECS) + 45)
}
/// Gate floor in Gbps. Defaults to 0.0 — a **liveness** gate: a gated cell
/// fails only if it errored/hung or delivered literally nothing, never on a
/// throughput number. This is deliberate: the project's stance is "no
/// automated throughput target", and VZ throughput is wildly run-to-run
/// variable (an idle-VM freeze drops a 5 Gbps path to 0.4 Gbps with no code
/// change). Set `ARCBOX_E2E_IPERF_MIN_GBPS` on a quiet machine to turn this
/// into a real per-host throughput regression gate.
fn min_gbps() -> Result<f64> {
    match std::env::var("ARCBOX_E2E_IPERF_MIN_GBPS") {
        Err(_) => Ok(0.0),
        // A present-but-bad value must NOT silently disable the gate — a
        // run set up to enforce a floor would then pass everything.
        Ok(v) => {
            let f: f64 = v
                .parse()
                .with_context(|| format!("ARCBOX_E2E_IPERF_MIN_GBPS={v:?} is not a number"))?;
            if !f.is_finite() || f < 0.0 {
                bail!("ARCBOX_E2E_IPERF_MIN_GBPS={v:?} must be a non-negative number");
            }
            Ok(f)
        }
    }
}

/// A host-side `iperf3 -s` bound to `127.0.0.1:port`, killed on drop. The
/// guest reaches it at `10.0.2.1:port` through the TcpBridge translation.
struct HostIperfServer {
    child: Child,
    port: u16,
}

impl HostIperfServer {
    fn spawn() -> Result<Self> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .context("probing a free iperf3 port")?
            .local_addr()?
            .port();
        let child = Command::new("iperf3")
            .args(["-s", "-B", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawning host iperf3 -s (is iperf3 installed?)")?;
        // Wait for the server to accept connections.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(Self { child, port });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        bail!("host iperf3 server never accepted on 127.0.0.1:{port}");
    }
}

impl Drop for HostIperfServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Extracts the delivered throughput (bits/s) from iperf3 `-J` output:
/// `end.sum_received.bits_per_second` — the receiver's view, correct for
/// both forward (server receives) and `-R` (client receives).
fn parse_bps(json: &str) -> Result<f64> {
    // `docker_output` returns stdout+stderr merged, so docker's own lines
    // (e.g. "WARNING: The requested image's platform ... does not match")
    // can bracket iperf3's `-J` object. iperf3 emits exactly one top-level
    // JSON object, so slice from the first '{' to the last '}' rather than
    // parsing the whole string (which serde rejects on any surrounding
    // non-whitespace) — otherwise a benign docker warning fails the cell.
    let start = json.find('{').context("no JSON object in iperf3 output")?;
    let end = json
        .rfind('}')
        .context("no JSON object end in iperf3 output")?;
    let v: serde_json::Value =
        serde_json::from_str(&json[start..=end]).context("parsing iperf3 JSON")?;
    if let Some(err) = v.get("error").and_then(serde_json::Value::as_str) {
        bail!("iperf3 reported: {err}");
    }
    v.get("end")
        .and_then(|e| e.get("sum_received"))
        .and_then(|s| s.get("bits_per_second"))
        .and_then(serde_json::Value::as_f64)
        .context("iperf3 JSON missing end.sum_received.bits_per_second")
}

/// Records a cell's throughput to metrics and, for a `gated` cell, flags a
/// collapse below `floor` as a failure. A non-gated cell is a documented
/// known gap (see the module docs): its number is recorded and WARN-logged
/// but never fails the suite, so the test stays a green regression net for
/// the paths that work today while still trend-tracking the broken ones.
/// Returns the measured Gbps, or `None` if the cell errored (an error on a
/// gated cell is a failure; on a known-gap cell it is only a warning). Kept
/// a free function so it doesn't hold a mutable borrow of `failures` across
/// the matrix loop.
fn record_cell(
    metrics: &mut RunMetrics,
    label: &str,
    result: Result<f64>,
    floor: f64,
    gated: bool,
    failures: &mut Vec<String>,
) -> Option<f64> {
    match result {
        Ok(gbps) => {
            metrics.record(&format!("{label}_gbps"), gbps);
            // A gated cell must clear the floor (default 0 ⇒ just "> 0",
            // a liveness check); a known-gap cell always WARN-logs its
            // number, which is itself the finding.
            let effective = floor.max(f64::MIN_POSITIVE);
            if !gated {
                tracing::warn!(label, gbps, "iperf cell (known gap)");
            } else if gbps < effective {
                failures.push(format!(
                    "{label}: {gbps:.3} Gbps below floor {floor:.2} Gbps (wedge/regression)"
                ));
            } else {
                tracing::info!(label, gbps, "iperf cell");
            }
            Some(gbps)
        }
        Err(error) if gated => {
            failures.push(format!("{label}: {error:#}"));
            None
        }
        Err(error) => {
            tracing::warn!(label, "iperf cell (known gap) errored: {error:#}");
            None
        }
    }
}

/// Runs one egress cell (guest iperf3 client → host server) and returns
/// Gbps. `host_net` selects the bare-guest datapath; `reverse` selects the
/// host→guest download direction; `parallel` selects `-P 4`.
fn egress_cell(
    data_dir: &Path,
    image: &str,
    port: u16,
    host_net: bool,
    reverse: bool,
    parallel: bool,
) -> Result<f64> {
    let port_s = port.to_string();
    let streams = PARALLEL_STREAMS.to_string();
    let secs = STREAM_SECS.to_string();
    let mut args: Vec<&str> = vec!["run", "--rm"];
    if host_net {
        args.push("--net=host");
    }
    args.extend([
        image,
        "-c",
        GUEST_GATEWAY_IP,
        "-p",
        &port_s,
        "-t",
        &secs,
        "-J",
    ]);
    if reverse {
        args.push("-R");
    }
    if parallel {
        args.extend(["-P", &streams]);
    }
    let json = docker_output(data_dir, &args, cell_timeout()).context("iperf3 client")?;
    Ok(parse_bps(&json)? / 1e9)
}

#[test]
#[ignore = "boots a VZ System VM; needs host iperf3 + a guest iperf3 image"]
fn net_iperf_throughput_matrix() -> Result<()> {
    run_vz_scenario_with_log(
        "network_iperf",
        "info,arcbox_net=debug",
        |daemon, data_dir, metrics| {
            metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
            let image = std::env::var("ARCBOX_E2E_IPERF_IMAGE")
                .unwrap_or_else(|_| "networkstatic/iperf3:latest".to_owned());
            metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

            let server = HostIperfServer::spawn()?;
            let floor = min_gbps()?;
            let mut failures = Vec::new();

            // Egress matrix: {bridge, host-net} × {upload, download} × {single, P4}.
            // KNOWN GAP: container (bridge) UPLOAD collapses to ~50-150 Mbps
            // vs ~3 Gbps bare-guest — a container-egress datapath limit this
            // test quantifies but does not yet fix (see module docs). Those
            // cells are recorded + WARN-logged but do not gate the suite;
            // every other cell must clear the collapse floor.
            let mut bridge_dl_single = None;
            let mut hostnet_dl_single = None;
            let mut bridge_ul_single = None;
            let mut hostnet_ul_single = None;
            for &host_net in &[false, true] {
                let ns = if host_net { "hostnet" } else { "bridge" };
                for &reverse in &[false, true] {
                    let dir = if reverse { "download" } else { "upload" };
                    for &parallel in &[false, true] {
                        let par = if parallel { "p4" } else { "single" };
                        let label = format!("{ns}_{dir}_{par}");
                        // Container upload is the documented gap; everything
                        // else is gated.
                        let gated = host_net || reverse;
                        let gbps = record_cell(
                            metrics,
                            &label,
                            egress_cell(data_dir, &image, server.port, host_net, reverse, parallel),
                            floor,
                            gated,
                            &mut failures,
                        );
                        match (host_net, reverse, parallel) {
                            (false, true, false) => bridge_dl_single = gbps,
                            (true, true, false) => hostnet_dl_single = gbps,
                            (false, false, false) => bridge_ul_single = gbps,
                            (true, false, false) => hostnet_ul_single = gbps,
                            _ => {}
                        }
                    }
                }
            }

            // Quantify the container-upload gap explicitly (recorded, not
            // gated) — this ratio is the headline finding of the suite.
            if let (Some(bridge), Some(hostnet)) = (bridge_ul_single, hostnet_ul_single)
                && hostnet > 0.0
            {
                let ratio = bridge / hostnet;
                metrics.record("veth_hop_ratio_upload", ratio);
                tracing::warn!(
                    bridge,
                    hostnet,
                    ratio,
                    "container-upload gap: bridge upload is {:.1}x slower than bare-guest",
                    1.0 / ratio.max(f64::MIN_POSITIVE)
                );
            }

            // Veth-hop cost: the bridge (container) download path adds a
            // bridge→veth→netns hop over the bare-guest path. Recorded as a
            // trend line only — not gated, since VZ variance moves the two
            // endpoints of the ratio independently and would flake a hard
            // bound.
            if let (Some(bridge), Some(hostnet)) = (bridge_dl_single, hostnet_dl_single)
                && hostnet > 0.0
            {
                let ratio = bridge / hostnet;
                metrics.record("veth_hop_ratio_download", ratio);
                tracing::info!(bridge, hostnet, ratio, "veth-hop download ratio");
            }

            // Inbound cell: iperf3 server in a container with a published
            // port, driven by the HOST iperf3 client — the reverse topology
            // through InboundListenerManager. `-R` makes the container
            // server send, so this also measures host→container.
            //
            // KNOWN GAP: the first programmatic exercise of this path shows
            // iperf3's control-message exchange failing over a published
            // port ("unable to receive control message ... Socket is not
            // connected"), i.e. the inbound relay does not yet carry a
            // multi-connection application cleanly. Recorded + WARN-logged,
            // not gated, until that is fixed.
            match inbound_cell(data_dir, &image) {
                Ok((up, down)) => {
                    metrics.record("inbound_host_to_container_gbps", up);
                    metrics.record("inbound_container_to_host_gbps", down);
                    if up.min(down) < floor {
                        tracing::warn!(up, down, "inbound port-forward (known gap) below floor");
                    } else {
                        tracing::info!(up, down, "inbound port-forward iperf cells");
                    }
                }
                Err(error) => {
                    tracing::warn!("inbound port-forward (known gap) errored: {error:#}");
                }
            }

            if failures.is_empty() {
                Ok(())
            } else {
                bail!(
                    "{} iperf cell(s) failed:\n{}",
                    failures.len(),
                    failures.join("\n")
                )
            }
        },
    )
}

/// Inbound: an iperf3 server in a container publishing an ephemeral host
/// port, driven by the host iperf3 client. Returns (host→container,
/// container→host) Gbps. Exercises the published-port datapath, which the
/// egress matrix never touches.
fn inbound_cell(data_dir: &Path, image: &str) -> Result<(f64, f64)> {
    const SRV: &str = "net-iperf-inbound-srv";
    // Publish container 5201 on an ephemeral 127.0.0.1 host port; guest
    // dockerd allocates it and ArcBox binds it (probe-confirmed helper-free).
    docker_output(
        data_dir,
        &[
            "run",
            "-d",
            "--name",
            SRV,
            "-p",
            "127.0.0.1::5201",
            image,
            "-s",
            "-p",
            "5201",
        ],
        Duration::from_secs(60),
    )
    .context("starting published iperf3 server container")?;

    let result = (|| {
        // Discover the mapped host port from `docker port`.
        let mapped = docker_output(
            data_dir,
            &["port", SRV, "5201/tcp"],
            Duration::from_secs(20),
        )
        .context("docker port")?;
        let host_port = mapped
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse::<u16>().ok())
            .with_context(|| format!("parsing mapped port from {mapped:?}"))?;

        // Wait for the published port to actually accept from the host —
        // guest dockerd reports the mapping before the in-container server
        // has bound and the inbound listener is wired.
        let ready_deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < ready_deadline
            && std::net::TcpStream::connect(("127.0.0.1", host_port)).is_err()
        {
            std::thread::sleep(Duration::from_millis(200));
        }
        let hp = host_port.to_string();
        let secs = STREAM_SECS.to_string();
        let run_host_client = |reverse: bool| -> Result<f64> {
            let mut args = vec![
                "iperf3",
                "-c",
                "127.0.0.1",
                "-p",
                &hp,
                "-t",
                &secs,
                "-J",
                "--connect-timeout",
                "5000",
            ];
            if reverse {
                args.push("-R");
            }
            let out = arcbox_e2e::docker::run_with_timeout(
                Command::new(args[0]).args(&args[1..]),
                cell_timeout(),
            )
            .context("host iperf3 client")?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !out.status.success() {
                // iperf3 -J puts the error in the JSON on stdout.
                bail!(
                    "host iperf3 client exited {} (stdout: {}) (stderr: {})",
                    out.status,
                    stdout.trim(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Ok(parse_bps(&stdout)? / 1e9)
        };
        // Forward: host client sends → container server receives = host→container.
        let host_to_container = run_host_client(false)?;
        // Reverse: container server sends → host client receives = container→host.
        let container_to_host = run_host_client(true)?;
        Ok((host_to_container, container_to_host))
    })();

    docker_ignore(data_dir, &["rm".into(), "-f".into(), SRV.into()]);
    result
}
