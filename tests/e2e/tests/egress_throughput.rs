//! Sustained-egress regression e2e (container→external download black hole).
//!
//! The incident: multi-MB container downloads from fast CDNs stalled
//! permanently (~40-100% of attempts), while the same URL downloaded fine
//! on the host. Two distinct defects produced the shape:
//!
//! 1. **Frame drops under backpressure** (fixed): the TCP shim terminates
//!    guest connections and never retransmits, and the socketpair write
//!    path dropped frames on `ENOBUFS`/queue-cap — a permanent sequence
//!    gap. Covered by the `GuestTx` lossless contract; the delivery
//!    counters in the daemon log must stay at zero drops during this test.
//! 2. **VZ virtio-net freeze** (open, ABX-420): the device stops moving
//!    frames in both directions for ~60-75 s and self-heals — during the
//!    freeze the socketpair is empty, guest routing is intact, and no
//!    guest kernel errors appear. Reproduces here on roughly 1 in 5
//!    downloads, so this scenario currently FAILS intermittently; the
//!    forensics it captures (eth0 counter deltas, recovery-time probe,
//!    delivery counters) are the post-mortem record for the hunt.
//!
//! The scenario needs no external network: a host-local HTTP server serves
//! large blobs and a container downloads them through the full egress
//! datapath (guest eth0 → classifier → TcpBridge fast path → host socket)
//! via the gateway-IP→loopback translation, which also regression-tests
//! `host.docker.internal` staying direct under a configured system proxy.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::{docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Blob size per download. Large enough to sustain a multi-second transfer
/// (the original stalls hit within the first ~64 KB..few MB).
const BLOB_BYTES: usize = 64 * 1024 * 1024;
/// Number of sequential downloads. The pre-fix stall rate was ~40-100% per
/// attempt, so several consecutive successes give strong signal.
const DOWNLOADS: usize = 6;
/// Ceiling for one in-container download (loopback moves 64 MB in seconds;
/// generous slack for slow CI hosts).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// Gateway IP the guest sees on its primary (userspace-netstack) NIC.
/// TcpBridge translates connections targeting it to host `127.0.0.1`
/// (the `host.docker.internal` mechanism), which is exactly the datapath
/// under test.
const GUEST_GATEWAY_IP: &str = "10.0.2.1";

fn init_tracing() {
    TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

/// Serves `BLOB_BYTES` of zeroes for any HTTP request, one thread per
/// connection, until the process exits. Returns the bound port.
fn spawn_blob_server() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding blob server")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                // Read the request until the header terminator (or EOF).
                let mut buf = [0u8; 4096];
                let mut request = Vec::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {BLOB_BYTES}\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                let chunk = vec![0u8; 64 * 1024];
                let mut remaining = BLOB_BYTES;
                while remaining > 0 {
                    let n = remaining.min(chunk.len());
                    if stream.write_all(&chunk[..n]).is_err() {
                        return;
                    }
                    remaining -= n;
                }
            });
        }
    });
    Ok(port)
}

#[test]
#[ignore = "boots a VZ System VM through a real daemon and drives sustained egress downloads"]
fn sustained_egress_downloads_do_not_stall() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-egress-throughput-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    // Probe a free port for the daemon's host DNS service so this test can
    // run alongside a developer's live daemon (fixed 5553) and parallel
    // test runs. The bind is dropped before the daemon starts — a benign
    // TOCTOU for a test harness.
    let dns_port = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .context("probing a free DNS port")?
        .port();

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            ("ARCBOX_DNS_PORT".to_owned(), dns_port.to_string()),
            // Per-SYN datapath tracing: stall forensics need the gated-SYN,
            // handshake-retransmit, and RST decisions, which log at debug.
            (
                "RUST_LOG".to_owned(),
                "info,arcbox_net=debug,splicetcp=debug".to_owned(),
            ),
        ],
    })?;

    let mut metrics = RunMetrics::new("egress_throughput", Some("vz"));
    let result = scenario(&mut daemon, data_dir.path(), &mut metrics);
    metrics.passed = result.is_ok();
    if let Err(error) = metrics.write(Some(data_dir.path())) {
        tracing::warn!("writing run metrics failed: {error:#}");
    }
    if result.is_err() {
        let kept = data_dir.keep();
        tracing::warn!(path = %kept.display(), "preserving test directory");
    }
    result
}

fn scenario(daemon: &mut DaemonHandle, data_dir: &Path, metrics: &mut RunMetrics) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;

    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
    metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

    let port = spawn_blob_server()?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{port}/blob");
    tracing::info!(%url, blob_mb = BLOB_BYTES / (1024 * 1024), "blob server up");

    // ABX-423 experiment (ARCBOX_E2E_GUEST_SAMPLER): a persistent in-guest
    // 1 Hz sampler recording eth0 packet counters and virtio interrupt
    // counts for the whole scenario. Its timeline across a freeze is the
    // guest-side vs device-side discriminator: frozen tx_packets = the
    // guest driver stopped transmitting (NAPI/interrupt wedge in the
    // guest); advancing tx_packets with a silent host datapath = frames
    // vanish on the device side. Read back with `docker logs` (vsock,
    // unaffected by the freeze).
    let sampler = std::env::var_os("ARCBOX_E2E_GUEST_SAMPLER").is_some();
    if sampler {
        let script = r#"while true; do
  echo "t=$(date +%s) tx=$(cat /sys/class/net/eth0/statistics/tx_packets) rx=$(cat /sys/class/net/eth0/statistics/rx_packets)"
  grep virtio /proc/interrupts | awk '{s=0; for(i=2;i<=NF;i++) if ($i+0==$i) s+=$i; printf "  irq %s %s\n", $1, s}'
  sleep 1
done"#;
        docker_output(
            data_dir,
            &[
                "run",
                "-d",
                "--name",
                "abx423-sampler",
                "--net=host",
                "--privileged",
                &image,
                "sh",
                "-c",
                script,
            ],
            Duration::from_secs(30),
        )
        .context("starting guest sampler")?;
        tracing::info!("guest sampler started (1 Hz eth0 + virtio irq counters)");
    }

    // ABX-423 experiment (ARCBOX_E2E_CANARY_PING): a 1 Hz gateway pinger
    // running for the whole scenario forces a guest virtio-net TX kick every
    // second. If a guest-side kick revives the frozen device, stalls shrink
    // from ~60-75 s to ~1-2 s and downloads stop failing.
    let canary = std::env::var_os("ARCBOX_E2E_CANARY_PING").is_some();
    if canary {
        docker_output(
            data_dir,
            &[
                "run",
                "-d",
                "--name",
                "abx423-canary",
                &image,
                "ping",
                "-i",
                "1",
                GUEST_GATEWAY_IP,
            ],
            Duration::from_secs(30),
        )
        .context("starting canary pinger")?;
        tracing::info!("canary pinger started (1 Hz guest TX kicks)");
    }

    let downloads = run_downloads(data_dir, metrics, &image, &url, "download", daemon.pid());
    if canary {
        arcbox_e2e::docker::docker_ignore(
            data_dir,
            &["rm".into(), "-f".into(), "abx423-canary".into()],
        );
    }
    if sampler {
        arcbox_e2e::docker::docker_ignore(
            data_dir,
            &["rm".into(), "-f".into(), "abx423-sampler".into()],
        );
    }
    downloads?;

    // Optional second phase: a real external URL (e.g. a fast CDN, possibly
    // through a host VPN). Environment-dependent, so never run in CI — set
    // ARCBOX_E2E_EGRESS_URL to enable during manual validation.
    if let Ok(external) = std::env::var("ARCBOX_E2E_EGRESS_URL") {
        tracing::info!(url = %external, "external egress phase");
        run_downloads(
            data_dir,
            metrics,
            &image,
            &external,
            "external_download",
            daemon.pid(),
        )?;
    }

    Ok(())
}

/// Runs all `DOWNLOADS` attempts (not aborting on the first stall, so the
/// failure pattern is visible), captures guest-side forensics after any
/// failure, and errors if any attempt stalled.
fn run_downloads(
    data_dir: &Path,
    metrics: &mut RunMetrics,
    image: &str,
    url: &str,
    label_prefix: &str,
    daemon_pid: u32,
) -> Result<()> {
    // Default 60 s tolerates slow CI. The ABX-423 hunt sets a short timeout
    // (e.g. 15 s) so a stall is detected while the ~60-75 s freeze is still
    // live and the forensics below observe it, not its aftermath.
    let wget_timeout = std::env::var("ARCBOX_E2E_WGET_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(60)
        .to_string();
    let mut failures = Vec::new();
    for attempt in 1..=DOWNLOADS {
        let label = format!("{label_prefix}_{attempt}");
        let result = metrics.time(&label, || {
            docker_output(
                data_dir,
                &[
                    "run",
                    "--rm",
                    image,
                    "wget",
                    "-q",
                    "-O",
                    "/dev/null",
                    "-T",
                    &wget_timeout,
                    url,
                ],
                DOWNLOAD_TIMEOUT,
            )
        });
        match result {
            Ok(_) => tracing::info!(attempt, label_prefix, "download completed"),
            Err(error) => {
                tracing::warn!(attempt, label_prefix, "download stalled: {error:#}");
                if failures.is_empty() {
                    // Thread census FIRST — the freeze may end within seconds
                    // of the wget timeout, and the VZ-internal thread states
                    // are the most perishable evidence.
                    sample_daemon(data_dir, daemon_pid);
                    capture_guest_forensics(data_dir, image);
                }
                failures.push(attempt);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{label_prefix}: attempts {failures:?} of {DOWNLOADS} stalled")
    }
}

/// Samples the daemon's threads (Virtualization.framework internals
/// included) into `<data_dir>/freeze-sample.txt` — the ABX-423 hunt's view
/// into where Apple's file-handle device threads are parked during a
/// freeze.
fn sample_daemon(data_dir: &Path, pid: u32) {
    let out = data_dir.join("freeze-sample.txt");
    match std::process::Command::new("sample")
        .args([&pid.to_string(), "2", "-file", &out.display().to_string()])
        .output()
    {
        Ok(o) if o.status.success() => {
            tracing::info!(path = %out.display(), "daemon thread sample captured");
        }
        Ok(o) => tracing::warn!(
            "sample failed: {}",
            String::from_utf8_lossy(&o.stderr).trim_end()
        ),
        Err(e) => tracing::warn!("sample not available: {e}"),
    }
}

/// Captures guest network state right after a stall: routing table,
/// interface addresses, and small-transfer probes that distinguish a total
/// datapath freeze from a per-connection loss.
fn capture_guest_forensics(data_dir: &Path, image: &str) {
    // Dump the in-guest sampler's timeline first — it covers the freeze
    // onset retroactively, so it has no live-window race at all.
    if std::env::var_os("ARCBOX_E2E_GUEST_SAMPLER").is_some() {
        match docker_output(
            data_dir,
            &["logs", "--tail", "400", "abx423-sampler"],
            Duration::from_secs(30),
        ) {
            Ok(out) => tracing::info!("guest sampler timeline:\n{}", out.trim_end()),
            Err(error) => tracing::warn!("guest sampler read failed: {error:#}"),
        }
    }

    // ABX-423 mitigation experiment (ARCBOX_E2E_TRY_LINK_BOUNCE): FIRST in
    // the sequence — the freeze often ends ~30 s after onset, and the other
    // probes would eat the remaining live window. Tries guest-side recovery
    // actions in escalating order — a link bounce (NAPI/queue re-enable)
    // and a virtio driver unbind/rebind (full device reset + feature
    // renegotiation), statically reconfiguring eth0 after each. If either
    // revives the datapath in seconds, an agent-side watchdog becomes a
    // shippable mitigation.
    if std::env::var_os("ARCBOX_E2E_TRY_LINK_BOUNCE").is_some() {
        let script = r#"
probe() { wget -q -O /dev/null -T 3 http://10.0.2.1:9/ 2>&1 | grep -q "timed out" && echo "$1: FROZEN" || echo "$1: alive"; }
restore() { ip link set eth0 up; ip addr replace 10.0.2.2/24 dev eth0; ip route replace default via 10.0.2.1 dev eth0; }
echo "t=$(date +%s)"
if ! probe baseline | tee /dev/stderr | grep -q FROZEN; then
  echo "freeze already over; skipping recovery actions"
  exit 0
fi
ip link set eth0 down; restore; sleep 1
echo "t=$(date +%s)"; probe after-link-bounce
d=$(basename $(dirname $(dirname $(ls -d /sys/bus/virtio/devices/*/net/eth0 2>/dev/null | head -1))))
if [ -n "$d" ]; then
  echo "$d" > /sys/bus/virtio/drivers/virtio_net/unbind; sleep 1
  echo "$d" > /sys/bus/virtio/drivers/virtio_net/bind; sleep 1
  restore
  echo "t=$(date +%s)"; probe after-driver-rebind
fi
"#;
        match docker_output(
            data_dir,
            &[
                "run",
                "--rm",
                "--net=host",
                "--privileged",
                image,
                "sh",
                "-c",
                script,
            ],
            Duration::from_secs(60),
        ) {
            Ok(out) => tracing::info!("link-bounce experiment:\n{}", out.trim_end()),
            Err(error) => tracing::warn!("link-bounce experiment failed: {error:#}"),
        }
    }

    // Two eth0 counter samples 2 s apart: tx_packets advancing while the
    // datapath sees nothing means the guest transmits into a black hole
    // (VZ consuming and dropping); frozen tx_packets means the guest-side
    // virtio TX queue is wedged (VZ not consuming the ring).
    let eth0_stats = "for f in tx_packets rx_packets tx_dropped rx_dropped; do \
         echo \"$f=$(cat /sys/class/net/eth0/statistics/$f)\"; done; \
         sleep 2; echo ---; \
         for f in tx_packets rx_packets tx_dropped rx_dropped; do \
         echo \"$f=$(cat /sys/class/net/eth0/statistics/$f)\"; done";
    let probes: [(&str, &[&str]); 4] = [
        (
            "ip route",
            &["run", "--rm", "--net=host", image, "ip", "route"],
        ),
        (
            "eth0 stats (2 samples, 2s apart)",
            &["run", "--rm", "--net=host", image, "sh", "-c", eth0_stats],
        ),
        (
            "ping gateway",
            &[
                "run",
                "--rm",
                image,
                "ping",
                "-c",
                "2",
                "-W",
                "3",
                GUEST_GATEWAY_IP,
            ],
        ),
        (
            "small http probe",
            &[
                "run",
                "--rm",
                image,
                "wget",
                "-q",
                "-O",
                "/dev/null",
                "-T",
                "5",
                "http://10.0.2.1:80/",
            ],
        ),
    ];
    for (name, args) in probes {
        match docker_output(data_dir, args, Duration::from_secs(30)) {
            Ok(out) => tracing::info!(probe = name, "forensics:\n{}", out.trim_end()),
            Err(error) => tracing::warn!(probe = name, "forensics probe failed: {error:#}"),
        }
    }

    // Measure the freeze duration: retry a tiny gateway probe until the
    // datapath answers again (connection refused counts as alive — an RST
    // made the round trip).
    let started = std::time::Instant::now();
    for _ in 0..30 {
        let alive = match docker_output(
            data_dir,
            &[
                "run",
                "--rm",
                image,
                "wget",
                "-q",
                "-O",
                "/dev/null",
                "-T",
                "3",
                "http://10.0.2.1:9/",
            ],
            Duration::from_secs(20),
        ) {
            Ok(_) => true,
            Err(error) => {
                let msg = format!("{error:#}");
                !msg.contains("timed out") && !msg.contains("timeout")
            }
        };
        if alive {
            tracing::info!(
                elapsed_secs = started.elapsed().as_secs(),
                "datapath recovered (probe answered)"
            );
            return;
        }
    }
    tracing::warn!(
        elapsed_secs = started.elapsed().as_secs(),
        "datapath still frozen after probe window"
    );
}
