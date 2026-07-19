//! Network-fault e2e — Phase 1 of internal-docs/plans/network-fault-e2e.md.
//!
//! The incident (2026-07-19): a container `apk` download hung 23+ minutes on
//! a guest-side TCP flow left `ESTABLISHED` (empty queues) after the daemon's
//! upstream leg died. The proxy neither propagated the death to the guest leg
//! (no RST/FIN) nor logged anything. `egress_throughput` only covers the
//! happy path; nothing tests flow *lifetime* across an upstream fault.
//!
//! This drives a real container through the full egress datapath
//! (guest eth0 → classifier → TcpBridge → host socket via the
//! `10.0.2.1`→loopback translation) to a host-local `ChaosOrigin` that
//! injects the fault, and asserts **bounded failure**: after the upstream
//! dies mid-transfer, the in-container client must observe an error within a
//! deadline — never hang. The property under test is that the daemon
//! propagates upstream death to the guest leg, not the guest kernel's own
//! long TCP timeout.
//!
//! Two faults, matching the plan's Tier-1 table:
//! - `rst_mid_transfer` (peer RST): a correct proxy forwards it, so this is a
//!   clean pass/fail regression.
//! - `silent_stall` (peer goes away without FIN/RST): closest to the field
//!   incident. There is no peer signal, so bounding it needs a proxy-side
//!   idle/liveness deadline that does not exist yet — this test captures the
//!   open gap and is expected to fail until that fix lands (kept `#[ignore]`,
//!   documented, so it is opt-in forensics, not CI noise).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Once;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::docker::{docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Gateway IP the guest sees on its primary NIC; TcpBridge translates
/// connections to it into host `127.0.0.1` — the datapath the incident lived
/// on. Same mechanism `egress_throughput` exercises.
const GUEST_GATEWAY_IP: &str = "10.0.2.1";
/// Body bytes ChaosOrigin sends before injecting the fault: enough that the
/// transfer is genuinely mid-stream (past headers, into the body loop).
const PARTIAL_BODY_BYTES: usize = 64 * 1024;
/// Advertised Content-Length — far larger than the partial body, so the
/// client is still expecting data when the fault hits.
const ADVERTISED_LEN: usize = 256 * 1024 * 1024;
/// The client must observe the failure within this bound. A propagated RST
/// arrives in well under a second; the generous margin absorbs slow CI.
const FAILURE_DEADLINE: Duration = Duration::from_secs(30);
/// Hard ceiling on the docker call — strictly greater than FAILURE_DEADLINE
/// so a hang is caught by the elapsed-time assertion (a clean, specific
/// failure) rather than the docker timeout (an opaque one).
const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);

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

#[derive(Clone, Copy)]
enum Fault {
    /// Send headers + partial body, then close with `SO_LINGER=0` so the
    /// close emits a RST to the daemon's upstream leg.
    RstMidTransfer,
    /// Send headers + partial body, then hold the socket open forever without
    /// writing or closing — the peer "goes away" with no FIN/RST.
    SilentStall,
}

/// A host-local HTTP origin that serves a partial body then injects `fault`
/// on every connection. Returns the bound port. One thread per connection;
/// runs until the process exits.
fn spawn_chaos_origin(fault: Fault) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding chaos origin")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || serve_faulty(stream, fault));
        }
    });
    Ok(port)
}

fn serve_faulty(mut stream: TcpStream, fault: Fault) {
    // Drain the request headers (or bail on EOF).
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

    let header =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {ADVERTISED_LEN}\r\nConnection: close\r\n\r\n");
    if stream.write_all(header.as_bytes()).is_err() {
        return;
    }
    let chunk = vec![0u8; PARTIAL_BODY_BYTES];
    if stream.write_all(&chunk).is_err() {
        return;
    }
    let _ = stream.flush();

    match fault {
        Fault::RstMidTransfer => {
            // SO_LINGER with a zero timeout turns the close into a RST rather
            // than a graceful FIN — the daemon's upstream leg sees ECONNRESET.
            // (std's set_linger is still unstable, so go through libc.)
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: `stream` owns the fd for the duration of the call, and
            // `linger` is a valid, correctly-sized SO_LINGER payload.
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    std::ptr::addr_of!(linger).cast(),
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                );
            }
            drop(stream);
        }
        Fault::SilentStall => {
            // Hold the fd open, produce nothing, never close: the upstream is
            // alive at the socket layer but dead at the application layer.
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }
}

/// Boots a VZ System VM through a real daemon on an isolated data dir and
/// runs `scenario`, mirroring the egress_throughput harness.
fn run_scenario(
    name: &str,
    scenario: impl FnOnce(&mut DaemonHandle, &Path, &mut RunMetrics) -> Result<()>,
) -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix(&format!("arcbox-{name}-"))
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    // Free DNS port so this runs alongside a developer's live daemon (5553).
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
            (
                "RUST_LOG".to_owned(),
                "info,arcbox_net=debug,splicetcp=debug".to_owned(),
            ),
        ],
    })?;

    let mut metrics = RunMetrics::new(name, Some("vz"));
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

/// Drives one container download against a ChaosOrigin and asserts the client
/// observes the failure within `FAILURE_DEADLINE`. `wget` is given no `-T`, so
/// the only thing that can bound it is the daemon propagating upstream death
/// to the guest leg — exactly the behavior the incident lacked.
fn assert_bounded_failure(
    daemon: &mut DaemonHandle,
    data_dir: &Path,
    metrics: &mut RunMetrics,
    fault: Fault,
) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
    metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

    let port = spawn_chaos_origin(fault)?;
    let url = format!("http://{GUEST_GATEWAY_IP}:{port}/blob");
    tracing::info!(%url, "chaos origin up");

    let started = Instant::now();
    // No `-T`: the bound must come from the datapath, not wget's own timer.
    let result = docker_output(
        data_dir,
        &["run", "--rm", &image, "wget", "-q", "-O", "/dev/null", &url],
        DOCKER_TIMEOUT,
    );
    let elapsed = started.elapsed();
    metrics.record("client_observed_end", elapsed.as_secs_f64());

    // The download MUST NOT succeed — the origin never sends a full body.
    if result.is_ok() {
        bail!("download unexpectedly succeeded against a faulty origin");
    }
    tracing::info!(?elapsed, "client returned: {:#}", result.unwrap_err());

    // Bounded-failure property: the client saw the error promptly. A value at
    // or beyond the deadline means the guest leg zombied (the incident) and
    // only the docker timeout unstuck it.
    if elapsed >= FAILURE_DEADLINE {
        bail!(
            "client hung {elapsed:?} (>= {FAILURE_DEADLINE:?}) before observing the upstream \
             death — guest leg was not reset (zombie flow regression)"
        );
    }
    Ok(())
}

/// Peer RST mid-transfer must reach the container promptly. A correct proxy
/// forwards it; this is a clean regression gate.
#[test]
#[ignore = "boots a VZ System VM through a real daemon; run on the e2e runner"]
fn upstream_rst_is_propagated_promptly() -> Result<()> {
    run_scenario("network_fault_rst", |daemon, data_dir, metrics| {
        assert_bounded_failure(daemon, data_dir, metrics, Fault::RstMidTransfer)
    })
}

/// Silent upstream death (no FIN/RST) — the field incident. Bounding it needs
/// a proxy-side liveness/idle deadline that does not exist yet, so this is
/// EXPECTED TO FAIL until that fix lands; it documents the gap and is the
/// test that flips green with the proxy fix (plan phase 3).
#[test]
#[ignore = "known-failing incident regression until proxy upstream-death handling lands"]
fn upstream_silent_stall_is_bounded() -> Result<()> {
    run_scenario("network_fault_silent", |daemon, data_dir, metrics| {
        assert_bounded_failure(daemon, data_dir, metrics, Fault::SilentStall)
    })
}
