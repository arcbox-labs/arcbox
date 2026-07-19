//! Network-fault e2e — Phase 1 of internal-docs/plans/network-fault-e2e.md.
//!
//! The incident (2026-07-19): a container download hung 23+ minutes on a
//! guest-side TCP flow left `ESTABLISHED` (empty queues) after its upstream
//! leg died, with no RST/FIN reaching the guest. `egress_throughput` only
//! covers the happy path; nothing tested flow *lifetime* across a fault.
//!
//! This drives a real container through the full egress datapath
//! (guest eth0 → classifier → TcpBridge → host socket via the
//! `10.0.2.1`→loopback translation) to a host-local `ChaosOrigin` that
//! serves a partial body then **resets** its connection, and asserts
//! **bounded failure**: the in-container client must observe the error within
//! a deadline — never hang. `wget` is given no `-T`, so the only thing that
//! can end it is ArcBox propagating the upstream RST to the guest leg.
//!
//! Scope: Phase 1 covers the parallel-safe, in-process fault — a peer RST.
//! The other incident shapes (a silent upstream death where the peer stops
//! answering, an unanswered-SYN connect blackhole) cannot be reproduced
//! in-process: the host kernel keeps ACKing for a merely-idle peer, and a
//! closed local port answers with RST rather than dropping the SYN. Those
//! need actual network-path interruption (firewall/route), which is the
//! plan's exclusive Tier 3, not Tier 1.

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

/// A host-local HTTP origin that serves a partial body then resets the
/// connection on every request. Returns the bound port. One thread per
/// connection; runs until the process exits.
fn spawn_chaos_origin() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding chaos origin")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || serve_then_reset(stream));
        }
    });
    Ok(port)
}

fn serve_then_reset(mut stream: TcpStream) {
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

    // SO_LINGER with a zero timeout turns the close into a RST rather than a
    // graceful FIN — the daemon's upstream leg sees ECONNRESET mid-transfer.
    // (std's set_linger is still unstable, so go through libc.)
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `stream` owns the fd for the duration of the call, and `linger`
    // is a valid, correctly-sized SO_LINGER payload.
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

/// Peer RST mid-transfer must reach the container promptly. A container
/// downloads from a ChaosOrigin that resets the connection after a partial
/// body; `wget` is given no `-T`, so the bound must come from the datapath
/// propagating the RST to the guest leg — the behavior the incident lacked.
#[test]
#[ignore = "boots a VZ System VM through a real daemon; run on the e2e runner"]
fn net_upstream_rst_is_propagated_promptly() -> Result<()> {
    run_scenario("network_fault_rst", |daemon, data_dir, metrics| {
        metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
        let image =
            std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
        metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

        let port = spawn_chaos_origin()?;
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

        // The download MUST NOT succeed — the origin resets before the body
        // completes.
        if result.is_ok() {
            bail!("download unexpectedly succeeded against a resetting origin");
        }
        tracing::info!(?elapsed, "client returned: {:#}", result.unwrap_err());

        // Bounded-failure property: the client saw the error promptly. A value
        // at or beyond the deadline means the guest leg zombied (the incident)
        // and only the docker timeout unstuck it.
        if elapsed >= FAILURE_DEADLINE {
            bail!(
                "client hung {elapsed:?} (>= {FAILURE_DEADLINE:?}) before observing the upstream \
                 RST — guest leg was not reset (zombie flow regression)"
            );
        }
        Ok(())
    })
}
