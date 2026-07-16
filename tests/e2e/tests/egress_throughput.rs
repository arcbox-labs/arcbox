//! Sustained-egress regression e2e (container→external download black hole).
//!
//! The incident: multi-MB container downloads from fast CDNs stalled
//! permanently mid-transfer (~40-100% of attempts), while the same URL
//! downloaded fine on the host. Root cause: the TCP shim terminates guest
//! connections and re-injects host→guest data over the VZ socketpair with
//! no retransmission; under sustained throughput the socketpair overflowed
//! (macOS `ENOBUFS`) and frames were dropped — a permanent sequence gap.
//!
//! This scenario reproduces the shape without external network dependence:
//! a host-local HTTP server serves large blobs, and a container downloads
//! them through the full egress datapath (guest eth0 → classifier →
//! TcpBridge fast path → host socket). Loopback burst rates exceed any CDN,
//! so the backpressure path is exercised harder than the original repro.
//! Every download must complete; a stall means frames were lost.

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

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            // Avoid the host DNS service port (5553) so this test daemon can
            // run alongside a developer's live daemon.
            ("ARCBOX_DNS_PORT".to_owned(), "15553".to_owned()),
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

    run_downloads(data_dir, metrics, &image, &url, "download")?;

    // Optional second phase: a real external URL (e.g. a fast CDN, possibly
    // through a host VPN). Environment-dependent, so never run in CI — set
    // ARCBOX_E2E_EGRESS_URL to enable during manual validation.
    if let Ok(external) = std::env::var("ARCBOX_E2E_EGRESS_URL") {
        tracing::info!(url = %external, "external egress phase");
        run_downloads(data_dir, metrics, &image, &external, "external_download")?;
    }

    Ok(())
}

fn run_downloads(
    data_dir: &Path,
    metrics: &mut RunMetrics,
    image: &str,
    url: &str,
    label_prefix: &str,
) -> Result<()> {
    for attempt in 1..=DOWNLOADS {
        let label = format!("{label_prefix}_{attempt}");
        metrics.time(&label, || {
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
                    "60",
                    url,
                ],
                DOWNLOAD_TIMEOUT,
            )
            .with_context(|| format!("{label_prefix} {attempt}/{DOWNLOADS} stalled or failed"))
        })?;
        tracing::info!(attempt, label_prefix, "download completed");
    }
    Ok(())
}
