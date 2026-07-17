//! StatsService.Watch e2e: live machine stats from a real VZ daemon.
//!
//! Boots the System VM, subscribes to the stats stream over the daemon's
//! gRPC socket, and asserts the P1 acceptance criteria: samples flow with
//! sane values, concurrent subscribers share a single guest stream (the
//! daemon log is the oracle for pump lifecycle, as with the idle-balloon
//! scenario), and a later subscriber gets a fresh pump after the first
//! generation wound down. It also runs one container and asserts its
//! per-container cgroup stats appear in the frames, name-enriched (P2).

use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use arcbox_e2e::docker::{docker_output, ensure_image};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_grpc::v1::stats_service_client::StatsServiceClient;
use arcbox_protocol::v1::{MachineStats, StatsWatchRequest};
use tonic::Streaming;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Budget for one stats frame; the agent samples at 1 Hz.
const SAMPLE_BUDGET: Duration = Duration::from_secs(10);
/// Budget for the first pump to stop after its subscribers disconnect
/// (the pump notices within its frame patience).
const PUMP_STOP_BUDGET: Duration = Duration::from_secs(15);
/// Ceiling for one docker CLI invocation.
const DOCKER_ATTEMPT: Duration = Duration::from_secs(30);
/// Name of the probe container whose per-container stats we assert.
const PROBE_NAME: &str = "stats-probe";

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

#[test]
#[ignore = "boots a VZ System VM through a real daemon and streams live machine stats"]
fn stats_watch_streams_sane_shared_samples() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
        // The scenario exercises the WatchStats agent RPC, so the guest
        // must run a matching agent. Build it here rather than relying on
        // a pre-staged one — an older agent lacks WatchStats and the stream
        // never yields. Keep this in sync with the xtask `stats_watch`
        // prebuild recipe.
        xshell::cmd!(
            shell,
            "cargo build --release -p arcbox-agent --target aarch64-unknown-linux-musl"
        )
        .run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-stats-watch-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            // Port 0 = kernel-assigned: the DNS service is not under test
            // and must not fight an installed ArcBox over the default port.
            ("ARCBOX_DNS_PORT".to_owned(), "0".to_owned()),
        ],
    })?;

    let mut metrics = RunMetrics::new("stats_watch", Some("vz"));
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
    let socket = daemon.grpc_socket();

    // A running container so the per-container assertions have a subject.
    // It touches memory (a tmpfs write) so memory.current is non-trivial.
    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
    metrics.time("docker_pull", || ensure_image(data_dir, &image))?;
    metrics.time("probe_start", || {
        docker_output(
            data_dir,
            &[
                "run",
                "-d",
                "--name",
                PROBE_NAME,
                &image,
                "sh",
                "-c",
                "dd if=/dev/zero of=/tmp/hold bs=1M count=32; sleep 600",
            ],
            DOCKER_ATTEMPT,
        )
        .context("starting probe container")
    })?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    // Phase 1 — two concurrent subscribers, sane and progressing samples,
    // and the probe container's per-container stats.
    runtime.block_on(async {
        let channel = connect_unix(&socket).await?;
        let mut client = StatsServiceClient::new(channel);

        let mut stream_a = watch(&mut client).await?;
        let first = next_sample(&mut stream_a).await.context("first sample")?;
        assert_sane(&first)?;

        // A second subscriber must ride the same pump (asserted from the
        // daemon log below), and still receive frames.
        let mut stream_b = watch(&mut client).await?;
        next_sample(&mut stream_b)
            .await
            .context("second subscriber's sample")?;

        let second = next_sample(&mut stream_a).await.context("second sample")?;
        if second.monotonic_ms <= first.monotonic_ms {
            bail!(
                "guest clock did not advance between samples ({} -> {})",
                first.monotonic_ms,
                second.monotonic_ms
            );
        }
        if second.cpu_total_ticks < first.cpu_total_ticks
            || second.disk_read_bytes < first.disk_read_bytes
            || second.net_rx_bytes < first.net_rx_bytes
        {
            bail!("cumulative counters went backwards without a guest reboot");
        }
        tracing::info!(
            monotonic_ms = second.monotonic_ms,
            cpu_total_ticks = second.cpu_total_ticks,
            psi = second.memory_psi_full_avg10,
            "samples flow and progress"
        );

        // The probe container's cgroup stats must appear (discovery is
        // per-tick, so it may take a frame or two), name-enriched by the
        // daemon from its registry.
        assert_probe_container(&mut stream_a).await
    })?;
    if count_log_matches(data_dir, "stats pump started")? != 1 {
        bail!("concurrent subscribers did not share a single stats pump");
    }

    // Dropping the runtime tears down the client's connection tasks and
    // closes the gRPC socket — merely letting `block_on` return would
    // freeze (not drop) them, and the daemon would keep both response
    // streams (and their broadcast receivers) alive indefinitely.
    drop(runtime);

    // Phase 2 — the pump winds down without subscribers, and a later
    // subscriber gets a fresh one.
    metrics.time("pump_stop", || {
        wait_for_log_count(data_dir, "stats pump stopped", 1, PUMP_STOP_BUDGET)
    })?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    runtime.block_on(async {
        let channel = connect_unix(&socket).await?;
        let mut client = StatsServiceClient::new(channel);
        let mut stream = watch(&mut client).await?;
        let sample = next_sample(&mut stream)
            .await
            .context("post-restart sample")?;
        assert_sane(&sample)
    })?;
    if count_log_matches(data_dir, "stats pump started")? != 2 {
        bail!("resubscription did not start a fresh stats pump");
    }

    docker_output(data_dir, &["rm", "-f", PROBE_NAME], DOCKER_ATTEMPT).ok();
    Ok(())
}

/// Consumes frames until the probe container appears, then asserts its
/// cgroup stats are sane and the daemon enriched its name. Bounded by a
/// few sample budgets so a never-appearing container fails instead of
/// hanging.
async fn assert_probe_container(stream: &mut Streaming<MachineStats>) -> Result<()> {
    for _ in 0..5 {
        let sample = next_sample(stream)
            .await
            .context("frame while awaiting probe")?;
        let Some(probe) = sample.containers.iter().find(|c| c.name == PROBE_NAME) else {
            continue;
        };
        if probe.id.len() != 64 {
            bail!("probe container id is not a full cgroup id: {:?}", probe.id);
        }
        if probe.memory_current_bytes == 0 {
            bail!("probe container reports zero memory");
        }
        if probe.pids == 0 {
            bail!("probe container reports zero pids");
        }
        // A bridged container's eth0 always accrues setup/DHCP traffic, so
        // its netns-read counters must be non-zero — proving per-container
        // network (P4) is wired, not just the cgroup metrics.
        if probe.net_rx_bytes == 0 {
            bail!("probe container reports zero network rx (netns read failed?)");
        }
        tracing::info!(
            id = %probe.id,
            memory = probe.memory_current_bytes,
            pids = probe.pids,
            net_rx = probe.net_rx_bytes,
            net_tx = probe.net_tx_bytes,
            "probe container stats present and enriched"
        );
        return Ok(());
    }
    bail!("probe container never appeared in the stats stream");
}

async fn watch(
    client: &mut StatsServiceClient<tonic::transport::Channel>,
) -> Result<Streaming<MachineStats>> {
    Ok(client
        .watch(StatsWatchRequest {
            machine_id: String::new(),
        })
        .await
        .context("subscribing to machine stats")?
        .into_inner())
}

async fn next_sample(stream: &mut Streaming<MachineStats>) -> Result<MachineStats> {
    match tokio::time::timeout(SAMPLE_BUDGET, stream.message()).await {
        Err(_) => bail!("no stats frame within {}s", SAMPLE_BUDGET.as_secs()),
        Ok(Err(status)) => bail!("stats stream error: {status}"),
        Ok(Ok(None)) => bail!("stats stream ended unexpectedly"),
        Ok(Ok(Some(sample))) => Ok(sample),
    }
}

fn assert_sane(sample: &MachineStats) -> Result<()> {
    if sample.memory_total_bytes == 0 {
        bail!("memory_total_bytes is zero");
    }
    if sample.memory_available_bytes > sample.memory_total_bytes {
        bail!("more memory available than exists");
    }
    if sample.online_cpus == 0 {
        bail!("online_cpus is zero");
    }
    if sample.cpu_busy_ticks > sample.cpu_total_ticks {
        bail!("busy CPU ticks exceed total");
    }
    if !(-1.0..=100.0).contains(&sample.memory_psi_full_avg10) {
        bail!("PSI gauge out of range: {}", sample.memory_psi_full_avg10);
    }
    Ok(())
}

fn count_log_matches(data_dir: &Path, needle: &str) -> Result<usize> {
    let path = data_dir.join("log/daemon.log");
    let log =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(log.matches(needle).count())
}

fn wait_for_log_count(
    data_dir: &Path,
    needle: &str,
    at_least: usize,
    budget: Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if count_log_matches(data_dir, needle)? >= at_least {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "log never showed {at_least}x {needle:?} within {}s",
                budget.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
