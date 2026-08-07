//! Sandbox cold-start bench: `Create` → `READY` over N serial iterations.
//!
//! Measures the user-visible cold start of a sandbox — the wall time from
//! the `Create` RPC leaving the client until the `READY` lifecycle event
//! arrives back — against one already-warm daemon, so the System VM boot
//! is excluded and only the nested Firecracker microVM start is timed.
//!
//! Readiness is taken from the `Events` stream, subscribed *before* the
//! first `Create`, rather than the smoke test's 500ms `Inspect` poll: at
//! the sub-second scale this bench targets, a 500ms poll interval is the
//! measurement.
//!
//! Requires nested virtualization (VZ backend, Apple Silicon M3+ with
//! macOS 15+). Run:
//!
//! ```console
//! cargo test -p arcbox-e2e --test sandbox_coldstart -- --ignored --nocapture
//! ```
//!
//! Knobs: `ARCBOX_COLDSTART_ITERS` (default 10), `ARCBOX_COLDSTART_VCPUS`
//! (1), `ARCBOX_COLDSTART_MEMORY_MIB` (512), `SKIP_BUILD`, `KEEP_TEST_DIR`.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::{env_flag, repo_root};
use arcbox_grpc::sandbox_v1::sandbox_process_service_client::SandboxProcessServiceClient;
use arcbox_grpc::sandbox_v1::sandbox_service_client::SandboxServiceClient;
use arcbox_grpc::sandbox_v1::sandbox_snapshot_service_client::SandboxSnapshotServiceClient;
use arcbox_protocol::sandbox_v1::{
    AttachExecutionRequest, CheckpointRequest, CreateSandboxRequest, NetworkMode, NetworkSpec,
    RemoveSandboxRequest, ResourceLimits, RestoreRequest, SandboxEventKind, SandboxEventsRequest,
    SandboxState, StartExecutionRequest, StdioChannel, execution_event, exit_status,
    watch_events_response,
};
use tonic::Streaming;
use tonic::transport::Channel;
use tracing::{info, warn};

/// Generous ceiling for daemon startup (asset staging + VM boot + agent).
const DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(240);
/// Ceiling for one sandbox to reach READY. The first iteration may build
/// the default template inside the guest, so this is far above the steady
/// state it measures.
const SANDBOX_READY_TIMEOUT: Duration = Duration::from_secs(180);

#[test]
#[ignore = "requires nested virtualization (VZ on M3+), boot assets, and a signed daemon"]
fn sandbox_coldstart() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    // Floor of 1: `report` assumes at least one sample per group.
    let iters = env_usize("ARCBOX_COLDSTART_ITERS", 10).max(1);
    let vcpus = env_usize("ARCBOX_COLDSTART_VCPUS", 1) as u32;
    let memory_mib = env_usize("ARCBOX_COLDSTART_MEMORY_MIB", 512) as u64;

    if !env_flag("SKIP_BUILD") {
        arcbox_e2e::sandbox::build_binaries()?;
    }

    let root = repo_root();
    let version = resolve_boot_version(&root)?;
    let temp_dir = tempfile::Builder::new()
        .prefix("arcbox-sandbox-coldstart-")
        .tempdir()
        .context("creating bench directory")?;
    let data_dir = temp_dir.path().to_owned();
    stage_dev_boot_assets(&root, &data_dir, &version)?;

    let mut metrics = RunMetrics::new("sandbox_coldstart", Some("vz"));
    let result = run_bench(
        &root,
        &data_dir,
        &version,
        &mut metrics,
        Params {
            iters,
            vcpus,
            memory_mib,
        },
    );
    metrics.passed = result.is_ok();
    match metrics.write(Some(&data_dir)) {
        Ok(paths) => {
            for path in paths {
                info!(path = %path.display(), "run metrics written");
            }
        }
        Err(error) => warn!("writing run metrics failed: {error:#}"),
    }

    if result.is_err() || env_flag("KEEP_TEST_DIR") {
        let path = temp_dir.keep();
        warn!(path = %path.display(), "preserving test directory");
    }
    result
}

struct Params {
    iters: usize,
    vcpus: u32,
    memory_mib: u64,
}

fn run_bench(
    root: &std::path::Path,
    data_dir: &std::path::Path,
    version: &str,
    metrics: &mut RunMetrics,
    params: Params,
) -> Result<()> {
    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version.to_owned()),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
        ],
    })?;

    let ready_started = Instant::now();
    daemon.wait_ready_blocking(DAEMON_READY_TIMEOUT)?;
    let daemon_ready = ready_started.elapsed();
    metrics.record("daemon_ready", daemon_ready.as_secs_f64());
    info!(seconds = daemon_ready.as_secs_f64(), "daemon ready");

    let socket = daemon.grpc_socket();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building bench runtime")?;

    let bench = rt.block_on(async {
        let channel = connect_unix(&socket).await?;
        drive(channel, metrics, params).await
    });

    match daemon.shutdown() {
        Ok(status) => info!(%status, "daemon stopped"),
        Err(error) => warn!("daemon shutdown failed: {error:#}"),
    }

    bench
}

/// One iteration's timings.
struct Sample {
    /// `Create` RPC call → response (the sandbox is STARTING at this point).
    create_rpc: Duration,
    /// `Create` call → `READY` event: the cold start itself.
    ready: Duration,
    /// `Create` call → stdout of the first command. READY claims the
    /// sandbox accepts executions; this is what makes that claim
    /// falsifiable, and is the number an SDK user actually waits out.
    first_exec: Duration,
    /// The same command again on the already-warm sandbox. Splits the gap
    /// after READY into "the sandbox was not yet executable" (first ≫
    /// second) and "every execution costs this" (first ≈ second).
    second_exec: Duration,
    /// Guest `/proc/uptime` sampled by the first command: how long the
    /// microVM kernel had been up when the first exec landed. Splits the
    /// create→exec gap into host-side cost (create→exec minus uptime) and
    /// in-guest boot (uptime minus the exec round-trip itself).
    guest_uptime: Option<f64>,
    /// `Remove` RPC call → response.
    remove: Duration,
}

async fn drive(channel: Channel, metrics: &mut RunMetrics, params: Params) -> Result<()> {
    let mut client = SandboxServiceClient::new(channel.clone());
    let mut processes = SandboxProcessServiceClient::new(channel.clone());
    let mut snapshots = SandboxSnapshotServiceClient::new(channel);

    // Subscribed before the first Create so no READY can be missed. Kind is
    // left unfiltered: a FAILED frame is what turns a hung bench into a
    // reported cause.
    let mut events = client
        .events(with_machine(SandboxEventsRequest::default()))
        .await
        .context("Events subscribe failed")?
        .into_inner();

    for (label, mode) in [
        ("networked", NetworkMode::Enabled),
        ("no-network", NetworkMode::None),
    ] {
        let mut samples = Vec::with_capacity(params.iters);
        for i in 0..params.iters {
            let id = format!("cold-{label}-{i}");
            // dmesg on the second iteration: a steady-state boot timeline,
            // not the one-time-cost first boot.
            let sample = one_cycle(
                &mut client,
                &mut processes,
                &mut events,
                &id,
                mode,
                &params,
                i == 1,
            )
            .await?;
            log_sample(label, i, &sample);
            samples.push(sample);
        }
        report(label, &samples, metrics);
    }

    // -- Restore group: the snapshot-resume path -------------------------
    // One warm networked template is checkpointed once; each iteration then
    // restores a clone with a fresh TAP (`network_override`) while the
    // template keeps running — the E2B-style "resume, don't boot" shape.
    let template_id = "cold-template";
    one_template(
        &mut client,
        &mut processes,
        &mut events,
        template_id,
        &params,
    )
    .await?;
    let checkpoint_started = Instant::now();
    let snapshot_id = snapshots
        .checkpoint(with_machine(CheckpointRequest {
            sandbox_id: template_id.to_owned(),
            name: "coldstart-bench".into(),
            ..Default::default()
        }))
        .await
        .context("Checkpoint failed")?
        .into_inner()
        .snapshot_id;
    info!(
        %snapshot_id,
        checkpoint_ms = checkpoint_started.elapsed().as_millis(),
        "template checkpointed"
    );

    let mut samples = Vec::with_capacity(params.iters);
    for i in 0..params.iters {
        let id = format!("cold-restore-{i}");
        let sample = one_restore_cycle(
            &mut client,
            &mut processes,
            &mut snapshots,
            &id,
            &snapshot_id,
        )
        .await?;
        log_sample("restore", i, &sample);
        samples.push(sample);
    }
    report("restore", &samples, metrics);

    client
        .remove(with_machine(RemoveSandboxRequest {
            id: template_id.to_owned(),
            force: true,
        }))
        .await
        .context("Remove template failed")?;

    Ok(())
}

/// Create the warm template the restore group snapshots: booted, one
/// execution completed so the exec path is warm in the captured memory.
async fn one_template(
    client: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    events: &mut Streaming<arcbox_protocol::sandbox_v1::WatchEventsResponse>,
    id: &str,
    params: &Params,
) -> Result<()> {
    client
        .create(with_machine(CreateSandboxRequest {
            id: id.to_owned(),
            limits: Some(ResourceLimits {
                vcpus: params.vcpus,
                memory_mib: params.memory_mib,
            }),
            network: Some(NetworkSpec {
                mode: NetworkMode::Enabled.into(),
            }),
            ..Default::default()
        }))
        .await
        .context("Create template failed")?;
    wait_for_ready(events, id).await?;
    run_and_collect(processes, id, &["/bin/echo", "template-warm"]).await?;
    Ok(())
}

/// Restore a clone from the template snapshot and drive the same back half
/// as a boot cycle. `ready` is the restore RPC completion: the RPC resumes
/// the VM synchronously, so its return is the usability claim.
async fn one_restore_cycle(
    client: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    snapshots: &mut SandboxSnapshotServiceClient<Channel>,
    id: &str,
    snapshot_id: &str,
) -> Result<Sample> {
    let started = Instant::now();
    snapshots
        .restore(with_machine(RestoreRequest {
            id: id.to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            network_override: true,
            ..Default::default()
        }))
        .await
        .with_context(|| format!("Restore {id} failed"))?;
    let restore_rpc = started.elapsed();

    finish_cycle(
        client,
        processes,
        id,
        started,
        restore_rpc,
        restore_rpc,
        false,
    )
    .await
}

fn log_sample(label: &str, iteration: usize, sample: &Sample) {
    info!(
        iteration,
        group = label,
        create_ms = sample.create_rpc.as_millis(),
        ready_ms = sample.ready.as_millis(),
        first_exec_ms = sample.first_exec.as_millis(),
        second_exec_ms = sample.second_exec.as_millis(),
        guest_uptime_s = sample.guest_uptime,
        remove_ms = sample.remove.as_millis(),
        "cold start"
    );
}

/// Log the interesting lines of a guest boot dmesg: the timeline from
/// kernel entry to init handoff, plus anything that took visibly long.
fn log_boot_timeline(id: &str, dmesg: &str) {
    for line in dmesg.lines() {
        let interesting = ["Linux version", "Freeing unused kernel", "Run /"]
            .iter()
            .any(|m| line.contains(m));
        if interesting {
            info!(%id, "dmesg: {line}");
        }
    }
    // The largest single gap between consecutive timestamped lines — where
    // the boot actually stalled.
    let stamps: Vec<(f64, &str)> = dmesg
        .lines()
        .filter_map(|l| {
            let ts = l.split(']').next()?.trim_start_matches('[').trim();
            Some((ts.parse::<f64>().ok()?, l))
        })
        .collect();
    if let Some((gap, before, line)) = stamps
        .windows(2)
        .map(|w| (w[1].0 - w[0].0, w[0].1, w[1].1))
        .max_by(|a, b| a.0.total_cmp(&b.0))
    {
        info!(%id, gap_s = gap, "dmesg: largest gap between: {before} → {line}");
    }
}

async fn one_cycle(
    client: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    events: &mut Streaming<arcbox_protocol::sandbox_v1::WatchEventsResponse>,
    id: &str,
    mode: NetworkMode,
    params: &Params,
    capture_dmesg: bool,
) -> Result<Sample> {
    let started = Instant::now();
    let created = client
        .create(with_machine(CreateSandboxRequest {
            id: id.to_owned(),
            limits: Some(ResourceLimits {
                vcpus: params.vcpus,
                memory_mib: params.memory_mib,
            }),
            network: Some(NetworkSpec { mode: mode.into() }),
            ..Default::default()
        }))
        .await
        .with_context(|| format!("Create {id} failed"))?
        .into_inner();
    let create_rpc = started.elapsed();
    if created.state() != SandboxState::Starting {
        bail!("{id}: unexpected create state {:?}", created.state());
    }

    wait_for_ready(events, id).await?;
    let ready = started.elapsed();

    finish_cycle(
        client,
        processes,
        id,
        started,
        create_rpc,
        ready,
        capture_dmesg,
    )
    .await
}

/// The shared back half of a cycle: first exec (sampling guest uptime),
/// warm exec, optional dmesg capture, remove.
async fn finish_cycle(
    client: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    id: &str,
    started: Instant,
    create_rpc: Duration,
    ready: Duration,
    capture_dmesg: bool,
) -> Result<Sample> {
    let stdout = run_and_collect(processes, id, &["/bin/cat", "/proc/uptime"]).await?;
    let first_exec = started.elapsed();
    let guest_uptime = stdout
        .split_whitespace()
        .next()
        .and_then(|t| t.parse::<f64>().ok());
    if guest_uptime.is_none() {
        bail!("{id}: unexpected /proc/uptime output: {stdout:?}");
    }

    let second_started = Instant::now();
    let stdout = run_and_collect(processes, id, &["/bin/echo", "warm-ok"]).await?;
    let second_exec = second_started.elapsed();
    if !stdout.contains("warm-ok") {
        bail!("{id}: warm command output missing marker: {stdout:?}");
    }

    if capture_dmesg {
        // One boot timeline per group: where the in-guest time goes.
        match run_and_collect(processes, id, &["/bin/dmesg"]).await {
            Ok(dmesg) => log_boot_timeline(id, &dmesg),
            Err(error) => warn!(%id, "dmesg capture failed: {error:#}"),
        }
    }

    let remove_started = Instant::now();
    client
        .remove(with_machine(RemoveSandboxRequest {
            id: id.to_owned(),
            force: true,
        }))
        .await
        .with_context(|| format!("Remove {id} failed"))?;

    Ok(Sample {
        create_rpc,
        ready,
        first_exec,
        second_exec,
        guest_uptime,
        remove: remove_started.elapsed(),
    })
}

/// Starts one command and drains its attach stream until exit, asserting a
/// zero exit code.
async fn run_and_collect(
    client: &mut SandboxProcessServiceClient<Channel>,
    id: &str,
    cmd: &[&str],
) -> Result<String> {
    let execution = client
        .start_execution(with_machine(StartExecutionRequest {
            sandbox_id: id.to_owned(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            stdin: false,
            ..Default::default()
        }))
        .await
        .context("StartExecution failed")?
        .into_inner();

    let mut stream = client
        .attach_execution(with_machine(AttachExecutionRequest {
            sandbox_id: id.to_owned(),
            execution_id: execution.id.clone(),
            stdout_offset: 0,
            stderr_offset: 0,
        }))
        .await
        .context("AttachExecution failed")?
        .into_inner();

    // Deadline the drain like wait_for_ready: a wedged exec must fail the
    // probe (writing metrics + preserving the test dir), not hang it.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut stdout = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = tokio::time::timeout(remaining, stream.message())
            .await
            .with_context(|| format!("{id}: command {cmd:?} timed out"))?
            .context("attach stream error")?;
        let Some(event) = event else {
            bail!("{id}: attach stream ended without an exit event");
        };
        match event.event {
            Some(execution_event::Event::Output(output)) => {
                if output.channel() != StdioChannel::Stderr {
                    stdout.push_str(&String::from_utf8_lossy(&output.data));
                }
            }
            Some(execution_event::Event::Exited(done)) => {
                let state = done.execution.context("exit event without execution")?;
                return match state.exit_status.as_ref().and_then(|s| s.status) {
                    Some(exit_status::Status::Code(0)) => Ok(stdout),
                    other => bail!("{id}: command {cmd:?} exit status {other:?}"),
                };
            }
            _ => {}
        }
    }
}

/// Consumes the shared event stream until `id` reports READY.
///
/// Frames for other sandboxes are skipped rather than buffered: the bench
/// is strictly serial, so the only live sandbox is the one being timed.
async fn wait_for_ready(
    events: &mut Streaming<arcbox_protocol::sandbox_v1::WatchEventsResponse>,
    id: &str,
) -> Result<()> {
    let deadline = Instant::now() + SANDBOX_READY_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("{id} did not reach READY within {SANDBOX_READY_TIMEOUT:?}");
        }
        let frame = tokio::time::timeout(remaining, events.message())
            .await
            .with_context(|| format!("{id}: READY timed out"))?
            .context("Events stream failed")?
            .context("Events stream ended before READY")?;
        let Some(watch_events_response::Payload::Event(event)) = frame.payload else {
            continue; // keepalive
        };
        if event.sandbox_id != id {
            continue;
        }
        match event.kind() {
            SandboxEventKind::Ready => return Ok(()),
            SandboxEventKind::Failed => {
                let reason = event
                    .attributes
                    .get("error")
                    .map_or("unknown", String::as_str);
                bail!("{id} failed while starting: {reason}");
            }
            _ => {}
        }
    }
}

fn report(label: &str, samples: &[Sample], metrics: &mut RunMetrics) {
    let ready: Vec<f64> = samples.iter().map(|s| s.ready.as_secs_f64()).collect();
    let exec: Vec<f64> = samples.iter().map(|s| s.first_exec.as_secs_f64()).collect();
    let warm_exec: Vec<f64> = samples
        .iter()
        .map(|s| s.second_exec.as_secs_f64())
        .collect();
    let uptime: Vec<f64> = samples.iter().filter_map(|s| s.guest_uptime).collect();
    let create: Vec<f64> = samples.iter().map(|s| s.create_rpc.as_secs_f64()).collect();
    let remove: Vec<f64> = samples.iter().map(|s| s.remove.as_secs_f64()).collect();

    // The first iteration of a group carries one-time cost (default
    // template build, pool warm-up) and is reported apart from the steady
    // state rather than folded into a median that hides it.
    let (first_ready, rest_ready) = ready.split_first().expect("at least one iteration");
    let (first_exec, rest_exec) = exec.split_first().expect("at least one iteration");
    info!(
        group = label,
        first_ready_ms = (first_ready * 1000.0).round(),
        ready_min_ms = ms(min(rest_ready)),
        ready_p50_ms = ms(percentile(rest_ready, 0.50)),
        ready_p90_ms = ms(percentile(rest_ready, 0.90)),
        ready_max_ms = ms(max(rest_ready)),
        first_exec_ms = (first_exec * 1000.0).round(),
        exec_p50_ms = ms(percentile(rest_exec, 0.50)),
        exec_p90_ms = ms(percentile(rest_exec, 0.90)),
        warm_exec_p50_ms = ms(percentile(&warm_exec, 0.50)),
        guest_uptime_p50_s = percentile(&uptime, 0.50),
        create_rpc_p50_ms = ms(percentile(&create, 0.50)),
        remove_p50_ms = ms(percentile(&remove, 0.50)),
        "cold start summary"
    );

    metrics.record(
        &format!("coldstart_{label}_warm_exec_p50"),
        percentile(&warm_exec, 0.50).unwrap_or_default(),
    );
    for (metric, first, rest) in [
        ("ready", first_ready, rest_ready),
        ("exec", first_exec, rest_exec),
    ] {
        metrics.record(&format!("coldstart_{label}_{metric}_first"), *first);
        metrics.record(
            &format!("coldstart_{label}_{metric}_p50"),
            percentile(rest, 0.50).unwrap_or(*first),
        );
        metrics.record(
            &format!("coldstart_{label}_{metric}_p90"),
            percentile(rest, 0.90).unwrap_or(*first),
        );
    }
}

fn ms(value: Option<f64>) -> f64 {
    value.map_or(f64::NAN, |v| (v * 1000.0).round())
}

fn min(values: &[f64]) -> Option<f64> {
    values.iter().copied().reduce(f64::min)
}

fn max(values: &[f64]) -> Option<f64> {
    values.iter().copied().reduce(f64::max)
}

/// Nearest-rank percentile over an unsorted slice.
fn percentile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = (q * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted.get(rank - 1).copied()
}

fn with_machine<T>(msg: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(msg);
    request.metadata_mut().insert(
        "x-machine",
        tonic::metadata::MetadataValue::from_static("default"),
    );
    request
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
