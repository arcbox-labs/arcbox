//! Sandbox e2e smoke: the full stack over the real gRPC surface.
//!
//! Drives `CLI-equivalent` tonic clients against an isolated daemon:
//! create (with an initial cmd) → ready → initial-cmd idle → Run →
//! file round-trip (WriteFile/ReadFile) → Checkpoint → Restore
//! (network_override) → Run in the restored sandbox → Stop/Remove.
//!
//! Requires nested virtualization (VZ backend on Apple Silicon M3+ with
//! macOS 15+): without `/dev/kvm` in the guest, Create fails with
//! FAILED_PRECONDITION and this scenario reports that reason.

use std::env;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_grpc::sandbox_v1::sandbox_service_client::SandboxServiceClient;
use arcbox_grpc::sandbox_v1::sandbox_snapshot_service_client::SandboxSnapshotServiceClient;
use arcbox_protocol::sandbox_v1::{
    CheckpointRequest, CreateSandboxRequest, FileChunk, InspectSandboxRequest,
    ListSandboxesRequest, ReadFileRequest, RemoveSandboxRequest, ResourceLimits, RestoreRequest,
    RunRequest, StopSandboxRequest, WriteFileOpen, WriteFileRequest, write_file_request,
};
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use crate::metrics::RunMetrics;
use crate::{env_flag, repo_root};

/// Generous ceiling for daemon startup (asset staging + VM boot + agent).
const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Ceiling for a sandbox to reach `ready` (includes the first default
/// rootfs build inside the guest).
const SANDBOX_READY_TIMEOUT: Duration = Duration::from_secs(120);

pub struct SandboxSmokeConfig {
    pub skip_build: bool,
    pub keep_test_dir: bool,
    pub version: Option<String>,
}

impl SandboxSmokeConfig {
    pub fn from_env() -> Self {
        Self {
            skip_build: env_flag("SKIP_BUILD"),
            keep_test_dir: env_flag("KEEP_TEST_DIR"),
            version: env::var("ARCBOX_BOOT_ASSET_VERSION").ok(),
        }
    }
}

/// Builds everything the smoke needs: host binaries + guest musl agents.
///
/// The `xtask e2e` prebuild recipe for the `sandbox` target must reproduce
/// exactly these commands (packages AND profiles) — see `xtask/AGENTS.md`.
pub fn build_binaries() -> Result<()> {
    info!("building release binaries + musl guest agents");
    let shell = xshell::Shell::new()?;
    shell.change_dir(repo_root());
    xshell::cmd!(
        shell,
        "cargo build --release -p arcbox-cli -p arcbox-daemon"
    )
    .run()?;
    xshell::cmd!(
        shell,
        "cargo build --release -p arcbox-agent -p arcbox-vm --bins --target aarch64-unknown-linux-musl"
    )
    .run()?;
    Ok(())
}

pub fn run(config: SandboxSmokeConfig) -> Result<()> {
    info!("starting sandbox smoke");

    if !config.skip_build {
        build_binaries()?;
    }

    let root = repo_root();
    let version = match config.version {
        Some(v) => v,
        None => crate::boot_assets::boot_version(&root.join("assets.lock"))?,
    };

    let temp_dir = tempfile::Builder::new()
        .prefix("arcbox-sandbox-smoke-")
        .tempdir()
        .context("creating smoke test directory")?;
    let data_dir = temp_dir.path().to_owned();

    crate::boot_assets::stage_dev_boot_assets(&root, &data_dir, &version)?;

    let mut metrics = RunMetrics::new("sandbox_smoke", Some("vz"));
    let result = run_scenario(&root, &data_dir, &version, &mut metrics);
    metrics.passed = result.is_ok();
    match metrics.write(Some(&data_dir)) {
        Ok(paths) => {
            for path in paths {
                info!(path = %path.display(), "run metrics written");
            }
        }
        Err(error) => warn!("writing run metrics failed: {error:#}"),
    }

    if result.is_err() || config.keep_test_dir {
        let path = temp_dir.keep();
        warn!(path = %path.display(), "preserving test directory");
    }
    result
}

fn run_scenario(
    root: &std::path::Path,
    data_dir: &std::path::Path,
    version: &str,
    metrics: &mut RunMetrics,
) -> Result<()> {
    // VZ is the default backend; make it explicit for the metrics label.
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
    daemon.wait_ready_blocking(READY_TIMEOUT)?;
    metrics.record("daemon_ready", ready_started.elapsed().as_secs_f64());
    info!(
        elapsed_seconds = ready_started.elapsed().as_secs(),
        "daemon ready"
    );

    let grpc_socket = daemon.grpc_socket();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building smoke runtime")?;

    let scenario = rt.block_on(async {
        let channel = connect_unix(&grpc_socket).await?;
        drive_sandboxes(channel, metrics).await
    });

    // Always shut the daemon down; a teardown failure must not mask the
    // scenario result.
    match daemon.shutdown() {
        Ok(status) => info!(%status, "daemon stopped"),
        Err(error) => warn!("daemon shutdown failed: {error:#}"),
    }

    scenario
}

/// Attach the default `x-machine` routing header.
fn with_machine<T>(msg: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(msg);
    request.metadata_mut().insert(
        "x-machine",
        tonic::metadata::MetadataValue::from_static("default"),
    );
    request
}

async fn drive_sandboxes(channel: Channel, metrics: &mut RunMetrics) -> Result<()> {
    let mut sandboxes = SandboxServiceClient::new(channel.clone());
    let mut snapshots = SandboxSnapshotServiceClient::new(channel);

    // -- Create (with an initial cmd, exercising the auto-run path) --------
    let create_started = Instant::now();
    let created = sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke1".into(),
            limits: Some(ResourceLimits {
                vcpus: 1,
                memory_mib: 256,
            }),
            cmd: vec!["/bin/true".into()],
            ..Default::default()
        }))
        .await
        .context("Create failed")?
        .into_inner();
    metrics.record("sandbox_create", create_started.elapsed().as_secs_f64());
    info!(id = %created.id, ip = %created.ip_address, state = %created.state, "sandbox created");
    if created.state != "starting" {
        bail!("unexpected create state {}", created.state);
    }

    // -- Wait for ready + the initial cmd's idle ---------------------------
    let ready_started = Instant::now();
    wait_for_state(&mut sandboxes, "smoke1", "ready", SANDBOX_READY_TIMEOUT).await?;
    metrics.record("sandbox_ready", ready_started.elapsed().as_secs_f64());

    let info = inspect(&mut sandboxes, "smoke1").await?;
    if info.last_exited_at == 0 {
        // The initial cmd may still be racing the readiness flip; give it a
        // short grace period before asserting.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let info = inspect(&mut sandboxes, "smoke1").await?;
            if info.last_exited_at > 0 {
                break;
            }
            if Instant::now() > deadline {
                bail!("initial cmd never ran (last_exited_at still 0)");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let info = inspect(&mut sandboxes, "smoke1").await?;
    if info.last_exit_code != 0 {
        bail!("initial cmd exited with {}", info.last_exit_code);
    }
    info!("initial cmd ran and sandbox returned to ready");

    // -- Run ----------------------------------------------------------------
    let run_started = Instant::now();
    let stdout = run_and_collect(&mut sandboxes, "smoke1", &["/bin/echo", "hello-sandbox"]).await?;
    if !stdout.contains("hello-sandbox") {
        bail!("run output missing marker: {stdout:?}");
    }
    metrics.record("sandbox_run", run_started.elapsed().as_secs_f64());
    wait_for_state(&mut sandboxes, "smoke1", "ready", Duration::from_secs(30)).await?;

    // -- File round-trip ------------------------------------------------
    let file_started = Instant::now();
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    write_file(&mut sandboxes, "smoke1", "/tmp/smoke.bin", &payload).await?;
    let back = read_file(&mut sandboxes, "smoke1", "/tmp/smoke.bin").await?;
    if back != payload {
        bail!(
            "file round-trip mismatch: sent {} bytes, got {}",
            payload.len(),
            back.len()
        );
    }
    metrics.record("sandbox_file_io", file_started.elapsed().as_secs_f64());
    info!("file round-trip verified");

    // -- Checkpoint / Restore --------------------------------------------
    let checkpoint_started = Instant::now();
    let snapshot_id = snapshots
        .checkpoint(with_machine(CheckpointRequest {
            sandbox_id: "smoke1".into(),
            name: "warm".into(),
            ..Default::default()
        }))
        .await
        .context("Checkpoint failed")?
        .into_inner()
        .snapshot_id;
    metrics.record(
        "sandbox_checkpoint",
        checkpoint_started.elapsed().as_secs_f64(),
    );
    info!(%snapshot_id, "checkpoint taken");

    let restore_started = Instant::now();
    let restored = snapshots
        .restore(with_machine(RestoreRequest {
            id: "smoke2".into(),
            snapshot_id: snapshot_id.clone(),
            network_override: true,
            ..Default::default()
        }))
        .await
        .context("Restore failed")?
        .into_inner();
    info!(id = %restored.id, ip = %restored.ip_address, "sandbox restored");
    let stdout = run_and_collect(&mut sandboxes, "smoke2", &["/bin/echo", "hello-restore"]).await?;
    if !stdout.contains("hello-restore") {
        bail!("restored sandbox run output missing marker: {stdout:?}");
    }
    metrics.record("sandbox_restore", restore_started.elapsed().as_secs_f64());

    // The file written before the checkpoint must exist in the restore.
    let restored_file = read_file(&mut sandboxes, "smoke2", "/tmp/smoke.bin").await?;
    if restored_file.len() != 1024 * 1024 {
        bail!(
            "restored sandbox lost the pre-checkpoint file ({} bytes)",
            restored_file.len()
        );
    }

    // -- Teardown -----------------------------------------------------------
    let teardown_started = Instant::now();
    sandboxes
        .stop(with_machine(StopSandboxRequest {
            id: "smoke1".into(),
            timeout_seconds: 20,
        }))
        .await
        .context("Stop failed")?;
    for id in ["smoke1", "smoke2"] {
        sandboxes
            .remove(with_machine(RemoveSandboxRequest {
                id: id.into(),
                force: true,
            }))
            .await
            .with_context(|| format!("Remove {id} failed"))?;
    }
    let remaining = sandboxes
        .list(with_machine(ListSandboxesRequest::default()))
        .await
        .context("List failed")?
        .into_inner();
    if !remaining.sandboxes.is_empty() {
        bail!(
            "{} sandboxes left after teardown",
            remaining.sandboxes.len()
        );
    }
    metrics.record("sandbox_teardown", teardown_started.elapsed().as_secs_f64());

    info!("sandbox smoke passed");
    Ok(())
}

async fn inspect(
    client: &mut SandboxServiceClient<Channel>,
    id: &str,
) -> Result<arcbox_protocol::sandbox_v1::SandboxInfo> {
    Ok(client
        .inspect(with_machine(InspectSandboxRequest { id: id.into() }))
        .await
        .context("Inspect failed")?
        .into_inner())
}

/// Polls Inspect until the sandbox reaches `state`, failing fast on
/// `failed` with the daemon-reported error.
async fn wait_for_state(
    client: &mut SandboxServiceClient<Channel>,
    id: &str,
    state: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let info = inspect(client, id).await?;
        if info.state == state {
            return Ok(());
        }
        if info.state == "failed" {
            bail!("sandbox {id} failed: {}", info.error);
        }
        if Instant::now() > deadline {
            bail!(
                "sandbox {id} did not reach {state} within {timeout:?} (state: {})",
                info.state
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Runs a command and returns concatenated stdout, asserting exit code 0.
async fn run_and_collect(
    client: &mut SandboxServiceClient<Channel>,
    id: &str,
    cmd: &[&str],
) -> Result<String> {
    let mut stream = client
        .run(with_machine(RunRequest {
            id: id.into(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        }))
        .await
        .context("Run failed")?
        .into_inner();

    let mut stdout = String::new();
    let mut exit_code = None;
    while let Some(output) = stream.message().await.context("run stream error")? {
        if output.stream == "stdout" {
            stdout.push_str(&String::from_utf8_lossy(&output.data));
        }
        if output.done {
            exit_code = Some(output.exit_code);
            break;
        }
    }
    match exit_code {
        Some(0) => Ok(stdout),
        Some(code) => bail!("command {cmd:?} exited with {code}: {stdout:?}"),
        None => bail!("run stream ended without a done frame"),
    }
}

async fn write_file(
    client: &mut SandboxServiceClient<Channel>,
    id: &str,
    path: &str,
    data: &[u8],
) -> Result<()> {
    let mut messages = vec![WriteFileRequest {
        payload: Some(write_file_request::Payload::Open(WriteFileOpen {
            id: id.into(),
            path: path.into(),
            mode: 0o644,
        })),
    }];
    for chunk in data.chunks(256 * 1024) {
        messages.push(WriteFileRequest {
            payload: Some(write_file_request::Payload::Chunk(FileChunk {
                data: chunk.to_vec(),
                done: false,
            })),
        });
    }
    messages.push(WriteFileRequest {
        payload: Some(write_file_request::Payload::Chunk(FileChunk {
            data: Vec::new(),
            done: true,
        })),
    });

    client
        .write_file(with_machine(tokio_stream::iter(messages)))
        .await
        .context("WriteFile failed")?;
    Ok(())
}

async fn read_file(
    client: &mut SandboxServiceClient<Channel>,
    id: &str,
    path: &str,
) -> Result<Vec<u8>> {
    let mut stream = client
        .read_file(with_machine(ReadFileRequest {
            id: id.into(),
            path: path.into(),
        }))
        .await
        .context("ReadFile failed")?
        .into_inner();
    let mut data = Vec::new();
    while let Some(chunk) = stream.message().await.context("read stream error")? {
        data.extend_from_slice(&chunk.data);
        if chunk.done {
            break;
        }
    }
    Ok(data)
}
