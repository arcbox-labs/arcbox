//! Sandbox e2e smoke: the full stack over the real gRPC surface.
//!
//! Drives CLI-equivalent tonic clients against an isolated daemon:
//! create (with an initial cmd) → ready → initial-cmd idle → execution
//! round-trip → CORE-55 acceptance (attach-resume without loss, offset-
//! idempotent stdin, signal without a stream, idle keepalive) → file
//! round-trip (WriteFile/ReadFile) → Checkpoint → Restore
//! (network_override) → execution in the restored sandbox → CORE-53
//! acceptance (the same endpoint answers a plain JSON POST) → Stop/Remove.
//!
//! Requires nested virtualization (VZ backend on Apple Silicon M3+ with
//! macOS 15+): without `/dev/kvm` in the guest, Create fails with
//! FAILED_PRECONDITION and this scenario reports that reason.

use std::env;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_grpc::sandbox_v1::sandbox_filesystem_service_client::SandboxFilesystemServiceClient;
use arcbox_grpc::sandbox_v1::sandbox_process_service_client::SandboxProcessServiceClient;
use arcbox_grpc::sandbox_v1::sandbox_service_client::SandboxServiceClient;
use arcbox_grpc::sandbox_v1::sandbox_snapshot_service_client::SandboxSnapshotServiceClient;
use arcbox_protocol::sandbox_v1::{
    AttachExecutionRequest, CheckpointRequest, CreateSandboxRequest, Execution, ExecutionEvent,
    FileChunk, GetCapabilitiesRequest, GetStdinStatusRequest, IdleAction, InspectSandboxRequest,
    ListSandboxesRequest, PauseSandboxRequest, ReadFileRequest, RemoveSandboxRequest,
    ResourceLimits, RestoreRequest, ResumeSandboxRequest, SandboxEventKind, SandboxEventsRequest,
    SandboxState, SetLifecycleRequest, Signal, SignalExecutionRequest, StartExecutionRequest,
    StdioChannel, StopSandboxRequest, WaitExecutionRequest, WatchEventsResponse, WriteFileOpen,
    WriteFileRequest, WriteStdinRequest, execution_event, exit_status, watch_events_response,
    write_file_request,
};
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use crate::metrics::RunMetrics;
use crate::{env_flag, repo_root};

/// Generous ceiling for daemon startup (asset staging + VM boot + agent).
/// Sized for a cold CDN fetch of the runtime binaries: measured startups
/// reach 150-180s when the CDN is slow, and the guest runtime
/// materialization added to the budget in v0.8.
const READY_TIMEOUT: Duration = Duration::from_secs(300);
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
        drive_sandboxes(channel, &grpc_socket, data_dir, metrics).await
    });

    // Always shut the daemon down; a teardown failure must not mask the
    // scenario result.
    match daemon.shutdown() {
        Ok(status) => info!(%status, "daemon stopped"),
        Err(error) => warn!("daemon shutdown failed: {error:#}"),
    }

    scenario
}

/// CORE-53 acceptance, against a daemon that is actually serving: the same
/// endpoint every other call in this scenario reached over gRPC also answers
/// a caller with no proto toolchain.
///
/// The request is written as raw bytes because that is exactly what
/// `curl --unix-socket -X POST -H 'Content-Type: application/json' -d '{}'`
/// puts on the wire — a passing assertion here is the claim itself, not a
/// client library's interpretation of it. The sandboxes this scenario just
/// created must come back in the JSON, so this proves a real response body
/// rather than only that an error is well-formed.
async fn assert_connect_json_lists_sandboxes(
    socket: &std::path::Path,
    expected: &[&str],
) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let request = "POST /arcbox.sandbox.v1.SandboxService/List HTTP/1.1\r\n\
         Host: localhost\r\nContent-Type: application/json\r\n\
         Connection: close\r\nContent-Length: 2\r\n\r\n{}";

    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .context("connecting to the control-plane socket")?;
    stream
        .write_all(request.as_bytes())
        .await
        .context("writing the Connect request")?;
    stream.flush().await.context("flushing")?;

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .context("Connect JSON response timed out")?
        .context("reading the Connect response")?;
    let raw = String::from_utf8_lossy(&raw).into_owned();

    if !raw.starts_with("HTTP/1.1 200") {
        bail!("Connect JSON List did not succeed: {raw}");
    }
    let body = dechunk(&raw);
    let json: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("Connect body was not JSON: {body}"))?;

    let listed: Vec<&str> = json
        .get("sandboxes")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|s| s.get("id").and_then(serde_json::Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    for id in expected {
        if !listed.contains(id) {
            bail!("Connect JSON List missing {id}; got {listed:?} from {body}");
        }
    }

    info!(
        sandboxes = listed.len(),
        "Connect JSON reached the same endpoint and returned live data"
    );
    Ok(())
}

/// Reassembles a `Transfer-Encoding: chunked` body.
///
/// The daemon streams the response, so there is no Content-Length. Real
/// clients hide this; reading the socket directly does not.
fn dechunk(response: &str) -> String {
    let Some((_, mut rest)) = response.split_once("\r\n\r\n") else {
        return String::new();
    };
    let mut body = String::new();
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if size == 0 || tail.len() < size {
            break;
        }
        body.push_str(&tail[..size]);
        rest = tail[size..].trim_start_matches("\r\n");
    }
    body
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

async fn drive_sandboxes(
    channel: Channel,
    socket: &std::path::Path,
    data_dir: &std::path::Path,
    metrics: &mut RunMetrics,
) -> Result<()> {
    // One client per service: the daemon serves all four together, but the
    // split (CORE-57) is what lets a cloud deployment put the data plane
    // somewhere else, so the test drives them as separate endpoints.
    let mut sandboxes = SandboxServiceClient::new(channel.clone());
    let mut processes = SandboxProcessServiceClient::new(channel.clone());
    let mut files = SandboxFilesystemServiceClient::new(channel.clone());
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
    info!(id = %created.id, ip = %created.ip_address, state = ?created.state(), "sandbox created");
    if created.state() != SandboxState::Starting {
        bail!("unexpected create state {:?}", created.state());
    }

    // -- Wait for ready + the initial cmd's idle ---------------------------
    let ready_started = Instant::now();
    wait_for_state(
        &mut sandboxes,
        "smoke1",
        SandboxState::Ready,
        SANDBOX_READY_TIMEOUT,
    )
    .await?;
    metrics.record("sandbox_ready", ready_started.elapsed().as_secs_f64());

    let info = inspect(&mut sandboxes, "smoke1").await?;
    if info.last_exited_at.is_none() {
        // The initial cmd may still be racing the readiness flip; give it a
        // short grace period before asserting.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let info = inspect(&mut sandboxes, "smoke1").await?;
            if info.last_exited_at.is_some() {
                break;
            }
            if Instant::now() > deadline {
                bail!("initial cmd never ran (last_exited_at still unset)");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    let info = inspect(&mut sandboxes, "smoke1").await?;
    match info.last_exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Code(0)) => {}
        other => bail!("initial cmd exit status: {other:?}"),
    }
    info!("initial cmd ran and sandbox returned to ready");

    // -- Execution round-trip (run semantics) ------------------------------
    let run_started = Instant::now();
    let stdout = run_and_collect(&mut processes, "smoke1", &["/bin/echo", "hello-sandbox"]).await?;
    if !stdout.contains("hello-sandbox") {
        bail!("run output missing marker: {stdout:?}");
    }
    metrics.record("sandbox_run", run_started.elapsed().as_secs_f64());
    wait_ready(&mut sandboxes, "smoke1").await?;

    // -- CORE-55 acceptance: drop the attach mid-output, resume without loss
    let resume_started = Instant::now();
    exec_attach_resume(&mut processes, "smoke1").await?;
    metrics.record(
        "sandbox_exec_resume",
        resume_started.elapsed().as_secs_f64(),
    );
    wait_ready(&mut sandboxes, "smoke1").await?;

    // -- CORE-55 acceptance: offset-idempotent stdin -----------------------
    let stdin_started = Instant::now();
    exec_stdin_idempotent(&mut processes, "smoke1").await?;
    metrics.record("sandbox_exec_stdin", stdin_started.elapsed().as_secs_f64());
    wait_ready(&mut sandboxes, "smoke1").await?;

    // -- CORE-55 acceptance: signal without a stream + idle keepalive ------
    let signal_started = Instant::now();
    exec_signal_and_keepalive(&mut processes, "smoke1").await?;
    metrics.record(
        "sandbox_exec_signal",
        signal_started.elapsed().as_secs_f64(),
    );
    wait_ready(&mut sandboxes, "smoke1").await?;

    // -- CORE-54: create from a docker: template ---------------------------
    let template_started = Instant::now();
    sandbox_from_docker_template(&mut sandboxes, &mut processes, data_dir).await?;
    metrics.record(
        "sandbox_docker_template",
        template_started.elapsed().as_secs_f64(),
    );

    // -- File round-trip ------------------------------------------------
    let file_started = Instant::now();
    let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    write_file(&mut files, "smoke1", "/tmp/smoke.bin", &payload).await?;
    let back = read_file(&mut files, "smoke1", "/tmp/smoke.bin").await?;
    if back != payload {
        bail!(
            "file round-trip mismatch: sent {} bytes, got {}",
            payload.len(),
            back.len()
        );
    }
    metrics.record("sandbox_file_io", file_started.elapsed().as_secs_f64());
    info!("file round-trip verified");

    // -- Pause / transparent auto-resume / explicit Resume (CORE-21) -------
    let pause_started = Instant::now();
    let origin_ip = pause_resume_scenario(&mut sandboxes, &mut processes, &mut files).await?;
    metrics.record(
        "sandbox_pause_resume",
        pause_started.elapsed().as_secs_f64(),
    );

    // -- CORE-13: capability handshake -------------------------------------
    let capabilities_started = Instant::now();
    assert_capabilities(&mut sandboxes).await?;
    metrics.record(
        "sandbox_capabilities",
        capabilities_started.elapsed().as_secs_f64(),
    );

    // -- CORE-21/60: idle auto-pause + SetLifecycle re-arm -----------------
    let lifecycle_started = Instant::now();
    idle_lifecycle_scenario(&mut sandboxes, &mut processes).await?;
    metrics.record(
        "sandbox_idle_lifecycle",
        lifecycle_started.elapsed().as_secs_f64(),
    );

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

    // Datapath proof for the *resumed origin*: the pause/resume phase asserts
    // only its addressing (its `run_and_collect` calls ride vsock, which never
    // crosses the TAP), because probing the gateway there would bake a
    // REACHABLE neighbour entry into the checkpoint above — and the clone,
    // restoring onto a TAP with a different gateway MAC, would inherit it and
    // blackhole until it aged out. After the checkpoint that hazard is gone
    // (no further snapshot of `smoke1` is taken; the reuse-NIC restore below
    // replays this same one), so ping here: it proves `restore_paused`'s
    // freshly activated invariant TAP actually moves packets, which is a
    // different code path from the clone's `network_overrides` restore.
    wait_ready(&mut sandboxes, "smoke1").await?;
    let resumed_ping = run_and_collect(
        &mut processes,
        "smoke1",
        &[
            "/bin/sh",
            "-c",
            "gw=$(ip route | sed -n 's/^default via \\([0-9.]*\\).*/\\1/p' | head -1); \
             echo \"gateway=$gw\"; ping -c 1 -W 2 \"$gw\"",
        ],
    )
    .await?;
    if !resumed_ping.contains(" 0% packet loss") {
        bail!("resumed sandbox could not reach its gateway over its new TAP: {resumed_ping:?}");
    }
    info!("resumed origin reaches its gateway over the post-resume TAP");

    // -- Fresh-network restore (origin still running) ----------------------
    // `network_override: true` gives the clone a new TAP via FC's
    // `network_overrides` snapshot-load field (Firecracker >= 1.12), so the
    // origin keeps its NIC and both run side by side.
    let fresh_net_started = Instant::now();
    let cloned = snapshots
        .restore(with_machine(RestoreRequest {
            id: "smoke3".into(),
            snapshot_id: snapshot_id.clone(),
            network_override: true,
            ..Default::default()
        }))
        .await
        .context("Fresh-network restore failed")?
        .into_inner();
    info!(id = %cloned.id, ip = %cloned.ip_address, "sandbox restored with fresh network while origin runs");
    // The origin's IP changed across pause/resume; compare against its
    // current allocation, which is also what the checkpoint recorded.
    if cloned.ip_address.is_empty() || cloned.ip_address == origin_ip {
        bail!(
            "fresh-network clone must get its own IP (origin {origin_ip}, clone {:?})",
            cloned.ip_address
        );
    }
    let stdout = run_and_collect(&mut processes, "smoke3", &["/bin/echo", "hello-clone"]).await?;
    if !stdout.contains("hello-clone") {
        bail!("fresh-network clone run output missing marker: {stdout:?}");
    }

    // The vsock channel working proves nothing about the new TAP. Under
    // invariant addressing (CORE-81) every guest carries the fixed
    // link-local identity and the pool IP lives host-side, so assert the
    // guest kept the invariant address and never sees a pool IP…
    wait_ready(&mut sandboxes, "smoke3").await?;
    let addr = run_and_collect(
        &mut processes,
        "smoke3",
        &["/bin/sh", "-c", "ip addr show eth0"],
    )
    .await?;
    // Mirrors GUEST_IP in virt/arcbox-vm/src/network/invariant.rs.
    if !addr.contains("169.254.100.2/") {
        bail!("clone eth0 does not carry the invariant guest IP (got: {addr:?})");
    }
    // `origin_ip` is the origin's *post-resume* allocation, distinct from the
    // one it was created with — both are pool IPs and neither may leak in.
    if addr.contains(&format!("{}/", created.ip_address))
        || addr.contains(&format!("{origin_ip}/"))
        || addr.contains(&format!("{}/", cloned.ip_address))
    {
        bail!("clone eth0 carries a pool IP; those must stay host-side (got: {addr:?})");
    }

    // …and that traffic flows through the new TAP: ping the gateway, which
    // is the local address of the clone's own TAP (sandboxes are isolated
    // point-to-point links, so peers are deliberately unreachable). Deriving
    // the gateway from `ip route` also proves the restored default route.
    wait_ready(&mut sandboxes, "smoke3").await?;
    let ping = run_and_collect(
        &mut processes,
        "smoke3",
        &[
            "/bin/sh",
            "-c",
            "gw=$(ip route | sed -n 's/^default via \\([0-9.]*\\).*/\\1/p' | head -1); \
             echo \"gateway=$gw\"; ping -c 1 -W 2 \"$gw\"",
        ],
    )
    .await?;
    if !ping.contains(" 0% packet loss") {
        bail!("clone could not reach its gateway over the new TAP: {ping:?}");
    }

    let origin = inspect(&mut sandboxes, "smoke1").await?;
    if origin.state() != SandboxState::Ready {
        bail!(
            "origin should keep running through a fresh-network restore, state={:?}",
            origin.state()
        );
    }
    metrics.record(
        "sandbox_restore_fresh_net",
        fresh_net_started.elapsed().as_secs_f64(),
    );

    // Stop the origin before the reuse-NIC restore: with
    // `network_override: false` the restored sandbox reuses the recorded NIC
    // (the origin's TAP), so the origin must release it first.
    let restore_started = Instant::now();
    sandboxes
        .stop(with_machine(StopSandboxRequest {
            id: "smoke1".into(),
            timeout_seconds: 20,
        }))
        .await
        .context("Stop origin before restore failed")?;

    let restored = snapshots
        .restore(with_machine(RestoreRequest {
            id: "smoke2".into(),
            snapshot_id: snapshot_id.clone(),
            network_override: false,
            ..Default::default()
        }))
        .await
        .context("Restore failed")?
        .into_inner();
    info!(id = %restored.id, "sandbox restored");
    let stdout = run_and_collect(&mut processes, "smoke2", &["/bin/echo", "hello-restore"]).await?;
    if !stdout.contains("hello-restore") {
        bail!("restored sandbox run output missing marker: {stdout:?}");
    }
    metrics.record("sandbox_restore", restore_started.elapsed().as_secs_f64());

    // The file written before the checkpoint must exist in the restore.
    let restored_file = read_file(&mut files, "smoke2", "/tmp/smoke.bin").await?;
    if restored_file.len() != 1024 * 1024 {
        bail!(
            "restored sandbox lost the pre-checkpoint file ({} bytes)",
            restored_file.len()
        );
    }

    // -- Teardown -----------------------------------------------------------
    let connect_started = Instant::now();
    assert_connect_json_lists_sandboxes(socket, &["smoke1", "smoke2", "smoke3"]).await?;
    metrics.record("connect_json", connect_started.elapsed().as_secs_f64());

    let teardown_started = Instant::now();
    for id in ["smoke1", "smoke2", "smoke3", "smoke-template"] {
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

/// CORE-54 acceptance: a sandbox is created knowing only a template
/// reference — no kernel, rootfs, or any other host path crosses the API.
///
/// The image is pulled through the daemon's Docker proxy into the guest's own
/// image store, then resolved to a bootable rootfs entirely inside the VM.
async fn sandbox_from_docker_template(
    client: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    data_dir: &std::path::Path,
) -> Result<()> {
    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());

    // The pull goes to the guest dockerd, which is exactly where the guest
    // template resolver will look for it.
    crate::docker::docker_output(data_dir, &["pull", &image], Duration::from_secs(300))
        .with_context(|| format!("docker pull {image} failed"))?;

    let created = client
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-template".into(),
            template: format!("docker:{image}"),
            limits: Some(ResourceLimits {
                vcpus: 1,
                memory_mib: 256,
            }),
            ..Default::default()
        }))
        .await
        .context("Create from docker template failed")?
        .into_inner();
    info!(id = %created.id, %image, "sandbox created from a docker template");

    // Conversion of a real image runs on the first create, so allow the same
    // budget as a cold sandbox boot.
    wait_for_state(
        client,
        "smoke-template",
        SandboxState::Ready,
        SANDBOX_READY_TIMEOUT,
    )
    .await?;

    // The workload must be the template's filesystem, not the built-in
    // busybox image: /etc/os-release only exists in the pulled image.
    let os_release = run_and_collect(
        processes,
        "smoke-template",
        &["/bin/sh", "-c", "cat /etc/os-release"],
    )
    .await?;
    if !os_release.to_ascii_lowercase().contains("id=") {
        bail!("template sandbox is not running the pulled image: {os_release:?}");
    }
    info!("docker template resolved and booted inside the guest");
    Ok(())
}

/// CORE-55 acceptance: kill the attach stream mid-output, re-attach at the
/// recorded offset, and require the assembled output to be byte-exact.
async fn exec_attach_resume(
    client: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
) -> Result<()> {
    use std::fmt::Write as _;

    const LINES: usize = 200;
    let expected = (0..LINES).fold(String::new(), |mut s, i| {
        let _ = writeln!(s, "line-{i}");
        s
    });

    let script = format!("i=0; while [ $i -lt {LINES} ]; do echo line-$i; i=$((i+1)); done");
    let execution = start_execution(
        client,
        sandbox_id,
        "resume-exec",
        &["/bin/sh", "-c", &script],
        false,
    )
    .await?;

    // First attach: consume a handful of output events, then drop the stream
    // mid-execution (the client "dies").
    let mut assembled = String::new();
    let mut next_offset = 0u64;
    {
        let mut stream = attach(client, sandbox_id, &execution.id, 0).await?;
        let mut outputs = 0;
        while let Some(event) = stream.message().await.context("first attach stream")? {
            match event.event {
                Some(execution_event::Event::Output(output)) => {
                    if output.channel() != StdioChannel::Stdout {
                        continue;
                    }
                    if output.offset != next_offset {
                        bail!(
                            "unexpected gap on live attach: offset {} after {}",
                            output.offset,
                            next_offset
                        );
                    }
                    assembled.push_str(&String::from_utf8_lossy(&output.data));
                    next_offset = output.offset + output.data.len() as u64;
                    outputs += 1;
                    if outputs >= 3 {
                        break; // drop the stream mid-output
                    }
                }
                Some(execution_event::Event::Exited(_)) => break,
                _ => {}
            }
        }
        // Dropping `stream` here severs the connection without any goodbye.
    }
    info!(
        resumed_from = next_offset,
        "dropped first attach mid-output; re-attaching"
    );

    // Second attach from the recorded offset: the rest must arrive with no
    // loss and no duplication, ending in a clean exit.
    let mut stream = attach(client, sandbox_id, &execution.id, next_offset).await?;
    let mut exited = None;
    while let Some(event) = stream.message().await.context("resumed attach stream")? {
        match event.event {
            Some(execution_event::Event::Output(output)) => {
                if output.channel() != StdioChannel::Stdout {
                    continue;
                }
                if output.offset != next_offset {
                    bail!(
                        "resume lost bytes: expected offset {}, got {}",
                        next_offset,
                        output.offset
                    );
                }
                assembled.push_str(&String::from_utf8_lossy(&output.data));
                next_offset = output.offset + output.data.len() as u64;
            }
            Some(execution_event::Event::Exited(done)) => {
                exited = done.execution;
                break;
            }
            _ => {}
        }
    }
    let done = exited.context("resumed attach ended without an exit event")?;
    match done.exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Code(0)) => {}
        other => bail!("resume execution exit status: {other:?}"),
    }
    if assembled != expected {
        bail!(
            "resumed output is not byte-exact: {} bytes vs expected {}",
            assembled.len(),
            expected.len()
        );
    }
    info!("attach-resume reassembled the full output without loss");
    Ok(())
}

/// CORE-55 acceptance: retried stdin writes are deduplicated by offset and
/// GetStdinStatus reports the resume point.
async fn exec_stdin_idempotent(
    client: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
) -> Result<()> {
    let execution = start_execution(client, sandbox_id, "stdin-exec", &["/bin/cat"], true).await?;

    let write = |data: &[u8], offset: u64, eof: bool| WriteStdinRequest {
        sandbox_id: sandbox_id.to_owned(),
        execution_id: execution.id.clone(),
        offset,
        data: data.to_vec(),
        eof,
    };

    let st = client
        .write_stdin(with_machine(write(b"hello ", 0, false)))
        .await
        .context("first stdin write")?
        .into_inner();
    if st.bytes_written != 6 {
        bail!("expected 6 bytes accepted, got {}", st.bytes_written);
    }

    // Retry the exact same write, as if the first response was lost: the
    // bytes must be deduplicated, not double-fed to `cat`.
    let st = client
        .write_stdin(with_machine(write(b"hello ", 0, false)))
        .await
        .context("retried stdin write")?
        .into_inner();
    if st.bytes_written != 6 {
        bail!("retry moved the offset: {}", st.bytes_written);
    }

    // A write past the accepted count is a gap and must be rejected.
    let gap = client
        .write_stdin(with_machine(write(b"x", 99, false)))
        .await;
    match gap {
        Err(status) if status.code() == tonic::Code::OutOfRange => {}
        Err(status) => bail!("gap write failed with {:?}, expected OutOfRange", status),
        Ok(_) => bail!("gap write was accepted"),
    }

    // Resync exactly the way a real client would: ask for the resume point.
    let st = client
        .get_stdin_status(with_machine(GetStdinStatusRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: execution.id.clone(),
        }))
        .await
        .context("stdin status")?
        .into_inner();
    if st.bytes_written != 6 || st.closed {
        bail!("unexpected stdin status: {st:?}");
    }

    // Finish the stream and close stdin so `cat` exits.
    client
        .write_stdin(with_machine(write(b"world\n", st.bytes_written, true)))
        .await
        .context("final stdin write")?;

    // The process must have seen the deduplicated byte stream exactly once.
    let (stdout, done) = collect_output(client, sandbox_id, &execution.id).await?;
    match done.exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Code(0)) => {}
        other => bail!("cat exit status: {other:?}"),
    }
    if stdout != "hello world\n" {
        bail!("stdin dedup failed, cat echoed {stdout:?}");
    }
    info!("offset-idempotent stdin verified");
    Ok(())
}

/// CORE-55 acceptance: a keepalive arrives on an idle attach stream, and a
/// signal delivered with no stream attached kills the process, reported as a
/// signal death (not an exit code).
async fn exec_signal_and_keepalive(
    client: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
) -> Result<()> {
    let execution = start_execution(
        client,
        sandbox_id,
        "signal-exec",
        &["/bin/sleep", "300"],
        false,
    )
    .await?;

    // The workload is silent: the first frame after the Started preamble on
    // an idle stream must be a daemon keepalive (15s cadence).
    let mut stream = attach(client, sandbox_id, &execution.id, 0).await?;
    let keepalive_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let event = tokio::time::timeout(Duration::from_secs(30), stream.message())
            .await
            .context("idle attach produced nothing (keepalive missing)")?
            .context("idle attach stream")?
            .context("idle attach closed unexpectedly")?;
        match event.event {
            Some(execution_event::Event::KeepAlive(_)) => break,
            Some(execution_event::Event::Exited(_)) => {
                bail!("sleep exited before the keepalive check")
            }
            _ if Instant::now() > keepalive_deadline => {
                bail!("no keepalive within 30s on an idle stream")
            }
            _ => {}
        }
    }
    drop(stream);
    info!("idle-stream keepalive observed");

    // Signal the process while holding no stream at all.
    client
        .signal_execution(with_machine(SignalExecutionRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: execution.id.clone(),
            signal: Signal::Sigkill.into(),
        }))
        .await
        .context("SignalExecution failed")?;

    let done = client
        .wait_execution(with_machine(WaitExecutionRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: execution.id.clone(),
            timeout_seconds: 30,
        }))
        .await
        .context("WaitExecution failed")?
        .into_inner();
    match done.exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Signal(9)) => {}
        other => bail!("expected a SIGKILL death, got {other:?}"),
    }
    info!("stream-free signal delivered and reported as a signal death");
    Ok(())
}

/// CORE-13 acceptance: the capability handshake answers real data —
/// version, protocol level, the lifecycle feature flags, and nested-virt
/// support (which must hold on any host this smoke can run on).
async fn assert_capabilities(sandboxes: &mut SandboxServiceClient<Channel>) -> Result<()> {
    let caps = sandboxes
        .get_capabilities(with_machine(GetCapabilitiesRequest {}))
        .await
        .context("GetCapabilities failed")?
        .into_inner();
    if caps.daemon_version.is_empty() {
        bail!("GetCapabilities reported an empty daemon_version");
    }
    if caps.protocol < 1 {
        bail!(
            "GetCapabilities protocol must be >= 1, got {}",
            caps.protocol
        );
    }
    for feature in [
        "pause_resume",
        "auto_resume",
        "idle_policy",
        "set_lifecycle",
    ] {
        if !caps.features.iter().any(|f| f == feature) {
            bail!("missing feature flag {feature:?} in {:?}", caps.features);
        }
    }
    let nested = caps
        .nested_virt
        .ok_or_else(|| anyhow::anyhow!("GetCapabilities left nested_virt unset"))?;
    if !nested.supported {
        bail!(
            "this smoke requires nested virtualization but the daemon reports: {}",
            nested.reason
        );
    }
    info!(
        version = %caps.daemon_version,
        protocol = caps.protocol,
        "capabilities verified"
    );
    Ok(())
}

/// CORE-21/60 acceptance: a sandbox created with `idle_timeout_seconds: 2`
/// and `on_idle: PAUSE` auto-pauses on the idle edge (visible as PAUSING
/// with reason=idle_timeout), a data-plane exec transparently resumes it,
/// and SetLifecycle then disarms the idle window (Some(0)) while re-arming
/// the TTL hard cap from now — with the absent `on_idle` left unchanged.
async fn idle_lifecycle_scenario(
    sandboxes: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
) -> Result<()> {
    const ID: &str = "smoke-idle";

    // Subscribe before creating so no transition is missed.
    let mut events = sandboxes
        .events(with_machine(SandboxEventsRequest {
            sandbox_id: ID.into(),
            ..Default::default()
        }))
        .await
        .context("Events subscribe failed")?
        .into_inner();

    let created = sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: ID.into(),
            limits: Some(ResourceLimits {
                vcpus: 1,
                memory_mib: 256,
            }),
            idle_timeout_seconds: 2,
            on_idle: IdleAction::Pause as i32,
            ..Default::default()
        }))
        .await
        .context("Create smoke-idle failed")?
        .into_inner();
    info!(id = %created.id, "idle-policy sandbox created");
    wait_for_state(sandboxes, ID, SandboxState::Ready, SANDBOX_READY_TIMEOUT).await?;

    // No execution runs, so the 2 s idle window expires and auto-pauses.
    next_event(&mut events, SandboxEventKind::Pausing, Some("idle_timeout")).await?;
    next_event(&mut events, SandboxEventKind::Paused, None).await?;
    let info = inspect(sandboxes, ID).await?;
    if info.state() != SandboxState::Paused {
        bail!("expected auto-paused sandbox, got {:?}", info.state());
    }
    if info.idle_timeout_seconds != 2 || info.on_idle() != IdleAction::Pause {
        bail!(
            "idle knobs not reported: timeout={} on_idle={:?}",
            info.idle_timeout_seconds,
            info.on_idle()
        );
    }
    info!("idle detector auto-paused the sandbox");

    // A data-plane exec transparently resumes it (latency blip, no error).
    let stdout = run_and_collect(processes, ID, &["/bin/echo", "idle-wake"]).await?;
    if !stdout.contains("idle-wake") {
        bail!("post-auto-resume exec output missing marker: {stdout:?}");
    }
    next_event(&mut events, SandboxEventKind::Resumed, Some("auto_resume")).await?;

    // Disarm the idle window and re-arm the TTL from now (CORE-60). This
    // races the freshly re-armed 2 s idle timer and must land well inside
    // it (one local unary call).
    let rearm_epoch = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    sandboxes
        .set_lifecycle(with_machine(SetLifecycleRequest {
            id: ID.into(),
            ttl_seconds: Some(600),
            idle_timeout_seconds: Some(0),
            on_idle: None,
        }))
        .await
        .context("SetLifecycle failed")?;

    // Outlive the original window: with idle detection disarmed the
    // sandbox must stay READY past the 2 s that previously paused it.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let info = inspect(sandboxes, ID).await?;
    if info.state() != SandboxState::Ready {
        bail!("idle window re-arm did not stick; state {:?}", info.state());
    }
    if info.idle_timeout_seconds != 0 {
        bail!(
            "idle_timeout_seconds not replaced: {}",
            info.idle_timeout_seconds
        );
    }
    if info.on_idle() != IdleAction::Pause {
        bail!(
            "absent on_idle must stay unchanged, got {:?}",
            info.on_idle()
        );
    }
    let deadline = info
        .ttl_deadline
        .ok_or_else(|| anyhow::anyhow!("ttl_deadline unset after SetLifecycle"))?;
    let ahead = deadline.seconds - rearm_epoch;
    if !(540..=660).contains(&ahead) {
        bail!("ttl_deadline not re-armed from now: {ahead}s ahead");
    }
    info!("SetLifecycle re-armed the TTL and disarmed the idle window");

    sandboxes
        .remove(with_machine(RemoveSandboxRequest {
            id: ID.into(),
            force: true,
        }))
        .await
        .context("Remove smoke-idle failed")?;
    Ok(())
}

/// CORE-21 acceptance: pause → paused honesty (state, paused_at,
/// storage_bytes, opt-out header) → transparent auto-resume on a data-plane
/// call → pause again → explicit Resume, with memory AND disk state proven
/// to survive and every transition visible on the Events stream.
///
/// Returns the origin's post-resume IP for the later restore assertions.
async fn pause_resume_scenario(
    sandboxes: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    files: &mut SandboxFilesystemServiceClient<Channel>,
) -> Result<String> {
    // Disk marker on the ext4 rootfs — unlike /tmp (tmpfs, which rides the
    // memory image) this proves the CoW overlay itself survives. The sync
    // pushes it out of the page cache into the overlay.
    let disk_marker: Vec<u8> = (0..64 * 1024).map(|i| (i % 199) as u8).collect();
    write_file(files, "smoke1", "/pause-disk-marker.bin", &disk_marker).await?;
    run_and_collect(processes, "smoke1", &["/bin/sh", "-c", "sync"]).await?;
    wait_ready(sandboxes, "smoke1").await?;

    // Subscribe before pausing so every transition is captured.
    let mut events = sandboxes
        .events(with_machine(SandboxEventsRequest {
            sandbox_id: "smoke1".into(),
            ..Default::default()
        }))
        .await
        .context("Events subscribe failed")?
        .into_inner();

    // -- Pause ------------------------------------------------------------
    sandboxes
        .pause(with_machine(PauseSandboxRequest {
            id: "smoke1".into(),
        }))
        .await
        .context("Pause failed")?;
    let info = inspect(sandboxes, "smoke1").await?;
    if info.state() != SandboxState::Paused {
        bail!("expected PAUSED after Pause, got {:?}", info.state());
    }
    if info.paused_at.is_none() {
        bail!("paused sandbox must report paused_at");
    }
    if info.storage_bytes == 0 {
        bail!("paused sandbox must report a nonzero storage_bytes");
    }
    next_event(&mut events, SandboxEventKind::Pausing, Some("pause")).await?;
    next_event(&mut events, SandboxEventKind::Paused, None).await?;
    info!(storage_bytes = info.storage_bytes, "sandbox paused");

    // Pause is idempotent on a paused sandbox.
    sandboxes
        .pause(with_machine(PauseSandboxRequest {
            id: "smoke1".into(),
        }))
        .await
        .context("idempotent Pause failed")?;

    // -- Opt-out header gets the honest FAILED_PRECONDITION ---------------
    let mut opted_out = with_machine(StartExecutionRequest {
        sandbox_id: "smoke1".into(),
        cmd: vec!["/bin/true".into()],
        stdin: false,
        ..Default::default()
    });
    opted_out.metadata_mut().insert(
        "x-arcbox-no-auto-resume",
        tonic::metadata::MetadataValue::from_static("1"),
    );
    match processes.start_execution(opted_out).await {
        Ok(_) => bail!("opted-out execution on a paused sandbox must fail"),
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {}
        Err(status) => bail!("opted-out execution: expected FAILED_PRECONDITION, got {status}"),
    }
    let info = inspect(sandboxes, "smoke1").await?;
    if info.state() != SandboxState::Paused {
        bail!(
            "the opted-out call must not wake the sandbox (state: {:?})",
            info.state()
        );
    }

    // -- Transparent auto-resume on a data-plane call ---------------------
    let stdout = run_and_collect(
        processes,
        "smoke1",
        &["/bin/sh", "-c", "wc -c < /pause-disk-marker.bin"],
    )
    .await?;
    if stdout.trim() != disk_marker.len().to_string() {
        bail!("disk marker size after auto-resume: {stdout:?}");
    }
    next_event(&mut events, SandboxEventKind::Resumed, Some("auto_resume")).await?;
    wait_ready(sandboxes, "smoke1").await?;
    let back = read_file(files, "smoke1", "/pause-disk-marker.bin").await?;
    if back != disk_marker {
        bail!("disk overlay state lost across pause/auto-resume");
    }
    let tmp = read_file(files, "smoke1", "/tmp/smoke.bin").await?;
    if tmp.len() != 1024 * 1024 {
        bail!(
            "tmpfs (memory) state lost across pause/auto-resume ({} bytes)",
            tmp.len()
        );
    }
    info!("transparent auto-resume verified (disk + memory intact)");

    // -- Pause again, resume explicitly -----------------------------------
    sandboxes
        .pause(with_machine(PauseSandboxRequest {
            id: "smoke1".into(),
        }))
        .await
        .context("second Pause failed")?;
    next_event(&mut events, SandboxEventKind::Paused, None).await?;
    sandboxes
        .resume(with_machine(ResumeSandboxRequest {
            id: "smoke1".into(),
        }))
        .await
        .context("Resume failed")?;
    next_event(&mut events, SandboxEventKind::Resumed, Some("resume")).await?;
    // Resume is idempotent on a live sandbox.
    sandboxes
        .resume(with_machine(ResumeSandboxRequest {
            id: "smoke1".into(),
        }))
        .await
        .context("idempotent Resume failed")?;
    wait_ready(sandboxes, "smoke1").await?;

    // Resume allocates a fresh TAP + IP, but under invariant addressing
    // (CORE-81) that is a purely host-side change: the guest keeps the fixed
    // link-local identity and the pool IP lives on the TAP. The pool IP
    // itself may legitimately be recycled — pause released it and this is
    // the only sandbox — so what is asserted is the addressing shape.
    //
    // Deliberately NOT a gateway ping here: probing the gateway leaves a
    // REACHABLE neighbour entry for it in the guest, and the checkpoint the
    // next phase takes of this very sandbox inherits that entry. The clone
    // restores onto a *different* TAP, whose gateway MAC differs, so the
    // inherited entry blackholes the clone until it ages out. The proof for
    // this sandbox's own post-resume TAP lives in the caller, just after the
    // checkpoint is taken — past the point where a warmed neighbour entry
    // could still be captured.
    let info = inspect(sandboxes, "smoke1").await?;
    let resumed_ip = info
        .network
        .as_ref()
        .map(|n| n.ip_address.clone())
        .unwrap_or_default();
    if resumed_ip.is_empty() {
        bail!("resumed sandbox must report an IP");
    }
    let addr =
        run_and_collect(processes, "smoke1", &["/bin/sh", "-c", "ip addr show eth0"]).await?;
    // Mirrors GUEST_IP in virt/arcbox-vm/src/network/invariant.rs.
    if !addr.contains("169.254.100.2/") {
        bail!("resumed eth0 does not carry the invariant guest IP (got: {addr:?})");
    }
    if addr.contains(&format!("{resumed_ip}/")) {
        bail!("resumed eth0 carries a pool IP; those must stay host-side (got: {addr:?})");
    }
    // The default route must survive the checkpoint/restore round trip.
    if !run_and_collect(processes, "smoke1", &["/bin/sh", "-c", "ip route"])
        .await?
        .contains("default via 169.254.100.1")
    {
        bail!("resumed sandbox lost its default route");
    }
    info!(ip = %resumed_ip, "explicit resume verified");
    Ok(resumed_ip)
}

/// Scans the events stream (skipping keepalives and unrelated kinds) until
/// `kind` arrives, asserting its "reason" attribute when specified.
async fn next_event(
    stream: &mut tonic::Streaming<WatchEventsResponse>,
    kind: SandboxEventKind,
    reason: Option<&str>,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .with_context(|| format!("timed out waiting for {kind:?} event"))?;
        let message = tokio::time::timeout(remaining, stream.message())
            .await
            .with_context(|| format!("timed out waiting for {kind:?} event"))?
            .context("events stream error")?
            .context("events stream ended")?;
        let Some(watch_events_response::Payload::Event(event)) = message.payload else {
            continue; // keepalive
        };
        if event.kind() != kind {
            continue;
        }
        if let Some(reason) = reason {
            let got = event.attributes.get("reason").map(String::as_str);
            if got != Some(reason) {
                bail!("{kind:?} event reason: expected {reason:?}, got {got:?}");
            }
        }
        return Ok(());
    }
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
/// `FAILED` with the daemon-reported error.
async fn wait_for_state(
    client: &mut SandboxServiceClient<Channel>,
    id: &str,
    state: SandboxState,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let info = inspect(client, id).await?;
        if info.state() == state {
            return Ok(());
        }
        if info.state() == SandboxState::Failed {
            bail!("sandbox {id} failed: {}", info.error);
        }
        if Instant::now() > deadline {
            bail!(
                "sandbox {id} did not reach {state:?} within {timeout:?} (state: {:?})",
                info.state()
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Waits for the post-execution `RUNNING → READY` flip.
async fn wait_ready(client: &mut SandboxServiceClient<Channel>, id: &str) -> Result<()> {
    wait_for_state(client, id, SandboxState::Ready, Duration::from_secs(30)).await
}

/// Starts an execution with a fixed id (idempotent per command).
async fn start_execution(
    client: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
    execution_id: &str,
    cmd: &[&str],
    stdin: bool,
) -> Result<Execution> {
    Ok(client
        .start_execution(with_machine(StartExecutionRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: execution_id.to_owned(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            stdin,
            ..Default::default()
        }))
        .await
        .context("StartExecution failed")?
        .into_inner())
}

/// Attaches to an execution's stdout from `stdout_offset`.
async fn attach(
    client: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
    execution_id: &str,
    stdout_offset: u64,
) -> Result<tonic::Streaming<ExecutionEvent>> {
    Ok(client
        .attach_execution(with_machine(AttachExecutionRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: execution_id.to_owned(),
            stdout_offset,
            stderr_offset: 0,
        }))
        .await
        .context("AttachExecution failed")?
        .into_inner())
}

/// Attaches from offset 0 and drains stdout until the execution exits.
async fn collect_output(
    client: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
    execution_id: &str,
) -> Result<(String, Execution)> {
    let mut stream = attach(client, sandbox_id, execution_id, 0).await?;
    let mut stdout = String::new();
    while let Some(event) = stream.message().await.context("attach stream error")? {
        match event.event {
            Some(execution_event::Event::Output(output)) => {
                if output.channel() != StdioChannel::Stderr {
                    stdout.push_str(&String::from_utf8_lossy(&output.data));
                }
            }
            Some(execution_event::Event::Exited(done)) => {
                let execution = done
                    .execution
                    .context("exit event without an execution state")?;
                return Ok((stdout, execution));
            }
            _ => {}
        }
    }
    bail!("attach stream ended without an exit event")
}

/// Runs a command via the execution API and returns stdout, asserting a
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

    let (stdout, done) = collect_output(client, id, &execution.id).await?;
    match done.exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Code(0)) => Ok(stdout),
        other => bail!("command {cmd:?} exit status {other:?}: {stdout:?}"),
    }
}

async fn write_file(
    client: &mut SandboxFilesystemServiceClient<Channel>,
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
    client: &mut SandboxFilesystemServiceClient<Channel>,
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
