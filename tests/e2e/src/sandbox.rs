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
use arcbox_grpc::sandbox_v1::template_service_client::TemplateServiceClient;
use arcbox_protocol::sandbox_v1::{
    AttachExecutionRequest, BuildTemplateRequest, CheckpointRequest, CommandProbe,
    CreateSandboxRequest, DeleteSnapshotRequest, DeleteTemplateRequest, Execution, ExecutionEvent,
    ExecutionState, ExposePortRequest, FileChunk, FileKind, FsEventKind, GetCapabilitiesRequest,
    GetStdinStatusRequest, GetTemplateRequest, IdleAction, InspectSandboxRequest, ListDirRequest,
    ListExecutionsRequest, ListExposedPortsRequest, ListSandboxesRequest, ListSnapshotsRequest,
    ListTemplatesRequest, MakeDirRequest, Mount, MoveEntryRequest, PauseSandboxRequest,
    PublishTemplateRequest, ReadFileRequest, ReadyProbe, RemoveEntryRequest, RemoveSandboxRequest,
    ResizeExecutionTtyRequest, ResourceLimits, RestoreRequest, ResumeSandboxRequest,
    SandboxEventKind, SandboxEventsRequest, SandboxState, SetLifecycleRequest, Signal,
    SignalExecutionRequest, StartExecutionRequest, StatFileRequest, StdioChannel,
    StopSandboxRequest, TemplateDefaults, TerminalSize, UnexposePortRequest, WaitExecutionRequest,
    WaitForPortRequest, WatchDirRequest, WatchEventsResponse, WriteFileOpen, WriteFileRequest,
    WriteStdinRequest, build_template_request, execution_event, exit_status, ready_probe,
    watch_dir_response, watch_events_response, write_file_request,
};
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use crate::metrics::RunMetrics;
use crate::{env_flag, repo_root};

/// Generous ceiling for daemon startup: asset staging + the cold
/// ~255 MiB runtime-binary download into the isolated data dir (dockerd,
/// containerd, k3s, FEX, ...) + the guest runtime materialization added in
/// v0.8 + VM boot + agent. Measured 2026-08-06: a constrained uplink put
/// the download alone at ~180 s.
const READY_TIMEOUT: Duration = Duration::from_secs(360);
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
        "cargo build --release -p arcbox-agent -p arcbox-vm-agent --bins --target aarch64-unknown-linux-musl"
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
    let mut templates = TemplateServiceClient::new(channel.clone());
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

    // -- CORE-107: the template catalog end-to-end -------------------------
    template_catalog_scenario(
        &mut sandboxes,
        &mut processes,
        &mut files,
        &mut snapshots,
        &mut templates,
        metrics,
    )
    .await?;

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

    // -- CORE-62: filesystem verbs + WatchDir ------------------------------
    let verbs_started = Instant::now();
    file_verbs_scenario(&mut files).await?;
    metrics.record("sandbox_file_verbs", verbs_started.elapsed().as_secs_f64());

    // -- CORE-58 phase 2: ListExecutions + WaitForPort ---------------------
    let process_started = Instant::now();
    process_plane_scenario(&mut sandboxes, &mut processes).await?;
    metrics.record(
        "sandbox_process_plane",
        process_started.elapsed().as_secs_f64(),
    );

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

    // -- CORE-8: TTY size + resize + non-default user ----------------------
    let tty_started = Instant::now();
    exec_tty_and_user_scenario(&mut processes, "smoke1").await?;
    metrics.record("sandbox_exec_tty_user", tty_started.elapsed().as_secs_f64());
    wait_ready(&mut sandboxes, "smoke1").await?;

    // -- CORE-11/12: rejection contracts on the lifecycle surface ----------
    let rejection_started = Instant::now();
    create_rejection_scenario(&mut sandboxes, &mut processes, "smoke1").await?;
    metrics.record(
        "sandbox_rejections",
        rejection_started.elapsed().as_secs_f64(),
    );

    // -- CORE-2/19/20: expose → unexpose, then caller-less TTL teardown ----
    let cleanup_started = Instant::now();
    expose_cleanup_scenario(&mut sandboxes).await?;
    metrics.record(
        "sandbox_expose_cleanup",
        cleanup_started.elapsed().as_secs_f64(),
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

/// CORE-107 acceptance: the template catalog end-to-end.
///
/// Covers all three Build sources — a Dockerfile built in-guest (publish →
/// create by bare name, with the template's default cmd/env observable from
/// inside the guest), a checkpoint promotion (whose create must restore the
/// checkpoint's MEMORY image), and a docker ref with `prewarm` (whose
/// creates must share one boot) — plus both ready-probe outcomes and
/// deletion down to an empty catalog.
///
/// Warm-vs-cold discriminators, chosen because a warm-restore failure
/// silently falls back to a cold boot that also reaches READY:
/// - `/run` is tmpfs in the sandbox guest (`vm-agent` mount table), so a
///   marker written there exists only in guest memory. The sandbox created
///   from the promoted template can carry it only by restoring the
///   checkpoint's memory image — a cold boot from the template rootfs
///   (which does carry the checkpoint's DISK state) loses it.
/// - The boot-time `/etc/resolv.conf` write (into the `/run` tmpfs) carries
///   a nanosecond mtime minted once in the prewarm BUILDER, so two creates
///   report the SAME stamp iff both restored the builder's memory image;
///   cold boots each write their own. NOT `boot_id`: the kernel mints
///   `/proc/sys/kernel/random/boot_id` lazily on first read, which nothing
///   in the cmd-less builder ever did, so every restored clone would mint
///   a fresh one and read as a cold boot.
async fn template_catalog_scenario(
    sandboxes: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    files: &mut SandboxFilesystemServiceClient<Channel>,
    snapshots: &mut SandboxSnapshotServiceClient<Channel>,
    templates: &mut TemplateServiceClient<Channel>,
    metrics: &mut RunMetrics,
) -> Result<()> {
    let image = std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
    let geometry = ResourceLimits {
        vcpus: 1,
        memory_mib: 256,
    };

    // -- Build (Dockerfile source) -----------------------------------------
    // The base image is already in the guest docker store (pulled by the
    // docker-template phase), so the in-guest build needs no registry.
    let build_started = Instant::now();
    let dockerfile = format!("FROM {image}\nRUN echo dockerfile-built > /template-mark\n");
    let draft = templates
        .build(with_machine(BuildTemplateRequest {
            name: "smoke-web".into(),
            source: Some(build_template_request::Source::Dockerfile(dockerfile)),
            defaults: Some(TemplateDefaults {
                limits: Some(geometry),
                cmd: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo \"$SMOKE_TEMPLATE_ENV\" > /run/tpl-env".into(),
                ],
                env: [("SMOKE_TEMPLATE_ENV".to_owned(), "from-template".to_owned())].into(),
                ..Default::default()
            }),
            labels: [("suite".to_owned(), "smoke".to_owned())].into(),
            ..Default::default()
        }))
        .await
        .context("template Build (dockerfile) failed")?
        .into_inner();
    if !draft.version.is_empty() || draft.digest.is_empty() {
        bail!(
            "Build must register a digested draft, got version={:?} digest={:?}",
            draft.version,
            draft.digest
        );
    }
    metrics.record("template_build", build_started.elapsed().as_secs_f64());
    info!(digest = %draft.digest, "template draft built from a Dockerfile in-guest");

    // -- Publish -----------------------------------------------------------
    let publish_started = Instant::now();
    let published = templates
        .publish(with_machine(PublishTemplateRequest {
            name: "smoke-web".into(),
            version: "1.0".into(),
        }))
        .await
        .context("template Publish failed")?
        .into_inner();
    if published.version != "1.0" || published.digest != draft.digest {
        bail!(
            "Publish must freeze the draft digest as 1.0, got version={:?} digest={:?}",
            published.version,
            published.digest
        );
    }
    metrics.record("template_publish", publish_started.elapsed().as_secs_f64());

    // -- Create by bare name; defaults observable in the guest -------------
    let create_started = Instant::now();
    let got = templates
        .get(with_machine(GetTemplateRequest {
            reference: "smoke-web".into(),
        }))
        .await
        .context("template Get failed")?
        .into_inner();
    if got.version != "1.0" {
        bail!(
            "bare-name Get must resolve the published version, got {:?}",
            got.version
        );
    }
    sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-tpl".into(),
            template: "smoke-web".into(),
            // No limits and no cmd: both must come from the template.
            ..Default::default()
        }))
        .await
        .context("Create from the published template failed")?;
    wait_for_state(
        sandboxes,
        "smoke-tpl",
        SandboxState::Ready,
        SANDBOX_READY_TIMEOUT,
    )
    .await?;
    // The template's default cmd (running under its default env) may still
    // be racing the readiness flip; poll for its artifact.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = run_and_collect(
            processes,
            "smoke-tpl",
            &[
                "/bin/sh",
                "-c",
                "cat /run/tpl-env 2>/dev/null; cat /template-mark",
            ],
        )
        .await?;
        if out.contains("from-template") && out.contains("dockerfile-built") {
            break;
        }
        if Instant::now() > deadline {
            bail!("template defaults not observable in the guest: {out:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    metrics.record("template_create", create_started.elapsed().as_secs_f64());
    info!("bare-name create resolved the published version and applied its default cmd + env");

    // A miss must classify as the TEMPLATE_NOT_FOUND surface, not a
    // generic failure.
    match sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-tpl-missing".into(),
            template: "smoke-no-such".into(),
            ..Default::default()
        }))
        .await
    {
        Ok(_) => bail!("Create from a missing template must fail"),
        Err(status) => {
            if status.code() != tonic::Code::NotFound
                || !status.message().contains("template not found")
            {
                bail!("missing template must be NotFound/'template not found', got {status:?}");
            }
        }
    }

    // -- Promotion → warm restore ------------------------------------------
    let promote_started = Instant::now();
    run_and_collect(
        processes,
        "smoke-tpl",
        &["/bin/sh", "-c", "echo warm > /run/smoke-warm-marker"],
    )
    .await?;
    wait_ready(sandboxes, "smoke-tpl").await?;
    let snapshot_id = snapshots
        .checkpoint(with_machine(CheckpointRequest {
            sandbox_id: "smoke-tpl".into(),
            name: "template-source".into(),
            ..Default::default()
        }))
        .await
        .context("Checkpoint for promotion failed")?
        .into_inner()
        .snapshot_id;
    let warm_tpl = templates
        .build(with_machine(BuildTemplateRequest {
            name: "smoke-warm".into(),
            source: Some(build_template_request::Source::SnapshotId(
                snapshot_id.clone(),
            )),
            defaults: Some(TemplateDefaults {
                // Must match the checkpoint's geometry (inherited from
                // smoke-web) or the restore is ineligible — which the
                // marker assertion below would catch as a cold boot.
                limits: Some(geometry),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .context("template Build (snapshot promotion) failed")?
        .into_inner();
    if warm_tpl.warm_snapshot_id.is_empty() {
        bail!("promotion must record a warm snapshot");
    }
    if warm_tpl.warm_snapshot_id == snapshot_id {
        bail!("promotion must copy the checkpoint, not alias it");
    }

    // The template-owned snapshot is not a user checkpoint: hidden from
    // the listing and shielded from user deletion while referenced.
    let listed = snapshots
        .list_snapshots(with_machine(ListSnapshotsRequest::default()))
        .await
        .context("ListSnapshots failed")?
        .into_inner();
    let ids: Vec<&str> = listed.snapshots.iter().map(|s| s.id.as_str()).collect();
    if !ids.contains(&snapshot_id.as_str()) {
        bail!("the user checkpoint must stay listed, got {ids:?}");
    }
    if ids.contains(&warm_tpl.warm_snapshot_id.as_str()) {
        bail!("the template-owned snapshot must be hidden from the listing");
    }
    if snapshots
        .delete_snapshot(with_machine(DeleteSnapshotRequest {
            snapshot_id: warm_tpl.warm_snapshot_id.clone(),
        }))
        .await
        .is_ok()
    {
        bail!("deleting a template-owned snapshot must be refused");
    }

    // The source sandbox is no longer needed; the template must outlive it.
    sandboxes
        .remove(with_machine(RemoveSandboxRequest {
            id: "smoke-tpl".into(),
            force: true,
        }))
        .await
        .context("Remove smoke-tpl failed")?;

    sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-warm1".into(),
            template: "smoke-warm".into(),
            ..Default::default()
        }))
        .await
        .context("Create from the promoted template failed")?;
    wait_for_state(
        sandboxes,
        "smoke-warm1",
        SandboxState::Ready,
        SANDBOX_READY_TIMEOUT,
    )
    .await?;
    let marker = run_and_collect(
        processes,
        "smoke-warm1",
        &[
            "/bin/sh",
            "-c",
            "cat /run/smoke-warm-marker 2>/dev/null || echo MISSING",
        ],
    )
    .await?;
    if !marker.contains("warm") || marker.contains("MISSING") {
        bail!(
            "tmpfs marker absent — the create cold-booted instead of restoring \
             the promoted checkpoint's memory image: {marker:?}"
        );
    }
    sandboxes
        .remove(with_machine(RemoveSandboxRequest {
            id: "smoke-warm1".into(),
            force: true,
        }))
        .await
        .context("Remove smoke-warm1 failed")?;
    metrics.record(
        "template_promote_warm",
        promote_started.elapsed().as_secs_f64(),
    );
    info!("promoted template restored the checkpoint's memory image");

    // -- Prewarm at build time ---------------------------------------------
    let prewarm_started = Instant::now();
    let prewarmed = templates
        .build(with_machine(BuildTemplateRequest {
            name: "smoke-prewarm".into(),
            source: Some(build_template_request::Source::DockerRef(image.clone())),
            defaults: Some(TemplateDefaults {
                limits: Some(geometry),
                ..Default::default()
            }),
            prewarm: true,
            ..Default::default()
        }))
        .await
        .context("template Build (prewarm) failed")?
        .into_inner();
    if prewarmed.warm_snapshot_id.is_empty() {
        bail!("a prewarm build must record a warm snapshot");
    }
    // Warm-vs-cold discriminator: the boot-time write of /etc/resolv.conf
    // (a symlink into the /run tmpfs; invariant-network restores never
    // rewrite it) carries a nanosecond mtime minted once in the BUILDER.
    // Both clones restore that memory+tmpfs image, so their stamps are
    // identical; cold boots each write their own. NOT boot_id — the
    // kernel mints /proc/sys/kernel/random/boot_id lazily on first read,
    // which nothing in the cmd-less builder ever did, so every clone
    // would mint a fresh one and read as a cold boot.
    let mut stamps = Vec::new();
    for id in ["smoke-prewarm1", "smoke-prewarm2"] {
        sandboxes
            .create(with_machine(CreateSandboxRequest {
                id: id.into(),
                template: "smoke-prewarm".into(),
                ..Default::default()
            }))
            .await
            .with_context(|| format!("Create {id} from the prewarmed template failed"))?;
        wait_for_state(sandboxes, id, SandboxState::Ready, SANDBOX_READY_TIMEOUT).await?;
        stamps.push(
            run_and_collect(
                processes,
                id,
                &["/bin/stat", "-c", "%y", "/etc/resolv.conf"],
            )
            .await?
            .trim()
            .to_owned(),
        );
        sandboxes
            .remove(with_machine(RemoveSandboxRequest {
                id: id.into(),
                force: true,
            }))
            .await
            .with_context(|| format!("Remove {id} failed"))?;
    }
    // Sub-second precision is what makes stamp equality meaningful; a
    // seconds-only stat would risk a false pass, so fail loudly instead.
    if !stamps[0].contains('.') {
        bail!("resolv.conf stamp has no sub-second precision: {stamps:?}");
    }
    if stamps[0] != stamps[1] {
        bail!(
            "prewarmed creates must share the builder's boot image (memory \
             restore), got distinct resolv.conf stamps {stamps:?}"
        );
    }
    metrics.record("template_prewarm", prewarm_started.elapsed().as_secs_f64());
    info!("both prewarmed creates restored the builder's memory image");

    // -- Ready probes: command form gates READY, port form fails on expiry --
    let probe_started = Instant::now();
    templates
        .build(with_machine(BuildTemplateRequest {
            name: "smoke-probe".into(),
            source: Some(build_template_request::Source::DockerRef(image.clone())),
            defaults: Some(TemplateDefaults {
                limits: Some(geometry),
                cmd: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "sleep 2; touch /run/probe-up; sleep 300".into(),
                ],
                ready_probe: Some(ReadyProbe {
                    timeout_seconds: 60,
                    probe: Some(ready_probe::Probe::Command(CommandProbe {
                        cmd: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            "test -f /run/probe-up".into(),
                        ],
                    })),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .context("template Build (command probe) failed")?;
    // Subscribe BEFORE the create so READY cannot be missed: the gating
    // proof is *when* READY fires, not that a ready state is eventually
    // reached — the cmd claims the workload slot the moment it starts,
    // so a state poll observes Running whether or not the probe gated
    // anything.
    let mut probe_events = sandboxes
        .events(with_machine(SandboxEventsRequest {
            sandbox_id: "smoke-probe1".into(),
            ..Default::default()
        }))
        .await
        .context("probe events subscribe failed")?
        .into_inner();
    sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-probe1".into(),
            template: "smoke-probe".into(),
            ..Default::default()
        }))
        .await
        .context("Create with a command probe failed")?;
    next_event(
        &mut probe_events,
        SandboxEventKind::Ready,
        None,
        SANDBOX_READY_TIMEOUT,
    )
    .await?;
    // At the instant READY was delivered the probe must already have
    // passed: the marker its command requires appears ~2 s into the
    // default cmd, so a build that dropped probe gating fires READY
    // before the marker exists and this read fails. File reads ride the
    // vsock file channel, not the (busy) workload slot.
    read_file(files, "smoke-probe1", "/run/probe-up")
        .await
        .context("READY fired before the ready probe passed (/run/probe-up missing)")?;
    // The cmd keeps running, so the settled state is Running.
    wait_for_state(
        sandboxes,
        "smoke-probe1",
        SandboxState::Running,
        SANDBOX_READY_TIMEOUT,
    )
    .await?;
    sandboxes
        .remove(with_machine(RemoveSandboxRequest {
            id: "smoke-probe1".into(),
            force: true,
        }))
        .await
        .context("Remove smoke-probe1 failed")?;

    templates
        .build(with_machine(BuildTemplateRequest {
            name: "smoke-probe-fail".into(),
            source: Some(build_template_request::Source::DockerRef(image.clone())),
            defaults: Some(TemplateDefaults {
                limits: Some(geometry),
                cmd: vec!["/bin/sh".into(), "-c".into(), "sleep 300".into()],
                ready_probe: Some(ReadyProbe {
                    timeout_seconds: 5,
                    // Nothing ever listens here.
                    probe: Some(ready_probe::Probe::Port(59999)),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .context("template Build (port probe) failed")?;
    sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-probe-fail1".into(),
            template: "smoke-probe-fail".into(),
            ..Default::default()
        }))
        .await
        .context("Create with a doomed port probe failed")?;
    wait_for_state(
        sandboxes,
        "smoke-probe-fail1",
        SandboxState::Failed,
        SANDBOX_READY_TIMEOUT,
    )
    .await?;
    sandboxes
        .remove(with_machine(RemoveSandboxRequest {
            id: "smoke-probe-fail1".into(),
            force: true,
        }))
        .await
        .context("Remove smoke-probe-fail1 failed")?;
    metrics.record("template_probe", probe_started.elapsed().as_secs_f64());
    info!("command probe gated READY; port probe expiry transitioned FAILED");

    // -- Delete down to an empty catalog -----------------------------------
    let delete_started = Instant::now();
    for name in [
        "smoke-web",
        "smoke-warm",
        "smoke-prewarm",
        "smoke-probe",
        "smoke-probe-fail",
    ] {
        templates
            .delete(with_machine(DeleteTemplateRequest {
                reference: name.into(),
            }))
            .await
            .with_context(|| format!("template Delete {name} failed"))?;
    }
    let listed = templates
        .list(with_machine(ListTemplatesRequest::default()))
        .await
        .context("template List after delete failed")?
        .into_inner();
    if !listed.templates.is_empty() {
        bail!(
            "the catalog must be empty after the deletes, got {} rows",
            listed.templates.len()
        );
    }
    // With the referencing template gone, the user checkpoint deletes
    // normally.
    snapshots
        .delete_snapshot(with_machine(DeleteSnapshotRequest { snapshot_id }))
        .await
        .context("deleting the user checkpoint after the template delete failed")?;
    metrics.record("template_delete", delete_started.elapsed().as_secs_f64());

    info!("template catalog scenario passed");
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
        "list_exposed_ports",
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
    next_event(
        &mut events,
        SandboxEventKind::Pausing,
        Some("idle_timeout"),
        EVENT_TIMEOUT,
    )
    .await?;
    next_event(&mut events, SandboxEventKind::Paused, None, EVENT_TIMEOUT).await?;
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
    next_event(
        &mut events,
        SandboxEventKind::Resumed,
        Some("auto_resume"),
        EVENT_TIMEOUT,
    )
    .await?;

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

/// CORE-19/20 acceptance: host resources a sandbox owns are released by the
/// daemon's cleanup watcher when the guest reaps the sandbox with no
/// daemon-side caller involved. TTL expiry is deliberately the trigger —
/// it is the teardown path where nobody is around to clean up: the reap
/// happens inside the guest, the cleanup ticket rides the always-open
/// `WatchSandboxCleanup` stream, and the daemon must drop its expose
/// listener on its own. DNS deregistration rides the same ticket arm
/// (`connect/sandbox_cleanup.rs::complete`) and is covered by runtime unit
/// tests; the host listener is the half observable from outside the daemon.
async fn expose_cleanup_scenario(sandboxes: &mut SandboxServiceClient<Channel>) -> Result<()> {
    const ID: &str = "smoke-cleanup";

    sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: ID.into(),
            limits: Some(ResourceLimits {
                vcpus: 1,
                memory_mib: 256,
            }),
            ..Default::default()
        }))
        .await
        .context("Create smoke-cleanup failed")?;
    wait_for_state(sandboxes, ID, SandboxState::Ready, SANDBOX_READY_TIMEOUT).await?;

    // First the caller-driven path: expose, prove the listener, unexpose,
    // prove it is gone. This is the half a client controls explicitly.
    let first_port = expose_and_assert(sandboxes, ID, 8080).await?;
    sandboxes
        .unexpose_port(with_machine(UnexposePortRequest {
            id: ID.into(),
            sandbox_port: 8080,
            ..Default::default()
        }))
        .await
        .context("UnexposePort failed")?;
    if tokio::net::TcpStream::connect(("127.0.0.1", first_port))
        .await
        .is_ok()
    {
        bail!("host listener 127.0.0.1:{first_port} still accepting after UnexposePort");
    }
    // Refusing connections is not the same as releasing the port: a listener
    // shut down but never closed rejects connects while still holding the
    // bind. Re-binding is what proves the resource is actually gone.
    std::net::TcpListener::bind(("127.0.0.1", first_port))
        .with_context(|| format!("host port {first_port} still bound after UnexposePort"))?;
    let listed = sandboxes
        .list_exposed_ports(with_machine(ListExposedPortsRequest { id: ID.into() }))
        .await
        .context("ListExposedPorts after unexpose failed")?
        .into_inner();
    if !listed.ports.is_empty() {
        bail!("UnexposePort left mappings behind: {listed:?}");
    }
    info!(host_port = first_port, "UnexposePort released the listener");

    // Then the caller-less path: a fresh exposure the guest's TTL reap must
    // clean up on its own.
    let host_port = expose_and_assert(sandboxes, ID, 8081).await?;

    sandboxes
        .set_lifecycle(with_machine(SetLifecycleRequest {
            id: ID.into(),
            ttl_seconds: Some(1),
            ..Default::default()
        }))
        .await
        .context("SetLifecycle (ttl) failed")?;

    // The guest reaps the sandbox first...
    let reap_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match sandboxes
            .inspect(with_machine(InspectSandboxRequest { id: ID.into() }))
            .await
        {
            Err(status) if status.code() == tonic::Code::NotFound => break,
            Ok(_) | Err(_) if Instant::now() < reap_deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok(info) => bail!(
                "sandbox never TTL-reaped (state: {:?})",
                info.into_inner().state()
            ),
            Err(status) => bail!("Inspect failed while waiting for the TTL reap: {status}"),
        }
    }
    // ...then the cleanup ticket must release the host listener. Re-binding
    // the port from this process is the strongest observable: a closed but
    // still-bound listener fails it, and so does any leaked forwarder. A
    // fresh budget — the reap wait above must not eat the cleanup window.
    let release_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match std::net::TcpListener::bind(("127.0.0.1", host_port)) {
            Ok(_) => break,
            Err(_) if Instant::now() < release_deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => {
                bail!("host port {host_port} never released after the TTL reap: {error}")
            }
        }
    }
    info!(host_port, "TTL reap released the host listener");
    Ok(())
}

/// Expose `sandbox_port` on a host port this process reserved, and assert the
/// listener accepts and is listed. Returns the host port.
///
/// The port is reserved by binding `127.0.0.1:0` and dropping the probe
/// rather than passing `host_port: 0`: an omitted host port makes the daemon
/// reuse the guest relay port, and every System VM allocates those from the
/// same 40000+ pool, so two concurrent isolated smoke runs would
/// deterministically collide on the host loopback (the fixed-port isolation
/// rule in tests/e2e/AGENTS.md). The reuse race in the drop-to-expose gap is
/// negligible here.
async fn expose_and_assert(
    sandboxes: &mut SandboxServiceClient<Channel>,
    id: &str,
    sandbox_port: u32,
) -> Result<u16> {
    let host_port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|probe| probe.local_addr())
        .context("reserving an ephemeral host port")?
        .port();
    let exposed = sandboxes
        .expose_port(with_machine(ExposePortRequest {
            id: id.to_owned(),
            sandbox_port,
            host_port: u32::from(host_port),
            ..Default::default()
        }))
        .await
        .context("ExposePort failed")?
        .into_inner();
    if exposed.host_port != u32::from(host_port) {
        bail!(
            "ExposePort bound {} instead of the requested {host_port}",
            exposed.host_port
        );
    }

    // The daemon's loopback listener accepts (the guest side needs no
    // workload behind it for the TCP handshake — accept happens host-side).
    tokio::net::TcpStream::connect(("127.0.0.1", host_port))
        .await
        .with_context(|| format!("host listener 127.0.0.1:{host_port} not accepting"))?;
    let listed = sandboxes
        .list_exposed_ports(with_machine(ListExposedPortsRequest { id: id.to_owned() }))
        .await
        .context("ListExposedPorts failed")?
        .into_inner();
    if !listed
        .ports
        .iter()
        .any(|p| p.sandbox_port == sandbox_port && p.host_port == u32::from(host_port))
    {
        bail!("exposed mapping missing from ListExposedPorts: {listed:?}");
    }
    info!(host_port, sandbox_port, "expose listener live on loopback");
    Ok(host_port)
}

/// CORE-8 acceptance, the TTY half: the initial `tty_size` reaches the guest
/// PTY, `ResizeExecutionTty` changes it mid-session, a resize is refused for
/// an execution that has no PTY, and a non-default `user` is honored.
///
/// `stty size` prints `<rows> <cols>`, read back from inside the guest — the
/// only way to prove the size survived every host layer (the CORE-8 bug was
/// that it was dropped on the way down). Both sizes below must be values no
/// fallback path can produce, or the assertion passes on a dropped field:
/// 80x24 is the default at three independent layers
/// (`sandbox/execution.rs`'s and `sandbox/workload.rs`'s `tty_size.map_or`,
/// and vm-agent's `default_tty_width`/`default_tty_height` serde defaults).
///
/// The user is a numeric uid pair because the default sandbox rootfs ships
/// an `/etc/passwd` with root only; `resolve_user` takes numeric ids without
/// a passwd entry, so this asserts the plumbing without depending on the
/// image's user database.
async fn exec_tty_and_user_scenario(
    processes: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
) -> Result<()> {
    let initial = processes
        .start_execution(with_machine(StartExecutionRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: "tty-initial".into(),
            cmd: vec!["/bin/sh".into(), "-c".into(), "stty size".into()],
            tty: true,
            tty_size: Some(TerminalSize {
                width: 100,
                height: 37,
            }),
            ..Default::default()
        }))
        .await
        .context("StartExecution (tty) failed")?
        .into_inner();
    let (out, done) = collect_output(processes, sandbox_id, &initial.id).await?;
    match done.exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Code(0)) => {}
        other => bail!("tty `stty size` exit status {other:?}: {out:?}"),
    }
    if !out.contains("37 100") {
        bail!("initial tty_size never reached the PTY; `stty size` said {out:?}");
    }
    info!("initial tty_size reached the guest PTY");

    // Resize mid-session against an interactive shell. Stdin bytes and
    // resizes ride one ordered per-session queue, so a resize enqueued
    // before the command bytes is in effect when `stty` runs. The start size
    // is distinct from both the defaults and the resized size, so a failure
    // message says which half broke.
    let shell = processes
        .start_execution(with_machine(StartExecutionRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: "tty-resize".into(),
            cmd: vec!["/bin/sh".into()],
            tty: true,
            tty_size: Some(TerminalSize {
                width: 90,
                height: 30,
            }),
            stdin: true,
            ..Default::default()
        }))
        .await
        .context("StartExecution (tty shell) failed")?
        .into_inner();
    processes
        .resize_execution_tty(with_machine(ResizeExecutionTtyRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: shell.id.clone(),
            size: Some(TerminalSize {
                width: 120,
                height: 50,
            }),
        }))
        .await
        .context("ResizeExecutionTty failed")?;
    // A TTY execution cannot take `eof` (the proto says send Ctrl-D), so the
    // shell is ended with `exit`.
    processes
        .write_stdin(with_machine(WriteStdinRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: shell.id.clone(),
            offset: 0,
            data: b"stty size\nexit\n".to_vec(),
            eof: false,
        }))
        .await
        .context("tty stdin write failed")?;
    let (out, done) = collect_output(processes, sandbox_id, &shell.id).await?;
    match done.exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Code(0)) => {}
        other => bail!("tty shell exit status {other:?}: {out:?}"),
    }
    if !out.contains("50 120") {
        bail!("ResizeExecutionTty did not reach the PTY; `stty size` said {out:?}");
    }
    info!("ResizeExecutionTty resized the live guest PTY");

    // Without a PTY there is nothing to resize; that must be an error rather
    // than a silently dropped request.
    let plain =
        start_execution(processes, sandbox_id, "no-tty-resize", &["/bin/cat"], true).await?;
    let refused = processes
        .resize_execution_tty(with_machine(ResizeExecutionTtyRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: plain.id.clone(),
            size: Some(TerminalSize {
                width: 120,
                height: 50,
            }),
        }))
        .await;
    match refused {
        Err(status) if status.code() == tonic::Code::InvalidArgument => {}
        Err(status) => {
            bail!("resize without a TTY failed with {status:?}, expected InvalidArgument")
        }
        Ok(_) => bail!("resize was accepted for an execution with no TTY"),
    }
    processes
        .write_stdin(with_machine(WriteStdinRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: plain.id.clone(),
            offset: 0,
            data: Vec::new(),
            eof: true,
        }))
        .await
        .context("closing the no-tty execution's stdin")?;
    collect_output(processes, sandbox_id, &plain.id).await?;

    let uid = run_with_user(
        processes,
        sandbox_id,
        "uid-check",
        &["/bin/id", "-u"],
        "65534:65534",
    )
    .await?;
    if uid.trim() != "65534" {
        bail!("`user` was ignored: id -u printed {uid:?}");
    }
    let gid = run_with_user(
        processes,
        sandbox_id,
        "gid-check",
        &["/bin/id", "-g"],
        "65534:65534",
    )
    .await?;
    if gid.trim() != "65534" {
        bail!("the group half of `user` was ignored: id -g printed {gid:?}");
    }
    info!("non-default user and group reached the guest process");
    Ok(())
}

/// Run a command as `user` and return its stdout, asserting a zero exit.
async fn run_with_user(
    client: &mut SandboxProcessServiceClient<Channel>,
    sandbox_id: &str,
    execution_id: &str,
    cmd: &[&str],
    user: &str,
) -> Result<String> {
    let execution = client
        .start_execution(with_machine(StartExecutionRequest {
            sandbox_id: sandbox_id.to_owned(),
            execution_id: execution_id.to_owned(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            user: user.to_owned(),
            ..Default::default()
        }))
        .await
        .with_context(|| format!("StartExecution as {user} failed"))?
        .into_inner();
    let (stdout, done) = collect_output(client, sandbox_id, &execution.id).await?;
    match done.exit_status.as_ref().and_then(|s| s.status) {
        Some(exit_status::Status::Code(0)) => Ok(stdout),
        other => bail!("{cmd:?} as {user} exit status {other:?}: {stdout:?}"),
    }
}

/// The rejection contracts a client can hit on the lifecycle surface:
/// declared-but-unimplemented spec fields (CORE-11/12), a reused sandbox id,
/// and addressing a sandbox that does not exist. Each is a documented status
/// code, and each is asserted here because the guest enforces them far from
/// the daemon boundary where a refactor could silently turn one into a
/// generic INTERNAL — or, worse, into a success that ignores the field.
async fn create_rejection_scenario(
    sandboxes: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
    live_id: &str,
) -> Result<()> {
    let base = || CreateSandboxRequest {
        limits: Some(ResourceLimits {
            vcpus: 1,
            memory_mib: 256,
        }),
        ..Default::default()
    };

    // `mounts` and `ssh_public_key` are still live proto fields (unlike the
    // reserved `image`/`kernel`/`rootfs`), documented as FAILED_PRECONDITION.
    let mounted = sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-reject-mounts".into(),
            mounts: vec![Mount {
                source: "/tmp".into(),
                target: "/host-tmp".into(),
                readonly: true,
            }],
            ..base()
        }))
        .await;
    match mounted {
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {}
        Err(status) => bail!("mounts rejected with {status:?}, expected FailedPrecondition"),
        Ok(_) => bail!("a create with mounts was accepted"),
    }

    let keyed = sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: "smoke-reject-ssh".into(),
            ssh_public_key: Some("ssh-ed25519 AAAA test".into()),
            ..base()
        }))
        .await;
    match keyed {
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {}
        Err(status) => {
            bail!("ssh_public_key rejected with {status:?}, expected FailedPrecondition")
        }
        Ok(_) => bail!("a create with ssh_public_key was accepted"),
    }

    // A live id reused for a *different* request is a collision, not an
    // idempotent replay — the retry-safety contract cuts both ways.
    let collided = sandboxes
        .create(with_machine(CreateSandboxRequest {
            id: live_id.to_owned(),
            cmd: vec!["/bin/false".into()],
            ..base()
        }))
        .await;
    match collided {
        Err(status) if status.code() == tonic::Code::AlreadyExists => {}
        Err(status) => bail!("id reuse rejected with {status:?}, expected AlreadyExists"),
        Ok(_) => bail!("a differing create reused an existing sandbox id"),
    }

    let missing = processes
        .start_execution(with_machine(StartExecutionRequest {
            sandbox_id: "smoke-does-not-exist".into(),
            cmd: vec!["/bin/true".into()],
            ..Default::default()
        }))
        .await;
    match missing {
        Err(status) if status.code() == tonic::Code::NotFound => {}
        Err(status) => bail!("exec on a missing sandbox failed with {status:?}, expected NotFound"),
        Ok(_) => bail!("an execution started in a sandbox that does not exist"),
    }
    info!("field, id-reuse, and missing-sandbox rejections all carry their documented codes");
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
    next_event(
        &mut events,
        SandboxEventKind::Pausing,
        Some("pause"),
        EVENT_TIMEOUT,
    )
    .await?;
    next_event(&mut events, SandboxEventKind::Paused, None, EVENT_TIMEOUT).await?;
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
    next_event(
        &mut events,
        SandboxEventKind::Resumed,
        Some("auto_resume"),
        EVENT_TIMEOUT,
    )
    .await?;
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
    next_event(&mut events, SandboxEventKind::Paused, None, EVENT_TIMEOUT).await?;
    sandboxes
        .resume(with_machine(ResumeSandboxRequest {
            id: "smoke1".into(),
        }))
        .await
        .context("Resume failed")?;
    next_event(
        &mut events,
        SandboxEventKind::Resumed,
        Some("resume"),
        EVENT_TIMEOUT,
    )
    .await?;
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

/// Post-boot event waits: pause/resume/idle edges on an already-booted
/// sandbox, where a minute is generous. Waits that span a boot pass their
/// own budget.
const EVENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Scans the events stream (skipping keepalives and unrelated kinds) until
/// `kind` arrives, asserting its "reason" attribute when specified.
async fn next_event(
    stream: &mut tonic::Streaming<WatchEventsResponse>,
    kind: SandboxEventKind,
    reason: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
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

/// CORE-62 acceptance: the filesystem verbs round-trip against a live
/// sandbox — mkdir -p semantics, symlink-free stat metadata, a full
/// listing, rename, the non-empty-remove guard — and a recursive WatchDir
/// opened before the mutations reports them as events (with keepalives
/// interleaved) until the client cancels it.
async fn file_verbs_scenario(files: &mut SandboxFilesystemServiceClient<Channel>) -> Result<()> {
    let make_dir = MakeDirRequest {
        id: "smoke1".into(),
        path: "/tmp/verbs/nested".into(),
        mode: 0,
    };
    files
        .make_dir(with_machine(make_dir.clone()))
        .await
        .context("MakeDir failed")?;
    // `mkdir -p` semantics: an existing directory succeeds.
    files
        .make_dir(with_machine(make_dir))
        .await
        .context("MakeDir on an existing directory failed")?;

    let stat = files
        .stat(with_machine(StatFileRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs/nested".into(),
        }))
        .await
        .context("Stat directory failed")?
        .into_inner();
    if stat.kind() != FileKind::Directory {
        bail!("expected a directory, got {:?}", stat.kind());
    }

    // Open the watch BEFORE mutating, so the mutations below are events.
    let mut watch = files
        .watch_dir(with_machine(WatchDirRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs".into(),
            recursive: true,
        }))
        .await
        .context("WatchDir failed")?
        .into_inner();

    let payload = b"file-verbs payload".to_vec();
    write_file(files, "smoke1", "/tmp/verbs/nested/a.bin", &payload).await?;

    let stat = files
        .stat(with_machine(StatFileRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs/nested/a.bin".into(),
        }))
        .await
        .context("Stat file failed")?
        .into_inner();
    if stat.kind() != FileKind::File || stat.size != payload.len() as u64 {
        bail!("unexpected file stat: {stat:?}");
    }
    if stat.mode != 0o644 {
        bail!("expected default 0644 mode, got {:o}", stat.mode);
    }
    if stat.name != "a.bin" {
        bail!("expected base name a.bin, got {:?}", stat.name);
    }

    let listing = files
        .list_dir(with_machine(ListDirRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs/nested".into(),
        }))
        .await
        .context("ListDir failed")?
        .into_inner();
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    if names != ["a.bin"] {
        bail!("unexpected listing: {names:?}");
    }

    files
        .r#move(with_machine(MoveEntryRequest {
            id: "smoke1".into(),
            from_path: "/tmp/verbs/nested/a.bin".into(),
            to_path: "/tmp/verbs/nested/b.bin".into(),
        }))
        .await
        .context("Move failed")?;

    // The old path is gone — and carries the FILE_NOT_FOUND classification's
    // transport code (NOT_FOUND).
    let err = files
        .stat(with_machine(StatFileRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs/nested/a.bin".into(),
        }))
        .await
        .err()
        .context("Stat of the moved-away path unexpectedly succeeded")?;
    if err.code() != tonic::Code::NotFound {
        bail!("expected NOT_FOUND for the old path, got {err:?}");
    }
    let back = read_file(files, "smoke1", "/tmp/verbs/nested/b.bin").await?;
    if back != payload {
        bail!("moved file content mismatch");
    }

    // The watch saw the mutations: drain until both the file's creation and
    // the rename appear (keepalives and intermediate events are skipped).
    let deadline = Instant::now() + Duration::from_secs(30);
    let (mut saw_created, mut saw_renamed, mut saw_keepalive) = (false, false, false);
    while !(saw_created && saw_renamed) {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("WatchDir events did not arrive within 30s")?;
        let frame = tokio::time::timeout(remaining, watch.message())
            .await
            .context("WatchDir stream stalled")?
            .context("WatchDir stream error")?
            .context("WatchDir stream ended before the expected events")?;
        match frame.payload {
            Some(watch_dir_response::Payload::Event(event)) => {
                info!(kind = ?event.kind(), path = %event.path, renamed_to = %event.renamed_to,
                      "watch event");
                if event.path == "/tmp/verbs/nested/a.bin"
                    && matches!(event.kind(), FsEventKind::Created | FsEventKind::Modified)
                {
                    saw_created = true;
                }
                if event.kind() == FsEventKind::Renamed
                    && event.path == "/tmp/verbs/nested/a.bin"
                    && event.renamed_to == "/tmp/verbs/nested/b.bin"
                {
                    saw_renamed = true;
                }
            }
            Some(watch_dir_response::Payload::KeepAlive(_)) => saw_keepalive = true,
            None => {}
        }
    }
    if !saw_keepalive {
        bail!("WatchDir never interleaved a keepalive frame");
    }
    // Client-side cancellation: dropping the stream tears the watch down.
    drop(watch);

    // A non-empty directory refuses a non-recursive remove...
    let err = files
        .remove(with_machine(RemoveEntryRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs".into(),
            recursive: false,
        }))
        .await
        .err()
        .context("non-recursive Remove of a non-empty directory succeeded")?;
    if err.code() != tonic::Code::FailedPrecondition {
        bail!("expected FAILED_PRECONDITION, got {err:?}");
    }
    // ...and a recursive one takes the tree out.
    files
        .remove(with_machine(RemoveEntryRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs".into(),
            recursive: true,
        }))
        .await
        .context("recursive Remove failed")?;
    let err = files
        .stat(with_machine(StatFileRequest {
            id: "smoke1".into(),
            path: "/tmp/verbs".into(),
        }))
        .await
        .err()
        .context("Stat of the removed tree unexpectedly succeeded")?;
    if err.code() != tonic::Code::NotFound {
        bail!("expected NOT_FOUND after the recursive remove, got {err:?}");
    }

    info!("filesystem verbs + WatchDir verified");
    Ok(())
}

/// CORE-58 phase 2 acceptance: WaitForPort fails fast with
/// DEADLINE_EXCEEDED while nothing listens, flips once a workload binds
/// the port (the guest watches its own listen table — no client polling),
/// and ListExecutions rediscovers the listener both while it runs and
/// after it exits.
async fn process_plane_scenario(
    sandboxes: &mut SandboxServiceClient<Channel>,
    processes: &mut SandboxProcessServiceClient<Channel>,
) -> Result<()> {
    const PORT: u32 = 23456;

    // The listener below needs busybox `nc`; fail with a clear message if
    // the rootfs busybox was built without it.
    let nc_probe = run_and_collect(processes, "smoke1", &["/bin/sh", "-c", "command -v nc"]).await;
    if nc_probe.is_err() {
        bail!("the sandbox rootfs busybox has no `nc` applet; the WaitForPort phase needs one");
    }
    wait_ready(sandboxes, "smoke1").await?;

    // No listener: a 1 s budget elapses as DEADLINE_EXCEEDED.
    let err = processes
        .wait_for_port(with_machine(WaitForPortRequest {
            sandbox_id: "smoke1".into(),
            port: PORT,
            timeout_seconds: 1,
        }))
        .await
        .err()
        .context("WaitForPort succeeded with nothing listening")?;
    if err.code() != tonic::Code::DeadlineExceeded {
        bail!("expected DEADLINE_EXCEEDED, got {err:?}");
    }

    // Start a listener, then wait for the port to come up.
    let listener = start_execution(
        processes,
        "smoke1",
        "port-listener",
        &["/bin/sh", "-c", "exec nc -l -p 23456 >/dev/null"],
        false,
    )
    .await?;
    processes
        .wait_for_port(with_machine(WaitForPortRequest {
            sandbox_id: "smoke1".into(),
            port: PORT,
            timeout_seconds: 30,
        }))
        .await
        .context("WaitForPort did not observe the listener")?;

    // ListExecutions rediscovers the running listener by id.
    let listing = processes
        .list_executions(with_machine(ListExecutionsRequest {
            sandbox_id: "smoke1".into(),
        }))
        .await
        .context("ListExecutions failed")?
        .into_inner();
    let found = listing
        .executions
        .iter()
        .find(|e| e.id == listener.id)
        .context("listener missing from ListExecutions")?;
    if found.state() != ExecutionState::Running {
        bail!("expected the listener RUNNING, got {:?}", found.state());
    }

    // Tear the listener down and confirm the exited record stays listed.
    processes
        .signal_execution(with_machine(SignalExecutionRequest {
            sandbox_id: "smoke1".into(),
            execution_id: listener.id.clone(),
            signal: Signal::Sigkill.into(),
        }))
        .await
        .context("SignalExecution failed")?;
    let done = processes
        .wait_execution(with_machine(WaitExecutionRequest {
            sandbox_id: "smoke1".into(),
            execution_id: listener.id.clone(),
            timeout_seconds: 30,
        }))
        .await
        .context("WaitExecution failed")?
        .into_inner();
    if done.state() != ExecutionState::Exited {
        bail!("listener did not exit after SIGKILL: {done:?}");
    }
    let listing = processes
        .list_executions(with_machine(ListExecutionsRequest {
            sandbox_id: "smoke1".into(),
        }))
        .await
        .context("ListExecutions (after exit) failed")?
        .into_inner();
    let found = listing
        .executions
        .iter()
        .find(|e| e.id == listener.id)
        .context("exited listener missing from ListExecutions")?;
    if found.state() != ExecutionState::Exited {
        bail!("expected the listener EXITED, got {:?}", found.state());
    }

    wait_ready(sandboxes, "smoke1").await?;
    info!("ListExecutions + WaitForPort verified");
    Ok(())
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
