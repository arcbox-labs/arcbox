//! Machine lifecycle e2e: the first real end-to-end exercise of the distro
//! machine path through a live VZ daemon.
//!
//! create (pulls the alpine image from the live `image.arcboxcdn.com/linux`
//! mirror) → start (boot shim → overlay → distro init; readiness = agent
//! ping + routable IP) → inspect → system info → piped exec → interactive
//! PTY session → per-machine stats → graceful stop → remove.
//!
//! Requirements beyond the usual daemon e2e setup: boot assets ≥ 0.6.4 (the
//! first bundle carrying `/sbin/arcbox-machine-init` and a squashfs-capable
//! kernel). Until `assets.lock` points there, run with
//! `ARCBOX_BOOT_ASSET_VERSION=0.6.4`.

use std::sync::Once;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_grpc::v1::machine_service_client::MachineServiceClient;
use arcbox_grpc::v1::stats_service_client::StatsServiceClient;
use arcbox_protocol::v1::{
    CreateMachineRequest, InspectMachineRequest, ListMachinesRequest, MachineAgentRequest,
    MachineExecInput, MachineExecRequest, RemoveMachineRequest, StartMachineRequest,
    StatsWatchRequest, StopMachineRequest, TerminalSize, machine_exec_input,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Budget for create: a cold image pull from the live CDN (~4 MB alpine)
/// plus registry staging.
const CREATE_BUDGET: Duration = Duration::from_secs(120);
/// Budget for start: shim boot, overlay staging, distro init, agent
/// readiness, DHCP.
const START_BUDGET: Duration = Duration::from_secs(120);
/// Budget for one RPC against a running machine.
const RPC_BUDGET: Duration = Duration::from_secs(30);

const MACHINE: &str = "e2e-alpine";

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
#[ignore = "boots a real VZ daemon, pulls a distro image from the live CDN, and drives a machine end to end"]
fn machine_lifecycle_end_to_end() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
        // The machine agent must speak MachineExec*; build it fresh.
        xshell::cmd!(
            shell,
            "cargo build --release -p arcbox-agent --target aarch64-unknown-linux-musl"
        )
        .run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-machine-e2e-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            ("ARCBOX_DNS_PORT".to_owned(), "0".to_owned()),
        ],
    })?;

    let mut metrics = RunMetrics::new("machine_lifecycle", Some("vz"));
    let result = scenario(&mut daemon, &mut metrics);
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

fn scenario(daemon: &mut DaemonHandle, metrics: &mut RunMetrics) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
    let socket = daemon.grpc_socket();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(async {
        let channel = connect_unix(&socket).await?;
        let mut machines = MachineServiceClient::new(channel.clone());

        // Create: pulls alpine from the live mirror and registers the
        // machine with the boot shim contract.
        tokio::time::timeout(
            CREATE_BUDGET,
            machines.create(CreateMachineRequest {
                name: MACHINE.to_owned(),
                cpus: 1,
                memory: 1024 * 1024 * 1024,
                disk_size: 2 * 1024 * 1024 * 1024,
                distro: "alpine".to_owned(),
                ..Default::default()
            }),
        )
        .await
        .context("create timed out (CDN pull)")?
        .context("create failed")?;

        // Start blocks until the agent is reachable and reports a routable
        // IP — the whole shim → overlay → distro-init chain must work.
        tokio::time::timeout(
            START_BUDGET,
            machines.start(StartMachineRequest {
                id: MACHINE.to_owned(),
            }),
        )
        .await
        .context("start timed out")?
        .context("start failed")?;

        // Inspect: running, addressed, timestamped.
        let info = machines
            .inspect(InspectMachineRequest {
                id: MACHINE.to_owned(),
            })
            .await
            .context("inspect failed")?
            .into_inner();
        if info.state != "running" {
            bail!("machine is {:?} after start", info.state);
        }
        let ip = info.network.as_ref().map(|n| n.ip_address.clone());
        let Some(ip) = ip.filter(|ip| !ip.is_empty()) else {
            bail!("machine has no IP after readiness");
        };
        if info.started_at.is_none() {
            bail!("started_at not set after start");
        }
        tracing::info!(%ip, "machine running");

        // System info comes from the agent inside the machine root.
        let sys = tokio::time::timeout(
            RPC_BUDGET,
            machines.get_system_info(MachineAgentRequest {
                id: MACHINE.to_owned(),
            }),
        )
        .await
        .context("system info timed out")?
        .context("system info failed")?
        .into_inner();
        if sys.hostname.is_empty() || sys.total_memory == 0 {
            bail!("implausible system info: {sys:?}");
        }
        if !sys.ip_addresses.contains(&ip) {
            bail!(
                "agent does not report the machine IP {ip}: {:?}",
                sys.ip_addresses
            );
        }

        exec_piped(&mut machines).await?;
        exec_interactive(&mut machines).await?;
        stats_first_frame(channel.clone()).await?;

        // Graceful stop, then remove; the registry must forget the machine.
        machines
            .stop(StopMachineRequest {
                id: MACHINE.to_owned(),
                force: false,
            })
            .await
            .context("stop failed")?;
        let info = machines
            .inspect(InspectMachineRequest {
                id: MACHINE.to_owned(),
            })
            .await
            .context("inspect after stop failed")?
            .into_inner();
        if info.state != "stopped" {
            bail!("machine is {:?} after stop", info.state);
        }

        machines
            .remove(RemoveMachineRequest {
                id: MACHINE.to_owned(),
                force: false,
                volumes: false,
            })
            .await
            .context("remove failed")?;
        let listed = machines
            .list(ListMachinesRequest { all: true })
            .await
            .context("list failed")?
            .into_inner()
            .machines;
        if listed.iter().any(|m| m.name == MACHINE) {
            bail!("machine still listed after remove");
        }
        Ok(())
    })
}

/// Piped exec: separate stdout stream, exit code on the final frame.
async fn exec_piped(machines: &mut MachineServiceClient<Channel>) -> Result<()> {
    let mut stream = tokio::time::timeout(
        RPC_BUDGET,
        machines.exec(MachineExecRequest {
            id: MACHINE.to_owned(),
            cmd: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo machine-exec-ok".to_owned(),
            ],
            ..Default::default()
        }),
    )
    .await
    .context("exec timed out")?
    .context("exec failed")?
    .into_inner();

    let mut stdout = Vec::new();
    let mut exit_code = None;
    while let Some(output) = tokio::time::timeout(RPC_BUDGET, stream.message())
        .await
        .context("exec output timed out")?
        .context("exec stream error")?
    {
        if output.stream == "stdout" {
            stdout.extend_from_slice(&output.data);
        }
        if output.done {
            exit_code = Some(output.exit_code);
        }
    }
    if exit_code != Some(0) {
        bail!("exec exit code {exit_code:?}");
    }
    if !String::from_utf8_lossy(&stdout).contains("machine-exec-ok") {
        bail!("exec stdout missing marker: {stdout:?}");
    }
    Ok(())
}

/// Interactive session: PTY-merged output, driven over the bidi stream.
async fn exec_interactive(machines: &mut MachineServiceClient<Channel>) -> Result<()> {
    let (tx, rx) = tokio::sync::mpsc::channel::<MachineExecInput>(4);
    tx.send(MachineExecInput {
        payload: Some(machine_exec_input::Payload::Init(MachineExecRequest {
            id: MACHINE.to_owned(),
            cmd: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo interactive-ok".to_owned(),
            ],
            tty: true,
            tty_size: Some(TerminalSize {
                width: 80,
                height: 24,
            }),
            ..Default::default()
        })),
    })
    .await
    .ok();
    // Stdin EOF: the command needs no input.
    tx.send(MachineExecInput {
        payload: Some(machine_exec_input::Payload::Stdin(Vec::new())),
    })
    .await
    .ok();
    drop(tx);

    let mut stream =
        tokio::time::timeout(RPC_BUDGET, machines.exec_session(ReceiverStream::new(rx)))
            .await
            .context("exec session timed out")?
            .context("exec session failed")?
            .into_inner();

    let mut output = Vec::new();
    let mut exit_code = None;
    while let Some(frame) = tokio::time::timeout(RPC_BUDGET, stream.message())
        .await
        .context("session output timed out")?
        .context("session stream error")?
    {
        output.extend_from_slice(&frame.data);
        if frame.done {
            exit_code = Some(frame.exit_code);
        }
    }
    if exit_code != Some(0) {
        bail!("session exit code {exit_code:?}");
    }
    if !String::from_utf8_lossy(&output).contains("interactive-ok") {
        bail!("session output missing marker: {output:?}");
    }
    Ok(())
}

/// Per-machine stats: the first frame must arrive and be sane.
async fn stats_first_frame(channel: Channel) -> Result<()> {
    let mut stats = StatsServiceClient::new(channel);
    let mut stream = stats
        .watch(StatsWatchRequest {
            machine_id: MACHINE.to_owned(),
        })
        .await
        .context("stats watch failed")?
        .into_inner();
    let sample = tokio::time::timeout(RPC_BUDGET, stream.message())
        .await
        .context("no stats frame in budget")?
        .context("stats stream error")?
        .context("stats stream ended")?;
    if sample.memory_total_bytes == 0 || sample.online_cpus == 0 {
        bail!("implausible machine stats: {sample:?}");
    }
    Ok(())
}
