//! Machine management commands.

use crate::connect::{StreamItemExt as _, UnaryExt as _};
use anyhow::{Context, Result};
use arcbox_cli::terminal::{RawModeGuard, TerminalSize};
use arcbox_connect::v1 as pb;
use arcbox_connect::v1::MachineServiceClient;
use arcbox_protocol::v1::TerminalSize as ProtoTerminalSize;
use arcbox_protocol::v1::{
    CreateMachineRequest, DirectoryMount, InspectMachineRequest, ListMachinesRequest,
    MachineAgentRequest, MachineExecInput, MachineExecRequest, RemoveMachineRequest,
    StartMachineRequest, StopMachineRequest, machine_exec_input,
};
use clap::{Args, Subcommand};
use humantime::format_duration;
use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;

pub struct UnixConnector {
    socket_path: PathBuf,
}

impl UnixConnector {
    pub(crate) fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

impl tonic::codegen::Service<tonic::transport::Uri> for UnixConnector {
    type Response = hyper_util::rt::TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: tonic::transport::Uri) -> Self::Future {
        let socket_path = self.socket_path.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(socket_path).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

/// A tonic client, kept only for the interactive exec session.
///
/// See the call site in [`exec_session`] for why that one RPC cannot use the
/// Connect client yet. The daemon serves both formats at the same endpoint,
/// so this reaches identical handlers.
async fn legacy_machine_client()
-> Result<arcbox_grpc::v1::machine_service_client::MachineServiceClient<tonic::transport::Channel>>
{
    let socket_path = super::resolve_grpc_socket_path();
    let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector::new(socket_path.clone()))
        .await
        .with_context(|| {
            format!(
                "Failed to connect to the ArcBox daemon at {}",
                socket_path.display()
            )
        })?;
    Ok(arcbox_grpc::v1::machine_service_client::MachineServiceClient::new(channel))
}

pub fn machine_client() -> MachineServiceClient<connectrpc::client::SharedHttp2Connection> {
    let (transport, config) = crate::connect::daemon(&super::resolve_grpc_socket_path());
    MachineServiceClient::new(transport, config)
}

/// Returns the number of machines visible through the daemon gRPC API.
pub async fn machine_count() -> Result<usize> {
    let client = machine_client();
    let response = client
        .list(crate::connect::request::<pb::ListMachinesRequest, _>(
            &ListMachinesRequest { all: true },
        )?)
        .await
        .context("Failed to list machines")?;

    Ok(response
        .prost::<arcbox_protocol::v1::ListMachinesResponse>()?
        .machines
        .len())
}

fn parse_mount(mount: &str) -> Result<DirectoryMount> {
    let mut parts = mount.splitn(2, ':');
    let host = parts.next().unwrap_or_default().trim();
    let guest = parts.next().unwrap_or_default().trim();

    if host.is_empty() || guest.is_empty() {
        anyhow::bail!("Invalid mount '{}', expected host_path:guest_path", mount);
    }

    Ok(DirectoryMount {
        host_path: host.to_string(),
        guest_path: guest.to_string(),
        readonly: false,
    })
}

fn title_case_state(state: &str) -> String {
    let mut chars = state.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// Machine subcommands.
#[derive(Subcommand)]
pub enum MachineCommands {
    /// Create a new machine
    Create(CreateArgs),
    /// Start a machine
    Start(StartArgs),
    /// Stop a machine
    Stop(StopArgs),
    /// Remove a machine
    #[command(alias = "rm")]
    Remove(RemoveArgs),
    /// List machines
    #[command(name = "ls", alias = "list")]
    List(ListArgs),
    /// Show machine status
    Status(StatusArgs),
    /// Inspect machine details
    Inspect(InspectArgs),
    /// Ping machine agent
    Ping(PingArgs),
    /// Show guest system info
    Info(InfoArgs),
    /// SSH into a machine
    Ssh(SshArgs),
    /// Execute a command in a machine
    Exec(ExecArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    /// Machine name
    pub name: String,
    /// Number of CPUs (default: host core count, decided by the daemon)
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub cpus: Option<u32>,
    /// Memory in MB
    #[arg(long, default_value = "4096")]
    pub memory: u64,
    /// Disk size in GB
    #[arg(long, default_value = "50")]
    pub disk: u64,
    /// Distribution (ubuntu, alpine, etc.)
    #[arg(long)]
    pub distro: Option<String>,
    /// Distribution version
    #[arg(long, name = "distro-version")]
    pub distro_version: Option<String>,
    /// Directory mounts (host:guest)
    #[arg(short, long)]
    pub mount: Vec<String>,
    /// Custom kernel path (for advanced users / testing)
    #[arg(long)]
    pub kernel: Option<String>,
    /// Custom kernel command line (for advanced users / testing)
    #[arg(long)]
    pub cmdline: Option<String>,
}

#[derive(Args)]
pub struct StartArgs {
    /// Machine name
    pub name: String,
}

#[derive(Args)]
pub struct StopArgs {
    /// Machine name
    pub name: String,
    /// Force stop
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Machine name
    pub name: String,
    /// Force removal
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Show all machines
    #[arg(short, long)]
    pub all: bool,
    /// Only show IDs
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Machine name
    pub name: String,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Machine name
    pub name: String,
}

#[derive(Args)]
pub struct PingArgs {
    /// Machine name
    pub name: String,
}

#[derive(Args)]
pub struct InfoArgs {
    /// Machine name
    pub name: String,
}

#[derive(Args)]
pub struct SshArgs {
    /// Machine name
    pub name: String,
    /// Command to run
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct ExecArgs {
    /// Machine name
    pub name: String,
    /// Command to run
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

/// Executes the machine command.
pub async fn execute(cmd: MachineCommands) -> Result<()> {
    match cmd {
        MachineCommands::Create(args) => execute_create(args).await,
        MachineCommands::Start(args) => execute_start(args).await,
        MachineCommands::Stop(args) => execute_stop(args).await,
        MachineCommands::Remove(args) => execute_remove(args).await,
        MachineCommands::List(args) => execute_list(args).await,
        MachineCommands::Status(args) => execute_status(args).await,
        MachineCommands::Inspect(args) => execute_inspect(args).await,
        MachineCommands::Ping(args) => execute_ping(args).await,
        MachineCommands::Info(args) => execute_info(args).await,
        MachineCommands::Ssh(args) => execute_ssh(args).await,
        MachineCommands::Exec(args) => execute_exec(args).await,
    }
}

async fn execute_create(args: CreateArgs) -> Result<()> {
    let client = machine_client();
    let mounts = args
        .mount
        .iter()
        .map(|m| parse_mount(m))
        .collect::<Result<Vec<_>>>()?;

    client
        .create(crate::connect::request::<pb::CreateMachineRequest, _>(
            &CreateMachineRequest {
                name: args.name.clone(),
                // 0 = let the daemon apply its default (host core count).
                cpus: args.cpus.unwrap_or(0),
                memory: args.memory.saturating_mul(1024_u64 * 1024),
                disk_size: args.disk.saturating_mul(1024_u64 * 1024 * 1024),
                distro: args.distro.clone().unwrap_or_default(),
                version: args.distro_version.clone().unwrap_or_default(),
                arch: std::env::consts::ARCH.to_string(),
                mounts,
                ssh_public_key: String::new(),
                kernel: args.kernel.clone().unwrap_or_default(),
                cmdline: args.cmdline.clone().unwrap_or_default(),
            },
        )?)
        .await
        .context("Failed to create machine")?;

    println!("Machine '{}' created successfully", args.name);
    match args.cpus {
        Some(cpus) => println!("  CPUs:   {cpus}"),
        None => println!("  CPUs:   default (host core count)"),
    }
    println!("  Memory: {} MB", args.memory);
    println!("  Disk:   {} GB", args.disk);
    println!();
    println!("To start the machine, run:");
    println!("  abctl machine start {}", args.name);

    Ok(())
}

async fn execute_start(args: StartArgs) -> Result<()> {
    let client = machine_client();

    println!("Starting machine '{}'...", args.name);

    client
        .start(crate::connect::request::<pb::StartMachineRequest, _>(
            &StartMachineRequest {
                id: args.name.clone(),
            },
        )?)
        .await
        .context("Failed to start machine")?;

    const MAX_AGENT_WAIT_ATTEMPTS: u32 = 20;
    let mut delay = std::time::Duration::from_millis(200);
    for attempt in 1..=MAX_AGENT_WAIT_ATTEMPTS {
        match client
            .ping(crate::connect::request::<pb::MachineAgentRequest, _>(
                &MachineAgentRequest {
                    id: args.name.clone(),
                },
            )?)
            .await
        {
            Ok(_) => break,
            Err(e) => {
                if attempt == MAX_AGENT_WAIT_ATTEMPTS {
                    return Err(anyhow::Error::new(e))
                        .context("Failed to wait for machine agent readiness");
                }
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay.saturating_mul(2), std::time::Duration::from_secs(2));
            }
        }
    }

    println!("Machine '{}' started", args.name);
    if let Ok(resp) = client
        .inspect(crate::connect::request::<pb::InspectMachineRequest, _>(
            &InspectMachineRequest {
                id: args.name.clone(),
            },
        )?)
        .await
    {
        if let Some(network) = resp.prost::<arcbox_protocol::v1::MachineInfo>()?.network {
            if !network.ip_address.is_empty() {
                println!("IP:      {}", network.ip_address);
            }
        }
    }

    Ok(())
}

async fn execute_stop(args: StopArgs) -> Result<()> {
    let client = machine_client();

    println!("Stopping machine '{}'...", args.name);

    client
        .stop(crate::connect::request::<pb::StopMachineRequest, _>(
            &StopMachineRequest {
                id: args.name.clone(),
                force: args.force,
            },
        )?)
        .await
        .context("Failed to stop machine")?;

    println!("Machine '{}' stopped", args.name);

    Ok(())
}

async fn execute_remove(args: RemoveArgs) -> Result<()> {
    let client = machine_client();

    client
        .remove(crate::connect::request::<pb::RemoveMachineRequest, _>(
            &RemoveMachineRequest {
                id: args.name.clone(),
                force: args.force,
                // Removal always deletes the machine directory; the wire field
                // is retained for compatibility only.
                volumes: false,
            },
        )?)
        .await
        .context("Failed to remove machine")?;

    println!("Machine '{}' removed", args.name);

    Ok(())
}

async fn execute_list(args: ListArgs) -> Result<()> {
    let client = machine_client();
    let machines = client
        .list(crate::connect::request::<pb::ListMachinesRequest, _>(
            &ListMachinesRequest { all: args.all },
        )?)
        .await
        .context("Failed to list machines")?
        .prost::<arcbox_protocol::v1::ListMachinesResponse>()?
        .machines;

    if args.quiet {
        for machine in &machines {
            println!("{}", machine.name);
        }
        return Ok(());
    }

    if machines.is_empty() {
        println!("No machines found.");
        println!();
        println!("To create a machine, run:");
        println!("  abctl machine create <name>");
        return Ok(());
    }

    // Print header
    println!(
        "{:<20} {:<18} {:<12} {:<6} {:<12} {:<10}",
        "NAME", "DISTRO", "STATE", "CPUS", "MEMORY", "DISK"
    );

    // Print machines
    for machine in &machines {
        let distro = if machine.distro.is_empty() {
            "-".to_string()
        } else if machine.distro_version.is_empty() {
            machine.distro.clone()
        } else {
            format!("{}:{}", machine.distro, machine.distro_version)
        };
        println!(
            "{:<20} {:<18} {:<12} {:<6} {:<12} {:<10}",
            machine.name,
            distro,
            title_case_state(&machine.state),
            machine.cpus,
            format!("{} MB", machine.memory / (1024 * 1024)),
            format!("{} GB", machine.disk_size / (1024 * 1024 * 1024)),
        );
    }

    Ok(())
}

async fn execute_status(args: StatusArgs) -> Result<()> {
    let client = machine_client();
    let machine = client
        .inspect(crate::connect::request::<pb::InspectMachineRequest, _>(
            &InspectMachineRequest {
                id: args.name.clone(),
            },
        )?)
        .await
        .context("Failed to get machine status")?
        .prost::<arcbox_protocol::v1::MachineInfo>()?;

    let cpus = machine.hardware.as_ref().map_or(0, |h| h.cpus);
    let memory_mb = machine
        .hardware
        .as_ref()
        .map_or(0, |h| h.memory / (1024 * 1024));
    let disk_gb = machine
        .storage
        .as_ref()
        .map_or(0, |s| s.disk_size / (1024 * 1024 * 1024));
    let ip_address = machine
        .network
        .as_ref()
        .map(|n| n.ip_address.as_str())
        .filter(|ip| !ip.is_empty())
        .unwrap_or("-");

    println!("Machine: {}", machine.name);
    println!("State:   {}", title_case_state(&machine.state));
    println!("CPUs:    {}", cpus);
    println!("Memory:  {} MB", memory_mb);
    println!("Disk:    {} GB", disk_gb);
    println!("VM ID:   {}", machine.id);
    println!("IP:      {}", ip_address);

    Ok(())
}

async fn execute_inspect(args: InspectArgs) -> Result<()> {
    let client = machine_client();
    let machine = client
        .inspect(crate::connect::request::<pb::InspectMachineRequest, _>(
            &InspectMachineRequest {
                id: args.name.clone(),
            },
        )?)
        .await
        .context("Failed to inspect machine")?
        .prost::<arcbox_protocol::v1::MachineInfo>()?;

    let payload = serde_json::json!({
        "id": machine.id,
        "name": machine.name,
        "state": machine.state,
        "cpus": machine.hardware.as_ref().map_or(0, |h| h.cpus),
        "memory_mb": machine.hardware.as_ref().map_or(0, |h| h.memory / (1024 * 1024)),
        "disk_gb": machine.storage.as_ref().map_or(0, |s| s.disk_size / (1024 * 1024 * 1024)),
        "ip_address": machine.network.as_ref().map(|n| n.ip_address.clone()).filter(|ip| !ip.is_empty()),
        "kernel": machine.os.as_ref().map_or(String::new(), |os| os.kernel.clone()),
        "distro": machine.os.as_ref().map_or(String::new(), |os| os.distro.clone()),
        "distro_version": machine.os.as_ref().map_or(String::new(), |os| os.version.clone()),
    });

    println!(
        "{}",
        serde_json::to_string(&payload).context("Failed to serialize machine info")?
    );

    Ok(())
}

async fn execute_ping(args: PingArgs) -> Result<()> {
    let client = machine_client();
    let started = std::time::Instant::now();
    let response = client
        .ping(crate::connect::request::<pb::MachineAgentRequest, _>(
            &MachineAgentRequest {
                id: args.name.clone(),
            },
        )?)
        .await
        .context("Failed to ping agent")?
        .prost::<arcbox_protocol::v1::MachinePingResponse>()?;
    let elapsed = started.elapsed();

    println!(
        "pong: {} (version: {}, latency: {} ms)",
        response.message,
        response.version,
        elapsed.as_millis()
    );
    Ok(())
}

async fn execute_info(args: InfoArgs) -> Result<()> {
    let client = machine_client();
    let info = client
        .get_system_info(crate::connect::request::<pb::MachineAgentRequest, _>(
            &MachineAgentRequest {
                id: args.name.clone(),
            },
        )?)
        .await
        .context("Failed to get system info")?
        .prost::<arcbox_protocol::v1::MachineSystemInfo>()?;

    let total_mb = info.total_memory / 1024 / 1024;
    let available_mb = info.available_memory / 1024 / 1024;

    println!("Kernel: {}", info.kernel_version);
    println!("OS: {} {}", info.os_name, info.os_version);
    println!("Arch: {}", info.arch);
    println!("Hostname: {}", info.hostname);
    println!("CPUs: {}", info.cpu_count);
    println!("Memory: {} MB", total_mb);
    println!("Memory Available: {} MB", available_mb);
    println!(
        "Uptime: {}",
        format_duration(std::time::Duration::from_secs(info.uptime))
    );
    if !info.ip_addresses.is_empty() {
        println!("IP Addresses: {}", info.ip_addresses.join(", "));
    }

    Ok(())
}

async fn execute_ssh(args: SshArgs) -> Result<()> {
    if args.command.is_empty() {
        return exec_session_interactive(&args.name, vec!["/bin/sh".to_string(), "-l".to_string()])
            .await;
    }
    exec_via_grpc(&args.name, args.command, HashMap::new(), false).await
}

/// Runs an interactive PTY session in a machine: local terminal in raw mode,
/// stdin and SIGWINCH resizes pumped up, merged PTY output written to stdout.
async fn exec_session_interactive(name: &str, cmd: Vec<String>) -> Result<()> {
    let (msg_tx, msg_rx) = tokio::sync::mpsc::channel::<MachineExecInput>(16);

    let tty_size = TerminalSize::current().ok().map(|s| ProtoTerminalSize {
        width: u32::from(s.cols),
        height: u32::from(s.rows),
    });

    // The first message in the stream must be the Init payload.
    msg_tx
        .send(MachineExecInput {
            payload: Some(machine_exec_input::Payload::Init(MachineExecRequest {
                id: name.to_string(),
                cmd,
                tty: true,
                tty_size,
                ..Default::default()
            })),
        })
        .await
        .context("Failed to send exec session init")?;

    let raw_guard = RawModeGuard::new()?;

    // Resize pump: SIGWINCH → resize messages.
    let resize_tx = msg_tx.clone();
    match arcbox_cli::terminal::ResizeWatcher::new() {
        Ok(mut watcher) => {
            tokio::spawn(async move {
                while let Some(size) = watcher.recv().await {
                    let msg = MachineExecInput {
                        payload: Some(machine_exec_input::Payload::Resize(ProtoTerminalSize {
                            width: u32::from(size.cols),
                            height: u32::from(size.rows),
                        })),
                    };
                    if resize_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            });
        }
        Err(e) => tracing::warn!(error = %e, "terminal resize forwarding disabled"),
    }

    // Stdin pump: local terminal → session stream.
    let stdin_tx = msg_tx;
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdin_tx
                        .send(MachineExecInput {
                            payload: Some(machine_exec_input::Payload::Stdin(buf[..n].to_vec())),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // The one call still on tonic. `connectrpc::client::BidiStream` takes
    // `&mut self` for both `send` and `message` and exposes no split, so a
    // bidi stream cannot be driven from both directions at once — which is
    // exactly what an interactive PTY needs. Everything else in the CLI has
    // moved; this waits on a split (or an owned sender) upstream.
    let mut stream = legacy_machine_client()
        .await?
        .exec_session(tonic::Request::new(ReceiverStream::new(msg_rx)))
        .await
        .context("Failed to open machine exec session")?
        .into_inner();

    let mut exit_code = 0i32;
    let mut received_done = false;
    while let Some(output) = stream
        .message()
        .await
        .context("Failed to read session output")?
    {
        if !output.data.is_empty() {
            // The PTY merges stdout/stderr into one stream.
            std::io::stdout()
                .write_all(&output.data)
                .context("Failed to write output")?;
            std::io::stdout().flush()?;
        }
        if output.done {
            exit_code = output.exit_code;
            received_done = true;
        }
    }

    // Restore the terminal before exiting.
    drop(raw_guard);

    if !received_done {
        anyhow::bail!("session stream closed without a terminal status frame");
    }
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

async fn execute_exec(args: ExecArgs) -> Result<()> {
    exec_via_grpc(&args.name, args.command, HashMap::new(), false).await
}

/// Runs a command in a machine via the daemon's gRPC Exec RPC.
async fn exec_via_grpc(
    name: &str,
    cmd: Vec<String>,
    env: HashMap<String, String>,
    tty: bool,
) -> Result<()> {
    let client = machine_client();
    let mut stream = client
        .exec(crate::connect::request::<pb::MachineExecRequest, _>(
            &MachineExecRequest {
                id: name.to_string(),
                cmd,
                working_dir: String::new(),
                user: String::new(),
                env,
                tty,
                tty_size: None,
            },
        )?)
        .await
        .context("Failed to execute command in machine")?;

    let mut exit_code = 0i32;
    while let Some(item) = stream
        .message::<pb::MachineExecOutput>()
        .await
        .context("Failed to read exec output")?
    {
        let output: arcbox_protocol::v1::MachineExecOutput = item.prost()?;
        if !output.data.is_empty() {
            match output.stream.as_str() {
                "stderr" => {
                    std::io::stderr()
                        .write_all(&output.data)
                        .context("Failed to write stderr")?;
                }
                _ => {
                    std::io::stdout()
                        .write_all(&output.data)
                        .context("Failed to write stdout")?;
                }
            }
        }
        if output.done {
            exit_code = output.exit_code;
        }
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}
