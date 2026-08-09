//! Machine management commands.

use anyhow::{Context, Result};
use arcbox_cli::terminal::{RawModeGuard, TerminalSize};
use arcbox_connect::v1 as pb;
use arcbox_connect::v1::MachineServiceClient;
use arcbox_connect::v1::TerminalSize as ProtoTerminalSize;
use arcbox_connect::v1::{
    CreateMachineRequest, DirectoryMount, InspectMachineRequest, ListMachinesRequest,
    MachineAgentRequest, MachineExecInput, MachineExecRequest, RemoveMachineRequest,
    StartMachineRequest, StopMachineRequest, machine_exec_input,
};
use clap::{Args, Subcommand};
use humantime::format_duration;
use std::collections::HashMap;
use std::io::Write;
use tokio::io::AsyncReadExt as _;

pub fn machine_client() -> MachineServiceClient<connectrpc::client::SharedHttp2Connection> {
    let (transport, config) = crate::connect::daemon(&super::resolve_grpc_socket_path());
    MachineServiceClient::new(transport, config)
}

/// Returns the number of machines visible through the daemon gRPC API.
pub async fn machine_count() -> Result<usize> {
    let client = machine_client();
    let response: pb::ListMachinesResponse = client
        .list(ListMachinesRequest {
            all: true,
            ..Default::default()
        })
        .await
        .context("Failed to list machines")?
        .into_owned();

    Ok(response.machines.len())
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
        ..Default::default()
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
        .create(CreateMachineRequest {
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
            ..Default::default()
        })
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
        .start(StartMachineRequest {
            id: args.name.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_operation(error, &args.name, "start"))?;

    const MAX_AGENT_WAIT_ATTEMPTS: u32 = 20;
    let mut delay = std::time::Duration::from_millis(200);
    for attempt in 1..=MAX_AGENT_WAIT_ATTEMPTS {
        match client
            .ping(MachineAgentRequest {
                id: args.name.clone(),
                ..Default::default()
            })
            .await
        {
            Ok(_) => break,
            Err(e) => {
                if attempt == MAX_AGENT_WAIT_ATTEMPTS {
                    return Err(crate::error::machine_request(
                        e,
                        &args.name,
                        "agent readiness",
                    ));
                }
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay.saturating_mul(2), std::time::Duration::from_secs(2));
            }
        }
    }

    println!("Machine '{}' started", args.name);
    if let Ok(resp) = client
        .inspect(InspectMachineRequest {
            id: args.name.clone(),
            ..Default::default()
        })
        .await
    {
        let info: pb::MachineInfo = resp.into_owned();
        // An unset `network` derefs to the default instance (empty IP), so
        // the "no IP" case needs no separate branch.
        if !info.network.ip_address.is_empty() {
            println!("IP:      {}", info.network.ip_address);
        }
    }

    Ok(())
}

async fn execute_stop(args: StopArgs) -> Result<()> {
    let client = machine_client();

    println!("Stopping machine '{}'...", args.name);

    client
        .stop(StopMachineRequest {
            id: args.name.clone(),
            force: args.force,
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_operation(error, &args.name, "stop"))?;

    println!("Machine '{}' stopped", args.name);

    Ok(())
}

async fn execute_remove(args: RemoveArgs) -> Result<()> {
    let client = machine_client();

    client
        .remove(RemoveMachineRequest {
            id: args.name.clone(),
            force: args.force,
            // Removal always deletes the machine directory; the wire field
            // is retained for compatibility only.
            volumes: false,
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_operation(error, &args.name, "remove"))?;

    println!("Machine '{}' removed", args.name);

    Ok(())
}

async fn execute_list(args: ListArgs) -> Result<()> {
    let client = machine_client();
    let machines = client
        .list(ListMachinesRequest {
            all: args.all,
            ..Default::default()
        })
        .await
        .context("Failed to list machines")?
        .into_owned()
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
    let machine: pb::MachineInfo = client
        .inspect(InspectMachineRequest {
            id: args.name.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_operation(error, &args.name, "inspect"))?
        .into_owned();

    // Unset sub-messages deref to their default instances, which carry the
    // same zero/empty values the old Option-based fallbacks produced.
    let cpus = machine.hardware.cpus;
    let memory_mb = machine.hardware.memory / (1024 * 1024);
    let disk_gb = machine.storage.disk_size / (1024 * 1024 * 1024);
    let ip_address = Some(machine.network.ip_address.as_str())
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
    let machine: pb::MachineInfo = client
        .inspect(InspectMachineRequest {
            id: args.name.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_operation(error, &args.name, "inspect"))?
        .into_owned();

    // Sub-message derefs fall back to default instances (zero/empty), which
    // matches the old Option-based fallbacks — the JSON shape is unchanged,
    // including `ip_address: null` when the machine has no address.
    let payload = serde_json::json!({
        "id": machine.id,
        "name": machine.name,
        "state": machine.state,
        "cpus": machine.hardware.cpus,
        "memory_mb": machine.hardware.memory / (1024 * 1024),
        "disk_gb": machine.storage.disk_size / (1024 * 1024 * 1024),
        "ip_address": Some(machine.network.ip_address.clone()).filter(|ip| !ip.is_empty()),
        "kernel": machine.os.kernel.clone(),
        "distro": machine.os.distro.clone(),
        "distro_version": machine.os.version.clone(),
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
    let response: pb::MachinePingResponse = client
        .ping(MachineAgentRequest {
            id: args.name.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_request(error, &args.name, "ping"))?
        .into_owned();
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
    let info: pb::MachineSystemInfo = client
        .get_system_info(MachineAgentRequest {
            id: args.name.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_request(error, &args.name, "system information"))?
        .into_owned();

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
    let command = cmd.first().cloned().unwrap_or_default();
    let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel::<MachineExecInput>(16);

    let tty_size = TerminalSize::current().ok().map(|s| ProtoTerminalSize {
        width: u32::from(s.cols),
        height: u32::from(s.rows),
        ..Default::default()
    });

    // The first message in the stream must be the Init payload.
    msg_tx
        .send(MachineExecInput {
            payload: MachineExecRequest {
                id: name.to_string(),
                cmd,
                tty: true,
                tty_size: tty_size.into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
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
                        payload: ProtoTerminalSize {
                            width: u32::from(size.cols),
                            height: u32::from(size.rows),
                            ..Default::default()
                        }
                        .into(),
                        ..Default::default()
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
                            ..Default::default()
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

    // An interactive PTY drives both directions at once, so split the bidi
    // stream into independently owned halves: the send half moves into a
    // forwarder task, the receive half stays here.
    let client = machine_client();
    let stream = client.exec_session().await.map_err(|error| {
        crate::error::machine_request(error, name, "interactive command execution")
    })?;
    let (mut send, mut recv) = stream.into_split();

    // Forwarder: inputs from the pumps → wire. When every pump has dropped
    // its sender the channel drains, and closing the send half ends the
    // request body cleanly; the session keeps running until the server
    // finishes the response side.
    tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            if send.send(msg).await.is_err() {
                break;
            }
        }
        send.close_send();
    });

    let mut exit_code = None;
    while let Some(item) = recv
        .message::<pb::MachineExecOutput>()
        .await
        .map_err(|error| crate::error::machine_exec_output(error, name, &command))?
    {
        let output = item.to_owned_message();
        if !output.data.is_empty() {
            // The PTY merges stdout/stderr into one stream.
            std::io::stdout()
                .write_all(&output.data)
                .context("Failed to write output")?;
            std::io::stdout().flush()?;
        }
        if output.done {
            exit_code = Some(output.exit_code);
        }
    }

    // Restore the terminal before exiting.
    drop(raw_guard);

    let exit_code = exec_exit_code(exit_code, name, &command)?;
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
    let command = cmd.first().cloned().unwrap_or_default();
    let client = machine_client();
    let mut stream = client
        .exec(MachineExecRequest {
            id: name.to_string(),
            cmd,
            working_dir: String::new(),
            user: String::new(),
            env: env.into_iter().collect(),
            tty,
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::machine_request(error, name, "command execution"))?;

    let mut exit_code = None;
    while let Some(item) = stream
        .message::<pb::MachineExecOutput>()
        .await
        .map_err(|error| crate::error::machine_exec_output(error, name, &command))?
    {
        let output = item.to_owned_message();
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
            exit_code = Some(output.exit_code);
        }
    }

    let exit_code = exec_exit_code(exit_code, name, &command)?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn exec_exit_code(exit_code: Option<i32>, name: &str, command: &str) -> Result<i32> {
    exit_code.ok_or_else(|| {
        crate::error::machine_exec_output(
            connectrpc::ConnectError::internal(
                "exec stream closed without a terminal status frame",
            ),
            name,
            command,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_requires_a_terminal_status_frame() {
        assert_eq!(exec_exit_code(Some(7), "dev", "false").unwrap(), 7);

        let error = exec_exit_code(None, "dev", "date").unwrap_err();
        assert_eq!(
            crate::error::render(&error, false),
            "Error: Could not read output from 'date' in machine 'dev'."
        );
        assert!(
            crate::error::render(&error, true)
                .contains("exec stream closed without a terminal status frame")
        );
    }
}
