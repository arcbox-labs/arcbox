//! Sandbox management commands.
//!
//! Sandboxes are short-lived, strongly-isolated microVMs bound to a single
//! workload. All sandbox commands take `<machine>` as the first argument,
//! which identifies the guest VM that hosts the sandbox manager.
//!
//! The machine name is forwarded to the daemon via the `x-machine` gRPC
//! metadata header for routing to the correct arcbox-agent instance.

use anyhow::{Context, Result};
use arcbox_grpc::{SandboxServiceClient, SandboxSnapshotServiceClient};
use arcbox_protocol::sandbox_v1::{
    CheckpointRequest, CreateSandboxRequest, DeleteSnapshotRequest, InspectSandboxRequest,
    ListSandboxesRequest, ListSnapshotsRequest, RemoveSandboxRequest, ResourceLimits,
    RestoreRequest, RunRequest, SandboxEventsRequest, StopSandboxRequest,
};
use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

use super::machine::UnixConnector;
use std::path::PathBuf;

fn resolve_grpc_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("ARCBOX_GRPC_SOCKET") {
        return PathBuf::from(path);
    }

    if let Ok(path) = std::env::var("ARCBOX_SOCKET") {
        let docker_socket = PathBuf::from(path);
        if let Some(parent) = docker_socket.parent() {
            let preferred = parent.join("arcbox-grpc.sock");
            if preferred.exists() {
                return preferred;
            }
            let legacy = parent.join("arcbox.sock");
            if legacy.exists() {
                return legacy;
            }
            return preferred;
        }
    }

    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".arcbox")
        .join("arcbox.sock")
}

async fn sandbox_channel() -> Result<Channel> {
    let socket_path = resolve_grpc_socket_path();
    tonic::transport::Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector::new(socket_path.clone()))
        .await
        .with_context(|| {
            format!(
                "Failed to connect to ArcBox gRPC daemon at {}",
                socket_path.display()
            )
        })
}

/// Attaches `x-machine: <name>` metadata to a tonic request.
fn with_machine<T>(mut request: tonic::Request<T>, machine: &str) -> Result<tonic::Request<T>> {
    let val = MetadataValue::try_from(machine)
        .with_context(|| format!("invalid machine name: {machine}"))?;
    request.metadata_mut().insert("x-machine", val);
    Ok(request)
}

/// Sandbox subcommands.
#[derive(Subcommand)]
pub enum SandboxCommands {
    /// Create a new sandbox in a machine
    Create(CreateArgs),
    /// Stop a sandbox gracefully
    Stop(StopArgs),
    /// Remove a sandbox
    #[command(alias = "rm")]
    Remove(RemoveArgs),
    /// List sandboxes in a machine
    #[command(name = "ls", alias = "list")]
    List(ListArgs),
    /// Inspect sandbox details
    Inspect(InspectArgs),
    /// Run a command inside a sandbox (streaming output)
    Run(RunArgs),
    /// Subscribe to sandbox lifecycle events
    Events(EventsArgs),
    /// Checkpoint a sandbox into a snapshot
    Checkpoint(CheckpointArgs),
    /// Restore a sandbox from a snapshot
    Restore(RestoreArgs),
    /// List snapshots
    #[command(name = "snapshots")]
    ListSnapshots(ListSnapshotsArgs),
    /// Delete a snapshot
    #[command(name = "snapshot-rm")]
    DeleteSnapshot(DeleteSnapshotArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Caller-supplied sandbox ID (empty = auto-generated)
    #[arg(long)]
    pub id: Option<String>,
    /// Kernel image path (empty = machine default)
    #[arg(long)]
    pub kernel: Option<String>,
    /// Root filesystem image path (empty = machine default)
    #[arg(long)]
    pub rootfs: Option<String>,
    /// Number of vCPUs (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub cpus: u32,
    /// Memory in MiB (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub memory: u64,
    /// Key=value labels
    #[arg(short, long)]
    pub label: Vec<String>,
    /// Sandbox auto-destruction timeout in seconds (0 = no limit)
    #[arg(long, default_value = "0")]
    pub ttl: u32,
}

#[derive(Args)]
pub struct StopArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Sandbox ID
    pub id: String,
    /// Seconds to wait before force-killing (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub timeout: u32,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Sandbox ID
    pub id: String,
    /// Force removal even if running
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Filter by state (starting/ready/running/stopped/failed)
    #[arg(long)]
    pub state: Option<String>,
    /// Only show IDs
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Sandbox ID
    pub id: String,
}

#[derive(Args)]
pub struct RunArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Sandbox ID
    pub id: String,
    /// Command and arguments
    #[arg(trailing_var_arg = true, required = true)]
    pub cmd: Vec<String>,
    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,
    /// Kill after this many seconds (0 = no timeout)
    #[arg(long, default_value = "0")]
    pub timeout: u32,
}

#[derive(Args)]
pub struct EventsArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Filter by sandbox ID (empty = all sandboxes)
    #[arg(long)]
    pub id: Option<String>,
    /// Filter by action (empty = all actions)
    #[arg(long)]
    pub action: Option<String>,
}

#[derive(Args)]
pub struct CheckpointArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Sandbox ID to checkpoint
    pub id: String,
    /// Human-readable snapshot name
    #[arg(long, default_value = "")]
    pub name: String,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Snapshot ID to restore from
    pub snapshot_id: String,
    /// Assign a new sandbox ID (empty = auto-generated)
    #[arg(long)]
    pub sandbox_id: Option<String>,
    /// Sandbox auto-destruction timeout in seconds (0 = no limit)
    #[arg(long, default_value = "0")]
    pub ttl: u32,
}

#[derive(Args)]
pub struct ListSnapshotsArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Filter by origin sandbox ID (empty = all)
    #[arg(long)]
    pub sandbox_id: Option<String>,
}

#[derive(Args)]
pub struct DeleteSnapshotArgs {
    /// Guest machine that hosts the sandbox manager
    pub machine: String,
    /// Snapshot ID
    pub snapshot_id: String,
}

/// Executes a sandbox subcommand.
pub async fn execute(cmd: SandboxCommands) -> Result<()> {
    match cmd {
        SandboxCommands::Create(args) => execute_create(args).await,
        SandboxCommands::Stop(args) => execute_stop(args).await,
        SandboxCommands::Remove(args) => execute_remove(args).await,
        SandboxCommands::List(args) => execute_list(args).await,
        SandboxCommands::Inspect(args) => execute_inspect(args).await,
        SandboxCommands::Run(args) => execute_run(args).await,
        SandboxCommands::Events(args) => execute_events(args).await,
        SandboxCommands::Checkpoint(args) => execute_checkpoint(args).await,
        SandboxCommands::Restore(args) => execute_restore(args).await,
        SandboxCommands::ListSnapshots(args) => execute_list_snapshots(args).await,
        SandboxCommands::DeleteSnapshot(args) => execute_delete_snapshot(args).await,
    }
}

fn parse_labels(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for kv in raw {
        let mut parts = kv.splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
        let val = parts.next().unwrap_or_default().trim();
        if key.is_empty() {
            anyhow::bail!("invalid label '{}', expected key=value", kv);
        }
        map.insert(key.to_string(), val.to_string());
    }
    Ok(map)
}

async fn execute_create(args: CreateArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let labels = parse_labels(&args.label)?;
    let req = CreateSandboxRequest {
        id: args.id.unwrap_or_default(),
        labels,
        kernel: args.kernel.unwrap_or_default(),
        rootfs: args.rootfs.unwrap_or_default(),
        limits: Some(ResourceLimits {
            vcpus: args.cpus,
            memory_mib: args.memory,
        }),
        ttl_seconds: args.ttl,
        ..Default::default()
    };

    let resp = client
        .create(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to create sandbox")?
        .into_inner();

    println!("Sandbox created");
    println!("  ID:    {}", resp.id);
    println!("  IP:    {}", resp.ip_address);
    println!("  State: {}", resp.state);
    Ok(())
}

async fn execute_stop(args: StopArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let req = StopSandboxRequest {
        id: args.id.clone(),
        timeout_seconds: args.timeout,
    };
    client
        .stop(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to stop sandbox")?;

    println!("Sandbox '{}' stopped", args.id);
    Ok(())
}

async fn execute_remove(args: RemoveArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let req = RemoveSandboxRequest {
        id: args.id.clone(),
        force: args.force,
    };
    client
        .remove(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to remove sandbox")?;

    println!("Sandbox '{}' removed", args.id);
    Ok(())
}

async fn execute_list(args: ListArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let req = ListSandboxesRequest {
        state: args.state.unwrap_or_default(),
        labels: HashMap::new(),
    };
    let sandboxes = client
        .list(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to list sandboxes")?
        .into_inner()
        .sandboxes;

    if args.quiet {
        for sb in &sandboxes {
            println!("{}", sb.id);
        }
        return Ok(());
    }

    if sandboxes.is_empty() {
        println!("No sandboxes found in machine '{}'.", args.machine);
        return Ok(());
    }

    println!("{:<36} {:<12} {:<18} CREATED", "ID", "STATE", "IP");
    for sb in &sandboxes {
        println!(
            "{:<36} {:<12} {:<18} {}",
            sb.id,
            sb.state,
            sb.ip_address,
            sb.created_at,
        );
    }
    Ok(())
}

async fn execute_inspect(args: InspectArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let req = InspectSandboxRequest { id: args.id.clone() };
    let info = client
        .inspect(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to inspect sandbox")?
        .into_inner();

    let payload = serde_json::json!({
        "id": info.id,
        "state": info.state,
        "labels": info.labels,
        "limits": info.limits.map(|l| serde_json::json!({
            "vcpus": l.vcpus,
            "memory_mib": l.memory_mib,
        })),
        "network": info.network.map(|n| serde_json::json!({
            "ip_address": n.ip_address,
            "gateway": n.gateway,
            "tap_name": n.tap_name,
        })),
        "created_at": info.created_at,
        "ready_at": info.ready_at,
        "last_exited_at": info.last_exited_at,
        "last_exit_code": info.last_exit_code,
        "error": info.error,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize sandbox info")?
    );
    Ok(())
}

async fn execute_run(args: RunArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let req = RunRequest {
        id: args.id.clone(),
        cmd: args.cmd,
        tty: args.tty,
        timeout_seconds: args.timeout,
        ..Default::default()
    };

    let mut stream = client
        .run(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to run command in sandbox")?
        .into_inner();

    let mut exit_code = 0i32;
    while let Some(output) = stream
        .message()
        .await
        .context("Failed to read run output")?
    {
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

async fn execute_events(args: EventsArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let req = SandboxEventsRequest {
        id: args.id.unwrap_or_default(),
        action: args.action.unwrap_or_default(),
    };

    let mut stream = client
        .events(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to subscribe to sandbox events")?
        .into_inner();

    println!("Listening for sandbox events (Ctrl+C to stop)...");
    while let Some(event) = stream
        .message()
        .await
        .context("Failed to read sandbox event")?
    {
        println!(
            "[{}] sandbox={} action={}",
            event.timestamp, event.sandbox_id, event.action
        );
        if !event.attributes.is_empty() {
            for (k, v) in &event.attributes {
                println!("  {}={}", k, v);
            }
        }
    }
    Ok(())
}

async fn execute_checkpoint(args: CheckpointArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxSnapshotServiceClient::new(channel);

    let req = CheckpointRequest {
        sandbox_id: args.id.clone(),
        name: args.name.clone(),
        labels: HashMap::new(),
    };
    let resp = client
        .checkpoint(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to checkpoint sandbox")?
        .into_inner();

    println!("Snapshot created");
    println!("  Snapshot ID:  {}", resp.snapshot_id);
    println!("  Snapshot dir: {}", resp.snapshot_dir);
    println!("  Created at:   {}", resp.created_at);
    Ok(())
}

async fn execute_restore(args: RestoreArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxSnapshotServiceClient::new(channel);

    let req = RestoreRequest {
        id: args.sandbox_id.unwrap_or_default(),
        snapshot_id: args.snapshot_id.clone(),
        ttl_seconds: args.ttl,
        ..Default::default()
    };
    let resp = client
        .restore(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to restore sandbox")?
        .into_inner();

    println!("Sandbox restored");
    println!("  ID: {}", resp.id);
    println!("  IP: {}", resp.ip_address);
    Ok(())
}

async fn execute_list_snapshots(args: ListSnapshotsArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxSnapshotServiceClient::new(channel);

    let req = ListSnapshotsRequest {
        sandbox_id: args.sandbox_id.unwrap_or_default(),
        labels: HashMap::new(),
    };
    let snapshots = client
        .list_snapshots(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to list snapshots")?
        .into_inner()
        .snapshots;

    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }

    println!(
        "{:<36} {:<36} {:<20} CREATED",
        "SNAPSHOT ID", "SANDBOX ID", "NAME"
    );
    for snap in &snapshots {
        println!(
            "{:<36} {:<36} {:<20} {}",
            snap.id, snap.sandbox_id, snap.name, snap.created_at,
        );
    }
    Ok(())
}

async fn execute_delete_snapshot(args: DeleteSnapshotArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxSnapshotServiceClient::new(channel);

    let req = DeleteSnapshotRequest {
        snapshot_id: args.snapshot_id.clone(),
    };
    client
        .delete_snapshot(with_machine(tonic::Request::new(req), &args.machine)?)
        .await
        .context("Failed to delete snapshot")?;

    println!("Snapshot '{}' deleted", args.snapshot_id);
    Ok(())
}
