//! Sandbox management commands.
//!
//! Sandboxes are short-lived, strongly-isolated microVMs. The underlying guest
//! VM is managed transparently by the daemon and is not visible to the user.

use anyhow::{Context, Result};
use arcbox_core::vm_lifecycle::DEFAULT_MACHINE_NAME;
use arcbox_grpc::{SandboxServiceClient, SandboxSnapshotServiceClient};
use arcbox_protocol::sandbox_v1::{
    CheckpointRequest, CreateSandboxRequest, DeleteSnapshotRequest, ExecInput, ExecRequest,
    InspectSandboxRequest, ListSandboxesRequest, ListSnapshotsRequest, RemoveSandboxRequest,
    ResourceLimits, RestoreRequest, RunRequest, SandboxEventsRequest, StopSandboxRequest,
    TerminalSize as ProtoTerminalSize, exec_input,
};
use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use tokio::io::AsyncReadExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

use super::machine::UnixConnector;
use arcbox_cli::terminal::{RawModeGuard, TerminalSize};

async fn sandbox_channel() -> Result<Channel> {
    let socket_path = super::resolve_grpc_socket_path();
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

/// Attaches the default `x-machine` metadata header to a tonic request for
/// daemon-side routing to the guest VM agent.
fn attach_machine<T>(mut request: tonic::Request<T>) -> tonic::Request<T> {
    // SAFETY: DEFAULT_MACHINE_NAME is a valid ASCII string.
    let val = MetadataValue::from_static(DEFAULT_MACHINE_NAME);
    request.metadata_mut().insert("x-machine", val);
    request
}

/// Sandbox subcommands.
#[derive(Subcommand)]
pub enum SandboxCommands {
    /// Create a new sandbox
    Create(CreateArgs),
    /// Stop a sandbox gracefully
    Stop(StopArgs),
    /// Remove a sandbox
    #[command(alias = "rm")]
    Remove(RemoveArgs),
    /// List sandboxes
    #[command(name = "ls", alias = "list")]
    List(ListArgs),
    /// Inspect sandbox details
    Inspect(InspectArgs),
    /// Run a command inside a sandbox (streaming output, no stdin)
    Run(RunArgs),
    /// Execute an interactive command inside a sandbox (bidirectional)
    Exec(ExecArgs),
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
    /// Caller-supplied sandbox ID (empty = auto-generated)
    #[arg(long)]
    pub id: Option<String>,
    /// Kernel image path (empty = daemon default)
    #[arg(long)]
    pub kernel: Option<String>,
    /// Root filesystem ext4 image path (empty = daemon default)
    #[arg(long, conflicts_with_all = ["from_dockerfile", "from_image"])]
    pub rootfs: Option<String>,
    /// Build sandbox rootfs from a Dockerfile
    #[arg(long, conflicts_with_all = ["rootfs", "from_image"])]
    pub from_dockerfile: Option<String>,
    /// Build sandbox rootfs from an existing Docker image
    #[arg(long, conflicts_with_all = ["rootfs", "from_dockerfile"])]
    pub from_image: Option<String>,
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
    /// Sandbox ID
    pub id: String,
    /// Seconds to wait before force-killing (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub timeout: u32,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Sandbox ID
    pub id: String,
    /// Force removal even if running
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Filter by state (starting/ready/running/stopped/failed)
    #[arg(long)]
    pub state: Option<String>,
    /// Only show IDs
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Sandbox ID
    pub id: String,
}

#[derive(Args)]
pub struct RunArgs {
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
pub struct ExecArgs {
    /// Sandbox ID
    pub id: String,
    /// Command and arguments
    #[arg(trailing_var_arg = true, required = true)]
    pub cmd: Vec<String>,
    /// Allocate a pseudo-TTY
    #[arg(short = 't', long)]
    pub tty: bool,
    /// Kill after this many seconds (0 = no timeout)
    #[arg(long, default_value = "0")]
    pub timeout: u32,
}

#[derive(Args)]
pub struct EventsArgs {
    /// Filter by sandbox ID (empty = all sandboxes)
    #[arg(long)]
    pub id: Option<String>,
    /// Filter by action (empty = all actions)
    #[arg(long)]
    pub action: Option<String>,
}

#[derive(Args)]
pub struct CheckpointArgs {
    /// Sandbox ID to checkpoint
    pub id: String,
    /// Human-readable snapshot name
    #[arg(long, default_value = "")]
    pub name: String,
}

#[derive(Args)]
pub struct RestoreArgs {
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
    /// Filter by origin sandbox ID (empty = all)
    #[arg(long)]
    pub sandbox_id: Option<String>,
}

#[derive(Args)]
pub struct DeleteSnapshotArgs {
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
        SandboxCommands::Exec(args) => execute_exec(args).await,
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

    // Resolve rootfs from whichever flag was provided.
    let rootfs = if let Some(path) = &args.from_dockerfile {
        arcbox_cli::rootfs_builder::resolve_from_dockerfile(path)
            .await
            .context("Failed to build Docker image from Dockerfile")?
    } else if let Some(image_ref) = &args.from_image {
        arcbox_cli::rootfs_builder::resolve_from_image(image_ref)
            .await
            .context("Failed to resolve Docker image")?
    } else {
        args.rootfs.clone().unwrap_or_default()
    };

    let req = CreateSandboxRequest {
        id: args.id.unwrap_or_default(),
        labels,
        kernel: args.kernel.unwrap_or_default(),
        rootfs,
        limits: Some(ResourceLimits {
            vcpus: args.cpus,
            memory_mib: args.memory,
        }),
        ttl_seconds: args.ttl,
        ..Default::default()
    };

    let resp = client
        .create(attach_machine(tonic::Request::new(req)))
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
        .stop(attach_machine(tonic::Request::new(req)))
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
        .remove(attach_machine(tonic::Request::new(req)))
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
        .list(attach_machine(tonic::Request::new(req)))
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
        println!("No sandboxes found.");
        return Ok(());
    }

    println!("{:<36} {:<12} {:<18} CREATED", "ID", "STATE", "IP");
    for sb in &sandboxes {
        println!(
            "{:<36} {:<12} {:<18} {}",
            sb.id, sb.state, sb.ip_address, sb.created_at,
        );
    }
    Ok(())
}

async fn execute_inspect(args: InspectArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let req = InspectSandboxRequest { id: args.id };
    let info = client
        .inspect(attach_machine(tonic::Request::new(req)))
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
        id: args.id,
        cmd: args.cmd,
        tty: args.tty,
        timeout_seconds: args.timeout,
        ..Default::default()
    };

    let mut stream = client
        .run(attach_machine(tonic::Request::new(req)))
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

async fn execute_exec(args: ExecArgs) -> Result<()> {
    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel);

    let (msg_tx, msg_rx) = tokio::sync::mpsc::channel::<ExecInput>(16);

    // Detect initial terminal size when TTY is requested.
    let tty_size = if args.tty {
        TerminalSize::current().ok().map(|s| ProtoTerminalSize {
            width: u32::from(s.cols),
            height: u32::from(s.rows),
        })
    } else {
        None
    };

    // The first message in the stream must be the Init payload.
    msg_tx
        .send(ExecInput {
            payload: Some(exec_input::Payload::Init(ExecRequest {
                id: args.id,
                cmd: args.cmd,
                tty: args.tty,
                tty_size,
                timeout_seconds: args.timeout,
                ..Default::default()
            })),
        })
        .await
        .context("Failed to send exec init")?;

    // Enable raw terminal mode when TTY is requested.
    let raw_guard = if args.tty {
        Some(RawModeGuard::new()?)
    } else {
        None
    };

    // Stdin pump: local terminal → gRPC stream.
    // NOTE: TTY resize (SIGWINCH) is not yet forwarded — the gRPC→agent
    // pipeline has no resize wire message. Will be added when the full
    // resize path is wired up.
    let stdin_tx = msg_tx;
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdin_tx
                        .send(ExecInput {
                            payload: Some(exec_input::Payload::Stdin(buf[..n].to_vec())),
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

    let request = attach_machine(tonic::Request::new(ReceiverStream::new(msg_rx)));
    let mut stream = client
        .exec(request)
        .await
        .context("Failed to exec in sandbox")?
        .into_inner();

    let mut exit_code = 0i32;
    let mut received_done = false;
    while let Some(output) = stream
        .message()
        .await
        .context("Failed to read exec output")?
    {
        if !output.data.is_empty() {
            match output.stream.as_str() {
                "stderr" => {
                    std::io::stderr()
                        .write_all(&output.data)
                        .context("Failed to write stderr")?;
                    std::io::stderr().flush()?;
                }
                _ => {
                    std::io::stdout()
                        .write_all(&output.data)
                        .context("Failed to write stdout")?;
                    std::io::stdout().flush()?;
                }
            }
        }
        if output.done {
            exit_code = output.exit_code;
            received_done = true;
        }
    }

    // Drop the raw mode guard before exiting so the terminal is restored.
    drop(raw_guard);

    if !received_done {
        anyhow::bail!("exec stream closed without a terminal status frame");
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
        .events(attach_machine(tonic::Request::new(req)))
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
        sandbox_id: args.id,
        name: args.name,
        labels: HashMap::new(),
    };
    let resp = client
        .checkpoint(attach_machine(tonic::Request::new(req)))
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
        snapshot_id: args.snapshot_id,
        ttl_seconds: args.ttl,
        ..Default::default()
    };
    let resp = client
        .restore(attach_machine(tonic::Request::new(req)))
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
        .list_snapshots(attach_machine(tonic::Request::new(req)))
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
        .delete_snapshot(attach_machine(tonic::Request::new(req)))
        .await
        .context("Failed to delete snapshot")?;

    println!("Snapshot '{}' deleted", args.snapshot_id);
    Ok(())
}
