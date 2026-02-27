use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use vmm_grpc::proto::sandbox::{
    CheckpointRequest, CreateSandboxRequest, DeleteSnapshotRequest, InspectSandboxRequest,
    ListSandboxesRequest, ListSnapshotsRequest, RemoveSandboxRequest, ResourceLimits,
    RestoreRequest, SandboxEventsRequest, StopSandboxRequest,
    sandbox_service_client::SandboxServiceClient,
    sandbox_snapshot_service_client::SandboxSnapshotServiceClient,
};

/// vmm — firecracker-vmm sandbox management CLI
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Unix socket path of the vmm-daemon.
    #[arg(
        short,
        long,
        default_value = "/run/firecracker-vmm/vmm.sock",
        env = "VMM_SOCKET"
    )]
    socket: String,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Create a sandbox (returns immediately; VM boots asynchronously).
    Create {
        /// Caller-supplied sandbox ID (auto-generated when omitted).
        #[arg(long, default_value = "")]
        id: String,
        /// Number of vCPUs (0 = daemon default).
        #[arg(long, default_value_t = 0)]
        vcpus: u32,
        /// Memory in MiB (0 = daemon default).
        #[arg(long, default_value_t = 0)]
        memory: u64,
        /// Kernel image path (daemon default when omitted).
        #[arg(long, default_value = "")]
        kernel: String,
        /// Root filesystem image path (daemon default when omitted).
        #[arg(long, default_value = "")]
        rootfs: String,
        /// Auto-destroy TTL in seconds (0 = no limit).
        #[arg(long, default_value_t = 0)]
        ttl: u32,
        /// Labels in key=value format (repeatable).
        #[arg(long = "label")]
        labels: Vec<String>,
    },

    /// Stop a sandbox gracefully.
    Stop {
        /// Sandbox ID.
        id: String,
        /// Seconds to wait before force-killing (0 = daemon default of 30 s).
        #[arg(long, default_value_t = 0)]
        timeout: u32,
    },

    /// Forcibly remove a sandbox and release all resources.
    Remove {
        /// Sandbox ID.
        id: String,
        /// Force removal even if sandbox is running.
        #[arg(short, long)]
        force: bool,
    },

    /// List sandboxes.
    List {
        /// Filter by state (starting|ready|running|stopping|stopped|failed).
        #[arg(long, default_value = "")]
        state: String,
    },

    /// Show detailed information about a sandbox.
    Inspect {
        /// Sandbox ID.
        id: String,
    },

    /// Subscribe to sandbox lifecycle events (streams until Ctrl-C).
    Events {
        /// Filter by sandbox ID (empty = all sandboxes).
        #[arg(long, default_value = "")]
        id: String,
        /// Filter by action (empty = all actions).
        #[arg(long, default_value = "")]
        action: String,
    },

    /// Checkpoint and restore management.
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
}

#[derive(Subcommand, Debug)]
enum SnapshotCmd {
    /// Checkpoint a sandbox into a reusable snapshot.
    Create {
        /// Sandbox ID to checkpoint.
        sandbox_id: String,
        /// Human-readable label for the snapshot.
        #[arg(long, default_value = "")]
        name: String,
    },
    /// Restore a new sandbox from a checkpoint.
    Restore {
        /// Snapshot ID.
        snapshot_id: String,
        /// ID to assign to the restored sandbox (auto-generated when omitted).
        #[arg(long, default_value = "")]
        id: String,
        /// Assign a fresh TAP interface and IP to the restored sandbox.
        #[arg(long)]
        network_override: bool,
        /// Auto-destroy TTL in seconds (0 = no limit).
        #[arg(long, default_value_t = 0)]
        ttl: u32,
    },
    /// List checkpoints.
    List {
        /// Filter by sandbox ID (empty = all).
        #[arg(long, default_value = "")]
        sandbox_id: String,
    },
    /// Delete a checkpoint and its on-disk data.
    Delete {
        /// Snapshot ID.
        snapshot_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt().with_env_filter("warn").init();

    let channel = connect_uds(&cli.socket).await?;

    match cli.command {
        Cmd::Create {
            id,
            vcpus,
            memory,
            kernel,
            rootfs,
            ttl,
            labels,
        } => {
            let mut client = SandboxServiceClient::new(channel);
            let label_map = parse_labels(&labels)?;
            let resp = client
                .create(CreateSandboxRequest {
                    id,
                    limits: Some(ResourceLimits {
                        vcpus,
                        memory_mib: memory,
                    }),
                    kernel,
                    rootfs,
                    ttl_seconds: ttl,
                    labels: label_map,
                    ..Default::default()
                })
                .await
                .context("create sandbox")?;
            let r = resp.into_inner();
            println!("Sandbox ID:  {}", r.id);
            println!("IP address:  {}", r.ip_address);
            println!(
                "State:       {} (poll `vmm inspect` or watch `vmm events`)",
                r.state
            );
        }

        Cmd::Stop { id, timeout } => {
            let mut client = SandboxServiceClient::new(channel);
            client
                .stop(StopSandboxRequest {
                    id,
                    timeout_seconds: timeout,
                })
                .await
                .context("stop sandbox")?;
            println!("Sandbox stopped.");
        }

        Cmd::Remove { id, force } => {
            let mut client = SandboxServiceClient::new(channel);
            client
                .remove(RemoveSandboxRequest { id, force })
                .await
                .context("remove sandbox")?;
            println!("Sandbox removed.");
        }

        Cmd::List { state } => {
            let mut client = SandboxServiceClient::new(channel);
            let resp = client
                .list(ListSandboxesRequest {
                    state,
                    ..Default::default()
                })
                .await
                .context("list sandboxes")?;
            let sandboxes = resp.into_inner().sandboxes;
            if sandboxes.is_empty() {
                println!("No sandboxes found.");
            } else {
                println!("{:<36}  {:<10}  IP", "ID", "STATE");
                for s in sandboxes {
                    println!("{:<36}  {:<10}  {}", s.id, s.state, s.ip_address);
                }
            }
        }

        Cmd::Inspect { id } => {
            let mut client = SandboxServiceClient::new(channel);
            let resp = client
                .inspect(InspectSandboxRequest { id })
                .await
                .context("inspect sandbox")?;
            let s = resp.into_inner();
            let limits = s.limits.unwrap_or_default();
            let net = s.network.unwrap_or_default();
            println!("ID:           {}", s.id);
            println!("State:        {}", s.state);
            println!("vCPUs:        {}", limits.vcpus);
            println!("Memory (MiB): {}", limits.memory_mib);
            println!("IP address:   {}", net.ip_address);
            println!("Gateway:      {}", net.gateway);
            println!("TAP:          {}", net.tap_name);
            if !s.error.is_empty() {
                println!("Error:        {}", s.error);
            }
        }

        Cmd::Events { id, action } => {
            let mut client = SandboxServiceClient::new(channel);
            let mut stream = client
                .events(SandboxEventsRequest { id, action })
                .await
                .context("subscribe events")?
                .into_inner();
            println!("Listening for events (Ctrl-C to stop)…");
            loop {
                match stream.message().await {
                    Ok(Some(ev)) => println!(
                        "  ts={}  sandbox={}  action={}  attrs={:?}",
                        ev.timestamp, ev.sandbox_id, ev.action, ev.attributes
                    ),
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("stream error: {e}");
                        break;
                    }
                }
            }
        }

        Cmd::Snapshot(snap_cmd) => run_snapshot(channel, snap_cmd).await?,
    }

    Ok(())
}

async fn run_snapshot(channel: Channel, cmd: SnapshotCmd) -> Result<()> {
    match cmd {
        SnapshotCmd::Create { sandbox_id, name } => {
            let mut client = SandboxSnapshotServiceClient::new(channel);
            let resp = client
                .checkpoint(CheckpointRequest {
                    sandbox_id,
                    name,
                    labels: Default::default(),
                })
                .await
                .context("checkpoint sandbox")?;
            let r = resp.into_inner();
            println!("Snapshot ID:  {}", r.snapshot_id);
            println!("Directory:    {}", r.snapshot_dir);
            println!("Created at:   {}", r.created_at);
        }

        SnapshotCmd::Restore {
            snapshot_id,
            id,
            network_override,
            ttl,
        } => {
            let mut client = SandboxSnapshotServiceClient::new(channel);
            let resp = client
                .restore(RestoreRequest {
                    id,
                    snapshot_id,
                    network_override,
                    ttl_seconds: ttl,
                    labels: Default::default(),
                })
                .await
                .context("restore sandbox")?;
            let r = resp.into_inner();
            println!("Restored sandbox ID: {}", r.id);
            println!("IP address:          {}", r.ip_address);
        }

        SnapshotCmd::List { sandbox_id } => {
            let mut client = SandboxSnapshotServiceClient::new(channel);
            let resp = client
                .list_snapshots(ListSnapshotsRequest {
                    sandbox_id,
                    labels: Default::default(),
                })
                .await
                .context("list snapshots")?;
            let snaps = resp.into_inner().snapshots;
            if snaps.is_empty() {
                println!("No snapshots found.");
            } else {
                println!(
                    "{:<36}  {:<36}  {:<20}  CREATED",
                    "ID", "SANDBOX_ID", "NAME"
                );
                for s in snaps {
                    println!(
                        "{:<36}  {:<36}  {:<20}  {}",
                        s.id, s.sandbox_id, s.name, s.created_at
                    );
                }
            }
        }

        SnapshotCmd::Delete { snapshot_id } => {
            let mut client = SandboxSnapshotServiceClient::new(channel);
            client
                .delete_snapshot(DeleteSnapshotRequest { snapshot_id })
                .await
                .context("delete snapshot")?;
            println!("Snapshot deleted.");
        }
    }
    Ok(())
}

/// Parse `"key=value"` label strings into a `HashMap`.
fn parse_labels(labels: &[String]) -> Result<std::collections::HashMap<String, String>> {
    labels
        .iter()
        .map(|l| {
            let (k, v) = l
                .split_once('=')
                .with_context(|| format!("label must be key=value, got: {l}"))?;
            Ok((k.to_owned(), v.to_owned()))
        })
        .collect()
}

/// Connect to the daemon via a Unix domain socket.
///
/// tonic 0.12 / hyper 1.x requires wrapping the stream in `TokioIo`.
async fn connect_uds(socket_path: &str) -> Result<Channel> {
    let path = socket_path.to_owned();
    let channel = Endpoint::try_from("http://[::]:0")
        .context("endpoint")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&p).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| format!("failed to connect to {socket_path}"))?;
    Ok(channel)
}
