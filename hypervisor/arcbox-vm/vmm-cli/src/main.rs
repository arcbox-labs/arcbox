use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use vmm_grpc::proto::arcbox::{
    machine_service_client::MachineServiceClient,
    system_service_client::SystemServiceClient,
    CreateMachineRequest, InspectMachineRequest, ListMachinesRequest,
    RemoveMachineRequest, StartMachineRequest, StopMachineRequest,
    SshInfoRequest, SystemPingRequest,
};
use vmm_grpc::proto::vmm::{
    vmm_service_client::VmmServiceClient,
    CreateSnapshotRequest, DeleteSnapshotRequest, GetMetricsRequest,
    ListSnapshotsRequest, PauseVmRequest, RestoreSnapshotRequest, ResumeVmRequest,
};

/// vmm — firecracker-vmm management CLI
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
    /// Create and boot a new VM.
    Create {
        /// VM name (must be unique).
        name: String,
        /// Number of vCPUs.
        #[arg(short, long, default_value_t = 1)]
        cpus: u32,
        /// Memory in MiB.
        #[arg(short, long, default_value_t = 512)]
        memory: u64,
        /// Kernel image path (uses daemon config default when omitted).
        #[arg(long, default_value = "")]
        kernel: String,
    },
    /// Start a stopped VM.
    Start {
        /// VM ID or name.
        id: String,
    },
    /// Stop a running VM.
    Stop {
        /// VM ID or name.
        id: String,
        /// Force-kill instead of graceful shutdown.
        #[arg(short, long)]
        force: bool,
    },
    /// Remove a VM.
    Remove {
        /// VM ID or name.
        id: String,
        /// Force removal.
        #[arg(short, long)]
        force: bool,
    },
    /// List VMs.
    List {
        /// Show all VMs (including stopped).
        #[arg(short, long)]
        all: bool,
    },
    /// Inspect a VM (detailed JSON output).
    Inspect {
        /// VM ID or name.
        id: String,
    },
    /// Print SSH connection info for a VM.
    SshInfo {
        /// VM ID or name.
        id: String,
    },
    /// Pause a running VM.
    Pause {
        /// VM ID or name.
        id: String,
    },
    /// Resume a paused VM.
    Resume {
        /// VM ID or name.
        id: String,
    },
    /// Snapshot management.
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Show VM metrics.
    Metrics {
        /// VM ID or name.
        id: String,
    },
    /// Check daemon liveness.
    Ping,
    /// Show daemon version.
    Version,
}

#[derive(Subcommand, Debug)]
enum SnapshotCmd {
    /// Create a snapshot.
    Create {
        /// VM ID.
        id: String,
        /// Optional label.
        #[arg(long)]
        name: Option<String>,
        /// Snapshot type: full or diff.
        #[arg(long, default_value = "full")]
        r#type: String,
    },
    /// List snapshots for a VM.
    List {
        /// VM ID.
        id: String,
    },
    /// Restore a VM from a snapshot.
    Restore {
        /// Name for the restored VM.
        name: String,
        /// Snapshot directory path.
        snapshot_dir: String,
        /// Assign a fresh network interface.
        #[arg(long)]
        network_override: bool,
    },
    /// Delete a snapshot.
    Delete {
        /// VM ID.
        vm_id: String,
        /// Snapshot ID.
        snapshot_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .init();

    let channel = connect_uds(&cli.socket).await?;

    match cli.command {
        Cmd::Create { name, cpus, memory, kernel } => {
            let mut client = MachineServiceClient::new(channel);
            let resp = client
                .create(CreateMachineRequest {
                    name: name.clone(),
                    cpus,
                    memory: memory * 1024 * 1024,
                    kernel,
                    ..Default::default()
                })
                .await
                .context("create VM")?;
            println!("Created VM: {}", resp.into_inner().id);
        }

        Cmd::Start { id } => {
            let mut client = MachineServiceClient::new(channel);
            client
                .start(StartMachineRequest { id })
                .await
                .context("start VM")?;
            println!("VM started");
        }

        Cmd::Stop { id, force } => {
            let mut client = MachineServiceClient::new(channel);
            client
                .stop(StopMachineRequest { id, force })
                .await
                .context("stop VM")?;
            println!("VM stopped");
        }

        Cmd::Remove { id, force } => {
            let mut client = MachineServiceClient::new(channel);
            client
                .remove(RemoveMachineRequest { id, force, volumes: false })
                .await
                .context("remove VM")?;
            println!("VM removed");
        }

        Cmd::List { all } => {
            let mut client = MachineServiceClient::new(channel);
            let resp = client
                .list(ListMachinesRequest { all })
                .await
                .context("list VMs")?;
            let machines = resp.into_inner().machines;
            if machines.is_empty() {
                println!("No VMs found.");
            } else {
                println!("{:<36}  {:<20}  {:<10}  {:>6}  {:>8}  {}",
                    "ID", "NAME", "STATE", "CPUS", "MEM(MiB)", "IP");
                for m in machines {
                    println!("{:<36}  {:<20}  {:<10}  {:>6}  {:>8}  {}",
                        m.id, m.name, m.state, m.cpus,
                        m.memory / (1024 * 1024),
                        m.ip_address);
                }
            }
        }

        Cmd::Inspect { id } => {
            let mut client = MachineServiceClient::new(channel);
            let resp = client
                .inspect(InspectMachineRequest { id })
                .await
                .context("inspect VM")?;
            println!("{:#?}", resp.into_inner());
        }

        Cmd::SshInfo { id } => {
            let mut client = MachineServiceClient::new(channel);
            let resp = client
                .ssh_info(SshInfoRequest { id })
                .await
                .context("SSH info")?;
            let info = resp.into_inner();
            println!("Host:    {}", info.host);
            println!("Port:    {}", info.port);
            println!("User:    {}", info.user);
            println!("Command: {}", info.command);
        }

        Cmd::Pause { id } => {
            let mut client = VmmServiceClient::new(channel);
            client
                .pause(PauseVmRequest { id })
                .await
                .context("pause VM")?;
            println!("VM paused");
        }

        Cmd::Resume { id } => {
            let mut client = VmmServiceClient::new(channel);
            client
                .resume(ResumeVmRequest { id })
                .await
                .context("resume VM")?;
            println!("VM resumed");
        }

        Cmd::Snapshot(snap_cmd) => run_snapshot(channel, snap_cmd).await?,

        Cmd::Metrics { id } => {
            let mut client = VmmServiceClient::new(channel);
            let resp = client
                .get_metrics(GetMetricsRequest { id })
                .await
                .context("get metrics")?;
            let m = resp.into_inner();
            println!("VM ID:               {}", m.vm_id);
            println!("Balloon target (MiB): {}", m.balloon_target_mib);
            println!("Balloon actual (MiB): {}", m.balloon_actual_mib);
        }

        Cmd::Ping => {
            let mut client = SystemServiceClient::new(channel);
            let resp = client
                .ping(SystemPingRequest {})
                .await
                .context("ping")?;
            let r = resp.into_inner();
            println!("OK  api={} build={}", r.api_version, r.build_version);
        }

        Cmd::Version => {
            let mut client = SystemServiceClient::new(channel);
            let resp = client
                .get_version(vmm_grpc::proto::arcbox::GetVersionRequest {})
                .await
                .context("get version")?;
            let v = resp.into_inner();
            println!("Version:   {}", v.version);
            println!("API:       {}", v.api_version);
            println!("OS/Arch:   {}/{}", v.os, v.arch);
            println!("Commit:    {}", v.git_commit);
        }
    }

    Ok(())
}

async fn run_snapshot(channel: Channel, cmd: SnapshotCmd) -> Result<()> {
    let mut client = VmmServiceClient::new(channel);
    match cmd {
        SnapshotCmd::Create { id, name, r#type } => {
            let resp = client
                .create_snapshot(CreateSnapshotRequest {
                    id,
                    name: name.unwrap_or_default(),
                    snapshot_type: r#type,
                })
                .await
                .context("create snapshot")?;
            let s = resp.into_inner();
            println!("Snapshot ID:  {}", s.snapshot_id);
            println!("Directory:    {}", s.snapshot_dir);
            println!("Created at:   {}", s.created_at);
        }

        SnapshotCmd::List { id } => {
            let resp = client
                .list_snapshots(ListSnapshotsRequest { id })
                .await
                .context("list snapshots")?;
            let snaps = resp.into_inner().snapshots;
            if snaps.is_empty() {
                println!("No snapshots found.");
            } else {
                println!("{:<36}  {:<20}  {:<8}  {}", "ID", "NAME", "TYPE", "CREATED");
                for s in snaps {
                    println!("{:<36}  {:<20}  {:<8}  {}", s.id, s.name, s.snapshot_type, s.created_at);
                }
            }
        }

        SnapshotCmd::Restore { name, snapshot_dir, network_override } => {
            let resp = client
                .restore_snapshot(RestoreSnapshotRequest {
                    name,
                    snapshot_dir,
                    network_override,
                })
                .await
                .context("restore snapshot")?;
            println!("Restored VM: {}", resp.into_inner().id);
        }

        SnapshotCmd::Delete { vm_id, snapshot_id } => {
            client
                .delete_snapshot(DeleteSnapshotRequest { vm_id, snapshot_id })
                .await
                .context("delete snapshot")?;
            println!("Snapshot deleted");
        }
    }
    Ok(())
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
