//! macOS guest management commands (Apple Silicon only).
//!
//! Disposable, single-purpose macOS VMs: install a base image once from an
//! IPSW, then copy-on-write clone it to boot clean, throwaway guests. This is a
//! distinct noun from `arcbox machine` (Linux) and talks to its own
//! `MacosService`.

use anyhow::{Context, Result};
use arcbox_grpc::v1::macos_service_client::MacosServiceClient;
use arcbox_protocol::v1::{
    CreateMacosMachineRequest, Empty, MacosImagePullRequest, MacosImageRemoveRequest,
    RemoveMacosMachineRequest, StartMacosMachineRequest, StopMacosMachineRequest,
};
use clap::{Args, Subcommand};
use tonic::transport::{Channel, Endpoint};

use super::machine::UnixConnector;

async fn macos_client() -> Result<MacosServiceClient<Channel>> {
    let socket_path = super::resolve_grpc_socket_path();
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector::new(socket_path.clone()))
        .await
        .with_context(|| {
            format!(
                "Failed to connect to ArcBox gRPC daemon at {}",
                socket_path.display()
            )
        })?;
    Ok(MacosServiceClient::new(channel))
}

fn title_case(state: &str) -> String {
    let mut chars = state.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// macOS guest management commands (Apple Silicon only).
#[derive(Subcommand)]
pub enum MacosCommands {
    /// Create a guest by copy-on-write cloning a base image
    Create(CreateArgs),
    /// Start a guest
    Start(NameArgs),
    /// Stop a guest
    Stop(NameArgs),
    /// Remove a guest
    #[command(alias = "rm")]
    Remove(RemoveArgs),
    /// List guests
    #[command(name = "ls", alias = "list")]
    List,
    /// Manage macOS base images
    #[command(subcommand)]
    Image(ImageCommands),
}

#[derive(Args)]
pub struct CreateArgs {
    /// Guest name.
    pub name: String,
    /// Base image to clone.
    #[arg(long)]
    pub image: String,
    /// Number of CPUs.
    #[arg(long, default_value = "4", value_parser = clap::value_parser!(u32).range(1..))]
    pub cpus: u32,
    /// Memory in MiB.
    #[arg(long, default_value = "8192")]
    pub memory: u64,
}

#[derive(Args)]
pub struct NameArgs {
    /// Guest name.
    pub name: String,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Guest name.
    pub name: String,
    /// Remove even if running (stops it first).
    #[arg(short, long)]
    pub force: bool,
}

/// macOS base image commands.
#[derive(Subcommand)]
pub enum ImageCommands {
    /// Install a base image from a local IPSW (long-running)
    Pull(PullArgs),
    /// List base images
    #[command(name = "ls", alias = "list")]
    List,
    /// Remove a base image
    #[command(alias = "rm")]
    Remove(ImageRemoveArgs),
}

#[derive(Args)]
pub struct PullArgs {
    /// Base image name.
    pub name: String,
    /// Path to a local IPSW restore image. Omit to download the latest from Apple.
    #[arg(long)]
    pub ipsw: Option<String>,
    /// System disk size in GB.
    #[arg(long, default_value = "64")]
    pub disk: u64,
}

#[derive(Args)]
pub struct ImageRemoveArgs {
    /// Base image name.
    pub name: String,
}

/// Executes a macOS command.
pub async fn execute(cmd: MacosCommands) -> Result<()> {
    match cmd {
        MacosCommands::Create(args) => execute_create(args).await,
        MacosCommands::Start(args) => execute_start(args).await,
        MacosCommands::Stop(args) => execute_stop(args).await,
        MacosCommands::Remove(args) => execute_remove(args).await,
        MacosCommands::List => execute_list().await,
        MacosCommands::Image(c) => execute_image(c).await,
    }
}

async fn execute_create(args: CreateArgs) -> Result<()> {
    let mut client = macos_client().await?;
    client
        .create(tonic::Request::new(CreateMacosMachineRequest {
            name: args.name.clone(),
            image: args.image.clone(),
            cpus: args.cpus,
            memory_mib: args.memory,
        }))
        .await
        .context("Failed to create macOS guest")?;

    println!(
        "macOS guest '{}' created from image '{}'",
        args.name, args.image
    );
    println!("  CPUs:   {}", args.cpus);
    println!("  Memory: {} MiB", args.memory);
    println!();
    println!("To start it, run:");
    println!("  arcbox macos start {}", args.name);
    Ok(())
}

async fn execute_start(args: NameArgs) -> Result<()> {
    let mut client = macos_client().await?;
    println!("Starting macOS guest '{}'...", args.name);
    client
        .start(tonic::Request::new(StartMacosMachineRequest {
            name: args.name.clone(),
        }))
        .await
        .context("Failed to start macOS guest")?;
    println!("macOS guest '{}' started", args.name);
    Ok(())
}

async fn execute_stop(args: NameArgs) -> Result<()> {
    let mut client = macos_client().await?;
    println!("Stopping macOS guest '{}'...", args.name);
    client
        .stop(tonic::Request::new(StopMacosMachineRequest {
            name: args.name.clone(),
        }))
        .await
        .context("Failed to stop macOS guest")?;
    println!("macOS guest '{}' stopped", args.name);
    Ok(())
}

async fn execute_remove(args: RemoveArgs) -> Result<()> {
    let mut client = macos_client().await?;
    client
        .remove(tonic::Request::new(RemoveMacosMachineRequest {
            name: args.name.clone(),
            force: args.force,
        }))
        .await
        .context("Failed to remove macOS guest")?;
    println!("macOS guest '{}' removed", args.name);
    Ok(())
}

async fn execute_list() -> Result<()> {
    let mut client = macos_client().await?;
    let machines = client
        .list(tonic::Request::new(Empty {}))
        .await
        .context("Failed to list macOS guests")?
        .into_inner()
        .machines;

    if machines.is_empty() {
        println!("No macOS guests found.");
        println!();
        println!("To create one, run:");
        println!("  arcbox macos create <name> --image <base>");
        return Ok(());
    }

    println!(
        "{:<20} {:<12} {:<6} {:<12} {:<16}",
        "NAME", "STATE", "CPUS", "MEMORY", "IMAGE"
    );
    for m in &machines {
        println!(
            "{:<20} {:<12} {:<6} {:<12} {:<16}",
            m.name,
            title_case(&m.state),
            m.cpus,
            format!("{} MiB", m.memory_mib),
            m.image,
        );
    }
    Ok(())
}

async fn execute_image(cmd: ImageCommands) -> Result<()> {
    match cmd {
        ImageCommands::Pull(args) => {
            let mut client = macos_client().await?;
            let source = args
                .ipsw
                .as_deref()
                .unwrap_or("latest (download from Apple)");
            println!(
                "Installing macOS image '{}' from {source} (this can take 10-20 minutes)...",
                args.name
            );
            client
                .image_pull(tonic::Request::new(MacosImagePullRequest {
                    name: args.name.clone(),
                    ipsw_path: args.ipsw.unwrap_or_default(),
                    disk_gb: args.disk,
                }))
                .await
                .context("Failed to install macOS image")?;
            println!("macOS image '{}' installed", args.name);
            Ok(())
        }
        ImageCommands::List => {
            let mut client = macos_client().await?;
            let images = client
                .image_list(tonic::Request::new(Empty {}))
                .await
                .context("Failed to list macOS images")?
                .into_inner()
                .images;

            if images.is_empty() {
                println!("No macOS images found.");
                println!();
                println!("To install one, run:");
                println!("  arcbox macos image pull <name> --ipsw <path>");
                return Ok(());
            }

            println!(
                "{:<20} {:<6} {:<10} {:<8}",
                "NAME", "CPUS", "MEMORY", "DISK"
            );
            for image in &images {
                println!(
                    "{:<20} {:<6} {:<10} {:<8}",
                    image.name,
                    image.minimum_cpu_count,
                    format!("{} MB", image.minimum_memory_mib),
                    format!("{} GB", image.disk_gb),
                );
            }
            Ok(())
        }
        ImageCommands::Remove(args) => {
            let mut client = macos_client().await?;
            client
                .image_remove(tonic::Request::new(MacosImageRemoveRequest {
                    name: args.name.clone(),
                }))
                .await
                .context("Failed to remove macOS image")?;
            println!("macOS image '{}' removed", args.name);
            Ok(())
        }
    }
}
