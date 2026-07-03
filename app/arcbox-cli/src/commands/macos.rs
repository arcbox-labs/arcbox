//! macOS guest management commands (Apple Silicon only).
//!
//! Disposable, single-purpose macOS VMs: pull a pre-baked base image once,
//! then copy-on-write clone it to boot clean, throwaway guests. This is a
//! distinct noun from `arcbox machine` (Linux) and talks to its own
//! `MacosService`.

use anyhow::{Context, Result};
use arcbox_grpc::v1::macos_service_client::MacosServiceClient;
use arcbox_protocol::v1::{
    CreateMacosMachineRequest, Empty, InspectMacosMachineRequest, MacosImagePullRequest,
    MacosImageRemoveRequest, MacosImageResolveRequest, RemoveMacosMachineRequest,
    StartMacosMachineRequest, StopMacosMachineRequest,
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
    /// Print a running guest's IP address (from its DHCP lease)
    Ip(IpArgs),
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
pub struct IpArgs {
    /// Guest name.
    pub name: String,
    /// Keep retrying for up to this many seconds — a freshly started guest
    /// takes a few seconds to acquire its DHCP lease.
    #[arg(long, default_value = "0")]
    pub wait: u16,
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
    /// Pull a published base image (e.g. tahoe-base or tahoe-base@2026.07.02)
    Pull(SourceArgs),
    /// Resolve a reference against the published index without downloading:
    /// what version a pull would land, and what is installed locally
    Resolve(SourceArgs),
    /// List base images
    #[command(name = "ls", alias = "list")]
    List,
    /// Remove a base image
    #[command(alias = "rm")]
    Remove(ImageRemoveArgs),
}

/// Where an image comes from — shared by `pull` and `resolve`, which take
/// the same source.
#[derive(Args)]
pub struct SourceArgs {
    /// Image reference: stream name with optional pinned version
    /// (e.g. "tahoe-base" or "tahoe-base@2026.07.02").
    #[arg(required_unless_present = "manifest", conflicts_with = "manifest")]
    pub reference: Option<String>,
    /// Use a manifest directly (URL or daemon-local path), bypassing the
    /// published index.
    #[arg(long)]
    pub manifest: Option<String>,
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
        MacosCommands::Ip(args) => execute_ip(args).await,
        MacosCommands::Image(c) => execute_image(c).await,
    }
}

async fn execute_ip(args: IpArgs) -> Result<()> {
    let mut client = macos_client().await?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.wait.into());
    loop {
        let info = client
            .inspect(tonic::Request::new(InspectMacosMachineRequest {
                name: args.name.clone(),
            }))
            .await
            .context("Failed to inspect macOS guest")?
            .into_inner();
        if !info.ip_address.is_empty() {
            println!("{}", info.ip_address);
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            let hint = if info.state == "running" {
                "the guest has not acquired a DHCP lease yet — try --wait 30"
            } else {
                "is the guest running?"
            };
            anyhow::bail!("no IP address found for '{}' ({hint})", args.name);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
            use std::io::Write as _;

            let mut client = macos_client().await?;
            let what = args
                .reference
                .clone()
                .or_else(|| args.manifest.clone())
                .unwrap_or_default();
            let mut stream = client
                .image_pull(tonic::Request::new(MacosImagePullRequest {
                    reference: args.reference.unwrap_or_default(),
                    manifest_url: args.manifest.unwrap_or_default(),
                }))
                .await
                .context("Failed to pull macOS image")?
                .into_inner();

            let mut last_stage = String::new();
            let mut landed = None;
            while let Some(event) = stream
                .message()
                .await
                .context("Failed to pull macOS image")?
            {
                // The terminal event carries the landed image instead of
                // progress; report it as the outcome, not as a stage line.
                if let Some(image) = event.image {
                    landed = Some(image);
                    continue;
                }
                if event.stage != last_stage && !last_stage.is_empty() {
                    println!();
                }
                last_stage.clone_from(&event.stage);
                print!("\r{}: {:>3.0}%", event.stage, event.fraction * 100.0);
                let _ = std::io::stdout().flush();
            }
            println!();
            match landed {
                Some(image) => println!("macOS image '{}@{}' pulled", image.name, image.version),
                None => println!("macOS image '{what}' pulled"),
            }
            Ok(())
        }
        ImageCommands::Resolve(args) => {
            let mut client = macos_client().await?;
            let info = client
                .image_resolve(tonic::Request::new(MacosImageResolveRequest {
                    reference: args.reference.unwrap_or_default(),
                    manifest_url: args.manifest.unwrap_or_default(),
                }))
                .await
                .context("Failed to resolve macOS image")?
                .into_inner();
            println!("{}@{}", info.name, info.version);
            println!("os: macOS {}", info.os_version);
            println!(
                "requires: {} CPUs, {} MiB memory, {} GB disk",
                info.minimum_cpu_count, info.minimum_memory_mib, info.disk_gb
            );
            if info.installed_version.is_empty() {
                println!("installed: (none)");
            } else if info.installed_version == info.version {
                println!("installed: {} (up to date)", info.installed_version);
            } else {
                println!("installed: {} (update available)", info.installed_version);
            }
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
                println!("To pull one, run:");
                println!("  arcbox macos image pull tahoe-base");
                return Ok(());
            }

            println!(
                "{:<20} {:<14} {:<8} {:<8} {:<12}",
                "NAME", "VERSION", "OS", "DISK", "CREATED"
            );
            for image in &images {
                let created = chrono::DateTime::from_timestamp(image.created, 0)
                    .map(|t| t.format("%Y-%m-%d").to_string())
                    .unwrap_or_default();
                println!(
                    "{:<20} {:<14} {:<8} {:<8} {:<12}",
                    image.name,
                    if image.version.is_empty() {
                        "-"
                    } else {
                        &image.version
                    },
                    if image.os_version.is_empty() {
                        "-"
                    } else {
                        &image.os_version
                    },
                    format!("{} GB", image.disk_gb),
                    created,
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
