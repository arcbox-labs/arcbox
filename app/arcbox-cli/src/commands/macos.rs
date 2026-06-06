//! macOS guest image management commands.

use anyhow::{Context, Result};
use arcbox_protocol::v1::{Empty, MacImagePullRequest, MacImageRemoveRequest};
use clap::{Args, Subcommand};

use super::machine::machine_client;

/// macOS guest management commands (Apple Silicon only).
#[derive(Subcommand)]
pub enum MacosCommands {
    /// Manage macOS base images
    #[command(subcommand)]
    Image(ImageCommands),
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
    Remove(RemoveArgs),
}

#[derive(Args)]
pub struct PullArgs {
    /// Base image name.
    pub name: String,
    /// Path to a local IPSW restore image.
    #[arg(long)]
    pub ipsw: String,
    /// CPUs for the install VM.
    #[arg(long, default_value = "4")]
    pub cpus: u32,
    /// Memory in MB for the install VM.
    #[arg(long, default_value = "8192")]
    pub memory: u64,
    /// System disk size in GB.
    #[arg(long, default_value = "64")]
    pub disk: u64,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Base image name.
    pub name: String,
}

/// Executes a macOS command.
pub async fn execute(cmd: MacosCommands) -> Result<()> {
    match cmd {
        MacosCommands::Image(c) => execute_image(c).await,
    }
}

async fn execute_image(cmd: ImageCommands) -> Result<()> {
    match cmd {
        ImageCommands::Pull(args) => {
            let mut client = machine_client().await?;
            println!(
                "Installing macOS image '{}' from {} (this can take 10-20 minutes)...",
                args.name, args.ipsw
            );
            client
                .mac_image_pull(tonic::Request::new(MacImagePullRequest {
                    name: args.name.clone(),
                    ipsw_path: args.ipsw,
                    cpus: args.cpus,
                    memory: args.memory.saturating_mul(1024 * 1024),
                    disk_size: args.disk.saturating_mul(1024 * 1024 * 1024),
                }))
                .await
                .context("Failed to install macOS image")?;
            println!("macOS image '{}' installed", args.name);
            Ok(())
        }
        ImageCommands::List => {
            let mut client = machine_client().await?;
            let images = client
                .mac_image_list(tonic::Request::new(Empty {}))
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
            let mut client = machine_client().await?;
            client
                .mac_image_remove(tonic::Request::new(MacImageRemoveRequest {
                    name: args.name.clone(),
                }))
                .await
                .context("Failed to remove macOS image")?;
            println!("macOS image '{}' removed", args.name);
            Ok(())
        }
    }
}
