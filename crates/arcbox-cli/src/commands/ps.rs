//! Ps (list containers) command implementation.

use crate::client::{self, ContainerSummary};
use anyhow::Result;
use clap::Args;

/// Arguments for the ps command.
#[derive(Args)]
pub struct PsArgs {
    /// Show all containers (including stopped)
    #[arg(short, long)]
    pub all: bool,

    /// Only show container IDs
    #[arg(short, long)]
    pub quiet: bool,

    /// Show sizes
    #[arg(short, long)]
    pub size: bool,
}

/// Executes the ps command.
pub async fn execute(args: PsArgs) -> Result<()> {
    let daemon = client::get_client().await?;

    // Build query string
    let path = if args.all {
        "/v1.43/containers/json?all=true"
    } else {
        "/v1.43/containers/json"
    };

    let containers: Vec<ContainerSummary> = daemon.get(path).await?;

    if args.quiet {
        // Just print IDs
        for container in containers {
            println!("{}", client::short_id(&container.id));
        }
    } else {
        // Print table header
        println!(
            "{:<12} {:<20} {:<20} {:<15} {:<20}",
            "CONTAINER ID", "IMAGE", "COMMAND", "STATUS", "NAMES"
        );

        // Print containers
        for container in containers {
            let names = container
                .names
                .first()
                .map(|n| n.trim_start_matches('/'))
                .unwrap_or("unknown");

            println!(
                "{:<12} {:<20} {:<20} {:<15} {:<20}",
                client::short_id(&container.id),
                client::truncate(&container.image, 20),
                client::truncate(&container.command, 20),
                container.status,
                client::truncate(names, 20),
            );
        }
    }

    Ok(())
}
