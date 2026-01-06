//! Ps (list containers) command implementation.

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
    // TODO: Connect to daemon and list containers

    if args.quiet {
        // Just print IDs
    } else {
        println!(
            "{:<12} {:<20} {:<20} {:<15} {:<20}",
            "CONTAINER ID", "IMAGE", "COMMAND", "STATUS", "NAMES"
        );
    }

    Ok(())
}
