//! Rm (remove container) command implementation.

use anyhow::Result;
use clap::Args;

/// Arguments for the rm command.
#[derive(Args)]
pub struct RmArgs {
    /// Container names or IDs
    #[arg(required = true)]
    pub containers: Vec<String>,

    /// Force removal of running containers
    #[arg(short, long)]
    pub force: bool,

    /// Remove associated volumes
    #[arg(short, long)]
    pub volumes: bool,

    /// Remove the specified link
    #[arg(short, long)]
    pub link: bool,
}

/// Executes the rm command.
pub async fn execute(args: RmArgs) -> Result<()> {
    for container in &args.containers {
        tracing::info!("Removing container: {}", container);

        // TODO: Connect to daemon and remove container
        println!("{container}");
    }

    Ok(())
}
