//! Run command implementation.

use anyhow::Result;
use clap::Args;

/// Arguments for the run command.
#[derive(Args)]
pub struct RunArgs {
    /// Image to run
    pub image: String,

    /// Command to execute
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,

    /// Container name
    #[arg(long)]
    pub name: Option<String>,

    /// Run in detached mode
    #[arg(short, long)]
    pub detach: bool,

    /// Remove container when it exits
    #[arg(long)]
    pub rm: bool,

    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,

    /// Keep STDIN open
    #[arg(short, long)]
    pub interactive: bool,

    /// Environment variables
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Volume mounts
    #[arg(short, long)]
    pub volume: Vec<String>,

    /// Port mappings
    #[arg(short, long)]
    pub publish: Vec<String>,

    /// Working directory
    #[arg(short, long)]
    pub workdir: Option<String>,
}

/// Executes the run command.
pub async fn execute(args: RunArgs) -> Result<()> {
    tracing::info!("Running container from image: {}", args.image);

    // TODO: Connect to arcbox daemon and create/start container
    println!("arcbox run {} {:?}", args.image, args.command);

    if !args.detach {
        // TODO: Attach to container
    }

    Ok(())
}
