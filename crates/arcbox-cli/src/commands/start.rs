//! Start command implementation.

use anyhow::Result;
use clap::Args;

/// Arguments for the start command.
#[derive(Args)]
pub struct StartArgs {
    /// Container ID or name
    pub container: String,

    /// Attach to container
    #[arg(short, long)]
    pub attach: bool,

    /// Attach STDIN
    #[arg(short, long)]
    pub interactive: bool,
}

/// Executes the start command.
pub async fn execute(args: StartArgs) -> Result<()> {
    tracing::info!("Starting container: {}", args.container);

    // TODO: Connect to daemon and start container
    println!("{}", args.container);

    Ok(())
}
