//! Stop command implementation.

use anyhow::Result;
use clap::Args;

/// Arguments for the stop command.
#[derive(Args)]
pub struct StopArgs {
    /// Container ID or name
    pub container: String,

    /// Timeout in seconds
    #[arg(short, long, default_value = "10")]
    pub time: u32,
}

/// Executes the stop command.
pub async fn execute(args: StopArgs) -> Result<()> {
    tracing::info!("Stopping container: {}", args.container);

    // TODO: Connect to daemon and stop container
    println!("{}", args.container);

    Ok(())
}
