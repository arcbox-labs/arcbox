//! Stop command implementation.

use arcbox_cli::client;
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
    let daemon = client::get_client().await?;

    let path = format!("/v1.43/containers/{}/stop?t={}", args.container, args.time);
    daemon.post_empty::<()>(&path, None).await?;

    println!("{}", args.container);

    Ok(())
}
