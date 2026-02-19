//! Restart command implementation.

use anyhow::Result;
use arcbox_cli::client;
use clap::Args;

/// Arguments for the restart command.
#[derive(Args)]
pub struct RestartArgs {
    /// Container ID or name
    pub container: String,

    /// Timeout in seconds
    #[arg(short, long, default_value = "10")]
    pub time: u32,
}

/// Executes the restart command.
pub async fn execute(args: RestartArgs) -> Result<()> {
    let daemon = client::get_client().await?;

    let path = format!(
        "/v1.43/containers/{}/restart?t={}",
        args.container, args.time
    );
    daemon.post_empty::<()>(&path, None).await?;

    println!("{}", args.container);
    Ok(())
}
