//! Start command implementation.

use arcbox_cli::client;
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
    let daemon = client::get_client().await?;

    let path = format!("/v1.43/containers/{}/start", args.container);
    daemon.post_empty::<()>(&path, None).await?;

    println!("{}", args.container);

    // TODO: Implement attach mode if args.attach is set
    if args.attach {
        tracing::warn!("Attach mode not yet implemented");
    }

    Ok(())
}
