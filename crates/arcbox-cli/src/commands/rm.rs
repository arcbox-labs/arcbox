//! Rm (remove container) command implementation.

use anyhow::Result;
use arcbox_cli::client;
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
    let daemon = client::get_client().await?;

    for container in &args.containers {
        let path = format!(
            "/v1.43/containers/{}?force={}&v={}",
            container, args.force, args.volumes
        );

        match daemon.delete(&path).await {
            Ok(()) => {
                println!("{container}");
            }
            Err(e) => {
                eprintln!("Error removing {}: {}", container, e);
            }
        }
    }

    Ok(())
}
