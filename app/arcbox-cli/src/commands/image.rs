//! Image subcommands (docker-compatible `image ...` namespace).

use anyhow::Result;
use arcbox_cli::client::DaemonClient;
use clap::{Args, Subcommand};
use serde_json::Value;

#[derive(Subcommand)]
pub enum ImageCommands {
    /// Show detailed information on one or more images
    Inspect(ImageInspectArgs),
}

#[derive(Args)]
pub struct ImageInspectArgs {
    /// Image names or IDs to inspect
    #[arg(required = true)]
    pub images: Vec<String>,
}

pub async fn execute(args: ImageCommands) -> Result<()> {
    match args {
        ImageCommands::Inspect(inspect) => execute_inspect(inspect).await,
    }
}

async fn execute_inspect(args: ImageInspectArgs) -> Result<()> {
    let daemon = DaemonClient::new();
    if !daemon.is_running().await {
        anyhow::bail!("daemon is not running");
    }

    let mut inspected = Vec::with_capacity(args.images.len());
    for image in args.images {
        let encoded = url_encode_image_ref(&image);
        let path = format!("/v1.43/images/{}/json", encoded);
        let image_info: Value = daemon.get(&path).await?;
        inspected.push(image_info);
    }

    println!("{}", serde_json::to_string_pretty(&inspected)?);
    Ok(())
}

fn url_encode_image_ref(image: &str) -> String {
    image
        .replace('%', "%25")
        .replace('/', "%2F")
        .replace(':', "%3A")
}
