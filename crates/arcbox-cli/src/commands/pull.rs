//! Pull command implementation.

use std::sync::Arc;

use anyhow::Result;
use arcbox_image::{pull::ConsoleProgress, ImageRef, ImageStore, RegistryClient};
use clap::Args;

/// Arguments for the pull command.
#[derive(Args)]
pub struct PullArgs {
    /// Image to pull (e.g., alpine:latest, nginx:1.25)
    pub image: String,

    /// Pull all tags
    #[arg(short, long)]
    pub all_tags: bool,

    /// Suppress progress output
    #[arg(short, long)]
    pub quiet: bool,
}

/// Executes the pull command.
pub async fn execute(args: PullArgs) -> Result<()> {
    // Parse image reference.
    let reference = ImageRef::parse(&args.image)
        .ok_or_else(|| anyhow::anyhow!("invalid image reference: {}", args.image))?;

    if !args.quiet {
        println!("Pulling {}...", reference);
    }

    // Open image store.
    let store = Arc::new(ImageStore::open_default()?);

    // Create registry client.
    let client = RegistryClient::new(&reference.registry);

    // Create puller.
    let puller = arcbox_image::pull::ImagePuller::new(store, client);

    // Pull with or without progress.
    let image_id = if args.quiet {
        puller.pull(&reference).await?
    } else {
        puller
            .with_progress(ConsoleProgress)
            .pull(&reference)
            .await?
    };

    // Print result.
    let short_id = short_digest(&image_id);
    if !args.quiet {
        println!("Successfully pulled {}", reference);
        println!("Image ID: {short_id}");
    } else {
        println!("{short_id}");
    }

    Ok(())
}

/// Extracts short digest (12 chars after sha256: prefix).
fn short_digest(digest: &str) -> &str {
    let s = digest.strip_prefix("sha256:").unwrap_or(digest);
    &s[..12.min(s.len())]
}
