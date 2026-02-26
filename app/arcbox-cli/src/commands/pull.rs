//! Pull command implementation.

use anyhow::Result;
use arcbox_image::ImageRef;
use clap::Args;

use crate::client::DaemonClient;

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

    /// Show progress output (docker-compatible flag; currently informational)
    #[arg(long)]
    pub progress: bool,
}

/// Executes the pull command.
pub async fn execute(args: PullArgs) -> Result<()> {
    // Parse image reference.
    let reference = ImageRef::parse(&args.image)
        .ok_or_else(|| anyhow::anyhow!("invalid image reference: {}", args.image))?;

    if !args.quiet {
        println!("Pulling {}...", reference);
    }

    // Check if daemon is running - if so, use daemon API to ensure consistent data_dir.
    let daemon = DaemonClient::new();
    if daemon.is_running().await {
        return execute_via_daemon(&daemon, &reference, args.quiet).await;
    }

    anyhow::bail!("daemon is not running; start it with `arcbox daemon`")
}

/// Executes pull via daemon API.
async fn execute_via_daemon(
    daemon: &DaemonClient,
    reference: &ImageRef,
    quiet: bool,
) -> Result<()> {
    // Docker API: POST /images/create?fromImage=<image>&tag=<tag>
    let path = format!(
        "/v1.43/images/create?fromImage={}/{}&tag={}",
        reference.registry, reference.repository, reference.reference
    );

    // This is a streaming response - read it line by line for progress.
    let response = daemon.post_streaming(&path).await?;

    // Parse progress stream.
    for line in response.split('\n').filter(|l| !l.is_empty()) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(status) = json.get("status").and_then(|s| s.as_str()) {
                if !quiet {
                    tracing::info!("{}", status);
                }
            }
            if let Some(error) = json.get("error").and_then(|s| s.as_str()) {
                return Err(anyhow::anyhow!("pull failed: {}", error));
            }
        }
    }

    // Get image ID from images list.
    // URL-encode the filter JSON.
    let filter = format!("{{\"reference\":[\"{}\"]}}", reference);
    let encoded_filter = filter
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace('"', "%22")
        .replace('/', "%2F")
        .replace(':', "%3A");
    let images: Vec<serde_json::Value> = daemon
        .get(&format!("/v1.43/images/json?filters={}", encoded_filter))
        .await
        .unwrap_or_default();

    if let Some(image) = images.first() {
        if let Some(id) = image.get("Id").and_then(|s| s.as_str()) {
            let short_id = short_digest(id);
            if !quiet {
                println!("Pull complete: {short_id}");
                println!("Successfully pulled {}", reference);
                println!("Image ID: {short_id}");
            } else {
                println!("{short_id}");
            }
        }
    } else if !quiet {
        println!("Successfully pulled {}", reference);
    }

    Ok(())
}

/// Extracts short digest (12 chars after sha256: prefix).
fn short_digest(digest: &str) -> &str {
    let s = digest.strip_prefix("sha256:").unwrap_or(digest);
    &s[..12.min(s.len())]
}
