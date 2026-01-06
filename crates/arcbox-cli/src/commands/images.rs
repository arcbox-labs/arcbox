//! Images command implementation.

use anyhow::Result;
use arcbox_image::{ImageRef, ImageStore};
use clap::Args;

/// Arguments for the images command.
#[derive(Args)]
pub struct ImagesArgs {
    /// Show all images
    #[arg(short, long)]
    pub all: bool,

    /// Only show image IDs
    #[arg(short, long)]
    pub quiet: bool,

    /// Show digests
    #[arg(long)]
    pub digests: bool,

    /// Don't truncate output
    #[arg(long)]
    pub no_trunc: bool,

    /// Filter output based on conditions
    #[arg(short, long)]
    pub filter: Vec<String>,
}

/// Arguments for the rmi (remove image) command.
#[derive(Args)]
pub struct RmiArgs {
    /// Image names or IDs to remove
    #[arg(required = true)]
    pub images: Vec<String>,

    /// Force removal of the image
    #[arg(short, long)]
    pub force: bool,

    /// Do not delete untagged parents
    #[arg(long)]
    pub no_prune: bool,
}

/// Executes the images command.
pub async fn execute(args: ImagesArgs) -> Result<()> {
    let store = ImageStore::open_default()?;
    let images = store.list();

    if args.quiet {
        for image in &images {
            let id = if args.no_trunc {
                image.id.clone()
            } else {
                short_id(&image.id)
            };
            println!("{id}");
        }
    } else {
        // Print header.
        if args.digests {
            println!(
                "{:<30} {:<15} {:<71} {:<15} {:<10}",
                "REPOSITORY", "TAG", "DIGEST", "CREATED", "SIZE"
            );
        } else {
            println!(
                "{:<30} {:<15} {:<15} {:<15} {:<10}",
                "REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"
            );
        }

        for image in &images {
            let repo = format!(
                "{}/{}",
                image.reference.registry, image.reference.repository
            );
            // Simplify Docker Hub display.
            let repo = repo
                .strip_prefix("docker.io/library/")
                .unwrap_or(&repo)
                .to_string();

            let tag = &image.reference.reference;

            let id_or_digest = if args.digests {
                image.id.clone()
            } else if args.no_trunc {
                image.id.clone()
            } else {
                short_id(&image.id)
            };

            let created = format_duration_ago(image.created);
            let size = format_size(image.size);

            if args.digests {
                println!("{repo:<30} {tag:<15} {id_or_digest:<71} {created:<15} {size:<10}");
            } else {
                println!("{repo:<30} {tag:<15} {id_or_digest:<15} {created:<15} {size:<10}");
            }
        }
    }

    Ok(())
}

/// Executes the rmi command.
pub async fn execute_rmi(args: RmiArgs) -> Result<()> {
    let store = ImageStore::open_default()?;

    for image_name in &args.images {
        let reference = ImageRef::parse(image_name)
            .ok_or_else(|| anyhow::anyhow!("invalid image reference: {}", image_name))?;

        match store.remove(&reference) {
            Ok(()) => {
                println!("Untagged: {}", reference);
            }
            Err(e) => {
                if args.force {
                    tracing::warn!("Error removing {}: {}", image_name, e);
                } else {
                    return Err(e.into());
                }
            }
        }
    }

    Ok(())
}

/// Extracts short ID (12 chars after sha256: prefix).
fn short_id(digest: &str) -> String {
    let s = digest.strip_prefix("sha256:").unwrap_or(digest);
    s[..12.min(s.len())].to_string()
}

/// Formats a timestamp as a human-readable duration (e.g., "2 hours ago").
fn format_duration_ago(time: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(time);

    if duration.num_seconds() < 60 {
        "Just now".to_string()
    } else if duration.num_minutes() < 60 {
        let mins = duration.num_minutes();
        format!("{} minute{} ago", mins, if mins == 1 { "" } else { "s" })
    } else if duration.num_hours() < 24 {
        let hours = duration.num_hours();
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if duration.num_days() < 30 {
        let days = duration.num_days();
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else if duration.num_days() < 365 {
        let months = duration.num_days() / 30;
        format!("{} month{} ago", months, if months == 1 { "" } else { "s" })
    } else {
        let years = duration.num_days() / 365;
        format!("{} year{} ago", years, if years == 1 { "" } else { "s" })
    }
}

/// Formats a size in bytes as a human-readable string.
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}
