//! Images command implementation.

use anyhow::Result;
use arcbox_cli::client::{DaemonClient, ImageSummary};
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
    let daemon = DaemonClient::new();
    if daemon.is_running().await {
        return execute_via_daemon(&daemon, &args).await;
    }

    anyhow::bail!("daemon is not running; start it with `arcbox daemon`")
}

async fn execute_via_daemon(daemon: &DaemonClient, args: &ImagesArgs) -> Result<()> {
    let path = if args.all {
        "/v1.43/images/json?all=true"
    } else {
        "/v1.43/images/json"
    };

    let images: Vec<ImageSummary> = daemon.get(path).await?;

    if args.quiet {
        for image in &images {
            let id = if args.no_trunc {
                image.id.clone()
            } else {
                short_id(&image.id)
            };
            println!("{id}");
        }
        return Ok(());
    }

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
        let (repo, tag) = parse_repo_tag(
            image
                .repo_tags
                .first()
                .map(std::string::String::as_str)
                .unwrap_or("<none>:<none>"),
        );

        let id_or_digest = if args.digests || args.no_trunc {
            image.id.clone()
        } else {
            short_id(&image.id)
        };

        let created = format_duration_ago_ts(image.created);
        let size = format_size(image.size.max(0) as u64);

        if args.digests {
            println!("{repo:<30} {tag:<15} {id_or_digest:<71} {created:<15} {size:<10}");
        } else {
            println!("{repo:<30} {tag:<15} {id_or_digest:<15} {created:<15} {size:<10}");
        }
    }

    Ok(())
}

/// Executes the rmi command.
pub async fn execute_rmi(args: RmiArgs) -> Result<()> {
    let daemon = DaemonClient::new();
    if daemon.is_running().await {
        return execute_rmi_via_daemon(&daemon, &args).await;
    }

    anyhow::bail!("daemon is not running; start it with `arcbox daemon`")
}

async fn execute_rmi_via_daemon(daemon: &DaemonClient, args: &RmiArgs) -> Result<()> {
    let mut errors = Vec::new();

    for image_name in &args.images {
        let encoded = url_encode_image_ref(image_name);
        let path = format!(
            "/v1.43/images/{}?force={}&noprune={}",
            encoded, args.force, args.no_prune
        );

        match daemon.delete(&path).await {
            Ok(()) => println!("Untagged: {}", image_name),
            Err(e) => {
                if args.force {
                    tracing::warn!("Error removing {}: {}", image_name, e);
                } else {
                    errors.push(format!("{}: {}", image_name, e));
                }
            }
        }
    }

    if !errors.is_empty() {
        anyhow::bail!("failed to remove image(s): {}", errors.join("; "));
    }

    Ok(())
}

/// Extracts short ID (12 chars after sha256: prefix).
fn short_id(digest: &str) -> String {
    let s = digest.strip_prefix("sha256:").unwrap_or(digest);
    s[..12.min(s.len())].to_string()
}

fn parse_repo_tag(repo_tag: &str) -> (String, String) {
    if let Some((repo, tag)) = repo_tag.rsplit_once(':') {
        return (repo.to_string(), tag.to_string());
    }
    (repo_tag.to_string(), "<none>".to_string())
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

fn format_duration_ago_ts(timestamp: i64) -> String {
    if let Some(time) = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0) {
        format_duration_ago(time)
    } else {
        "unknown".to_string()
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

fn url_encode_image_ref(image: &str) -> String {
    image
        .replace('%', "%25")
        .replace('/', "%2F")
        .replace(':', "%3A")
}
