//! Boot asset cache commands.

use clap::{Args, Subcommand};

use super::OutputFormat;

mod cache;
mod status;

/// Boot asset management commands.
#[derive(Subcommand)]
pub enum BootCommands {
    /// Download boot assets in advance
    Prefetch(PrefetchArgs),
    /// Show boot asset status
    Status(StatusArgs),
    /// Clear cached boot assets
    Clear,
    /// List cached versions
    List,
}

/// Arguments for prefetch command.
#[derive(Args)]
pub struct PrefetchArgs {
    /// Force re-download even if cached
    #[arg(long, short)]
    pub force: bool,
    /// Asset version to download (default: current version)
    #[arg(long = "asset-version")]
    pub asset_version: Option<String>,
}

/// Arguments for status command.
#[derive(Args)]
pub struct StatusArgs {
    /// Skip network request for latest version check
    #[arg(long)]
    pub offline: bool,
}

/// Execute boot commands.
pub async fn execute(command: BootCommands, format: OutputFormat) -> anyhow::Result<()> {
    let config = arcbox_core::Config::load()?;
    let cache_dir = config.data_dir.join("boot");

    match command {
        BootCommands::Prefetch(args) => {
            cache::prefetch(&config.data_dir, cache_dir, args, format).await
        }
        BootCommands::Status(args) => status::status(cache_dir, args, format).await,
        BootCommands::Clear => cache::clear(cache_dir, format).await,
        BootCommands::List => cache::list(cache_dir, format).await,
    }
}
