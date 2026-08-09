//! Boot asset cache commands.

use arcbox_constants::paths::ArcboxProfile;
use arcbox_core::boot_assets::BootAssetConfig;
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
    let boot_config = boot_asset_config(&config);
    let cache_dir = boot_config.cache_dir.clone();

    match command {
        BootCommands::Prefetch(args) => {
            cache::prefetch(&config.data_dir, boot_config, args, format).await
        }
        BootCommands::Status(args) => status::status(boot_config, args, format).await,
        BootCommands::Clear => cache::clear(cache_dir, format).await,
        BootCommands::List => cache::list(cache_dir, format).await,
    }
}

fn boot_asset_config(config: &arcbox_core::Config) -> BootAssetConfig {
    BootAssetConfig::with_cache_dir(config.data_dir.join("boot"))
        .with_unpinned_manifest_allowed(config.profile == ArcboxProfile::Development)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcbox_core::boot_assets::BootAssetProvider;

    #[tokio::test]
    async fn development_profile_accepts_a_local_boot_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = arcbox_core::Config::for_profile(ArcboxProfile::Development);
        config.data_dir = directory.path().to_owned();
        let development = boot_asset_config(&config);
        std::fs::create_dir_all(development.version_cache_dir()).unwrap();
        std::fs::write(
            development.version_cache_dir().join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 0,
                "asset_version": development.version.clone(),
                "built_at": "now",
                "targets": {},
                "binaries": []
            }))
            .unwrap(),
        )
        .unwrap();

        BootAssetProvider::with_config(development)
            .unwrap()
            .read_cached_manifest_required()
            .await
            .unwrap();

        config.profile = ArcboxProfile::Production;
        let error = BootAssetProvider::with_config(boot_asset_config(&config))
            .unwrap()
            .read_cached_manifest_required()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("manifest SHA256 mismatch"));
    }
}
