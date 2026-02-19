//! Boot asset management commands.
//!
//! Manage kernel and initramfs files required for VM boot.

use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Boot asset management commands.
#[derive(Subcommand)]
pub enum BootCommands {
    /// Download boot assets in advance
    Prefetch(PrefetchArgs),

    /// Show boot asset status
    Status,

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

/// Execute boot commands.
pub async fn execute(command: BootCommands) -> anyhow::Result<()> {
    // Use Config::load() so the cache directory is consistent with daemon.
    let config = arcbox_core::Config::load().unwrap_or_default();
    let data_dir = config.data_dir.join("boot");

    match command {
        BootCommands::Prefetch(args) => prefetch(data_dir, args).await,
        BootCommands::Status => status(data_dir).await,
        BootCommands::Clear => clear(data_dir).await,
        BootCommands::List => list(data_dir).await,
    }
}

/// Prefetch boot assets.
async fn prefetch(data_dir: PathBuf, args: PrefetchArgs) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider, DownloadProgress};

    println!("Prefetching boot assets...");

    let mut config = BootAssetConfig::with_cache_dir(data_dir);

    if let Some(version) = args.asset_version {
        config = config.with_version(version);
    }

    let provider = BootAssetProvider::with_config(config.clone());

    // Check if already cached (unless force).
    if !args.force && provider.is_cached() {
        println!("Boot assets already cached (version: {})", config.version);
        println!("Use --force to re-download.");
        return Ok(());
    }

    // Clear cache if force.
    if args.force {
        provider.clear_cache().await?;
    }

    // Create progress callback.
    let progress_callback = Box::new(|progress: DownloadProgress| {
        if let Some(pct) = progress.percentage() {
            print!("\r{} [{}%]", progress.phase, pct);
        } else {
            print!("\r{}", progress.phase);
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();
    });

    // Prefetch with progress.
    provider
        .prefetch_with_progress(Some(progress_callback))
        .await?;

    println!("\n✓ Boot assets ready");

    Ok(())
}

/// Show boot asset status.
async fn status(data_dir: PathBuf) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let config = BootAssetConfig::with_cache_dir(data_dir.clone());
    let provider = BootAssetProvider::with_config(config.clone());
    let version_dir = config.version_cache_dir();

    println!("Boot Asset Status");
    println!("=================");
    println!();
    println!("Cache directory: {}", data_dir.display());
    println!("Current version: {}", config.version);
    println!("Architecture:    {}", config.arch);
    println!();

    if provider.is_cached() {
        println!("Status: ✓ Cached and valid");

        let kernel = version_dir.join("kernel");
        let initramfs = version_dir.join("initramfs.cpio.gz");

        if kernel.exists() {
            let meta = std::fs::metadata(&kernel)?;
            println!("  Kernel:    {} ({} bytes)", kernel.display(), meta.len());
        }

        if initramfs.exists() {
            let meta = std::fs::metadata(&initramfs)?;
            println!(
                "  Initramfs: {} ({} bytes)",
                initramfs.display(),
                meta.len()
            );
        }

        // Manifest is required for cached assets to be considered valid.
        // `is_cached()` already ensures the file exists; validate its contents.
        match provider.read_cached_manifest_required().await {
            Ok(manifest) => {
                println!(
                    "  Manifest:  ✓ {}",
                    version_dir.join("manifest.json").display()
                );
                println!("  Schema:    {}", manifest.schema_version);
                println!(
                    "  Build At:  {}",
                    manifest.built_at.as_deref().unwrap_or("unknown")
                );
                println!(
                    "  Kernel SHA: {}",
                    manifest.kernel_commit.as_deref().unwrap_or("unknown")
                );
                println!(
                    "  Agent SHA:  {}",
                    manifest.agent_commit.as_deref().unwrap_or("unknown")
                );
            }
            Err(e) => {
                println!("  Manifest:  ✗ INVALID");
                println!("  Error:     {}", e);
                println!();
                println!("Boot will FAIL with the current assets.");
                println!("Run 'arcbox boot prefetch --force' to re-download.");
            }
        }
    } else {
        // Determine what is missing for a more helpful diagnostic.
        let kernel_exists = version_dir.join("kernel").exists();
        let initramfs_exists = version_dir.join("initramfs.cpio.gz").exists();
        let manifest_exists = version_dir.join("manifest.json").exists();

        if !kernel_exists && !initramfs_exists && !manifest_exists {
            println!("Status: ✗ Not cached");
        } else {
            println!("Status: ✗ Incomplete");
            println!(
                "  Kernel:    {}",
                if kernel_exists { "✓" } else { "✗ missing" }
            );
            println!(
                "  Initramfs: {}",
                if initramfs_exists {
                    "✓"
                } else {
                    "✗ missing"
                }
            );
            println!(
                "  Manifest:  {}",
                if manifest_exists {
                    "✓"
                } else {
                    "✗ missing (required)"
                }
            );
        }

        println!();
        println!("Boot will FAIL without valid cached assets.");
        println!("Run 'arcbox boot prefetch' to download boot assets.");
    }

    Ok(())
}

/// Clear cached boot assets.
async fn clear(data_dir: PathBuf) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let config = BootAssetConfig::with_cache_dir(data_dir.clone());
    let provider = BootAssetProvider::with_config(config);

    if !data_dir.exists() {
        println!("Cache directory does not exist.");
        return Ok(());
    }

    println!("Clearing boot asset cache...");
    provider.clear_cache().await?;
    println!("✓ Cache cleared");

    Ok(())
}

/// List cached versions.
async fn list(data_dir: PathBuf) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let config = BootAssetConfig::with_cache_dir(data_dir);
    let provider = BootAssetProvider::with_config(config);

    let versions = provider.list_cached_versions().await?;

    if versions.is_empty() {
        println!("No cached versions found.");
        println!("Run 'arcbox boot prefetch' to download boot assets.");
    } else {
        println!("Cached versions:");
        for version in versions {
            println!("  - {}", version);
        }
    }

    Ok(())
}
