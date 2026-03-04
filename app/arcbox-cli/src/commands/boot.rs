//! Boot asset management commands.
//!
//! Manage kernel and rootfs files required for VM boot.

use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

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
    // Use Config::load() so the cache directory are consistent with daemon.
    let config = arcbox_core::Config::load().unwrap_or_default();
    let boot_cache_dir = config.data_dir.join("boot");

    match command {
        BootCommands::Prefetch(args) => prefetch(&config.data_dir, boot_cache_dir, args).await,
        BootCommands::Status => status(boot_cache_dir).await,
        BootCommands::Clear => clear(boot_cache_dir).await,
        BootCommands::List => list(boot_cache_dir).await,
    }
}

/// Prefetch boot assets and runtime binaries.
async fn prefetch(
    root_data_dir: &Path,
    boot_cache_dir: PathBuf,
    args: PrefetchArgs,
) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider, DownloadProgress};

    println!("Prefetching boot assets...");

    let mut config = BootAssetConfig::with_cache_dir(boot_cache_dir);

    if let Some(version) = args.asset_version {
        config = config.with_version(version);
    }

    let provider = BootAssetProvider::with_config(config.clone())?;

    // Clear cache if force.
    if args.force {
        provider.clear_cache().await?;
    }

    let make_progress_callback = || -> Box<dyn Fn(DownloadProgress) + Send + Sync> {
        Box::new(|progress: DownloadProgress| {
            use arcbox_core::boot_assets::PreparePhase;
            use std::io::Write;

            let status = match &progress.phase {
                PreparePhase::Checking => format!(
                    "[{}/{}] {} checking...",
                    progress.current, progress.total, progress.name
                ),
                PreparePhase::Downloading { downloaded, total } => {
                    if let Some(t) = total {
                        let pct = if *t > 0 { downloaded * 100 / t } else { 0 };
                        format!(
                            "[{}/{}] {} downloading {}%",
                            progress.current, progress.total, progress.name, pct
                        )
                    } else {
                        format!(
                            "[{}/{}] {} downloading {} bytes",
                            progress.current, progress.total, progress.name, downloaded
                        )
                    }
                }
                PreparePhase::Verifying => format!(
                    "[{}/{}] {} verifying...",
                    progress.current, progress.total, progress.name
                ),
                PreparePhase::Ready => format!(
                    "[{}/{}] {} ready",
                    progress.current, progress.total, progress.name
                ),
                PreparePhase::Cached => format!(
                    "[{}/{}] {} cached",
                    progress.current, progress.total, progress.name
                ),
            };
            print!("\r{:<60}", status);
            let _ = std::io::stdout().flush();
        })
    };

    // 1. Prefetch boot assets (kernel + rootfs).
    // prepare() is idempotent — skips download if already cached and valid.
    provider
        .prefetch_with_progress(Some(make_progress_callback()))
        .await?;
    println!("\n  Boot assets ready");

    // 2. Download runtime binaries (dockerd, containerd, shim, runc).
    // Also idempotent — skips if cached and checksum matches.
    let runtime_bin_dir = root_data_dir.join("runtime/bin");
    tokio::fs::create_dir_all(&runtime_bin_dir).await?;

    provider
        .prepare_binaries(&runtime_bin_dir, Some(make_progress_callback()))
        .await?;
    println!("\n  Runtime binaries ready");

    Ok(())
}

/// Show boot asset status.
async fn status(data_dir: PathBuf) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let config = BootAssetConfig::with_cache_dir(data_dir.clone());
    let provider = BootAssetProvider::with_config(config.clone())?;
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
        let rootfs = version_dir.join("rootfs.erofs");

        if kernel.exists() {
            let meta = std::fs::metadata(&kernel)?;
            println!("  Kernel:    {} ({} bytes)", kernel.display(), meta.len());
        }

        if rootfs.exists() {
            let meta = std::fs::metadata(&rootfs)?;
            println!("  Rootfs:    {} ({} bytes)", rootfs.display(), meta.len());
        }

        // Manifest is required for cached assets to be considered valid.
        // `is_cached()` already ensures the file exists; validate its contents.
        match provider.read_cached_manifest_required().await {
            Ok(manifest) => {
                println!(
                    "  Manifest:  ✓ {}",
                    version_dir.join("manifest.json").display()
                );
                println!("  Schema:    v{}", manifest.schema_version);
                println!("  Build At:  {}", manifest.built_at);
                println!(
                    "  Source:    {}",
                    manifest.source_sha.as_deref().unwrap_or("unknown")
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
        let rootfs_exists = version_dir.join("rootfs.erofs").exists();
        let manifest_exists = version_dir.join("manifest.json").exists();

        if !kernel_exists && !rootfs_exists && !manifest_exists {
            println!("Status: ✗ Not cached");
        } else {
            println!("Status: ✗ Incomplete");
            println!(
                "  Kernel:    {}",
                if kernel_exists { "✓" } else { "✗ missing" }
            );
            println!(
                "  Rootfs:    {}",
                if rootfs_exists { "✓" } else { "✗ missing" }
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
    let provider = BootAssetProvider::with_config(config)?;

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
    let provider = BootAssetProvider::with_config(config)?;

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
