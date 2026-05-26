//! Boot asset management commands.
//!
//! Manage kernel and rootfs files required for VM boot.

use super::OutputFormat;
use clap::{Args, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};

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

// =============================================================================
// JSON output structures
// =============================================================================

/// JSON output for `arcbox boot status`.
#[derive(Serialize)]
struct StatusOutput {
    version: String,
    arch: String,
    cache_dir: String,
    cached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    assets: Option<AssetDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<ManifestInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_version: Option<String>,
    update_available: bool,
}

/// Cached asset file details.
#[derive(Serialize)]
struct AssetDetails {
    kernel_path: String,
    kernel_size: u64,
    rootfs_path: String,
    rootfs_size: u64,
}

/// Parsed manifest metadata.
#[derive(Serialize)]
struct ManifestInfo {
    schema_version: u32,
    built_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sha: Option<String>,
}

/// NDJSON progress line for `arcbox boot prefetch`.
#[derive(Serialize, Default)]
struct PrefetchProgress {
    phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    downloaded_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    percent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// JSON output for `arcbox boot list`.
#[derive(Serialize)]
struct ListOutput {
    versions: Vec<String>,
}

/// JSON output for `arcbox boot clear`.
#[derive(Serialize)]
struct ClearOutput {
    cleared: bool,
}

// =============================================================================
// Command dispatch
// =============================================================================

/// Execute boot commands.
pub async fn execute(command: BootCommands, format: OutputFormat) -> anyhow::Result<()> {
    // Use Config::load() so the cache directory are consistent with daemon.
    let config = arcbox_core::Config::load().unwrap_or_default();
    let boot_cache_dir = config.data_dir.join("boot");

    match command {
        BootCommands::Prefetch(args) => {
            prefetch(&config.data_dir, boot_cache_dir, args, format).await
        }
        BootCommands::Status(args) => status(boot_cache_dir, args, format).await,
        BootCommands::Clear => clear(boot_cache_dir, format).await,
        BootCommands::List => list(boot_cache_dir, format).await,
    }
}

// =============================================================================
// Status
// =============================================================================

/// Show boot asset status.
async fn status(data_dir: PathBuf, args: StatusArgs, format: OutputFormat) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let config = BootAssetConfig::with_cache_dir(data_dir.clone());
    let provider = BootAssetProvider::with_config(config.clone())?;
    let version_dir = config.version_cache_dir();
    let cached = provider.is_cached();

    // Collect asset details if cached.
    let assets = if cached {
        let kernel = version_dir.join("kernel");
        let rootfs = version_dir.join("rootfs.erofs");
        let kernel_size = std::fs::metadata(&kernel).map_or(0, |m| m.len());
        let rootfs_size = std::fs::metadata(&rootfs).map_or(0, |m| m.len());
        Some(AssetDetails {
            kernel_path: kernel.display().to_string(),
            kernel_size,
            rootfs_path: rootfs.display().to_string(),
            rootfs_size,
        })
    } else {
        None
    };

    // Collect manifest info if cached.
    let manifest = if cached {
        provider
            .read_cached_manifest_required()
            .await
            .ok()
            .map(|m| ManifestInfo {
                schema_version: m.schema_version,
                built_at: m.built_at.clone(),
                source_sha: m.source_sha,
            })
    } else {
        None
    };

    // Fetch latest version unless --offline.
    let latest_version = if args.offline {
        None
    } else {
        provider.fetch_latest_version().await.unwrap_or(None)
    };

    let update_available = latest_version
        .as_ref()
        .is_some_and(|latest| *latest != config.version);

    match format {
        OutputFormat::Json => {
            let output = StatusOutput {
                version: config.version.clone(),
                arch: config.arch.clone(),
                cache_dir: data_dir.display().to_string(),
                cached,
                assets,
                manifest,
                latest_version,
                update_available,
            };
            println!("{}", serde_json::to_string(&output)?);
        }
        OutputFormat::Table | OutputFormat::Quiet => {
            println!("Boot Asset Status");
            println!("=================");
            println!();
            println!("Cache directory: {}", data_dir.display());
            println!("Current version: {}", config.version);
            println!("Architecture:    {}", config.arch);
            if let Some(ref latest) = latest_version {
                println!("Latest version:  {}", latest);
            }
            if update_available {
                println!("Update:          ✓ Update available");
            }
            println!();

            if cached {
                println!("Status: ✓ Cached and valid");

                if let Some(ref a) = assets {
                    println!("  Kernel:    {} ({} bytes)", a.kernel_path, a.kernel_size);
                    println!("  Rootfs:    {} ({} bytes)", a.rootfs_path, a.rootfs_size);
                }

                match provider.read_cached_manifest_required().await {
                    Ok(m) => {
                        println!(
                            "  Manifest:  ✓ {}",
                            version_dir.join("manifest.json").display()
                        );
                        println!("  Schema:    v{}", m.schema_version);
                        println!("  Build At:  {}", m.built_at);
                        println!(
                            "  Source:    {}",
                            m.source_sha.as_deref().unwrap_or("unknown")
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
        }
    }

    Ok(())
}

// =============================================================================
// Prefetch
// =============================================================================

/// Prefetch boot assets and runtime binaries.
async fn prefetch(
    root_data_dir: &Path,
    boot_cache_dir: PathBuf,
    args: PrefetchArgs,
    format: OutputFormat,
) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let mut config = BootAssetConfig::with_cache_dir(boot_cache_dir);

    if let Some(version) = args.asset_version {
        config = config.with_version(version);
    }

    let provider = BootAssetProvider::with_config(config.clone())?;

    // Clear cache if force.
    if args.force {
        provider.clear_cache().await?;
    }

    match format {
        OutputFormat::Json => {
            prefetch_json(&provider, root_data_dir).await?;
        }
        OutputFormat::Table | OutputFormat::Quiet => {
            prefetch_table(&provider, root_data_dir).await?;
        }
    }

    Ok(())
}

/// Build an NDJSON progress callback that prints one JSON line per progress event.
fn make_ndjson_progress_callback()
-> Box<dyn Fn(arcbox_core::boot_assets::DownloadProgress) + Send + Sync> {
    use arcbox_core::boot_assets::PreparePhase;

    Box::new(
        move |progress: arcbox_core::boot_assets::DownloadProgress| {
            let (phase, downloaded_bytes, total_bytes, percent) = match &progress.phase {
                PreparePhase::Checking => ("checking".to_string(), None, None, None),
                PreparePhase::Downloading { downloaded, total } => {
                    let pct = total.map(|t| (downloaded * 100).checked_div(t).unwrap_or(0));
                    ("downloading".to_string(), Some(*downloaded), *total, pct)
                }
                PreparePhase::Verifying => ("verifying".to_string(), None, None, None),
                PreparePhase::Ready => ("ready".to_string(), None, None, None),
                PreparePhase::Cached => ("cached".to_string(), None, None, None),
            };

            let line = PrefetchProgress {
                phase,
                name: Some(progress.name.clone()),
                current: Some(progress.current),
                total: Some(progress.total),
                downloaded_bytes,
                total_bytes,
                percent,
                ..Default::default()
            };
            if let Ok(json) = serde_json::to_string(&line) {
                println!("{json}");
            }
        },
    )
}

/// Emit a single NDJSON progress line.
fn emit_ndjson(p: PrefetchProgress) {
    if let Ok(json) = serde_json::to_string(&p) {
        println!("{json}");
    }
}

/// Prefetch with NDJSON progress output.
async fn prefetch_json(
    provider: &arcbox_core::boot_assets::BootAssetProvider,
    root_data_dir: &Path,
) -> anyhow::Result<()> {
    // Boot assets.
    if let Err(e) = provider
        .prefetch_with_progress(Some(make_ndjson_progress_callback()))
        .await
    {
        emit_ndjson(PrefetchProgress {
            phase: "error".to_string(),
            error: Some(e.to_string()),
            ..Default::default()
        });
        return Err(e.into());
    }

    // Runtime binaries.
    let runtime_bin_dir = root_data_dir.join("runtime/bin");
    tokio::fs::create_dir_all(&runtime_bin_dir).await?;

    if let Err(e) = provider
        .prepare_binaries(&runtime_bin_dir, Some(make_ndjson_progress_callback()))
        .await
    {
        emit_ndjson(PrefetchProgress {
            phase: "error".to_string(),
            error: Some(e.to_string()),
            ..Default::default()
        });
        return Err(e.into());
    }

    emit_ndjson(PrefetchProgress {
        phase: "complete".to_string(),
        ..Default::default()
    });

    Ok(())
}

/// Prefetch with human-readable table output.
async fn prefetch_table(
    provider: &arcbox_core::boot_assets::BootAssetProvider,
    root_data_dir: &Path,
) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::DownloadProgress;

    println!("Prefetching boot assets...");

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

    // 1. Boot assets.
    provider
        .prefetch_with_progress(Some(make_progress_callback()))
        .await?;
    println!("\n  Boot assets ready");

    // 2. Runtime binaries.
    let runtime_bin_dir = root_data_dir.join("runtime/bin");
    tokio::fs::create_dir_all(&runtime_bin_dir).await?;

    provider
        .prepare_binaries(&runtime_bin_dir, Some(make_progress_callback()))
        .await?;
    println!("\n  Runtime binaries ready");

    Ok(())
}

// =============================================================================
// Clear
// =============================================================================

/// Clear cached boot assets.
async fn clear(data_dir: PathBuf, format: OutputFormat) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let config = BootAssetConfig::with_cache_dir(data_dir.clone());
    let provider = BootAssetProvider::with_config(config)?;

    if !data_dir.exists() {
        match format {
            OutputFormat::Json => {
                println!(
                    "{}",
                    serde_json::to_string(&ClearOutput { cleared: false })?
                );
            }
            OutputFormat::Table | OutputFormat::Quiet => {
                println!("Cache directory does not exist.");
            }
        }
        return Ok(());
    }

    provider.clear_cache().await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(&ClearOutput { cleared: true })?);
        }
        OutputFormat::Table | OutputFormat::Quiet => {
            println!("Clearing boot asset cache...");
            println!("✓ Cache cleared");
        }
    }

    Ok(())
}

// =============================================================================
// List
// =============================================================================

/// List cached versions.
async fn list(data_dir: PathBuf, format: OutputFormat) -> anyhow::Result<()> {
    use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};

    let config = BootAssetConfig::with_cache_dir(data_dir);
    let provider = BootAssetProvider::with_config(config)?;

    let versions = provider.list_cached_versions().await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string(&ListOutput { versions })?);
        }
        OutputFormat::Table | OutputFormat::Quiet => {
            if versions.is_empty() {
                println!("No cached versions found.");
                println!("Run 'arcbox boot prefetch' to download boot assets.");
            } else {
                println!("Cached versions:");
                for version in versions {
                    println!("  - {}", version);
                }
            }
        }
    }

    Ok(())
}
