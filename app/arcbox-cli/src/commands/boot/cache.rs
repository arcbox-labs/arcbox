//! Boot asset cache mutation commands.

use std::path::{Path, PathBuf};

use arcbox_core::boot_assets::{BootAssetConfig, BootAssetProvider};
use serde::Serialize;

use super::super::OutputFormat;
use super::PrefetchArgs;

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

#[derive(Serialize)]
struct ListOutput {
    versions: Vec<String>,
}

#[derive(Serialize)]
struct ClearOutput {
    cleared: bool,
}

/// Prefetch boot assets and runtime binaries.
pub(super) async fn prefetch(
    root_data_dir: &Path,
    mut config: BootAssetConfig,
    args: PrefetchArgs,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if let Some(version) = args.asset_version {
        config = config.with_version(version);
    }

    let provider = BootAssetProvider::with_config(config.clone())?;

    // Clear cache if force.
    if args.force {
        provider.clear_cache().await?;
        clear_runtime_generation(root_data_dir, &provider.config().version).await?;
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

async fn clear_runtime_generation(root_data_dir: &Path, version: &str) -> std::io::Result<()> {
    let path = root_data_dir.join("runtime").join(version);
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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
    let runtime_bin_dir = root_data_dir
        .join("runtime")
        .join(&provider.config().version)
        .join("bin");
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
    let runtime_bin_dir = root_data_dir
        .join("runtime")
        .join(&provider.config().version)
        .join("bin");
    tokio::fs::create_dir_all(&runtime_bin_dir).await?;

    provider
        .prepare_binaries(&runtime_bin_dir, Some(make_progress_callback()))
        .await?;
    println!("\n  Runtime binaries ready");

    Ok(())
}

/// Clear cached boot assets.
pub(super) async fn clear(data_dir: PathBuf, format: OutputFormat) -> anyhow::Result<()> {
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

/// List cached versions.
pub(super) async fn list(data_dir: PathBuf, format: OutputFormat) -> anyhow::Result<()> {
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
                println!("Run 'abctl boot prefetch' to download boot assets.");
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

#[cfg(test)]
mod tests {
    use super::clear_runtime_generation;

    #[tokio::test]
    async fn force_clear_removes_only_the_selected_runtime_generation() {
        let directory = tempfile::tempdir().unwrap();
        let selected = directory.path().join("runtime/0.8.4/bin");
        let retained = directory.path().join("runtime/0.8.3/bin");
        std::fs::create_dir_all(&selected).unwrap();
        std::fs::create_dir_all(&retained).unwrap();
        std::fs::write(selected.join("dockerd"), b"old").unwrap();
        std::fs::write(retained.join("dockerd"), b"retained").unwrap();

        clear_runtime_generation(directory.path(), "0.8.4")
            .await
            .unwrap();

        assert!(!selected.exists());
        assert!(retained.join("dockerd").is_file());
    }
}
