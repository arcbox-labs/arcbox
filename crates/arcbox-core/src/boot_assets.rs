//! Boot asset management for VM startup.
//!
//! This module handles automatic downloading, verification, and caching
//! of kernel and initramfs files required for VM boot.
//!
//! ## Asset Sources
//!
//! Boot assets can be obtained from:
//! 1. **CDN/GitHub Releases** - Pre-built optimized kernel + initramfs
//! 2. **Local cache** - Previously downloaded assets
//! 3. **Custom paths** - User-provided kernel/initramfs
//!
//! ## Asset Structure
//!
//! Downloaded assets are stored in:
//! ```text
//! ~/.arcbox/boot/
//! ├── v0.1.0/
//! │   ├── kernel-arm64
//! │   ├── kernel-arm64.sha256
//! │   ├── initramfs-arm64.cpio.gz
//! │   └── initramfs-arm64.sha256
//! └── current -> v0.1.0/
//! ```

use crate::error::{CoreError, Result};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;
use tokio::fs;
use tokio::io::AsyncWriteExt;

// =============================================================================
// Constants
// =============================================================================

/// Current boot asset version.
/// This should match the arcbox release version.
pub const BOOT_ASSET_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Base URL for boot asset downloads.
/// Assets are hosted on GitHub Releases.
const DEFAULT_CDN_BASE_URL: &str = "https://github.com/arcboxd/boot-assets/releases/download";

/// Asset bundle filename pattern.
/// Format: boot-assets-{arch}-v{version}.tar.gz
const ASSET_BUNDLE_PATTERN: &str = "boot-assets";

/// Kernel filename inside the bundle.
const KERNEL_FILENAME: &str = "kernel";

/// Initramfs filename inside the bundle.
const INITRAMFS_FILENAME: &str = "initramfs.cpio.gz";

/// Checksum filename suffix.
const CHECKSUM_SUFFIX: &str = ".sha256";

/// Download buffer size (64KB).
const DOWNLOAD_BUFFER_SIZE: usize = 65536;

/// HTTP request timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 300;

// =============================================================================
// Configuration
// =============================================================================

/// Boot asset configuration.
#[derive(Debug, Clone)]
pub struct BootAssetConfig {
    /// Base URL for asset downloads.
    pub cdn_base_url: String,
    /// Asset version to download.
    pub version: String,
    /// Target architecture (arm64, x86_64).
    pub arch: String,
    /// Cache directory for downloaded assets.
    pub cache_dir: PathBuf,
    /// Enable checksum verification.
    pub verify_checksum: bool,
    /// Custom kernel path (overrides download).
    pub custom_kernel: Option<PathBuf>,
    /// Custom initramfs path (overrides download).
    pub custom_initramfs: Option<PathBuf>,
}

impl Default for BootAssetConfig {
    fn default() -> Self {
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else {
            "unknown"
        };

        let cache_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("arcbox")
            .join("boot");

        Self {
            cdn_base_url: DEFAULT_CDN_BASE_URL.to_string(),
            version: BOOT_ASSET_VERSION.to_string(),
            arch: arch.to_string(),
            cache_dir,
            verify_checksum: true,
            custom_kernel: None,
            custom_initramfs: None,
        }
    }
}

impl BootAssetConfig {
    /// Creates a new configuration with custom cache directory.
    pub fn with_cache_dir(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            ..Default::default()
        }
    }

    /// Sets custom kernel path.
    pub fn with_kernel(mut self, kernel: PathBuf) -> Self {
        self.custom_kernel = Some(kernel);
        self
    }

    /// Sets custom initramfs path.
    pub fn with_initramfs(mut self, initramfs: PathBuf) -> Self {
        self.custom_initramfs = Some(initramfs);
        self
    }

    /// Sets asset version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Gets the versioned cache directory.
    pub fn version_cache_dir(&self) -> PathBuf {
        self.cache_dir.join(&self.version)
    }

    /// Gets the asset bundle URL.
    pub fn bundle_url(&self) -> String {
        format!(
            "{}/v{}/{}-{}-v{}.tar.gz",
            self.cdn_base_url, self.version, ASSET_BUNDLE_PATTERN, self.arch, self.version
        )
    }

    /// Gets the checksum URL for the bundle.
    pub fn checksum_url(&self) -> String {
        format!("{}{}", self.bundle_url(), CHECKSUM_SUFFIX)
    }
}

// =============================================================================
// Boot Assets
// =============================================================================

/// Boot assets (kernel + initramfs).
#[derive(Debug, Clone)]
pub struct BootAssets {
    /// Path to kernel image.
    pub kernel: PathBuf,
    /// Path to initramfs.
    pub initramfs: PathBuf,
    /// Kernel command line.
    pub cmdline: String,
    /// Asset version.
    pub version: String,
}

impl BootAssets {
    /// Default kernel command line for ArcBox.
    ///
    /// Uses `rdinit=/init` for initramfs-based boot.
    pub fn default_cmdline() -> String {
        "console=hvc0 rdinit=/init quiet".to_string()
    }
}

// =============================================================================
// Progress Callback
// =============================================================================

/// Download progress information.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Bytes downloaded so far.
    pub downloaded: u64,
    /// Total bytes to download (if known).
    pub total: Option<u64>,
    /// Download phase description.
    pub phase: String,
}

impl DownloadProgress {
    /// Returns progress as a percentage (0-100), or None if total is unknown.
    pub fn percentage(&self) -> Option<u8> {
        self.total.map(|t| {
            if t == 0 {
                100
            } else {
                ((self.downloaded * 100) / t).min(100) as u8
            }
        })
    }
}

/// Progress callback type.
pub type ProgressCallback = Box<dyn Fn(DownloadProgress) + Send + Sync>;

// =============================================================================
// Boot Asset Provider
// =============================================================================

/// Boot asset provider with automatic downloading.
///
/// Manages kernel and initramfs files required for VM boot.
/// Assets are automatically downloaded from CDN if not cached.
pub struct BootAssetProvider {
    /// Configuration.
    config: BootAssetConfig,
}

impl BootAssetProvider {
    /// Creates a new boot asset provider with default configuration.
    pub fn new(cache_dir: PathBuf) -> Self {
        Self::with_config(BootAssetConfig::with_cache_dir(cache_dir))
    }

    /// Creates a new boot asset provider with custom configuration.
    pub fn with_config(config: BootAssetConfig) -> Self {
        Self {
            config,
        }
    }

    fn build_http_client(&self) -> Result<reqwest::Client> {
        let builder = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent(format!("arcbox/{}", BOOT_ASSET_VERSION));

        builder
            .build()
            .map_err(|e| CoreError::Config(format!("failed to create HTTP client: {}", e)))
    }

    /// Sets custom kernel path.
    pub fn with_kernel(mut self, kernel: PathBuf) -> Self {
        // Only set if path is not empty.
        if kernel.as_os_str().is_empty() {
            return self;
        }
        self.config.custom_kernel = Some(kernel);
        self
    }

    /// Sets custom initramfs path.
    pub fn with_initramfs(mut self, initramfs: PathBuf) -> Self {
        // Only set if path is not empty.
        if initramfs.as_os_str().is_empty() {
            return self;
        }
        self.config.custom_initramfs = Some(initramfs);
        self
    }

    /// Returns the configuration.
    pub fn config(&self) -> &BootAssetConfig {
        &self.config
    }

    /// Gets boot assets, downloading if necessary.
    ///
    /// # Errors
    /// Returns an error if assets cannot be found or downloaded.
    pub async fn get_assets(&self) -> Result<BootAssets> {
        self.get_assets_with_progress(None).await
    }

    /// Gets boot assets with progress callback.
    ///
    /// # Errors
    /// Returns an error if assets cannot be found or downloaded.
    pub async fn get_assets_with_progress(
        &self,
        progress: Option<ProgressCallback>,
    ) -> Result<BootAssets> {
        // Check for custom paths first.
        let kernel = if let Some(ref k) = self.config.custom_kernel {
            if !k.exists() {
                return Err(CoreError::Config(format!(
                    "custom kernel not found: {}",
                    k.display()
                )));
            }
            tracing::debug!("Using custom kernel: {}", k.display());
            k.clone()
        } else {
            self.get_kernel_path(&progress).await?
        };

        let initramfs = if let Some(ref i) = self.config.custom_initramfs {
            if !i.exists() {
                return Err(CoreError::Config(format!(
                    "custom initramfs not found: {}",
                    i.display()
                )));
            }
            tracing::debug!("Using custom initramfs: {}", i.display());
            i.clone()
        } else {
            self.get_initramfs_path(&progress).await?
        };

        Ok(BootAssets {
            kernel,
            initramfs,
            cmdline: BootAssets::default_cmdline(),
            version: self.config.version.clone(),
        })
    }

    /// Gets kernel path, downloading if needed.
    async fn get_kernel_path(&self, progress: &Option<ProgressCallback>) -> Result<PathBuf> {
        let kernel_path = self.config.version_cache_dir().join(KERNEL_FILENAME);

        if kernel_path.exists() {
            tracing::debug!("Using cached kernel: {}", kernel_path.display());
            return Ok(kernel_path);
        }

        // Need to download assets.
        self.download_assets(progress).await?;

        if kernel_path.exists() {
            Ok(kernel_path)
        } else {
            Err(CoreError::Config(format!(
                "kernel not found after download: {}",
                kernel_path.display()
            )))
        }
    }

    /// Gets initramfs path, downloading if needed.
    async fn get_initramfs_path(&self, progress: &Option<ProgressCallback>) -> Result<PathBuf> {
        let initramfs_path = self.config.version_cache_dir().join(INITRAMFS_FILENAME);

        if initramfs_path.exists() {
            tracing::debug!("Using cached initramfs: {}", initramfs_path.display());
            return Ok(initramfs_path);
        }

        // Need to download assets.
        self.download_assets(progress).await?;

        if initramfs_path.exists() {
            Ok(initramfs_path)
        } else {
            Err(CoreError::Config(format!(
                "initramfs not found after download: {}",
                initramfs_path.display()
            )))
        }
    }

    /// Downloads and extracts boot assets.
    async fn download_assets(&self, progress: &Option<ProgressCallback>) -> Result<()> {
        let cache_dir = self.config.version_cache_dir();

        // Create cache directory.
        fs::create_dir_all(&cache_dir)
            .await
            .map_err(|e| CoreError::Config(format!("failed to create cache directory: {}", e)))?;

        // Download checksum first (if verification enabled).
        let expected_checksum = if self.config.verify_checksum {
            if let Some(cb) = progress {
                cb(DownloadProgress {
                    downloaded: 0,
                    total: None,
                    phase: "Downloading checksum...".to_string(),
                });
            }

            match self.download_checksum().await {
                Ok(checksum) => Some(checksum),
                Err(e) => {
                    tracing::warn!("Failed to download checksum, skipping verification: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Download asset bundle.
        let bundle_path = cache_dir.join("bundle.tar.gz");

        if let Some(cb) = progress {
            cb(DownloadProgress {
                downloaded: 0,
                total: None,
                phase: "Downloading boot assets...".to_string(),
            });
        }

        self.download_file(&self.config.bundle_url(), &bundle_path, progress)
            .await?;

        // Verify checksum.
        if let Some(expected) = expected_checksum {
            if let Some(cb) = progress {
                cb(DownloadProgress {
                    downloaded: 0,
                    total: None,
                    phase: "Verifying checksum...".to_string(),
                });
            }

            let actual = self.compute_file_checksum(&bundle_path).await?;

            if actual != expected {
                // Remove corrupted file.
                let _ = fs::remove_file(&bundle_path).await;
                return Err(CoreError::Config(format!(
                    "checksum mismatch: expected {}, got {}",
                    expected, actual
                )));
            }

            tracing::debug!("Checksum verified: {}", actual);
        }

        // Extract bundle.
        if let Some(cb) = progress {
            cb(DownloadProgress {
                downloaded: 0,
                total: None,
                phase: "Extracting boot assets...".to_string(),
            });
        }

        self.extract_bundle(&bundle_path, &cache_dir).await?;

        // Clean up bundle file.
        let _ = fs::remove_file(&bundle_path).await;

        // Create "current" symlink.
        let current_link = self.config.cache_dir.join("current");
        let _ = fs::remove_file(&current_link).await;
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&cache_dir, &current_link);
        }

        if let Some(cb) = progress {
            cb(DownloadProgress {
                downloaded: 100,
                total: Some(100),
                phase: "Boot assets ready".to_string(),
            });
        }

        tracing::info!("Boot assets downloaded to {}", cache_dir.display());

        Ok(())
    }

    /// Downloads a file with progress reporting.
    async fn download_file(
        &self,
        url: &str,
        dest: &Path,
        progress: &Option<ProgressCallback>,
    ) -> Result<()> {
        tracing::info!("Downloading: {}", url);

        let client = self.build_http_client()?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| CoreError::Config(format!("failed to download {}: {}", url, e)))?;

        if !response.status().is_success() {
            return Err(CoreError::Config(format!(
                "download failed with status {}: {}",
                response.status(),
                url
            )));
        }

        let total_size = response.content_length();
        let mut downloaded: u64 = 0;

        // Create temporary file.
        let temp_path = dest.with_extension("tmp");
        let mut file = tokio::fs::File::create(&temp_path)
            .await
            .map_err(|e| CoreError::Config(format!("failed to create file: {}", e)))?;

        // Stream download.
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| CoreError::Config(format!("download error: {}", e)))?;

            file.write_all(&chunk)
                .await
                .map_err(|e| CoreError::Config(format!("write error: {}", e)))?;

            downloaded += chunk.len() as u64;

            if let Some(cb) = progress {
                cb(DownloadProgress {
                    downloaded,
                    total: total_size,
                    phase: format!("Downloading... {}", format_bytes(downloaded)),
                });
            }
        }

        file.flush()
            .await
            .map_err(|e| CoreError::Config(format!("flush error: {}", e)))?;

        // Rename to final path.
        fs::rename(&temp_path, dest)
            .await
            .map_err(|e| CoreError::Config(format!("rename error: {}", e)))?;

        tracing::debug!("Downloaded {} bytes to {}", downloaded, dest.display());

        Ok(())
    }

    /// Downloads and parses checksum file.
    async fn download_checksum(&self) -> Result<String> {
        let url = self.config.checksum_url();
        let client = self.build_http_client()?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| CoreError::Config(format!("failed to download checksum: {}", e)))?;

        if !response.status().is_success() {
            return Err(CoreError::Config(format!(
                "checksum download failed with status {}",
                response.status()
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| CoreError::Config(format!("failed to read checksum: {}", e)))?;

        // Parse checksum (format: "sha256sum  filename" or just "sha256sum").
        let checksum = text
            .split_whitespace()
            .next()
            .ok_or_else(|| CoreError::Config("empty checksum file".to_string()))?
            .to_lowercase();

        if checksum.len() != 64 {
            return Err(CoreError::Config(format!(
                "invalid checksum length: {}",
                checksum.len()
            )));
        }

        Ok(checksum)
    }

    /// Computes SHA256 checksum of a file.
    async fn compute_file_checksum(&self, path: &Path) -> Result<String> {
        let data = fs::read(path)
            .await
            .map_err(|e| CoreError::Config(format!("failed to read file for checksum: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();

        Ok(hex::encode(result))
    }

    /// Extracts tar.gz bundle to directory.
    async fn extract_bundle(&self, bundle_path: &Path, dest_dir: &Path) -> Result<()> {
        let bundle_path = bundle_path.to_path_buf();
        let dest_dir = dest_dir.to_path_buf();

        // Run extraction in blocking task.
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&bundle_path)
                .map_err(|e| CoreError::Config(format!("failed to open bundle: {}", e)))?;

            let decoder = GzDecoder::new(file);
            let mut archive = Archive::new(decoder);

            archive
                .unpack(&dest_dir)
                .map_err(|e| CoreError::Config(format!("failed to extract bundle: {}", e)))?;

            Ok(())
        })
        .await
        .map_err(|e| CoreError::Config(format!("extraction task failed: {}", e)))?
    }

    /// Prefetches boot assets (downloads if not cached).
    ///
    /// This can be called during daemon startup to reduce first-use latency.
    pub async fn prefetch(&self) -> Result<()> {
        self.prefetch_with_progress(None).await
    }

    /// Prefetches boot assets with progress callback.
    pub async fn prefetch_with_progress(&self, progress: Option<ProgressCallback>) -> Result<()> {
        let _ = self.get_assets_with_progress(progress).await?;
        Ok(())
    }

    /// Checks if boot assets are cached.
    pub fn is_cached(&self) -> bool {
        let cache_dir = self.config.version_cache_dir();
        cache_dir.join(KERNEL_FILENAME).exists() && cache_dir.join(INITRAMFS_FILENAME).exists()
    }

    /// Clears the boot asset cache.
    pub async fn clear_cache(&self) -> Result<()> {
        if self.config.cache_dir.exists() {
            fs::remove_dir_all(&self.config.cache_dir)
                .await
                .map_err(|e| CoreError::Config(format!("failed to clear cache: {}", e)))?;
        }
        Ok(())
    }

    /// Lists cached versions.
    pub async fn list_cached_versions(&self) -> Result<Vec<String>> {
        let mut versions = Vec::new();

        if !self.config.cache_dir.exists() {
            return Ok(versions);
        }

        let mut entries = fs::read_dir(&self.config.cache_dir)
            .await
            .map_err(|e| CoreError::Config(format!("failed to read cache dir: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CoreError::Config(format!("failed to read cache entry: {}", e)))?
        {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name() {
                    let name = name.to_string_lossy().to_string();
                    // Skip "current" symlink.
                    if name != "current" {
                        versions.push(name);
                    }
                }
            }
        }

        Ok(versions)
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Formats bytes as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Encodes bytes as hex string.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BootAssetConfig::default();

        assert!(!config.cdn_base_url.is_empty());
        assert!(!config.version.is_empty());
        assert!(!config.arch.is_empty());
        assert!(config.verify_checksum);
    }

    #[test]
    fn test_bundle_url() {
        let config = BootAssetConfig {
            cdn_base_url: "https://example.com/releases".to_string(),
            version: "1.0.0".to_string(),
            arch: "arm64".to_string(),
            ..Default::default()
        };

        let url = config.bundle_url();
        assert_eq!(
            url,
            "https://example.com/releases/v1.0.0/boot-assets-arm64-v1.0.0.tar.gz"
        );
    }

    #[test]
    fn test_checksum_url() {
        let config = BootAssetConfig {
            cdn_base_url: "https://example.com/releases".to_string(),
            version: "1.0.0".to_string(),
            arch: "arm64".to_string(),
            ..Default::default()
        };

        let url = config.checksum_url();
        assert_eq!(
            url,
            "https://example.com/releases/v1.0.0/boot-assets-arm64-v1.0.0.tar.gz.sha256"
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode([0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex::encode([]), "");
    }

    #[test]
    fn test_download_progress_percentage() {
        let progress = DownloadProgress {
            downloaded: 50,
            total: Some(100),
            phase: "test".to_string(),
        };
        assert_eq!(progress.percentage(), Some(50));

        let progress = DownloadProgress {
            downloaded: 100,
            total: Some(100),
            phase: "test".to_string(),
        };
        assert_eq!(progress.percentage(), Some(100));

        let progress = DownloadProgress {
            downloaded: 50,
            total: None,
            phase: "test".to_string(),
        };
        assert_eq!(progress.percentage(), None);
    }
}
