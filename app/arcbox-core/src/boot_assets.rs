//! Boot asset management for VM startup.
//!
//! This module handles automatic downloading, verification, and caching
//! of kernel/initramfs/rootfs/modloop files required for VM boot.
//!
//! ## Asset Sources
//!
//! Boot assets can be obtained from:
//! 1. **CDN/GitHub Releases** - Pre-built optimized boot bundle
//! 2. **Local cache** - Previously downloaded assets
//! 3. **Custom paths** - User-provided kernel/initramfs
//!
//! ## Asset Structure
//!
//! Downloaded assets are stored in:
//! ```text
//! ~/.arcbox/boot/
//! ├── v0.1.0/
//! │   ├── kernel
//! │   ├── initramfs.cpio.gz
//! │   ├── rootfs.squashfs
//! │   ├── modloop
//! │   └── manifest.json
//! └── current -> v0.1.0/
//! ```

use crate::error::{CoreError, Result};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tar::Archive;
use tokio::fs;
use tokio::io::AsyncWriteExt;

// =============================================================================
// Constants
// =============================================================================

/// Default boot asset version.
/// This is pinned to a known-good kernel/initramfs bundle.
pub const BOOT_ASSET_VERSION: &str = "0.1.2";

/// Base URL for boot asset downloads.
/// Assets are hosted on Cloudflare R2 via custom domain.
const DEFAULT_CDN_BASE_URL: &str = "https://dl.arcbox.dev/boot-assets";

/// Asset bundle filename pattern.
/// Format: boot-assets-{arch}-v{version}.tar.gz
const ASSET_BUNDLE_PATTERN: &str = "boot-assets";

/// Kernel filename inside the bundle.
const KERNEL_FILENAME: &str = "kernel";

/// Initramfs filename inside the bundle.
const INITRAMFS_FILENAME: &str = "initramfs.cpio.gz";

/// Manifest filename inside the bundle.
const MANIFEST_FILENAME: &str = "manifest.json";

/// Rootfs squashfs filename inside the bundle.
/// Introduced in schema_version 2 (squashfs rootfs architecture).
/// Stage 1 initramfs mounts this image as the guest OS root filesystem.
const ROOTFS_SQUASHFS_FILENAME: &str = "rootfs.squashfs";

/// Rootfs ext4 image filename inside the bundle.
/// Introduced in schema_version 4 (Alpine rootfs + OpenRC architecture).
/// The VMM attaches this as a VirtIO block device; initramfs mounts it at
/// /dev/vda and switch_roots to standard Alpine OpenRC init.
const ROOTFS_EXT4_FILENAME: &str = "rootfs.ext4";

/// Alpine modloop filename inside the bundle.
/// Introduced in schema_version 3.
/// Stage 1 initramfs loop-mounts this squashfs and bind-mounts its modules
/// tree into Stage 2 so modprobe works normally after switch_root.
const MODLOOP_FILENAME: &str = "modloop";

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

        let cache_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".arcbox")
            .join("boot");

        Self {
            cdn_base_url: DEFAULT_CDN_BASE_URL.to_string(),
            version: default_boot_asset_version(),
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

fn default_boot_asset_version() -> String {
    std::env::var("ARCBOX_BOOT_ASSET_VERSION").unwrap_or_else(|_| BOOT_ASSET_VERSION.to_string())
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
    /// Path to rootfs ext4 image (schema_version >= 4, DistroEngine mode).
    /// When present, the VMM attaches this as a VirtIO block device at /dev/vda
    /// and the initramfs mounts it directly (no squashfs+overlay).
    pub rootfs_image: Option<PathBuf>,
    /// Kernel command line.
    pub cmdline: String,
    /// Asset version.
    pub version: String,
    /// Parsed manifest metadata (if present in cache bundle).
    pub manifest: Option<BootAssetManifest>,
}

impl BootAssets {
    /// Default kernel command line for ArcBox.
    ///
    /// Uses `rdinit=/init` for initramfs-based boot.
    pub fn default_cmdline() -> String {
        "console=hvc0 console=ttyAMA0 rdinit=/init".to_string()
    }
}

/// Boot asset manifest metadata.
///
/// This file is generated in the boot-assets release pipeline and bundled
/// alongside kernel/initramfs as `manifest.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct BootAssetManifest {
    /// Manifest schema version.
    #[serde(default)]
    pub schema_version: u32,
    /// Boot asset version (must match configured version).
    pub asset_version: String,
    /// Target architecture (must match configured arch).
    pub arch: String,
    /// Kernel git commit used to build this asset.
    #[serde(default)]
    pub kernel_commit: Option<String>,
    /// arcbox-agent git commit used to build initramfs.
    #[serde(default)]
    pub agent_commit: Option<String>,
    /// Build timestamp in UTC (RFC3339 expected).
    #[serde(default)]
    pub built_at: Option<String>,
    /// Recommended kernel cmdline for this boot asset.
    #[serde(default)]
    pub kernel_cmdline: Option<String>,
    /// Runtime binary metadata bundled in this boot asset.
    #[serde(default)]
    pub runtime_assets: Vec<RuntimeAssetManifestEntry>,
    /// SHA256 of rootfs.squashfs (present in schema_version >= 2).
    /// The squashfs image is the Stage 2 root filesystem; Stage 1 initramfs
    /// mounts it via a tmpfs overlay so that pivot_root works for containers.
    #[serde(default)]
    pub rootfs_squashfs_sha256: Option<String>,
    /// SHA256 of modloop (present in schema_version >= 3).
    #[serde(default)]
    pub modloop_sha256: Option<String>,
    /// SHA256 of rootfs.ext4 (present in schema_version >= 4).
    /// The ext4 image is attached as a VirtIO block device; Alpine OpenRC
    /// handles all init instead of a custom two-stage init.
    #[serde(default)]
    pub rootfs_ext4_sha256: Option<String>,
}

/// Runtime artifact metadata in boot manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeAssetManifestEntry {
    /// Runtime component name (for example: dockerd, containerd, youki).
    pub name: String,
    /// Relative path inside boot asset bundle.
    pub path: String,
    /// Optional component version.
    #[serde(default)]
    pub version: Option<String>,
    /// Optional sha256 checksum for this file.
    #[serde(default)]
    pub sha256: Option<String>,
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
        Self { config }
    }

    fn build_http_client(&self) -> Result<reqwest::Client> {
        let builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent(format!("arcbox/{}", BOOT_ASSET_VERSION));

        builder
            .build()
            .map_err(|e| CoreError::config(format!("failed to create HTTP client: {}", e)))
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
        let using_custom_paths =
            self.config.custom_kernel.is_some() || self.config.custom_initramfs.is_some();

        // Check for custom paths first.
        let kernel = if let Some(ref k) = self.config.custom_kernel {
            if !k.exists() {
                return Err(CoreError::config(format!(
                    "custom kernel not found: {}",
                    k.display()
                )));
            }
            tracing::debug!("Using custom kernel: {}", k.display());
            // Decompress ZBOOT into cache dir so we never modify the user's
            // original file (it may be read-only or a build artifact).
            ensure_kernel_decompressed_to_cache(k, &self.config.version_cache_dir()).await?
        } else {
            self.get_kernel_path(&progress).await?
        };

        let initramfs = if let Some(ref i) = self.config.custom_initramfs {
            if !i.exists() {
                return Err(CoreError::config(format!(
                    "custom initramfs not found: {}",
                    i.display()
                )));
            }
            tracing::debug!("Using custom initramfs: {}", i.display());
            i.clone()
        } else {
            self.get_initramfs_path(&progress).await?
        };

        let manifest = if using_custom_paths {
            // Custom kernel/initramfs paths are used for local development.
            // Still try to load the cached manifest so the bundled runtime
            // validation in runtime.rs (which reads runtime_assets) continues
            // to work. If no cached manifest exists, silently fall back to None.
            self.read_cached_manifest().await.ok().flatten()
        } else {
            Some(self.read_cached_manifest_required().await?)
        };

        let cmdline = manifest
            .as_ref()
            .and_then(|m| m.kernel_cmdline.clone())
            .unwrap_or_else(BootAssets::default_cmdline);

        // Check for rootfs.ext4 (schema_version >= 4, DistroEngine mode).
        let rootfs_image = {
            let ext4_path = self.config.version_cache_dir().join(ROOTFS_EXT4_FILENAME);
            if ext4_path.exists() {
                Some(ext4_path)
            } else {
                None
            }
        };

        Ok(BootAssets {
            kernel,
            initramfs,
            rootfs_image,
            cmdline,
            version: self.config.version.clone(),
            manifest,
        })
    }

    /// Gets kernel path, downloading if needed.
    async fn get_kernel_path(&self, progress: &Option<ProgressCallback>) -> Result<PathBuf> {
        let kernel_path = self.config.version_cache_dir().join(KERNEL_FILENAME);

        if kernel_path.exists() {
            tracing::debug!("Using cached kernel: {}", kernel_path.display());
            ensure_kernel_decompressed(&kernel_path).await?;
            return Ok(kernel_path);
        }

        // Need to download assets.
        self.download_assets(progress).await?;

        if kernel_path.exists() {
            Ok(kernel_path)
        } else {
            Err(CoreError::config(format!(
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
            Err(CoreError::config(format!(
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
            .map_err(|e| CoreError::config(format!("failed to create cache directory: {}", e)))?;

        // Download checksum first (if verification enabled).
        let expected_checksum = if self.config.verify_checksum {
            if let Some(cb) = progress {
                cb(DownloadProgress {
                    downloaded: 0,
                    total: None,
                    phase: "Downloading checksum...".to_string(),
                });
            }

            Some(self.download_checksum().await?)
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
                return Err(CoreError::config(format!(
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
        ensure_kernel_decompressed(&cache_dir.join(KERNEL_FILENAME)).await?;
        self.validate_extracted_assets(&cache_dir).await?;

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
            .map_err(|e| CoreError::config(format!("failed to download {}: {}", url, e)))?;

        if !response.status().is_success() {
            return Err(CoreError::config(format!(
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
            .map_err(|e| CoreError::config(format!("failed to create file: {}", e)))?;

        // Stream download.
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| CoreError::config(format!("download error: {}", e)))?;

            file.write_all(&chunk)
                .await
                .map_err(|e| CoreError::config(format!("write error: {}", e)))?;

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
            .map_err(|e| CoreError::config(format!("flush error: {}", e)))?;

        // Rename to final path.
        fs::rename(&temp_path, dest)
            .await
            .map_err(|e| CoreError::config(format!("rename error: {}", e)))?;

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
            .map_err(|e| CoreError::config(format!("failed to download checksum: {}", e)))?;

        if !response.status().is_success() {
            return Err(CoreError::config(format!(
                "checksum download failed with status {}",
                response.status()
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| CoreError::config(format!("failed to read checksum: {}", e)))?;

        // Parse checksum (format: "sha256sum  filename" or just "sha256sum").
        let checksum = text
            .split_whitespace()
            .next()
            .ok_or_else(|| CoreError::config("empty checksum file".to_string()))?
            .to_lowercase();

        if checksum.len() != 64 {
            return Err(CoreError::config(format!(
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
            .map_err(|e| CoreError::config(format!("failed to read file for checksum: {}", e)))?;

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
                .map_err(|e| CoreError::config(format!("failed to open bundle: {}", e)))?;

            let decoder = GzDecoder::new(file);
            let mut archive = Archive::new(decoder);

            archive
                .unpack(&dest_dir)
                .map_err(|e| CoreError::config(format!("failed to extract bundle: {}", e)))?;

            Ok(())
        })
        .await
        .map_err(|e| CoreError::config(format!("extraction task failed: {}", e)))?
    }

    /// Validates required files after extraction.
    async fn validate_extracted_assets(&self, cache_dir: &Path) -> Result<()> {
        let kernel_path = cache_dir.join(KERNEL_FILENAME);
        if !kernel_path.exists() {
            return Err(CoreError::config(format!(
                "boot bundle missing required file: {}",
                kernel_path.display()
            )));
        }

        let initramfs_path = cache_dir.join(INITRAMFS_FILENAME);
        if !initramfs_path.exists() {
            return Err(CoreError::config(format!(
                "boot bundle missing required file: {}",
                initramfs_path.display()
            )));
        }

        let manifest = self.require_manifest_from_dir(cache_dir).await?;
        tracing::info!(
            "Boot asset manifest loaded: version={}, arch={}, kernel_commit={}, agent_commit={}",
            manifest.asset_version,
            manifest.arch,
            manifest.kernel_commit.as_deref().unwrap_or("unknown"),
            manifest.agent_commit.as_deref().unwrap_or("unknown"),
        );

        // schema_version 2-3 use rootfs.squashfs (squashfs rootfs architecture).
        // schema_version 4+ replaced squashfs with ext4 block device rootfs.
        if manifest.schema_version >= 2 && manifest.schema_version < 4 {
            let squashfs_path = cache_dir.join(ROOTFS_SQUASHFS_FILENAME);
            if !squashfs_path.exists() {
                return Err(CoreError::config(format!(
                    "boot bundle (schema_version={}) missing required file: {}. \
                     Run 'arcbox boot prefetch --force' to re-download the asset bundle.",
                    manifest.schema_version,
                    squashfs_path.display()
                )));
            }
        }

        // schema_version 3 adds modloop (Alpine kernel modules squashfs).
        // Stage 1 mounts this inside /newroot so Stage 2 has /lib/modules.
        if manifest.schema_version >= 3 && manifest.schema_version < 4 {
            let modloop_path = cache_dir.join(MODLOOP_FILENAME);
            if !modloop_path.exists() {
                return Err(CoreError::config(format!(
                    "boot bundle (schema_version={}) missing required file: {}. \
                     Run 'arcbox boot prefetch --force' to re-download the asset bundle.",
                    manifest.schema_version,
                    modloop_path.display()
                )));
            }
        }

        // schema_version 4 adds rootfs.ext4 (Alpine rootfs + OpenRC).
        // The VMM attaches this as a VirtIO block device; initramfs mounts
        // /dev/vda and switch_roots to /sbin/init (OpenRC).
        if manifest.schema_version >= 4 {
            let ext4_path = cache_dir.join(ROOTFS_EXT4_FILENAME);
            if !ext4_path.exists() {
                return Err(CoreError::config(format!(
                    "boot bundle (schema_version={}) missing required file: {}. \
                     Run 'arcbox boot prefetch --force' to re-download the asset bundle.",
                    manifest.schema_version,
                    ext4_path.display()
                )));
            }
        }

        Ok(())
    }

    fn validate_manifest(&self, manifest: &BootAssetManifest) -> Result<()> {
        if manifest.asset_version != self.config.version {
            return Err(CoreError::config(format!(
                "boot manifest version mismatch: expected '{}', got '{}'. \
                 Run 'arcbox boot prefetch --force' to re-download the correct version, \
                 or set ARCBOX_BOOT_ASSET_VERSION to match your cached assets.",
                self.config.version, manifest.asset_version
            )));
        }

        if manifest.arch != self.config.arch {
            return Err(CoreError::config(format!(
                "boot manifest arch mismatch: expected '{}', got '{}'. \
                 The cached boot assets were built for a different architecture. \
                 Run 'arcbox boot prefetch --force' to download assets for this platform.",
                self.config.arch, manifest.arch
            )));
        }

        Ok(())
    }

    async fn read_manifest_from_dir(&self, dir: &Path) -> Result<Option<BootAssetManifest>> {
        let manifest_path = dir.join(MANIFEST_FILENAME);
        if !manifest_path.exists() {
            return Ok(None);
        }

        let bytes = fs::read(&manifest_path).await.map_err(|e| {
            CoreError::config(format!(
                "failed to read boot manifest {}: {}",
                manifest_path.display(),
                e
            ))
        })?;

        let manifest: BootAssetManifest = serde_json::from_slice(&bytes).map_err(|e| {
            CoreError::config(format!(
                "failed to parse boot manifest {}: {}",
                manifest_path.display(),
                e
            ))
        })?;

        self.validate_manifest(&manifest)?;
        Ok(Some(manifest))
    }

    async fn require_manifest_from_dir(&self, dir: &Path) -> Result<BootAssetManifest> {
        let manifest_path = dir.join(MANIFEST_FILENAME);
        self.read_manifest_from_dir(dir).await?.ok_or_else(|| {
            CoreError::config(format!(
                "boot manifest required but missing: {}. \
                 Boot assets without a manifest are not supported. \
                 Run 'arcbox boot prefetch --force' to re-download a valid asset bundle.",
                manifest_path.display()
            ))
        })
    }

    /// Reads cached manifest for the configured asset version.
    pub async fn read_cached_manifest(&self) -> Result<Option<BootAssetManifest>> {
        self.read_manifest_from_dir(&self.config.version_cache_dir())
            .await
    }

    /// Reads cached manifest and requires it to exist.
    pub async fn read_cached_manifest_required(&self) -> Result<BootAssetManifest> {
        self.require_manifest_from_dir(&self.config.version_cache_dir())
            .await
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
        cache_dir.join(KERNEL_FILENAME).exists()
            && cache_dir.join(INITRAMFS_FILENAME).exists()
            && cache_dir.join(MANIFEST_FILENAME).exists()
    }

    /// Clears the boot asset cache.
    pub async fn clear_cache(&self) -> Result<()> {
        if self.config.cache_dir.exists() {
            fs::remove_dir_all(&self.config.cache_dir)
                .await
                .map_err(|e| CoreError::config(format!("failed to clear cache: {}", e)))?;
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
            .map_err(|e| CoreError::config(format!("failed to read cache dir: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CoreError::config(format!("failed to read cache entry: {}", e)))?
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
// ZBOOT Decompression
// =============================================================================

/// EFI ZBOOT magic identifier at offset 4..8 in the PE/COFF header.
const ZBOOT_MAGIC: &[u8; 4] = b"zimg";

/// ARM64 Linux kernel magic at offset 56 in the raw Image header.
const ARM64_MAGIC: &[u8; 4] = b"ARMd";

/// Minimum header size needed to detect ZBOOT format.
const ZBOOT_HEADER_SIZE: usize = 64;

/// Ensures the kernel file at `path` is a raw Image, decompressing in-place
/// if it is an EFI ZBOOT compressed kernel.
///
/// This operation is idempotent: if the file is already a raw Image it
/// returns immediately without modification.
///
/// Use this only for cache-owned files. For user-provided paths, use
/// [`ensure_kernel_decompressed_to_cache`] instead.
async fn ensure_kernel_decompressed(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        if let Some(raw) = detect_and_decompress_zboot(&path)? {
            atomic_write_file(&path, &raw)?;
            tracing::info!("Kernel decompressed in-place: {} bytes", raw.len());
        }
        Ok(())
    })
    .await
    .map_err(|e| CoreError::config(format!("kernel decompression task failed: {e}")))?
}

/// Decompresses a ZBOOT kernel into the cache directory, leaving the
/// user-provided source file untouched. Returns the path to use — either
/// the original (if already raw) or the cached decompressed copy.
async fn ensure_kernel_decompressed_to_cache(source: &Path, cache_dir: &Path) -> Result<PathBuf> {
    let source = source.to_path_buf();
    let cache_dir = cache_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        match detect_and_decompress_zboot(&source)? {
            None => {
                // Already a raw Image — use as-is.
                Ok(source)
            }
            Some(raw) => {
                // Write decompressed kernel into cache dir.
                std::fs::create_dir_all(&cache_dir)
                    .map_err(|e| CoreError::config(format!("failed to create cache dir: {e}")))?;
                let cached_path = cache_dir.join("kernel-custom-decompressed");
                atomic_write_file(&cached_path, &raw)?;
                tracing::info!(
                    "Custom kernel decompressed to cache: {} → {} ({} bytes)",
                    source.display(),
                    cached_path.display(),
                    raw.len()
                );
                Ok(cached_path)
            }
        }
    })
    .await
    .map_err(|e| CoreError::config(format!("kernel decompression task failed: {e}")))?
}

/// Detects EFI ZBOOT format and decompresses the gzip payload if present.
///
/// Returns `Ok(Some(raw_image))` if the file was ZBOOT and was decompressed,
/// `Ok(None)` if the file is already a raw Image (idempotent passthrough).
fn detect_and_decompress_zboot(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| CoreError::config(format!("failed to open kernel: {e}")))?;

    // Read header to check format.
    let mut header = [0u8; ZBOOT_HEADER_SIZE];
    let n = file
        .read(&mut header)
        .map_err(|e| CoreError::config(format!("failed to read kernel header: {e}")))?;

    if n < ZBOOT_HEADER_SIZE {
        return Ok(None);
    }

    if header[4..8] != *ZBOOT_MAGIC {
        return Ok(None);
    }

    tracing::info!("Detected EFI ZBOOT kernel: {}", path.display());

    // Parse payload offset and size (u32 LE at offsets 8 and 12).
    let payload_offset = u32::from_le_bytes(header[8..12].try_into().unwrap()) as u64;
    let payload_size = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;

    let file_len = file
        .metadata()
        .map_err(|e| CoreError::config(format!("failed to stat kernel: {e}")))?
        .len();

    if payload_offset + payload_size as u64 > file_len {
        return Err(CoreError::config(format!(
            "ZBOOT payload range ({payload_offset}..{}) exceeds file size ({file_len})",
            payload_offset + payload_size as u64
        )));
    }

    file.seek(SeekFrom::Start(payload_offset))
        .map_err(|e| CoreError::config(format!("failed to seek to ZBOOT payload: {e}")))?;

    let mut compressed = vec![0u8; payload_size];
    file.read_exact(&mut compressed)
        .map_err(|e| CoreError::config(format!("failed to read ZBOOT payload: {e}")))?;

    drop(file);

    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut raw_image = Vec::new();
    decoder
        .read_to_end(&mut raw_image)
        .map_err(|e| CoreError::config(format!("failed to decompress ZBOOT kernel: {e}")))?;

    if raw_image.len() < 60 || raw_image[56..60] != *ARM64_MAGIC {
        return Err(CoreError::config(
            "decompressed kernel missing ARM64 magic (expected 'ARMd' at offset 56)".to_string(),
        ));
    }

    Ok(Some(raw_image))
}

/// Atomically writes `data` to `path` via a `.tmp` sibling + rename.
fn atomic_write_file(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, data)
        .map_err(|e| CoreError::config(format!("failed to write decompressed kernel: {e}")))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| CoreError::config(format!("failed to rename decompressed kernel: {e}")))?;
    Ok(())
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
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_config() {
        let config = BootAssetConfig::default();

        assert!(!config.cdn_base_url.is_empty());
        assert!(!config.version.is_empty());
        assert!(!config.arch.is_empty());
        assert!(config.verify_checksum);
    }

    #[test]
    fn test_default_config_uses_boot_asset_version() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original = std::env::var("ARCBOX_BOOT_ASSET_VERSION").ok();
        // SAFETY: Test code running under ENV_LOCK mutex, single-threaded access.
        unsafe { std::env::remove_var("ARCBOX_BOOT_ASSET_VERSION") };

        let config = BootAssetConfig::default();
        assert_eq!(config.version, BOOT_ASSET_VERSION.to_string());

        restore_env(original);
    }

    #[test]
    fn test_default_config_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original = std::env::var("ARCBOX_BOOT_ASSET_VERSION").ok();
        // SAFETY: Test code running under ENV_LOCK mutex, single-threaded access.
        unsafe { std::env::set_var("ARCBOX_BOOT_ASSET_VERSION", "9.9.9") };

        let config = BootAssetConfig::default();
        assert_eq!(config.version, "9.9.9");

        restore_env(original);
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

    #[tokio::test]
    async fn test_read_cached_manifest_ok() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let version = "1.0.0".to_string();
        let version_dir = cache_dir.join(&version);
        std::fs::create_dir_all(&version_dir).unwrap();
        std::fs::write(
            version_dir.join(MANIFEST_FILENAME),
            r#"{
  "schema_version": 1,
  "asset_version": "1.0.0",
  "arch": "arm64",
  "kernel_commit": "abc123",
  "agent_commit": "def456",
  "built_at": "2026-02-17T00:00:00Z",
  "kernel_cmdline": "console=hvc0 rdinit=/init quiet",
  "runtime_assets": [
    {
      "name": "dockerd",
      "path": "runtime/bin/dockerd",
      "version": "28.0.0",
      "sha256": "deadbeef"
    }
  ]
}"#,
        )
        .unwrap();

        let config = BootAssetConfig {
            cache_dir,
            version,
            arch: "arm64".to_string(),
            ..Default::default()
        };
        let provider = BootAssetProvider::with_config(config);

        let manifest = provider.read_cached_manifest().await.unwrap().unwrap();
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.asset_version, "1.0.0");
        assert_eq!(manifest.arch, "arm64");
        assert_eq!(
            manifest.kernel_cmdline.as_deref(),
            Some("console=hvc0 rdinit=/init quiet")
        );
        assert_eq!(manifest.runtime_assets.len(), 1);
        assert_eq!(manifest.runtime_assets[0].name, "dockerd");
        assert_eq!(manifest.runtime_assets[0].path, "runtime/bin/dockerd");
        assert_eq!(
            manifest.runtime_assets[0].version.as_deref(),
            Some("28.0.0")
        );
        assert_eq!(
            manifest.runtime_assets[0].sha256.as_deref(),
            Some("deadbeef")
        );
    }

    #[tokio::test]
    async fn test_read_cached_manifest_version_mismatch() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let version = "1.0.0".to_string();
        let version_dir = cache_dir.join(&version);
        std::fs::create_dir_all(&version_dir).unwrap();
        std::fs::write(
            version_dir.join(MANIFEST_FILENAME),
            r#"{
  "schema_version": 1,
  "asset_version": "2.0.0",
  "arch": "arm64"
}"#,
        )
        .unwrap();

        let config = BootAssetConfig {
            cache_dir,
            version,
            arch: "arm64".to_string(),
            ..Default::default()
        };
        let provider = BootAssetProvider::with_config(config);

        let err = provider.read_cached_manifest().await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("manifest version mismatch"));
    }

    #[tokio::test]
    async fn test_read_cached_manifest_missing_is_none() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let version = "1.0.0".to_string();
        std::fs::create_dir_all(cache_dir.join(&version)).unwrap();

        let config = BootAssetConfig {
            cache_dir,
            version,
            arch: "arm64".to_string(),
            ..Default::default()
        };
        let provider = BootAssetProvider::with_config(config);

        let manifest = provider.read_cached_manifest().await.unwrap();
        assert!(manifest.is_none());
    }

    #[tokio::test]
    async fn test_read_cached_manifest_required_missing_errors() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let version = "1.0.0".to_string();
        std::fs::create_dir_all(cache_dir.join(&version)).unwrap();

        let config = BootAssetConfig {
            cache_dir,
            version,
            arch: "arm64".to_string(),
            ..Default::default()
        };
        let provider = BootAssetProvider::with_config(config);

        let err = provider.read_cached_manifest_required().await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("boot manifest required but missing"));
    }

    #[tokio::test]
    async fn test_read_cached_manifest_arch_mismatch() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let version = "1.0.0".to_string();
        let version_dir = cache_dir.join(&version);
        std::fs::create_dir_all(&version_dir).unwrap();
        std::fs::write(
            version_dir.join(MANIFEST_FILENAME),
            r#"{
  "schema_version": 1,
  "asset_version": "1.0.0",
  "arch": "x86_64"
}"#,
        )
        .unwrap();

        let config = BootAssetConfig {
            cache_dir,
            version,
            arch: "arm64".to_string(),
            ..Default::default()
        };
        let provider = BootAssetProvider::with_config(config);

        let err = provider.read_cached_manifest().await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("manifest arch mismatch"));
    }

    #[test]
    fn test_is_cached_requires_all_files() {
        let temp = tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let version = "1.0.0".to_string();
        let version_dir = cache_dir.join(&version);
        std::fs::create_dir_all(&version_dir).unwrap();

        let config = BootAssetConfig {
            cache_dir: cache_dir.clone(),
            version: version.clone(),
            arch: "arm64".to_string(),
            ..Default::default()
        };
        let provider = BootAssetProvider::with_config(config);

        // No files: not cached.
        assert!(!provider.is_cached());

        // Only kernel: not cached.
        std::fs::write(version_dir.join(KERNEL_FILENAME), b"kernel").unwrap();
        assert!(!provider.is_cached());

        // Kernel + initramfs but no manifest: not cached.
        std::fs::write(version_dir.join(INITRAMFS_FILENAME), b"initramfs").unwrap();
        assert!(!provider.is_cached());

        // All three files: cached.
        std::fs::write(version_dir.join(MANIFEST_FILENAME), b"{}").unwrap();
        assert!(provider.is_cached());
    }

    fn restore_env(original: Option<String>) {
        // SAFETY: This is test code that runs single-threaded, so modifying
        // environment variables is safe.
        unsafe {
            match original {
                Some(value) => std::env::set_var("ARCBOX_BOOT_ASSET_VERSION", value),
                None => std::env::remove_var("ARCBOX_BOOT_ASSET_VERSION"),
            }
        }
    }

    /// Builds a minimal EFI ZBOOT kernel file for testing.
    ///
    /// Layout:
    /// - bytes 0..4: PE stub ("MZ\0\0")
    /// - bytes 4..8: ZBOOT magic ("zimg")
    /// - bytes 8..12: payload_offset (u32 LE)
    /// - bytes 12..16: payload_size (u32 LE)
    /// - bytes 16..payload_offset: padding
    /// - bytes payload_offset..: gzip-compressed raw Image
    fn build_zboot_kernel(raw_image: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        // Compress the raw image with gzip.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(raw_image).unwrap();
        let compressed = encoder.finish().unwrap();

        let payload_offset: u32 = 64; // Place payload after a 64-byte header.
        let payload_size: u32 = compressed.len() as u32;

        let mut buf = vec![0u8; payload_offset as usize + compressed.len()];
        // PE stub.
        buf[0] = b'M';
        buf[1] = b'Z';
        // ZBOOT magic.
        buf[4..8].copy_from_slice(b"zimg");
        // Payload offset.
        buf[8..12].copy_from_slice(&payload_offset.to_le_bytes());
        // Payload size.
        buf[12..16].copy_from_slice(&payload_size.to_le_bytes());
        // Compressed payload.
        buf[payload_offset as usize..].copy_from_slice(&compressed);

        buf
    }

    /// Builds a minimal raw ARM64 kernel Image for testing.
    ///
    /// Places the ARM64 magic "ARMd" at offset 56.
    fn build_raw_arm64_image() -> Vec<u8> {
        let mut img = vec![0u8; 256];
        img[56..60].copy_from_slice(b"ARMd");
        img
    }

    #[tokio::test]
    async fn test_ensure_kernel_decompressed_zboot() {
        let temp = tempdir().unwrap();
        let kernel_path = temp.path().join("kernel");

        let raw_image = build_raw_arm64_image();
        let zboot = build_zboot_kernel(&raw_image);

        // Write ZBOOT kernel.
        std::fs::write(&kernel_path, &zboot).unwrap();
        assert_ne!(std::fs::read(&kernel_path).unwrap(), raw_image);

        // Decompress.
        ensure_kernel_decompressed(&kernel_path).await.unwrap();

        // After decompression, file should be the raw image.
        let result = std::fs::read(&kernel_path).unwrap();
        assert_eq!(result, raw_image);
    }

    #[tokio::test]
    async fn test_ensure_kernel_decompressed_raw_passthrough() {
        let temp = tempdir().unwrap();
        let kernel_path = temp.path().join("kernel");

        let raw_image = build_raw_arm64_image();
        std::fs::write(&kernel_path, &raw_image).unwrap();

        // Should be a no-op for already-raw kernel.
        ensure_kernel_decompressed(&kernel_path).await.unwrap();

        let result = std::fs::read(&kernel_path).unwrap();
        assert_eq!(result, raw_image);
    }

    #[tokio::test]
    async fn test_ensure_kernel_decompressed_corrupt_offset() {
        let temp = tempdir().unwrap();
        let kernel_path = temp.path().join("kernel");

        // Build a ZBOOT header with payload_offset pointing beyond the file.
        let mut buf = vec![0u8; 64];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[4..8].copy_from_slice(b"zimg");
        // Payload offset far beyond file size.
        buf[8..12].copy_from_slice(&9999u32.to_le_bytes());
        buf[12..16].copy_from_slice(&100u32.to_le_bytes());

        std::fs::write(&kernel_path, &buf).unwrap();

        let result = ensure_kernel_decompressed(&kernel_path).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exceeds file size"), "got: {msg}");
    }
}
