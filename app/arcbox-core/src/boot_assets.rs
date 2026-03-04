//! Boot asset management for VM startup.
//!
//! Thin wrapper around `arcbox_boot::AssetManager` (schema v7).
//! All downloading, caching, and verification logic lives in the
//! `arcbox-boot` crate; this module provides daemon-specific
//! configuration defaults, error mapping, and the `BootAssets` struct
//! that `vm_lifecycle` consumes.

use crate::error::{CoreError, Result};
use arcbox_boot::asset_manager::{AssetManager, AssetManagerConfig};
use arcbox_boot::download::{PrepareProgress, ProgressCallback as InnerProgressCallback};
use arcbox_constants::env::BOOT_ASSET_VERSION as BOOT_ASSET_VERSION_ENV;
use std::path::{Path, PathBuf};

// Re-exports for consumers (CLI, lib.rs).
pub use arcbox_boot::download::{PreparePhase, PrepareProgress as DownloadProgress};
pub use arcbox_boot::manifest::Manifest as BootAssetManifest;

// =============================================================================
// Constants
// =============================================================================

/// Boot asset version pinned by this daemon release.
pub const BOOT_ASSET_VERSION: &str = "0.2.2";

/// Default CDN base URL.
const DEFAULT_CDN_BASE_URL: &str = "https://dl.arcbox.dev/boot-assets";

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
    /// Target architecture.
    pub arch: String,
    /// Cache directory for downloaded assets.
    pub cache_dir: PathBuf,
    /// Custom kernel path (skip download).
    pub custom_kernel: Option<PathBuf>,
}

impl Default for BootAssetConfig {
    fn default() -> Self {
        let version = std::env::var(BOOT_ASSET_VERSION_ENV)
            .unwrap_or_else(|_| BOOT_ASSET_VERSION.to_string());

        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        }
        .to_string();

        Self {
            cdn_base_url: DEFAULT_CDN_BASE_URL.to_string(),
            version,
            arch,
            cache_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".arcbox")
                .join("boot"),
            custom_kernel: None,
        }
    }
}

impl BootAssetConfig {
    /// Creates config with an explicit cache directory.
    pub fn with_cache_dir(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            ..Default::default()
        }
    }

    /// Override asset version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Returns the versioned cache directory (e.g. `~/.arcbox/boot/0.2.0`).
    pub fn version_cache_dir(&self) -> PathBuf {
        self.cache_dir.join(&self.version)
    }
}

// =============================================================================
// Boot Assets (consumed by vm_lifecycle)
// =============================================================================

/// Boot assets required for VM startup.
///
/// Contains kernel + EROFS read-only rootfs. No initramfs.
#[derive(Debug, Clone)]
pub struct BootAssets {
    /// Path to kernel image.
    pub kernel: PathBuf,
    /// Path to EROFS rootfs image (attached as /dev/vda, read-only).
    pub rootfs_image: PathBuf,
    /// Kernel command line.
    pub cmdline: String,
    /// Asset version.
    pub version: String,
    /// Parsed manifest metadata.
    pub manifest: BootAssetManifest,
}

impl BootAssets {
    /// Default kernel command line for EROFS rootfs boot.
    pub fn default_cmdline() -> String {
        "console=hvc0 root=/dev/vda ro rootfstype=erofs earlycon".to_string()
    }
}

// =============================================================================
// Progress Callback
// =============================================================================

/// Progress callback type.
pub type ProgressCallback = Box<dyn Fn(PrepareProgress) + Send + Sync>;

// =============================================================================
// Boot Asset Provider
// =============================================================================

/// Boot asset provider — delegates to `arcbox_boot::AssetManager`.
pub struct BootAssetProvider {
    manager: AssetManager,
    config: BootAssetConfig,
}

impl BootAssetProvider {
    /// Creates a provider with default config rooted at `cache_dir`.
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        let config = BootAssetConfig::with_cache_dir(cache_dir);
        Self::with_config(config)
    }

    /// Creates a provider from explicit config.
    pub fn with_config(config: BootAssetConfig) -> Result<Self> {
        let inner_config = Self::build_inner_config(&config);
        let manager = AssetManager::new(inner_config)
            .map_err(|e| CoreError::config(format!("invalid boot asset config: {e}")))?;
        Ok(Self { manager, config })
    }

    /// Override the kernel path.
    pub fn with_kernel(mut self, kernel: PathBuf) -> Result<Self> {
        if kernel.as_os_str().is_empty() {
            return Ok(self);
        }
        self.config.custom_kernel = Some(kernel);
        self.rebuild_manager()?;
        Ok(self)
    }

    /// Returns the configuration.
    pub fn config(&self) -> &BootAssetConfig {
        &self.config
    }

    /// Prepare boot assets (download if not cached), returning
    /// the `BootAssets` struct that `vm_lifecycle` consumes.
    pub async fn get_assets(&self) -> Result<BootAssets> {
        self.get_assets_with_progress(None).await
    }

    /// Prepare boot assets with optional progress callback.
    pub async fn get_assets_with_progress(
        &self,
        progress: Option<ProgressCallback>,
    ) -> Result<BootAssets> {
        let cb: Option<InnerProgressCallback> = progress.map(|p| -> InnerProgressCallback { p });
        let prepared = self
            .manager
            .prepare(cb)
            .await
            .map_err(|e| CoreError::config(format!("boot asset error: {e}")))?;

        Ok(BootAssets {
            kernel: prepared.kernel,
            rootfs_image: prepared.rootfs,
            cmdline: prepared.kernel_cmdline,
            version: prepared.version,
            manifest: prepared.manifest,
        })
    }

    /// Prepare host-side binaries (dockerd, containerd, shim, runc) into `dest_dir`.
    pub async fn prepare_binaries(
        &self,
        dest_dir: &Path,
        progress: Option<ProgressCallback>,
    ) -> Result<()> {
        let cb: Option<InnerProgressCallback> = progress.map(|p| -> InnerProgressCallback { p });
        self.manager
            .prepare_binaries(dest_dir, cb)
            .await
            .map_err(|e| CoreError::config(format!("binary prepare error: {e}")))
    }

    // =========================================================================
    // CLI convenience methods
    // =========================================================================

    /// Returns true if the current version's boot assets are fully cached
    /// (manifest + kernel + rootfs all present).
    pub fn is_cached(&self) -> bool {
        let dir = self.config.version_cache_dir();
        dir.join("manifest.json").exists()
            && dir.join("kernel").exists()
            && dir.join("rootfs.erofs").exists()
    }

    /// Prefetches boot assets (downloads if not cached).
    pub async fn prefetch_with_progress(&self, progress: Option<ProgressCallback>) -> Result<()> {
        let _ = self.get_assets_with_progress(progress).await?;
        Ok(())
    }

    /// Removes the version cache directory for the current version.
    pub async fn clear_cache(&self) -> Result<()> {
        let dir = self.config.version_cache_dir();
        if dir.exists() {
            tokio::fs::remove_dir_all(&dir)
                .await
                .map_err(|e| CoreError::config(format!("failed to clear cache: {e}")))?;
        }
        Ok(())
    }

    /// Reads and returns the cached manifest for the current version.
    pub async fn read_cached_manifest_required(&self) -> Result<BootAssetManifest> {
        let path = self.config.version_cache_dir().join("manifest.json");
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| CoreError::config(format!("failed to read manifest: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::config(format!("failed to parse manifest: {e}")))
    }

    /// Lists all cached version directories.
    pub async fn list_cached_versions(&self) -> Result<Vec<String>> {
        let cache_dir = &self.config.cache_dir;
        if !cache_dir.exists() {
            return Ok(Vec::new());
        }
        let mut versions = Vec::new();
        let mut entries = tokio::fs::read_dir(cache_dir)
            .await
            .map_err(|e| CoreError::config(format!("failed to read cache dir: {e}")))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CoreError::config(format!("failed to read cache entry: {e}")))?
        {
            let path = entry.path();
            if path.is_dir() && path.join("manifest.json").exists() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    versions.push(name.to_string());
                }
            }
        }
        versions.sort();
        Ok(versions)
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    fn build_inner_config(config: &BootAssetConfig) -> AssetManagerConfig {
        AssetManagerConfig {
            cdn_base_url: config.cdn_base_url.clone(),
            version: config.version.clone(),
            arch: config.arch.clone(),
            cache_dir: config.cache_dir.clone(),
            custom_kernel: config.custom_kernel.clone(),
        }
    }

    fn rebuild_manager(&mut self) -> Result<()> {
        let inner_config = Self::build_inner_config(&self.config);
        self.manager = AssetManager::new(inner_config)
            .map_err(|e| CoreError::config(format!("invalid boot asset config: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_config() {
        let config = BootAssetConfig::default();
        assert!(!config.cdn_base_url.is_empty());
        assert!(!config.version.is_empty());
        assert!(!config.arch.is_empty());
    }

    #[test]
    fn test_default_config_uses_boot_asset_version() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original = std::env::var(BOOT_ASSET_VERSION_ENV).ok();
        // SAFETY: Test code running under ENV_LOCK mutex.
        unsafe { std::env::remove_var(BOOT_ASSET_VERSION_ENV) };

        let config = BootAssetConfig::default();
        assert_eq!(config.version, BOOT_ASSET_VERSION);

        restore_env(original);
    }

    #[test]
    fn test_default_config_env_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let original = std::env::var(BOOT_ASSET_VERSION_ENV).ok();
        // SAFETY: Test code running under ENV_LOCK mutex.
        unsafe { std::env::set_var(BOOT_ASSET_VERSION_ENV, "9.9.9") };

        let config = BootAssetConfig::default();
        assert_eq!(config.version, "9.9.9");

        restore_env(original);
    }

    #[test]
    fn test_version_cache_dir() {
        let config = BootAssetConfig {
            version: "1.0.0".to_string(),
            cache_dir: PathBuf::from("/tmp/boot"),
            ..Default::default()
        };
        assert_eq!(config.version_cache_dir(), PathBuf::from("/tmp/boot/1.0.0"));
    }

    #[test]
    fn test_is_cached_requires_all_assets() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().to_path_buf();
        let version = "1.0.0".to_string();
        let version_dir = cache_dir.join(&version);
        std::fs::create_dir_all(&version_dir).unwrap();

        let config = BootAssetConfig {
            cache_dir: cache_dir.clone(),
            version: version.clone(),
            ..Default::default()
        };
        let provider = BootAssetProvider::with_config(config).unwrap();

        // Empty dir: not cached.
        assert!(!provider.is_cached());

        // Manifest only: not cached.
        std::fs::write(version_dir.join("manifest.json"), b"{}").unwrap();
        assert!(!provider.is_cached());

        // Manifest + kernel: not cached.
        std::fs::write(version_dir.join("kernel"), b"vmlinux").unwrap();
        assert!(!provider.is_cached());

        // Manifest + kernel + rootfs: cached.
        std::fs::write(version_dir.join("rootfs.erofs"), b"erofs").unwrap();
        assert!(provider.is_cached());
    }

    fn restore_env(original: Option<String>) {
        // SAFETY: Test code running under ENV_LOCK mutex.
        unsafe {
            match original {
                Some(value) => std::env::set_var(BOOT_ASSET_VERSION_ENV, value),
                None => std::env::remove_var(BOOT_ASSET_VERSION_ENV),
            }
        }
    }
}
