use super::BootAssetManifest;
use super::config::BootAssetConfig;
use super::lockfile::boot_asset_manifest_sha256;
use crate::error::{CoreError, Result};
use arcbox_boot::asset_manager::{AssetManager, AssetManagerConfig};
use arcbox_boot::download::{PrepareProgress, ProgressCallback as InnerProgressCallback};
use arcbox_constants::cmdline::HV_EARLYCON_DIRECTIVE;
use sha2::Digest;
use std::path::{Path, PathBuf};

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
    #[must_use]
    pub fn default_cmdline() -> String {
        format!(
            "console=hvc0 root=/dev/vda ro rootfstype=erofs {HV_EARLYCON_DIRECTIVE} swiotlb=noforce"
        )
    }
}

/// Progress callback type.
pub type ProgressCallback = Box<dyn Fn(PrepareProgress) + Send + Sync>;

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
    #[must_use]
    pub const fn config(&self) -> &BootAssetConfig {
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

        if let Some(expected) = boot_asset_manifest_sha256() {
            let manifest_path = self.config.version_cache_dir().join("manifest.json");
            let bytes = std::fs::read(&manifest_path)
                .map_err(|e| CoreError::config(format!("read manifest: {e}")))?;
            let actual = format!("{:x}", sha2::Sha256::digest(&bytes));
            if actual != expected {
                return Err(CoreError::config(format!(
                    "manifest SHA256 mismatch: expected {expected}, got {actual}"
                )));
            }
        }

        Ok(BootAssets {
            kernel: prepared.kernel,
            rootfs_image: prepared.rootfs,
            cmdline: prepared.kernel_cmdline,
            version: prepared.version,
            manifest: prepared.manifest,
        })
    }

    /// Prepare host-side runtime binaries into `dest_dir` — every binary in the
    /// boot manifest for the guest arch: dockerd, containerd,
    /// containerd-shim-runc-v2, runc, docker-init, k3s, and (when the release
    /// ships it) the optional FEX x86_64 interpreter used for
    /// `linux/amd64` workloads. ArcBox's FEX carries a small patch making it
    /// binfmt-only — no FEXServer.
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

    /// Returns true if the current version's boot assets are fully cached
    /// (manifest + kernel + rootfs all present).
    #[must_use]
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

    /// Fetch the latest boot-asset version string from the CDN.
    ///
    /// Returns `Ok(Some(version))` on success, `Ok(None)` if the CDN response
    /// is malformed, or `Err` on network/parse failure.
    pub async fn fetch_latest_version(&self) -> Result<Option<String>> {
        let url = format!("{}/latest.json", self.config.cdn_base_url);
        let resp = reqwest::get(&url)
            .await
            .map_err(|e| CoreError::config(format!("failed to fetch latest version: {e}")))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::config(format!("failed to parse latest.json: {e}")))?;
        Ok(body
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(String::from))
    }

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
