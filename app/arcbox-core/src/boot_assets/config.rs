use super::lockfile::{boot_asset_cdn, boot_asset_version};
use arcbox_constants::env::BOOT_ASSET_VERSION as BOOT_ASSET_VERSION_ENV;
use std::path::PathBuf;

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
    /// Allow a locally built development manifest to differ from `assets.lock`.
    pub allow_unpinned_manifest: bool,
}

impl Default for BootAssetConfig {
    fn default() -> Self {
        let version = std::env::var(BOOT_ASSET_VERSION_ENV)
            .unwrap_or_else(|_| boot_asset_version().to_string());

        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        }
        .to_string();

        Self {
            cdn_base_url: boot_asset_cdn().to_string(),
            version,
            arch,
            cache_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".arcbox")
                .join("boot"),
            custom_kernel: None,
            allow_unpinned_manifest: false,
        }
    }
}

impl BootAssetConfig {
    /// Creates config with an explicit cache directory.
    #[must_use]
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

    /// Allow local development boot assets whose manifest is generated after
    /// the daemon was compiled.
    #[must_use]
    pub const fn with_unpinned_manifest_allowed(mut self, allowed: bool) -> Self {
        self.allow_unpinned_manifest = allowed;
        self
    }

    /// Returns the versioned cache directory (e.g. `~/.arcbox/boot/0.2.0`).
    #[must_use]
    pub fn version_cache_dir(&self) -> PathBuf {
        self.cache_dir.join(&self.version)
    }
}
