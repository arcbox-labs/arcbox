use super::BootAssetManifest;
use super::REQUIRED_RUNTIME_BINARIES;
use super::config::BootAssetConfig;
use super::lockfile::boot_asset_manifest_sha256;
use crate::error::{CoreError, Result};
use arcbox_boot::asset_manager::{AssetManager, AssetManagerConfig};
use arcbox_boot::download::{PrepareProgress, ProgressCallback as InnerProgressCallback};
use arcbox_boot::manifest::Binary;
use arcbox_constants::cmdline::HV_EARLYCON_DIRECTIVE;
use semver::Version;
use sha2::Digest;
use std::cmp::Ordering;
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

        self.verify_manifest_pin()?;

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
        // The binaries are verified against manifest-supplied hashes, so
        // their integrity is only as good as the manifest itself — check
        // the pin on both sides of the inner call. Before: reject an
        // already-tampered cached manifest without downloading anything it
        // names. After: catch tampering that raced the prepare (the inner
        // manager re-reads the file). The residual window — swapping the
        // file between the inner read and either check — closes only when
        // arcbox-boot verifies the bytes it parses (tracked in ABX-411).
        if self.cached_manifest_path().exists() {
            self.verify_manifest_pin()?;
        }

        let cb: Option<InnerProgressCallback> = progress.map(|p| -> InnerProgressCallback { p });
        self.manager
            .prepare_binaries(dest_dir, cb)
            .await
            .map_err(|e| CoreError::config(format!("binary prepare error: {e}")))?;

        let manifest = self.read_cached_manifest_required().await?;
        self.repair_cached_binary_permissions(&manifest, dest_dir)
            .await?;
        self.validate_cached_binaries(dest_dir).await
    }

    /// Validate every cached runtime binary selected by the pinned manifest.
    ///
    /// This performs no downloads. It uses `arcbox-boot`'s checksum and
    /// `install_dir` rules, then enforces the executable contract required by
    /// runtime startup.
    pub async fn validate_cached_binaries(&self, dest_dir: &Path) -> Result<()> {
        let manifest = self.read_cached_manifest_required().await?;
        let selected = manifest
            .binaries
            .iter()
            .filter(|binary| binary.targets.contains_key(&self.config.arch))
            .collect::<Vec<_>>();
        for name in REQUIRED_RUNTIME_BINARIES {
            let expected_path = dest_dir.join(name);
            if !selected.iter().any(|binary| {
                binary.name == name && binary_install_path(dest_dir, binary) == expected_path
            }) {
                return Err(CoreError::config(format!(
                    "manifest is missing required runtime binary '{name}' for architecture {} at {}",
                    self.config.arch,
                    expected_path.display()
                )));
            }
        }

        manifest
            .validate_binaries(&self.config.arch, dest_dir)
            .await
            .map_err(|error| {
                CoreError::config(format!("cached runtime binary validation failed: {error}"))
            })?;

        for binary in selected {
            let path = binary_install_path(dest_dir, binary);
            let metadata = regular_binary_metadata(binary, &path).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                if metadata.permissions().mode() & 0o111 == 0 {
                    return Err(CoreError::config(format!(
                        "runtime binary '{}' is not executable at {}",
                        binary.name,
                        path.display()
                    )));
                }
            }
        }

        Ok(())
    }

    async fn repair_cached_binary_permissions(
        &self,
        manifest: &BootAssetManifest,
        dest_dir: &Path,
    ) -> Result<()> {
        for binary in manifest
            .binaries
            .iter()
            .filter(|binary| binary.targets.contains_key(&self.config.arch))
        {
            let path = binary_install_path(dest_dir, binary);
            let metadata = regular_binary_metadata(binary, &path).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                if metadata.permissions().mode() & 0o111 == 0 {
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o755);
                    tokio::fs::set_permissions(&path, permissions)
                        .await
                        .map_err(|error| {
                            CoreError::config(format!(
                                "failed to make runtime binary '{}' executable at {}: {error}",
                                binary.name,
                                path.display()
                            ))
                        })?;
                }
            }
        }
        Ok(())
    }

    fn cached_manifest_path(&self) -> PathBuf {
        self.config.version_cache_dir().join("manifest.json")
    }

    /// Verifies the cached `manifest.json` against the sha256 pin compiled
    /// in from `assets.lock`. Fail-closed on mismatch; a missing pin only
    /// warns — dev workflows drop the pin deliberately to boot locally
    /// built assets.
    fn verify_manifest_pin(&self) -> Result<()> {
        if self.config.allow_unpinned_manifest {
            tracing::warn!(
                "development profile allows a locally built boot manifest to bypass the \
                 production assets.lock pin"
            );
            return Ok(());
        }
        let Some(expected) = boot_asset_manifest_sha256() else {
            tracing::warn!(
                "assets.lock carries no boot manifest_sha256 pin; skipping manifest \
                 verification (expected only in local development builds)"
            );
            return Ok(());
        };
        let bytes = std::fs::read(self.cached_manifest_path())
            .map_err(|e| CoreError::config(format!("read manifest: {e}")))?;
        let actual = format!("{:x}", sha2::Sha256::digest(&bytes));
        if actual == expected {
            Ok(())
        } else {
            Err(CoreError::config(format!(
                "manifest SHA256 mismatch: expected {expected}, got {actual}"
            )))
        }
    }

    /// Returns true if the current version's boot assets are fully cached.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        let dir = self.config.version_cache_dir();
        let kernel_ready = self
            .config
            .custom_kernel
            .as_ref()
            .map_or_else(|| dir.join("kernel").is_file(), |kernel| kernel.is_file());
        dir.join("manifest.json").is_file() && kernel_ready && dir.join("rootfs.erofs").is_file()
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
        self.verify_manifest_pin()?;
        let path = self.config.version_cache_dir().join("manifest.json");
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| CoreError::config(format!("failed to read manifest: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::config(format!("failed to parse manifest: {e}")))
    }

    pub(crate) fn cached_manifest_has_binary(&self, name: &str) -> Result<bool> {
        self.verify_manifest_pin()?;
        let path = self.cached_manifest_path();
        let bytes = std::fs::read(&path)
            .map_err(|e| CoreError::config(format!("failed to read {}: {e}", path.display())))?;
        let manifest: BootAssetManifest = serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::config(format!("failed to parse {}: {e}", path.display())))?;
        Ok(manifest_has_binary(
            &manifest,
            &self.manager.config().arch,
            name,
        ))
    }

    /// Lists cached version directories in ascending semantic-version order.
    ///
    /// Prereleases follow SemVer precedence. Invalid names sort lexically after
    /// valid versions so stray cache directories remain visible and deterministic.
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
        versions.sort_by(
            |left, right| match (Version::parse(left), Version::parse(right)) {
                (Ok(left_version), Ok(right_version)) => left_version
                    .cmp_precedence(&right_version)
                    .then_with(|| left.cmp(right)),
                (Ok(_), Err(_)) => Ordering::Less,
                (Err(_), Ok(_)) => Ordering::Greater,
                (Err(_), Err(_)) => left.cmp(right),
            },
        );
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

fn binary_install_path(dest_dir: &Path, binary: &Binary) -> PathBuf {
    binary.install_dir.as_ref().map_or_else(
        || dest_dir.join(&binary.name),
        |directory| {
            dest_dir
                .parent()
                .unwrap_or(dest_dir)
                .join(directory)
                .join(&binary.name)
        },
    )
}

async fn regular_binary_metadata(binary: &Binary, path: &Path) -> Result<std::fs::Metadata> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        CoreError::config(format!("failed to inspect {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() {
        return Err(CoreError::config(format!(
            "runtime binary '{}' is not a regular file at {}",
            binary.name,
            path.display()
        )));
    }
    Ok(metadata)
}

fn manifest_has_binary(manifest: &BootAssetManifest, arch: &str, name: &str) -> bool {
    manifest
        .binaries
        .iter()
        .any(|binary| binary.name == name && binary.targets.contains_key(arch))
}

#[cfg(test)]
mod manifest_tests {
    use super::{BootAssetConfig, BootAssetManifest, BootAssetProvider, manifest_has_binary};
    use crate::boot_assets::REQUIRED_RUNTIME_BINARIES;

    #[cfg(unix)]
    fn cached_runtime_fixture() -> (tempfile::TempDir, BootAssetProvider, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        use sha2::{Digest as _, Sha256};

        let directory = tempfile::tempdir().unwrap();
        let mut config = BootAssetConfig::with_cache_dir(directory.path().join("boot"))
            .with_unpinned_manifest_allowed(true);
        config.arch = "test-arch".to_owned();
        let version_dir = config.version_cache_dir();
        let bin_dir = directory
            .path()
            .join("runtime")
            .join(&config.version)
            .join("bin");
        let kernel_dir = bin_dir.parent().unwrap().join("kernel");
        std::fs::create_dir_all(&version_dir).unwrap();
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&kernel_dir).unwrap();

        let mut binaries = Vec::new();
        for name in REQUIRED_RUNTIME_BINARIES {
            let path = bin_dir.join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            binaries.push(serde_json::json!({
                "name": name,
                "version": "1",
                "targets": {"test-arch": {
                    "path": format!("runtime/{name}"),
                    "sha256": format!("{:x}", Sha256::digest(name.as_bytes()))
                }}
            }));
        }

        let vmlinux = kernel_dir.join("vmlinux");
        std::fs::write(&vmlinux, b"vmlinux").unwrap();
        std::fs::set_permissions(&vmlinux, std::fs::Permissions::from_mode(0o755)).unwrap();
        binaries.push(serde_json::json!({
            "name": "vmlinux",
            "version": "1",
            "install_dir": "kernel",
            "targets": {"test-arch": {
                "path": "runtime/vmlinux",
                "sha256": format!("{:x}", Sha256::digest(b"vmlinux"))
            }}
        }));

        std::fs::write(
            version_dir.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 0,
                "asset_version": config.version,
                "built_at": "now",
                "targets": {},
                "binaries": binaries
            }))
            .unwrap(),
        )
        .unwrap();
        let provider = BootAssetProvider::with_config(config).unwrap();
        (directory, provider, bin_dir)
    }

    #[test]
    fn binary_capability_is_scoped_to_the_current_architecture() {
        let manifest: BootAssetManifest = serde_json::from_value(serde_json::json!({
            "schema_version": 0,
            "asset_version": "0.6.13",
            "built_at": "now",
            "targets": {},
            "binaries": [{
                "name": "FEX",
                "version": "1",
                "targets": {
                    "arm64": {
                        "path": "FEX",
                        "sha256": "0".repeat(64)
                    }
                }
            }]
        }))
        .unwrap();

        assert!(manifest_has_binary(&manifest, "arm64", "FEX"));
        assert!(!manifest_has_binary(&manifest, "x86_64", "FEX"));
        assert!(!manifest_has_binary(&manifest, "arm64", "dockerd"));
    }

    #[tokio::test]
    async fn required_manifest_read_rejects_bytes_that_do_not_match_the_pin() {
        let directory = tempfile::tempdir().unwrap();
        let config = BootAssetConfig::with_cache_dir(directory.path().to_owned());
        std::fs::create_dir_all(config.version_cache_dir()).unwrap();
        std::fs::write(
            config.version_cache_dir().join("manifest.json"),
            r#"{
                "schema_version": 0,
                "asset_version": "0.8.4",
                "built_at": "now",
                "targets": {},
                "binaries": []
            }"#,
        )
        .unwrap();
        let provider = BootAssetProvider::with_config(config).unwrap();

        let error = provider.read_cached_manifest_required().await.unwrap_err();

        assert!(error.to_string().contains("manifest SHA256 mismatch"));
    }

    #[test]
    fn cache_accepts_a_configured_custom_kernel() {
        let directory = tempfile::tempdir().unwrap();
        let config = BootAssetConfig::with_cache_dir(directory.path().join("boot"))
            .with_custom_kernel(Some(directory.path().join("custom-kernel")));
        std::fs::create_dir_all(config.version_cache_dir()).unwrap();
        std::fs::write(
            config.version_cache_dir().join("manifest.json"),
            b"manifest",
        )
        .unwrap();
        std::fs::write(config.version_cache_dir().join("rootfs.erofs"), b"rootfs").unwrap();
        std::fs::write(config.custom_kernel.as_ref().unwrap(), b"kernel").unwrap();
        let provider = BootAssetProvider::with_config(config.clone()).unwrap();

        assert!(provider.is_cached());
        std::fs::remove_file(config.custom_kernel.unwrap()).unwrap();
        assert!(!provider.is_cached());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cached_binary_validation_checks_manifest_paths_hashes_and_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, provider, bin_dir) = cached_runtime_fixture();
        let kernel_dir = bin_dir.parent().unwrap().join("kernel");
        let dockerd = bin_dir.join("dockerd");
        let vmlinux = kernel_dir.join("vmlinux");

        provider.validate_cached_binaries(&bin_dir).await.unwrap();

        std::fs::set_permissions(&dockerd, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = provider
            .validate_cached_binaries(&bin_dir)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("dockerd' is not executable"));

        std::fs::set_permissions(&dockerd, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&dockerd, b"corrupt dockerd").unwrap();
        let error = provider
            .validate_cached_binaries(&bin_dir)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("sha256 mismatch for 'dockerd'"),
            "{error}"
        );

        std::fs::write(&dockerd, b"dockerd").unwrap();
        std::fs::remove_file(&vmlinux).unwrap();
        let error = provider
            .validate_cached_binaries(&bin_dir)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("vmlinux"));
    }

    #[tokio::test]
    async fn cached_binary_validation_requires_the_full_runtime_contract() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = BootAssetConfig::with_cache_dir(directory.path().join("boot"))
            .with_unpinned_manifest_allowed(true);
        config.arch = "arm64".to_owned();
        std::fs::create_dir_all(config.version_cache_dir()).unwrap();
        std::fs::write(
            config.version_cache_dir().join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 0,
                "asset_version": config.version,
                "built_at": "now",
                "targets": {},
                "binaries": [{
                    "name": "dockerd",
                    "version": "1",
                    "targets": {"arm64": {"path": "dockerd", "sha256": "00"}}
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let provider = BootAssetProvider::with_config(config).unwrap();

        let error = provider
            .validate_cached_binaries(directory.path())
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing required runtime binary 'containerd' for architecture arm64")
        );
    }

    #[tokio::test]
    async fn cached_binary_validation_requires_runtime_binaries_in_bin() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = BootAssetConfig::with_cache_dir(directory.path().join("boot"))
            .with_unpinned_manifest_allowed(true);
        config.arch = "arm64".to_owned();
        std::fs::create_dir_all(config.version_cache_dir()).unwrap();
        let binaries = REQUIRED_RUNTIME_BINARIES
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "version": "1",
                    "install_dir": (name == "dockerd").then_some("kernel"),
                    "targets": {"arm64": {"path": name, "sha256": "00"}}
                })
            })
            .to_vec();
        std::fs::write(
            config.version_cache_dir().join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 0,
                "asset_version": config.version,
                "built_at": "now",
                "targets": {},
                "binaries": binaries
            }))
            .unwrap(),
        )
        .unwrap();
        let bin_dir = directory
            .path()
            .join("runtime")
            .join(&config.version)
            .join("bin");
        let provider = BootAssetProvider::with_config(config).unwrap();

        let error = provider
            .validate_cached_binaries(&bin_dir)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing required runtime binary 'dockerd'")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cached_binary_validation_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let (_directory, provider, bin_dir) = cached_runtime_fixture();
        let dockerd = bin_dir.join("dockerd");
        let target = bin_dir.join("dockerd.real");
        std::fs::rename(&dockerd, &target).unwrap();
        symlink(&target, &dockerd).unwrap();

        let error = provider
            .validate_cached_binaries(&bin_dir)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("dockerd' is not a regular file"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn binary_prepare_repairs_cached_executable_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, provider, bin_dir) = cached_runtime_fixture();
        let dockerd = bin_dir.join("dockerd");
        std::fs::set_permissions(&dockerd, std::fs::Permissions::from_mode(0o644)).unwrap();

        provider.prepare_binaries(&bin_dir, None).await.unwrap();

        assert_ne!(
            std::fs::metadata(dockerd).unwrap().permissions().mode() & 0o111,
            0
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn binary_prepare_rejects_a_partial_runtime_contract() {
        let (_directory, provider, bin_dir) = cached_runtime_fixture();
        let manifest_path = provider.config().version_cache_dir().join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["binaries"]
            .as_array_mut()
            .unwrap()
            .retain(|binary| binary["name"] != "k3s");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let error = provider.prepare_binaries(&bin_dir, None).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("missing required runtime binary 'k3s'")
        );
    }
}
