//! Host tool manager — download, extract, install, and validate ArcBox-managed
//! host binaries from the versions pinned in `assets.lock`.

use crate::lockfile::ToolEntry;
use crate::registry::{self, ArtifactFormat};
use arcbox_asset::download::{download_and_verify, sha256_file};
use arcbox_asset::{PreparePhase, PrepareProgress, ProgressCallback};
use std::path::{Path, PathBuf};
use tracing::info;

/// Manages ArcBox host tool installation.
pub struct HostToolManager {
    /// Architecture string (e.g. "arm64", "x86_64").
    arch: String,
    /// Directory for downloaded artifacts (e.g. `~/.arcbox/runtime/bin/`).
    install_dir: PathBuf,
    /// Tool entries parsed from `assets.lock`.
    tools: Vec<ToolEntry>,
    /// Optional directory containing pre-built binaries from an app bundle
    /// (e.g. `Contents/MacOS/xbin/`).
    bundle_dir: Option<PathBuf>,
}

impl HostToolManager {
    /// Create a new manager from parsed tool entries.
    #[must_use]
    pub fn new(tools: Vec<ToolEntry>, arch: impl Into<String>, install_dir: PathBuf) -> Self {
        Self {
            arch: arch.into(),
            install_dir,
            tools,
            bundle_dir: None,
        }
    }

    /// Set an app-bundle directory containing pre-built binaries.
    ///
    /// When set, `install_one` will try to copy from this directory before
    /// falling back to a CDN download.
    #[must_use]
    pub fn with_bundle_dir(mut self, dir: PathBuf) -> Self {
        self.bundle_dir = Some(dir);
        self
    }

    /// Install all configured Docker tools.
    ///
    /// For each tool: check cache → try bundle → download → verify → extract → chmod.
    pub async fn install_all(
        &self,
        progress: Option<&ProgressCallback>,
    ) -> Result<(), HostToolError> {
        tokio::fs::create_dir_all(&self.install_dir)
            .await
            .map_err(HostToolError::Io)?;

        let total = self.tools.len();
        for (idx, tool) in self.tools.iter().enumerate() {
            self.install_one(tool, idx + 1, total, progress).await?;
        }

        Ok(())
    }

    /// Install a single tool.
    async fn install_one(
        &self,
        tool: &ToolEntry,
        current: usize,
        total: usize,
        progress: Option<&ProgressCallback>,
    ) -> Result<(), HostToolError> {
        let expected_sha =
            tool.sha256_for_arch(&self.arch)
                .ok_or_else(|| HostToolError::UnsupportedArch {
                    tool: tool.name.clone(),
                    arch: self.arch.clone(),
                })?;

        let dest = self.install_dir.join(&tool.name);
        let format = registry::artifact_format(&tool.name);

        let pg = |phase: PreparePhase| {
            if let Some(cb) = progress {
                cb(PrepareProgress {
                    name: tool.name.clone(),
                    current,
                    total,
                    phase,
                });
            }
        };

        pg(PreparePhase::Checking);

        // Check cache: if the binary exists and the checksum/sidecar matches, skip.
        if dest.exists() && self.is_cached(&tool.name, expected_sha, format).await {
            pg(PreparePhase::Cached);
            info!(tool = %tool.name, "already installed, checksum matches");
            return Ok(());
        }

        // Try to install from app bundle before downloading from CDN.
        if self
            .try_install_from_bundle(tool, &dest, expected_sha, format)
            .await?
        {
            mark_executable(&dest).await?;
            write_sidecar(&self.install_dir, &tool.name, expected_sha).await?;
            pg(PreparePhase::Ready);
            info!(tool = %tool.name, version = %tool.version, "installed from bundle");
            return Ok(());
        }

        let url = registry::download_url(&tool.name, &tool.version, &self.arch);

        match format {
            ArtifactFormat::Binary => {
                // Direct binary download — verified by arcbox-asset.
                download_and_verify(&url, &dest, expected_sha, &tool.name, |dl, tot| {
                    pg(PreparePhase::Downloading {
                        downloaded: dl,
                        total: tot,
                    });
                })
                .await
                .map_err(HostToolError::Asset)?;
            }
            ArtifactFormat::Tgz => {
                // Download tgz to temp, verify checksum, then extract the binary.
                let tgz_path = self.install_dir.join(format!("{}.tgz", tool.name));
                download_and_verify(&url, &tgz_path, expected_sha, &tool.name, |dl, tot| {
                    pg(PreparePhase::Downloading {
                        downloaded: dl,
                        total: tot,
                    });
                })
                .await
                .map_err(HostToolError::Asset)?;

                pg(PreparePhase::Verifying);
                extract_from_tgz(&tgz_path, registry::tgz_inner_path(&tool.name), &dest)?;
                let _ = tokio::fs::remove_file(&tgz_path).await;
            }
        }

        mark_executable(&dest).await?;
        write_sidecar(&self.install_dir, &tool.name, expected_sha).await?;

        pg(PreparePhase::Ready);
        info!(tool = %tool.name, version = %tool.version, "installed");
        Ok(())
    }

    /// Check whether the installed binary is up-to-date.
    ///
    /// For `Binary` artifacts the SHA-256 of the file on disk is compared
    /// directly against `expected_sha`.  For `Tgz` artifacts (e.g. `docker`)
    /// the expected hash refers to the *archive*, not the extracted binary, so
    /// we store/read a sidecar `{name}.sha256` file instead.
    async fn is_cached(&self, name: &str, expected_sha: &str, format: ArtifactFormat) -> bool {
        match format {
            ArtifactFormat::Binary => {
                let path = self.install_dir.join(name);
                sha256_file(&path)
                    .await
                    .is_ok_and(|actual| actual == expected_sha)
            }
            ArtifactFormat::Tgz => {
                let sidecar = self.install_dir.join(format!("{name}.sha256"));
                tokio::fs::read_to_string(&sidecar)
                    .await
                    .is_ok_and(|content| content.trim() == expected_sha)
            }
        }
    }

    /// Try to install a tool from the app bundle directory.
    ///
    /// Returns `true` if the tool was successfully installed from the bundle.
    /// Uses a randomized temp file to prevent symlink attacks, then atomically
    /// renames into `dest`.
    async fn try_install_from_bundle(
        &self,
        tool: &ToolEntry,
        dest: &Path,
        expected_sha: &str,
        format: ArtifactFormat,
    ) -> Result<bool, HostToolError> {
        let bundle_dir = match &self.bundle_dir {
            Some(dir) => dir,
            None => return Ok(false),
        };

        let src = bundle_dir.join(&tool.name);
        if !src.exists() {
            return Ok(false);
        }

        // Create a secure temp file in the install dir (randomized name,
        // O_CREAT|O_EXCL). Copy into the already-open handle to avoid TOCTOU
        // symlink races on the temp path.
        let tmp = tempfile::NamedTempFile::new_in(&self.install_dir).map_err(HostToolError::Io)?;
        {
            use tokio::io::AsyncWriteExt;
            let src_bytes = tokio::fs::read(&src).await;
            match src_bytes {
                Ok(bytes) => {
                    let std_file = tmp.as_file().try_clone().map_err(HostToolError::Io)?;
                    let mut async_file = tokio::fs::File::from_std(std_file);
                    if let Err(e) = async_file.write_all(&bytes).await {
                        let _ = tmp.close();
                        info!(tool = %tool.name, error = %e, "bundle copy failed, will download");
                        return Ok(false);
                    }
                    async_file.flush().await.map_err(HostToolError::Io)?;
                }
                Err(e) => {
                    let _ = tmp.close();
                    info!(tool = %tool.name, error = %e, "bundle read failed, will download");
                    return Ok(false);
                }
            }
        }
        let tmp_path = tmp.into_temp_path();

        // Verify the bundled binary.
        match format {
            ArtifactFormat::Binary => {
                // SHA-256 in assets.lock is for the binary itself.
                match sha256_file(&tmp_path).await {
                    Ok(actual) if actual == expected_sha => {}
                    Ok(_) => {
                        let _ = tmp_path.close();
                        info!(tool = %tool.name, "bundle checksum mismatch, will download");
                        return Ok(false);
                    }
                    Err(_) => {
                        let _ = tmp_path.close();
                        info!(tool = %tool.name, "bundle checksum read failed, will download");
                        return Ok(false);
                    }
                }
            }
            ArtifactFormat::Tgz => {
                // SHA-256 in assets.lock is for the archive, not the extracted
                // binary. Require a bundle-provided `{name}.sha256` file whose
                // contents match `expected_sha` to confirm the binary version.
                let checksum_path = bundle_dir.join(format!("{}.sha256", tool.name));
                match tokio::fs::read_to_string(&checksum_path).await {
                    Ok(contents) if contents.trim() == expected_sha => {}
                    Ok(_) => {
                        let _ = tmp_path.close();
                        info!(tool = %tool.name, "bundle archive checksum mismatch, will download");
                        return Ok(false);
                    }
                    Err(_) => {
                        let _ = tmp_path.close();
                        info!(tool = %tool.name, "bundle checksum file missing, will download");
                        return Ok(false);
                    }
                }
            }
        }

        // Atomic persist into final destination.
        if let Err(e) = tmp_path.persist(dest) {
            info!(tool = %tool.name, error = %e, "bundle persist failed, will download");
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate that all tools are installed and checksums match.
    pub async fn validate_all(&self) -> Result<(), HostToolError> {
        for tool in &self.tools {
            let expected_sha =
                tool.sha256_for_arch(&self.arch)
                    .ok_or_else(|| HostToolError::UnsupportedArch {
                        tool: tool.name.clone(),
                        arch: self.arch.clone(),
                    })?;

            let path = self.install_dir.join(&tool.name);
            if !path.exists() {
                return Err(HostToolError::NotInstalled(tool.name.clone()));
            }

            let format = registry::artifact_format(&tool.name);
            match format {
                ArtifactFormat::Binary => {
                    let actual = sha256_file(&path).await.map_err(HostToolError::Asset)?;
                    if actual != expected_sha {
                        return Err(HostToolError::Asset(
                            arcbox_asset::AssetError::ChecksumMismatch {
                                name: tool.name.clone(),
                                expected: expected_sha.to_string(),
                                actual,
                            },
                        ));
                    }
                }
                ArtifactFormat::Tgz => {
                    let sidecar = self.install_dir.join(format!("{}.sha256", tool.name));
                    let content = match tokio::fs::read_to_string(&sidecar).await {
                        Ok(content) => content,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            // Missing sidecar means an older install that didn't
                            // create one — treat as not installed so callers can
                            // trigger a reinstall.
                            return Err(HostToolError::NotInstalled(tool.name.clone()));
                        }
                        Err(e) => return Err(HostToolError::Io(e)),
                    };
                    if content.trim() != expected_sha {
                        return Err(HostToolError::Asset(
                            arcbox_asset::AssetError::ChecksumMismatch {
                                name: tool.name.clone(),
                                expected: expected_sha.to_string(),
                                actual: content.trim().to_string(),
                            },
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the install directory.
    #[must_use]
    pub fn install_dir(&self) -> &Path {
        &self.install_dir
    }

    /// Returns the list of tool entries.
    #[must_use]
    pub fn tools(&self) -> &[ToolEntry] {
        &self.tools
    }
}

/// Mark a file as executable (0o755).
#[cfg(unix)]
async fn mark_executable(path: &Path) -> Result<(), HostToolError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = tokio::fs::metadata(path)
        .await
        .map_err(HostToolError::Io)?
        .permissions();
    perms.set_mode(0o755);
    tokio::fs::set_permissions(path, perms)
        .await
        .map_err(HostToolError::Io)?;
    Ok(())
}

#[cfg(not(unix))]
async fn mark_executable(_path: &Path) -> Result<(), HostToolError> {
    Ok(())
}

/// Write a sidecar `{name}.sha256` file recording the expected checksum from
/// `assets.lock`.  Used for tgz-based tools where the on-disk binary cannot be
/// compared against the archive checksum directly.
async fn write_sidecar(
    install_dir: &Path,
    name: &str,
    expected_sha: &str,
) -> Result<(), HostToolError> {
    let sidecar = install_dir.join(format!("{name}.sha256"));
    tokio::fs::write(&sidecar, expected_sha)
        .await
        .map_err(HostToolError::Io)?;
    Ok(())
}

/// Extract a single file from a `.tgz` archive.
fn extract_from_tgz(
    archive_path: &Path,
    inner_path: &str,
    dest: &Path,
) -> Result<(), HostToolError> {
    let file = std::fs::File::open(archive_path).map_err(HostToolError::Io)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries().map_err(HostToolError::Io)? {
        let mut entry = entry.map_err(HostToolError::Io)?;
        let path = entry.path().map_err(HostToolError::Io)?;
        if path.to_string_lossy() == inner_path {
            entry.unpack(dest).map_err(HostToolError::Io)?;
            return Ok(());
        }
    }

    Err(HostToolError::ExtractFailed {
        archive: archive_path.display().to_string(),
        inner: inner_path.to_string(),
    })
}

/// Errors from host tool operations.
#[derive(Debug, thiserror::Error)]
pub enum HostToolError {
    #[error("asset error: {0}")]
    Asset(#[from] arcbox_asset::AssetError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tool '{tool}' has no binary for architecture '{arch}'")]
    UnsupportedArch { tool: String, arch: String },

    #[error("tool '{0}' is not installed")]
    NotInstalled(String),

    #[error("failed to extract '{inner}' from archive '{archive}'")]
    ExtractFailed { archive: String, inner: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{ArchEntry, ToolGroup};

    fn make_tool(name: &str, sha: &str) -> ToolEntry {
        ToolEntry {
            name: name.to_string(),
            group: ToolGroup::Docker,
            version: "1.0.0".to_string(),
            arch: std::collections::HashMap::from([(
                "arm64".to_string(),
                ArchEntry {
                    sha256: sha.to_string(),
                },
            )]),
        }
    }

    // -- is_cached tests --

    #[tokio::test]
    async fn is_cached_binary_hit() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"hello binary";
        let sha = sha256_bytes(content);
        tokio::fs::write(dir.path().join("my-tool"), content)
            .await
            .unwrap();

        let mgr = HostToolManager::new(vec![], "arm64", dir.path().to_path_buf());
        assert!(mgr.is_cached("my-tool", &sha, ArtifactFormat::Binary).await);
    }

    #[tokio::test]
    async fn is_cached_binary_miss() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("my-tool"), b"old version")
            .await
            .unwrap();

        let mgr = HostToolManager::new(vec![], "arm64", dir.path().to_path_buf());
        assert!(
            !mgr.is_cached("my-tool", "wrong-sha", ArtifactFormat::Binary)
                .await
        );
    }

    #[tokio::test]
    async fn is_cached_tgz_sidecar_hit() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("docker"), b"binary")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("docker.sha256"), "abc123")
            .await
            .unwrap();

        let mgr = HostToolManager::new(vec![], "arm64", dir.path().to_path_buf());
        assert!(mgr.is_cached("docker", "abc123", ArtifactFormat::Tgz).await);
    }

    #[tokio::test]
    async fn is_cached_tgz_sidecar_miss() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("docker"), b"binary")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("docker.sha256"), "old-sha")
            .await
            .unwrap();

        let mgr = HostToolManager::new(vec![], "arm64", dir.path().to_path_buf());
        assert!(
            !mgr.is_cached("docker", "new-sha", ArtifactFormat::Tgz)
                .await
        );
    }

    #[tokio::test]
    async fn is_cached_tgz_no_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("docker"), b"binary")
            .await
            .unwrap();

        let mgr = HostToolManager::new(vec![], "arm64", dir.path().to_path_buf());
        assert!(
            !mgr.is_cached("docker", "any-sha", ArtifactFormat::Tgz)
                .await
        );
    }

    // -- try_install_from_bundle tests --

    #[tokio::test]
    async fn bundle_install_binary_ok() {
        let install_dir = tempfile::tempdir().unwrap();
        let bundle_dir = tempfile::tempdir().unwrap();
        let content = b"good binary";
        let sha = sha256_bytes(content);

        tokio::fs::write(bundle_dir.path().join("my-tool"), content)
            .await
            .unwrap();

        let tool = make_tool("my-tool", &sha);
        let dest = install_dir.path().join("my-tool");

        let mgr = HostToolManager::new(vec![], "arm64", install_dir.path().to_path_buf())
            .with_bundle_dir(bundle_dir.path().to_path_buf());

        let ok = mgr
            .try_install_from_bundle(&tool, &dest, &sha, ArtifactFormat::Binary)
            .await
            .unwrap();
        assert!(ok);
        assert!(dest.exists());
    }

    #[tokio::test]
    async fn bundle_install_binary_checksum_mismatch() {
        let install_dir = tempfile::tempdir().unwrap();
        let bundle_dir = tempfile::tempdir().unwrap();

        tokio::fs::write(bundle_dir.path().join("my-tool"), b"bad binary")
            .await
            .unwrap();

        let tool = make_tool("my-tool", "wrong-sha");
        let dest = install_dir.path().join("my-tool");

        let mgr = HostToolManager::new(vec![], "arm64", install_dir.path().to_path_buf())
            .with_bundle_dir(bundle_dir.path().to_path_buf());

        let ok = mgr
            .try_install_from_bundle(&tool, &dest, "wrong-sha", ArtifactFormat::Binary)
            .await
            .unwrap();
        assert!(!ok);
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn bundle_install_tgz_requires_checksum_file() {
        let install_dir = tempfile::tempdir().unwrap();
        let bundle_dir = tempfile::tempdir().unwrap();

        tokio::fs::write(bundle_dir.path().join("docker"), b"docker binary")
            .await
            .unwrap();
        // No docker.sha256 in bundle → should fail.

        let tool = make_tool("docker", "archive-sha");
        let dest = install_dir.path().join("docker");

        let mgr = HostToolManager::new(vec![], "arm64", install_dir.path().to_path_buf())
            .with_bundle_dir(bundle_dir.path().to_path_buf());

        let ok = mgr
            .try_install_from_bundle(&tool, &dest, "archive-sha", ArtifactFormat::Tgz)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn bundle_install_tgz_with_checksum_file() {
        let install_dir = tempfile::tempdir().unwrap();
        let bundle_dir = tempfile::tempdir().unwrap();

        tokio::fs::write(bundle_dir.path().join("docker"), b"docker binary")
            .await
            .unwrap();
        tokio::fs::write(bundle_dir.path().join("docker.sha256"), "archive-sha")
            .await
            .unwrap();

        let tool = make_tool("docker", "archive-sha");
        let dest = install_dir.path().join("docker");

        let mgr = HostToolManager::new(vec![], "arm64", install_dir.path().to_path_buf())
            .with_bundle_dir(bundle_dir.path().to_path_buf());

        let ok = mgr
            .try_install_from_bundle(&tool, &dest, "archive-sha", ArtifactFormat::Tgz)
            .await
            .unwrap();
        assert!(ok);
        assert!(dest.exists());
    }

    #[tokio::test]
    async fn bundle_install_no_bundle_dir() {
        let install_dir = tempfile::tempdir().unwrap();
        let tool = make_tool("my-tool", "sha");
        let dest = install_dir.path().join("my-tool");

        let mgr = HostToolManager::new(vec![], "arm64", install_dir.path().to_path_buf());
        let ok = mgr
            .try_install_from_bundle(&tool, &dest, "sha", ArtifactFormat::Binary)
            .await
            .unwrap();
        assert!(!ok);
    }

    /// Compute SHA-256 hex of in-memory bytes (test helper).
    fn sha256_bytes(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}
