//! Docker tool manager — download, extract, install, and validate Docker CLI
//! binaries from the versions pinned in `assets.lock`.

use crate::lockfile::ToolEntry;
use crate::registry::{self, ArtifactFormat};
use arcbox_asset::download::{download_and_verify, sha256_file};
use arcbox_asset::{PreparePhase, PrepareProgress, ProgressCallback};
use std::path::{Path, PathBuf};
use tracing::info;

/// Manages Docker CLI tool installation.
pub struct DockerToolManager {
    /// Architecture string (e.g. "arm64", "x86_64").
    arch: String,
    /// Directory for downloaded artifacts (e.g. `~/.arcbox/runtime/bin/`).
    install_dir: PathBuf,
    /// Tool entries parsed from `assets.lock`.
    tools: Vec<ToolEntry>,
}

impl DockerToolManager {
    /// Create a new manager from parsed tool entries.
    #[must_use]
    pub fn new(tools: Vec<ToolEntry>, arch: impl Into<String>, install_dir: PathBuf) -> Self {
        Self {
            arch: arch.into(),
            install_dir,
            tools,
        }
    }

    /// Install all configured Docker tools.
    ///
    /// For each tool: check cache → download → verify → extract → chmod.
    pub async fn install_all(
        &self,
        progress: Option<&ProgressCallback>,
    ) -> Result<(), DockerToolError> {
        tokio::fs::create_dir_all(&self.install_dir)
            .await
            .map_err(DockerToolError::Io)?;

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
    ) -> Result<(), DockerToolError> {
        let expected_sha =
            tool.sha256_for_arch(&self.arch)
                .ok_or_else(|| DockerToolError::UnsupportedArch {
                    tool: tool.name.clone(),
                    arch: self.arch.clone(),
                })?;

        let dest = self.install_dir.join(&tool.name);

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

        // Check cache: if binary exists and checksum matches, skip.
        if dest.exists() {
            if let Ok(actual) = sha256_file(&dest).await {
                if actual == expected_sha {
                    pg(PreparePhase::Cached);
                    info!(tool = %tool.name, "already installed, checksum matches");
                    return Ok(());
                }
            }
        }

        let url = registry::download_url(&tool.name, &tool.version, &self.arch);
        let format = registry::artifact_format(&tool.name);

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
                .map_err(DockerToolError::Asset)?;
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
                .map_err(DockerToolError::Asset)?;

                pg(PreparePhase::Verifying);
                extract_from_tgz(&tgz_path, registry::tgz_inner_path(&tool.name), &dest)?;
                let _ = tokio::fs::remove_file(&tgz_path).await;
            }
        }

        // Mark executable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&dest)
                .await
                .map_err(DockerToolError::Io)?
                .permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&dest, perms)
                .await
                .map_err(DockerToolError::Io)?;
        }

        pg(PreparePhase::Ready);
        info!(tool = %tool.name, version = %tool.version, "installed");
        Ok(())
    }

    /// Validate that all tools are installed and checksums match.
    pub async fn validate_all(&self) -> Result<(), DockerToolError> {
        for tool in &self.tools {
            let expected_sha = tool.sha256_for_arch(&self.arch).ok_or_else(|| {
                DockerToolError::UnsupportedArch {
                    tool: tool.name.clone(),
                    arch: self.arch.clone(),
                }
            })?;

            let path = self.install_dir.join(&tool.name);
            if !path.exists() {
                return Err(DockerToolError::NotInstalled(tool.name.clone()));
            }

            let actual = sha256_file(&path).await.map_err(DockerToolError::Asset)?;
            if actual != expected_sha {
                return Err(DockerToolError::Asset(
                    arcbox_asset::AssetError::ChecksumMismatch {
                        name: tool.name.clone(),
                        expected: expected_sha.to_string(),
                        actual,
                    },
                ));
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

/// Extract a single file from a `.tgz` archive.
fn extract_from_tgz(
    archive_path: &Path,
    inner_path: &str,
    dest: &Path,
) -> Result<(), DockerToolError> {
    let file = std::fs::File::open(archive_path).map_err(DockerToolError::Io)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries().map_err(DockerToolError::Io)? {
        let mut entry = entry.map_err(DockerToolError::Io)?;
        let path = entry.path().map_err(DockerToolError::Io)?;
        if path.to_string_lossy() == inner_path {
            entry.unpack(dest).map_err(DockerToolError::Io)?;
            return Ok(());
        }
    }

    Err(DockerToolError::ExtractFailed {
        archive: archive_path.display().to_string(),
        inner: inner_path.to_string(),
    })
}

/// Errors from Docker tool operations.
#[derive(Debug, thiserror::Error)]
pub enum DockerToolError {
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
