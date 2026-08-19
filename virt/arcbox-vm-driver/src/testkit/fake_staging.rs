//! The fake's staging area: the directory standing in for a jail's chroot.
//!
//! One area per VM, at `{runtime_dir}/staged`, derived from the runtime dir
//! rather than held by whoever made it — so every grip on the same VM
//! computes the same area instead of drifting into two.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use crate::capability::{CheckpointImage, DiskSource, Staging};
use crate::error::{Error, Result};

/// `path` with its `.` and `..` components resolved as far as they can be
/// without touching the filesystem.
///
/// Enough for deciding whether a path lands inside a directory: a `..`
/// that walks out of one is what the check exists to catch, and symlinks
/// are beyond what a fake needs to model.
fn lexically_resolved(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push(component);
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// How a staged file gets into the staging area.
#[derive(Debug, Clone, Copy)]
enum Bring {
    /// A stand-in for a device node.
    Device,
    /// A private copy; the source stays.
    Copy,
    /// The source is consumed.
    Move,
}

/// One VM's staging area.
///
/// Files land under the names a jail would give them: `vmlinux`,
/// `{disk id}.ext4`, `snapshots/{image dir name}`.
#[derive(Debug, Clone)]
pub(super) struct StagingArea {
    root: PathBuf,
}

impl StagingArea {
    /// The area of a VM whose scratch space is `runtime_dir`.
    pub(super) fn new(runtime_dir: &Path) -> Self {
        Self {
            root: runtime_dir.join("staged"),
        }
    }

    /// Removes the area and everything in it; already gone is success.
    pub(super) async fn remove(&self) -> Result<()> {
        match tokio::fs::remove_dir_all(&self.root).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Where the disk `id` sits in the area.
    ///
    /// Refuses an id that is not a plain name, exactly as a real adapter
    /// must: staging writes and replaces at this path and unstaging moves
    /// what it finds there, so a `..` would reach a file outside the area.
    /// The fake enforces it because it is the reference driver — a gap it
    /// shares with the adapters is a gap no contract check can see.
    fn staged_disk(&self, id: &str) -> Result<PathBuf> {
        let mut components = Path::new(id).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(Error::InvalidSpec(format!(
                "disk id `{id}` must be a plain name"
            )));
        }
        Ok(self.root.join(format!("{id}.ext4")))
    }

    /// Brings `src` into the area at `dst`, and answers with where it
    /// landed. A source already inside the area is left where it is — the
    /// same short-circuit a real confinement makes.
    async fn bring_in(&self, src: &Path, dst: &Path, how: Bring) -> Result<PathBuf> {
        // Against the resolved path, not the written one: `starts_with`
        // compares components, so `{staged}/../elsewhere` would look like
        // it is already inside the area and be left where it is — and a
        // `Handover` would then report a move that never happened. The
        // answer names where the file is, not how it was spelled.
        let resolved = lexically_resolved(src);
        if resolved.starts_with(&self.root) {
            return Ok(resolved);
        }
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        match tokio::fs::remove_file(dst).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Error::Io(e)),
            _ => {}
        }
        match how {
            // A device node is not something a fake can make; a symlink is
            // the stand-in, and it is visibly not a copy.
            Bring::Device => tokio::fs::symlink(src, dst).await?,
            Bring::Copy => {
                tokio::fs::copy(src, dst).await?;
            }
            Bring::Move => match tokio::fs::rename(src, dst).await {
                Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                    tokio::fs::copy(src, dst).await?;
                    tokio::fs::remove_file(src).await?;
                }
                other => other?,
            },
        }
        Ok(dst.to_path_buf())
    }
}

#[async_trait]
impl Staging for StagingArea {
    async fn stage_kernel(&self, src: &Path) -> Result<PathBuf> {
        self.bring_in(src, &self.root.join("vmlinux"), Bring::Copy)
            .await
    }

    async fn stage_disk(&self, id: &str, source: DiskSource<'_>) -> Result<PathBuf> {
        let how = match source {
            DiskSource::Device(_) => Bring::Device,
            DiskSource::Image(_) => Bring::Copy,
            DiskSource::Handover(_) => Bring::Move,
        };
        let into = self.staged_disk(id)?;
        self.bring_in(source.path(), &into, how).await
    }

    async fn unstage_disk(&self, id: &str, dst: &Path) -> Result<bool> {
        let staged = self.staged_disk(id)?;
        if !tokio::fs::try_exists(&staged).await.unwrap_or(false) {
            return Ok(false);
        }
        match tokio::fs::rename(&staged, dst).await {
            Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                tokio::fs::copy(&staged, dst).await?;
                tokio::fs::remove_file(&staged).await?;
            }
            other => other?,
        }
        Ok(true)
    }

    async fn stage_checkpoint(&self, image: &CheckpointImage) -> Result<CheckpointImage> {
        let resolved = lexically_resolved(&image.dir);
        if resolved.starts_with(&self.root) {
            return Ok(CheckpointImage {
                dir: resolved,
                ..image.clone()
            });
        }
        let name = image.dir.file_name().ok_or_else(|| {
            Error::InvalidSpec(format!(
                "checkpoint dir {} has no usable name",
                image.dir.display()
            ))
        })?;
        let dir = self.root.join("snapshots").join(name);
        tokio::fs::create_dir_all(&dir).await?;
        let mut entries = tokio::fs::read_dir(&image.dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                tokio::fs::copy(entry.path(), dir.join(entry.file_name())).await?;
            }
        }
        Ok(CheckpointImage {
            dir,
            ..image.clone()
        })
    }
}
