//! [`JailStaging`]: the port's [`Staging`] over one VM's jail.
//!
//! The jail *is* the staging area: files land under its root, named as
//! [`render`] would have named them for a boot, so a spec that carries what
//! these hand back is rendered without staging anything twice. Without a
//! jail every verb is the identity — the VMM reads host paths as they are,
//! and there is nothing to bring anywhere.
//!
//! Built from a [`VmLayout`] and nothing else, so both grips on a VM reach
//! it: the [`FcPrepared`](crate::FcPrepared) that spawned the VMM, and the
//! handle of a VM this driver adopted, whose prepared half died with the
//! process that made it.

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{CheckpointImage, DiskSource, Error, Result, Staging};
use async_trait::async_trait;

use crate::render::{self, StageKind, VmLayout};
use crate::{NAME, jail};

/// One VM's staging area: its jail, and the layout that names paths in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailStaging {
    layout: VmLayout,
}

impl JailStaging {
    /// The staging area of the VM `layout` describes.
    pub fn new(layout: VmLayout) -> Self {
        Self { layout }
    }

    /// Where this VM's files live, from the host's and Firecracker's points
    /// of view.
    pub fn layout(&self) -> &VmLayout {
        &self.layout
    }

    /// Brings `src` into the jail at `in_jail` and answers with the host
    /// path it landed at — the path a spec must name for it, which
    /// rendering then passes to Firecracker chroot-relative.
    ///
    /// Goes through [`VmLayout::place`] rather than staging directly, so
    /// every path decision stays in `render`: without a jail this is the
    /// identity, and a source already inside the jail is named where it is
    /// instead of being copied onto itself.
    async fn bring_in(&self, src: &Path, in_jail: &str, kind: StageKind) -> Result<PathBuf> {
        let mut stage = Vec::new();
        let named = self.layout.place(src, in_jail, kind, &mut stage)?;
        if let Some(jail) = self.layout.jail() {
            jail::apply(jail, &stage).await?;
        }
        Ok(self.layout.host_view(&named))
    }
}

#[async_trait]
impl Staging for JailStaging {
    async fn stage_kernel(&self, src: &Path) -> Result<PathBuf> {
        self.bring_in(src, render::KERNEL_FILE, StageKind::LinkOrCopy)
            .await
    }

    async fn stage_disk(&self, id: &str, source: DiskSource<'_>) -> Result<PathBuf> {
        let kind = match source {
            DiskSource::Device(_) => StageKind::BlockNode,
            // Never a hard link: Firecracker writes guest blocks into a
            // disk, and a link would write them into the caller's file.
            DiskSource::Image(_) => StageKind::Copy,
            DiskSource::Handover(_) => StageKind::Move,
        };
        self.bring_in(source.path(), &render::staged_disk_file(id)?, kind)
            .await
    }

    async fn unstage_disk(&self, id: &str, dst: &Path) -> Result<bool> {
        let Some(staged) = self.layout.jail_path(&render::staged_disk_file(id)?)? else {
            return Ok(false);
        };
        if !tokio::fs::try_exists(&staged).await.unwrap_or(false) {
            return Ok(false);
        }
        // The jail is its own vfsmount, so this crosses one even on the
        // same filesystem; `move_file` handles the EXDEV that follows.
        jail::move_file(&staged, dst).await.map_err(Error::Io)?;
        Ok(true)
    }

    async fn stage_checkpoint(&self, image: &CheckpointImage) -> Result<CheckpointImage> {
        let Some(jail) = self.layout.jail() else {
            return Ok(image.clone());
        };
        // Through the jail's own question, which resolves: a dir spelled
        // through the root but landing outside it has to be brought in,
        // not loaded from where the VMM cannot reach. The answer is where
        // the files are, which is what the image must name.
        if let Some(view) = jail.view(&image.dir) {
            return Ok(CheckpointImage {
                dir: self.layout.host_view(&view),
                ..image.clone()
            });
        }
        let name = image
            .dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                Error::InvalidSpec(format!(
                    "{NAME}: checkpoint dir {} has no usable name",
                    image.dir.display()
                ))
            })?;
        let in_jail = render::checkpoint_dir(name);
        // Both files are read-only to Firecracker (mem is mapped
        // MAP_PRIVATE on load), so a root jailer links instead of copying
        // — the mem file is the guest's whole memory.
        self.bring_in(
            &image.dir.join("vmstate"),
            &format!("{in_jail}/vmstate"),
            StageKind::LinkOrCopy,
        )
        .await?;
        let mem = image.dir.join("mem");
        if tokio::fs::try_exists(&mem).await.unwrap_or(false) {
            self.bring_in(&mem, &format!("{in_jail}/mem"), StageKind::LinkOrCopy)
                .await?;
        }
        Ok(CheckpointImage {
            dir: jail.root.join(&in_jail),
            ..image.clone()
        })
    }
}
