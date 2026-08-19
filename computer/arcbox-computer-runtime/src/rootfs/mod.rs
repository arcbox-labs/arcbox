//! Build bootable ext4 rootfs images for sandboxes.
//!
//! Every builder here is backed by the pure-Rust `oci2rootfs` /
//! `arcbox-ext4` stack (no external binary, no mount, no root required for
//! the ext4 write itself), and one file per build path:
//!
//! - [`convert`] — [`RootfsBuilder::convert_layer_to_rootfs`]: convert a
//!   staged OCI image layout (or a Docker overlay2 layer directory) to ext4
//!   and inject `/sbin/vm-agent`, caching the product under the builder's
//!   own cache directory so a repeat create reuses it.
//! - [`default`] — [`RootfsBuilder::ensure_default_rootfs`]: the default
//!   busybox + vm-agent image used when a create supplies no rootfs.
//!   Rebuilt when the source binaries are newer than the cached image.
//! - [`inject`] — the `/sbin/vm-agent` write itself, through a loop mount.
//!
//! The rootfs convention the boot protocol relies on — the agent binary at
//! `/sbin/vm-agent` (and `/sbin/init` pointing at it), `/etc/resolv.conf`
//! symlinked into the `/run` tmpfs — is enforced only by the guest failing to
//! boot, so it is implemented once, here, with the agent binary source and
//! the output location supplied by the composer through [`RootfsPaths`].

mod convert;
mod default;
mod inject;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcbox_snapshot::snapshot_cow::BlockTools;

use crate::error::VmmError;

/// Where the rootfs builder finds its inputs and keeps its outputs.
#[derive(Debug, Clone)]
pub struct RootfsPaths {
    /// The `vm-agent` binary injected into every image at `/sbin/vm-agent`.
    pub vm_agent: PathBuf,
    /// Directory the generated ext4 images (and their `.ext4.tmp` build
    /// files) live in.
    pub cache_dir: PathBuf,
    /// Static busybox that becomes the default rootfs's userland
    /// (`/bin/busybox` plus one applet symlink per `busybox --list` entry).
    pub busybox: PathBuf,
}

/// Builds sandbox rootfs images; see the module docs.
pub struct RootfsBuilder {
    paths: RootfsPaths,
    /// Loop-device attach/detach for the `vm-agent` injection mount.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "the injection loop mount is Linux-only; other platforms never attach"
        )
    )]
    block_tools: Arc<dyn BlockTools>,
}

impl RootfsBuilder {
    /// A builder over `paths`, mounting through `block_tools`.
    pub fn new(paths: RootfsPaths, block_tools: Arc<dyn BlockTools>) -> Self {
        Self { paths, block_tools }
    }

    /// The paths this builder was composed with.
    pub fn paths(&self) -> &RootfsPaths {
        &self.paths
    }
}

fn rootfs_err(error: anyhow::Error) -> VmmError {
    VmmError::Rootfs(format!("{error:#}"))
}

/// Check if a file has a valid ext4 superblock magic (0x53EF at offset 0x438).
pub fn has_ext4_magic(path: &Path) -> bool {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 2];
    file.seek(SeekFrom::Start(0x438)).is_ok()
        && file.read_exact(&mut magic).is_ok()
        && magic == [0x53, 0xEF]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_ext4_magic_nonexistent() {
        assert!(!has_ext4_magic(Path::new("/nonexistent")));
    }
}
