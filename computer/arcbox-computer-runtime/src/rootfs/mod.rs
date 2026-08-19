//! Build bootable ext4 rootfs images for sandboxes.
//!
//! Every builder here is backed by the pure-Rust `oci2rootfs` /
//! `arcbox-ext4` stack (no external binary, no mount, no root required for
//! the ext4 write itself), and one file per build path:
//!
//! - `convert.rs` — [`RootfsBuilder::build_rootfs`]: one image the caller
//!   sizes and names, from a directory or from a source it resolved itself
//!   (a registry pull through `oci2rootfs::RemoteRef`). This is the
//!   Computer image production path; the caller owns the product's path,
//!   so it addresses it however its own catalog does.
//! - `convert.rs` — [`RootfsBuilder::convert_layer_to_rootfs`]: the same
//!   conversion for sandbox templates, which the builder caches under
//!   [`RootfsPaths::cache_dir`] by content key so a repeat create reuses
//!   it. The builder names the product here; the capacity is this path's
//!   own constant.
//! - `default.rs` — [`RootfsBuilder::ensure_default_rootfs`]: the default
//!   busybox + vm-agent image used when a create supplies no rootfs, built
//!   from [`RootfsPaths::busybox`]. Rebuilt when the source binaries are
//!   newer than the cached image.
//! - `inject.rs` — [`RootfsBuilder::inject_vm_agent`]: the `/sbin/vm-agent`
//!   write itself, through a loop mount. Public so a caller that produced
//!   an ext4 image some other way still gets the convention from here.
//!
//! The rootfs convention the boot protocol relies on — the agent binary at
//! `/sbin/vm-agent`, `/etc/resolv.conf` symlinked into the `/run` tmpfs — is
//! enforced only by the guest failing to boot, so it is implemented once,
//! here, with the agent binary source supplied by the composer through
//! [`RootfsPaths`]. A converted image's own `/sbin/init` is left alone (it
//! is the distro's), so whoever boots one selects PID 1 with an
//! `init=/sbin/vm-agent` boot argument; only the default busybox image
//! carries the `/sbin/init` symlink as a fallback.

mod convert;
mod default;
mod inject;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arcbox_snapshot::snapshot_cow::BlockTools;

use crate::error::VmmError;

/// Where the rootfs builder finds its inputs and keeps its outputs.
///
/// Only [`vm_agent`](Self::vm_agent) is needed by every entry point; the
/// other two belong to one build path each, named in their docs.
#[derive(Debug, Clone)]
pub struct RootfsPaths {
    /// The `vm-agent` binary injected into every image at `/sbin/vm-agent`.
    pub vm_agent: PathBuf,
    /// Directory the sandbox-template images (and their `.ext4.tmp` build
    /// files) live in — [`RootfsBuilder::convert_layer_to_rootfs`] and the
    /// sweeps only. A [`RootfsBuilder::build_rootfs`] product goes wherever
    /// its caller says.
    pub cache_dir: PathBuf,
    /// Static busybox that becomes the default rootfs's userland
    /// (`/bin/busybox` plus one applet symlink per `busybox --list` entry) —
    /// [`RootfsBuilder::ensure_default_rootfs`] only.
    pub busybox: PathBuf,
}

/// The granularity every image's capacity must respect.
///
/// 128 MiB is one whole ext4 block group at the 4 KiB block size
/// `arcbox-ext4` formats with — 32768 blocks to a group, and 4 KiB is the
/// only block size it accepts.
///
/// It is not a preference. `arcbox-ext4` rounds the superblock's block count
/// **up** to a whole group, so an image whose capacity is not a whole number
/// of groups declares more blocks than its file holds, and every mount of it
/// fails — `EXT4-fs: bad geometry: block count N exceeds size of device`,
/// reaching the caller as a bare `EINVAL` from `mount(2)`. Verified against
/// arcbox-ext4 0.1.2 on Linux 6.18. The 512 MiB images this crate builds for
/// itself are four whole groups, which is why nothing caught it earlier;
/// 32 GB is 256 of them.
pub const ROOTFS_CAPACITY_GRANULARITY: u64 = 128 * 1024 * 1024;

/// Where a rootfs build reads its image from.
pub enum RootfsSource {
    /// A local OCI image layout (carrying the `oci-layout` marker) or a
    /// Docker overlay2 chain-id directory.
    Directory(PathBuf),
    /// A source the caller resolved itself — a registry pull through
    /// `oci2rootfs::RemoteRef`, say — so the same pull that feeds the
    /// image also hands the caller the `ImageConfig` and manifest digest
    /// its own catalog records.
    Image(oci2rootfs::ImageSource),
}

/// One rootfs the caller sizes and names; see
/// [`RootfsBuilder::build_rootfs`].
pub struct RootfsSpec {
    /// What goes into the image.
    pub source: RootfsSource,
    /// Where the finished image lands. The build writes a sibling
    /// `.<uuid>.ext4.tmp` and renames onto this path, so an existing image
    /// is replaced atomically.
    pub out: PathBuf,
    /// ext4 capacity in bytes. The file is written sparsely and a Computer's
    /// writes land in its dm-snapshot COW overlay, whose ceiling is this
    /// capacity — so this bounds the Computer's writable space rather than
    /// charging host disk up front.
    pub size: u64,
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
