//! Block-device nodes for the jail: read a device's numbers, mirror it as
//! a node.
//!
//! A twin of `arcbox_snapshot::snapshot_cow::{device_major_minor,
//! mknod_blkdev}`, kept here so the adapter never depends on the snapshot
//! catalog: the driver only needs to mirror a device the caller already
//! created (a dm-snapshot rootfs) into the chroot, not to create one.

use std::path::Path;

use crate::error::{FcError, Result};

/// The `(major, minor)` device numbers of the block device at `path`.
///
/// Follows symlinks, so `/dev/mapper/<name>` resolves whether device-mapper
/// created a node there itself (no udev, the System VM) or udev left a
/// symlink to `/dev/dm-N` (a stock distro).
#[cfg(target_os = "linux")]
pub fn device_major_minor(path: &Path) -> Result<(u32, u32)> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    let metadata = std::fs::metadata(path).map_err(|source| FcError::Stat {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_block_device() {
        return Err(FcError::NotBlockDevice {
            path: path.to_path_buf(),
        });
    }
    let dev = metadata.rdev();
    // Linux packs 12-bit majors and 20-bit minors into `dev_t`; nix hands
    // them back as `u64`, and a value outside `u32` is a corrupt node, not
    // something to truncate.
    let narrow = |what: &'static str, value: u64| {
        u32::try_from(value).map_err(|_| FcError::BadDeviceNumber {
            path: path.to_path_buf(),
            what,
            value,
        })
    };
    Ok((
        narrow("major", nix::sys::stat::major(dev))?,
        narrow("minor", nix::sys::stat::minor(dev))?,
    ))
}

/// Create a block device node at `node_path` for `(major, minor)`, mode 0600.
///
/// The caller owns the node's ownership: a jailer chroot `chown`s it to the
/// jailer uid/gid right after, which is why the mode need not be wider.
#[cfg(target_os = "linux")]
pub fn mknod_blkdev(node_path: &Path, major: u32, minor: u32) -> Result<()> {
    use nix::sys::stat::{Mode, SFlag, makedev, mknod};

    mknod(
        node_path,
        SFlag::S_IFBLK,
        Mode::S_IRUSR | Mode::S_IWUSR,
        makedev(u64::from(major), u64::from(minor)),
    )
    .map_err(|source| FcError::Mknod {
        path: node_path.to_path_buf(),
        source,
    })
}

/// Block device nodes are a Linux concept; off Linux the crate compiles but
/// the operation is unavailable.
#[cfg(not(target_os = "linux"))]
pub fn device_major_minor(path: &Path) -> Result<(u32, u32)> {
    Err(FcError::LinuxOnly {
        what: format!("block device numbers for {}", path.display()),
    })
}

/// Block device nodes are a Linux concept; off Linux the crate compiles but
/// the operation is unavailable.
#[cfg(not(target_os = "linux"))]
pub fn mknod_blkdev(node_path: &Path, _major: u32, _minor: u32) -> Result<()> {
    Err(FcError::LinuxOnly {
        what: format!("mknod {}", node_path.display()),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn device_major_minor_rejects_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain");
        std::fs::write(&file, b"x").unwrap();
        let err = device_major_minor(&file).unwrap_err();
        assert!(matches!(err, FcError::NotBlockDevice { .. }), "{err}");
    }

    #[test]
    fn device_major_minor_reports_missing_paths() {
        let err = device_major_minor(Path::new("/nonexistent/arcbox-blkdev")).unwrap_err();
        assert!(matches!(err, FcError::Stat { .. }), "{err}");
    }
}
