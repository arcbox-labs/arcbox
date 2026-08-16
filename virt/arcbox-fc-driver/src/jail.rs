//! The jailer's chroot: where it is, and how host files get into it.
//!
//! Under the jailer, Firecracker runs chrooted into
//! `{chroot_base}/{firecracker binary name}/{id}/root` and can open only
//! paths inside it. Everything it needs — the kernel, the disks, a
//! checkpoint's vmstate and mem — is staged in first, owned by the jailed
//! uid/gid, and named to Firecracker by its chroot-relative path. This
//! module is that staging: the layout, and one primitive per way a file
//! can be brought in (hard link or copy, plain copy, block-device node).

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{Error, Result};
use nix::unistd::{Gid, Uid, chown};
use tracing::warn;

use crate::error::FcError;

pub mod blkdev;

/// The jailer's own default chroot base, used when a config names none.
pub const DEFAULT_CHROOT_BASE: &str = "/srv/jailer";

/// A checkpoint's files on the host, as [`stage_snapshot_files`] stages
/// them: the directory name they are staged under and the two files.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotFiles<'a> {
    /// The name of the per-checkpoint directory inside the jail
    /// (`/snapshots/{id}`).
    pub id: &'a str,
    /// The host path of the `vmstate` file.
    pub vmstate: &'a Path,
    /// The host path of the `mem` file, when the checkpoint has one.
    pub mem: Option<&'a Path>,
}

/// Compute the host-side absolute path to the jailer chroot root directory.
///
/// Returns `{chroot_base_dir}/{fc_binary_filename}/{id}/root`.
pub fn chroot_root(
    fc_binary: impl AsRef<Path>,
    chroot_base_dir: impl AsRef<Path>,
    id: &str,
) -> PathBuf {
    let exec_name = fc_binary
        .as_ref()
        .file_name()
        .expect("fc_binary must have a filename")
        .to_string_lossy();
    chroot_base_dir
        .as_ref()
        .join(exec_name.as_ref())
        .join(id)
        .join("root")
}

/// The Firecracker API socket of a jail, as the host sees it:
/// `{jail}/run/firecracker.socket` (the jailer's fixed location).
pub fn api_socket_path(chroot_root: &Path) -> PathBuf {
    chroot_root.join("run/firecracker.socket")
}

/// The hybrid-vsock Unix socket of a jail, as the host sees it:
/// `{jail}/run/firecracker.vsock`; Firecracker sees it as
/// [`VSOCK_UDS_IN_JAIL`].
pub fn vsock_uds_path(chroot_root: &Path) -> PathBuf {
    chroot_root.join("run/firecracker.vsock")
}

/// Where the vsock Unix socket lives from inside the jail.
pub const VSOCK_UDS_IN_JAIL: &str = "/run/firecracker.vsock";

/// Stage a read-only file into a jailer chroot: hard-link when possible,
/// copy otherwise.
///
/// A hard link shares the inode with the source, so it is only safe for
/// files FC never writes — the kernel image, a snapshot vmstate, and a
/// snapshot mem file (mapped MAP_PRIVATE on load). Do NOT use it for the
/// rootfs copy fallback: FC writes guest blocks into that file. Linking is
/// also reserved for the root jailer (uid/gid 0), because chown on a link
/// would mutate the shared source inode; a non-root jailer gets a private
/// copy with its own ownership.
pub async fn link_or_copy_for_jailer(src: &Path, dst: &Path, uid: u32, gid: u32) -> Result<()> {
    // Remove a stale entry first: hard_link fails on an existing dst, and a
    // leftover from a previous run must not survive by accident.
    if let Err(e) = tokio::fs::remove_file(dst).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
    }
    if uid == 0 && gid == 0 {
        match tokio::fs::hard_link(src, dst).await {
            Ok(()) => return Ok(()),
            // Cross-device (EXDEV) or filesystem quirk. warn, not debug: the
            // copy fallback silently forfeits the restore fast path, and at
            // default log levels a misplaced chroot base would only ever be
            // rediscovered by re-measuring.
            Err(e) => {
                warn!(src = %src.display(), dst = %dst.display(), error = %e,
                    "hard link failed; falling back to copy");
            }
        }
    }
    tokio::fs::copy(src, dst).await.map_err(Error::Io)?;
    chown(dst, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|source| {
        FcError::Chown {
            path: dst.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

/// Stage the kernel into the jailer chroot (link or copy).
///
/// Returns the chroot-relative kernel path (e.g. `"/vmlinux"`).
pub async fn stage_kernel_for_jailer(
    chroot_root: &Path,
    kernel_src: impl AsRef<Path>,
    uid: u32,
    gid: u32,
) -> Result<String> {
    tokio::fs::create_dir_all(chroot_root)
        .await
        .map_err(Error::Io)?;
    let kernel_dst = chroot_root.join("vmlinux");
    link_or_copy_for_jailer(kernel_src.as_ref(), &kernel_dst, uid, gid).await?;
    Ok("/vmlinux".to_string())
}

/// Copy rootfs into the jailer chroot and set ownership.
///
/// Returns the chroot-relative rootfs path (e.g. `"/rootfs.ext4"`).
pub async fn stage_rootfs_copy_for_jailer(
    chroot_root: &Path,
    rootfs_src: impl AsRef<Path>,
    uid: u32,
    gid: u32,
) -> Result<String> {
    tokio::fs::create_dir_all(chroot_root)
        .await
        .map_err(Error::Io)?;
    let rootfs_dst = chroot_root.join("rootfs.ext4");
    // Remove any stale entry — a previous crash or a failed mknod-then-chown
    // fallback may have left a block device node here, in which case
    // `tokio::fs::copy` would write into the device instead of replacing it.
    if let Err(e) = tokio::fs::remove_file(&rootfs_dst).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
    }
    tokio::fs::copy(rootfs_src, &rootfs_dst)
        .await
        .map_err(Error::Io)?;
    chown(
        &rootfs_dst,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|source| FcError::Chown {
        path: rootfs_dst,
        source,
    })?;
    Ok("/rootfs.ext4".to_string())
}

/// Create a block device node in the jailer chroot pointing to a dm device.
///
/// Returns the chroot-relative rootfs path (`"/rootfs.ext4"`).
pub async fn stage_rootfs_device_for_jailer(
    chroot_root: &Path,
    dm_device: impl AsRef<Path>,
    uid: u32,
    gid: u32,
) -> Result<String> {
    tokio::fs::create_dir_all(chroot_root)
        .await
        .map_err(Error::Io)?;
    let (major, minor) = blkdev::device_major_minor(dm_device.as_ref())?;
    let node_path = chroot_root.join("rootfs.ext4");
    // Remove any leftover entry from a previous crash so mknod can succeed
    // (and so we never end up writing into a stale device node).
    if let Err(e) = tokio::fs::remove_file(&node_path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
    }
    blkdev::mknod_blkdev(&node_path, major, minor)?;
    chown(
        &node_path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|source| FcError::Chown {
        path: node_path,
        source,
    })?;
    Ok("/rootfs.ext4".to_string())
}

/// Stage a snapshot's vmstate/mem into `{chroot}/snapshots/{snapshot_id}`
/// via [`link_or_copy_for_jailer`] and return their chroot-relative paths
/// `(vmstate, mem)` for `SnapshotLoadParams`.
pub async fn stage_snapshot_files(
    chroot: &Path,
    snapshot: &SnapshotFiles<'_>,
    uid: u32,
    gid: u32,
) -> Result<(String, Option<String>)> {
    let snap_in_chroot = chroot.join("snapshots").join(snapshot.id);
    std::fs::create_dir_all(&snap_in_chroot).map_err(Error::Io)?;
    chown(
        &snap_in_chroot,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|source| FcError::Chown {
        path: snap_in_chroot.clone(),
        source,
    })?;

    link_or_copy_for_jailer(snapshot.vmstate, &snap_in_chroot.join("vmstate"), uid, gid).await?;
    let mem = if let Some(mf) = snapshot.mem
        && mf.exists()
    {
        link_or_copy_for_jailer(mf, &snap_in_chroot.join("mem"), uid, gid).await?;
        Some(format!("/snapshots/{}/mem", snapshot.id))
    } else {
        None
    };
    Ok((format!("/snapshots/{}/vmstate", snapshot.id), mem))
}
