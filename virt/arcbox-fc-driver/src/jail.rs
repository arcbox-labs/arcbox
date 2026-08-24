//! The jailer's chroot: where it is, and how host files get into it.
//!
//! Under the jailer, Firecracker runs chrooted into
//! `{chroot_base}/{firecracker binary name}/{id}/root` and can open only
//! paths inside it. Everything it needs — the kernel, the disks, a
//! checkpoint's vmstate and mem — is staged in first, owned by the jailed
//! uid/gid, and named to Firecracker by its chroot-relative path. This
//! module is that staging: the layout, and one primitive per way a file
//! can be brought in (hard link or copy, plain copy, block-device node,
//! or the file itself moved in when the caller gives it up).

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{Error, JailRecord, Result};
use nix::unistd::{Gid, Uid, chown};
use tracing::warn;

use crate::error::FcError;
use crate::render::{StageKind, StagePlan};

pub mod blkdev;

/// The jail a VM is confined to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jail {
    /// The chroot root: `{chroot_base}/{firecracker binary name}/{id}/root`.
    pub root: PathBuf,
    /// The uid the VMM runs as.
    pub uid: u32,
    /// The gid the VMM runs as.
    pub gid: u32,
}

impl From<&Jail> for JailRecord {
    fn from(jail: &Jail) -> Self {
        Self {
            root: jail.root.clone(),
            uid: jail.uid,
            gid: jail.gid,
        }
    }
}

impl From<JailRecord> for Jail {
    fn from(record: JailRecord) -> Self {
        Self {
            root: record.root,
            uid: record.uid,
            gid: record.gid,
        }
    }
}

impl Jail {
    /// `host` as Firecracker sees it, when `host` is already inside the
    /// jail: `/` + its path relative to the root.
    ///
    /// Decided on the resolved path. `strip_prefix` compares components,
    /// so `{root}/../elsewhere` names the root on the way past and would
    /// otherwise answer `Some("/../elsewhere")` — a path Firecracker's
    /// chroot resolves to something else entirely, for a file that was
    /// never brought in. Every decision this jail makes about a host path
    /// asks through here, so the question cannot be asked the wrong way.
    ///
    /// Symlinks are deliberately not followed: a symlink inside the jail
    /// is a file the jailed Firecracker can open, which is exactly what is
    /// being asked.
    pub fn view(&self, host: &Path) -> Option<String> {
        lexically_resolved(host)
            .strip_prefix(&self.root)
            .ok()
            .map(|rel| format!("/{}", rel.display()))
    }

    /// Remove the jail and everything staged into it.
    ///
    /// The jailer's per-VM directory is `{base}/{exec}/{id}`, of which
    /// [`root`](Self::root) is the `root/` inside it — the whole thing
    /// goes, because the copy of the Firecracker binary and the cgroup
    /// bookkeeping beside it belong to this VM too.
    ///
    /// Already gone is not a failure: this is called wherever a VM ends,
    /// and a VM can end more than once.
    pub async fn remove(&self) -> Result<()> {
        let Some(dir) = self.root.parent() else {
            return Ok(());
        };
        match tokio::fs::remove_dir_all(dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io(e)),
        }
    }
}

/// `path` with its `.` and `..` components resolved as far as they can be
/// without touching the filesystem.
pub(crate) fn lexically_resolved(path: &Path) -> PathBuf {
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

/// What AF_UNIX leaves for a path: `sun_path` is 108 bytes, and the last
/// one is the terminator.
const SUN_PATH: usize = 107;

/// The widest listener port [`id_budget`] leaves room for.
///
/// [`VsockListen::listen`](arcbox_vm_driver::VsockListen::listen) takes a
/// `u32`, but reserving all ten digits costs ten bytes of id — on the
/// stock layout the difference between accepting and refusing the 36-byte
/// UUIDs an orchestrator mints. Refusing every id is a worse failure than
/// the `ENAMETOOLONG` a wider port would raise at bind time, which names
/// the path it could not bind; no consumer of this driver listens above
/// `u16::MAX`.
const WIDEST_RESERVED_PORT: u32 = u16::MAX as u32;

/// The longest VM id this jailer layout leaves room for.
///
/// The id is a directory component of the chroot, so every socket bound
/// under it carries the id in its path and has 107 bytes to fit in. Two
/// do: the API socket, and the guest dial-out listener — the vsock UDS
/// plus Firecracker's `_{port}` suffix ([`crate::vsock::listener_socket_path`]),
/// which is the longer of the two and is bound *before* the guest starts.
/// The budget is measured against whichever is longer, so it cannot be
/// invalidated by renaming one of them.
///
/// Getting this wrong does not announce itself. The jailer creates the
/// path and Firecracker binds it from inside the chroot, where the name is
/// short, while every `connect` from the host fails — a VMM that is up and
/// answering nothing, read as a boot that timed out.
///
/// Saturating on purpose. A base deep enough to spend all 107 bytes leaves
/// room for no id at all, and `0` is the answer that says so; the
/// subtraction wrapping into a huge budget would hand out ids that cannot
/// work. A chroot base under a deep temporary directory reaches this in
/// tests long before production does.
pub fn id_budget(fc_binary: impl AsRef<Path>, chroot_base_dir: impl AsRef<Path>) -> usize {
    // Everything around the id, measured on a one-byte id.
    let root = chroot_root(fc_binary, chroot_base_dir, "x");
    let fixed = [
        api_socket_path(&root),
        crate::vsock::listener_socket_path(&vsock_uds_path(&root), WIDEST_RESERVED_PORT),
    ]
    .iter()
    .map(|path| path.as_os_str().len())
    .max()
    .unwrap_or_default()
    .saturating_sub(1);
    SUN_PATH.saturating_sub(fixed)
}

/// Where the vsock Unix socket lives from inside the jail.
pub const VSOCK_UDS_IN_JAIL: &str = "/run/firecracker.vsock";

/// Move a file even when source and destination sit on different mounts.
///
/// The jailer chroot is its own vfsmount (bind + pivot_root), so a plain
/// `rename(2)` out of it fails with `EXDEV` regardless of the underlying
/// filesystem; fall back to copy + remove in that case.
pub async fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match tokio::fs::rename(from, to).await {
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            tokio::fs::copy(from, to).await?;
            // fsync the destination before removing the source: a crash between
            // the copy and the remove must not leave a zero-length/partial
            // snapshot file registered in the catalog.
            tokio::fs::File::open(to).await?.sync_all().await?;
            tokio::fs::remove_file(from).await
        }
        other => other,
    }
}

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
    copy_for_jailer(rootfs_src.as_ref(), &rootfs_dst, uid, gid).await?;
    Ok("/rootfs.ext4".to_string())
}

/// Stage a writable file into the jail as a private copy owned by the
/// jailed uid/gid — never a hard link: FC writes guest blocks into it.
pub async fn copy_for_jailer(src: &Path, dst: &Path, uid: u32, gid: u32) -> Result<()> {
    // Remove any stale entry — a previous crash or a failed mknod-then-chown
    // fallback may have left a block device node here, in which case
    // `tokio::fs::copy` would write into the device instead of replacing it.
    if let Err(e) = tokio::fs::remove_file(dst).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
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

/// Move a file the caller hands over into the jail and give it to the
/// jailed uid/gid — the file itself, not a copy of it, so a disk the size
/// of a guest's rootfs comes back without being duplicated.
///
/// A stale entry at the destination is removed first, exactly as a copy or
/// a device node would: a `rename` onto a directory left by a crash fails,
/// and one onto a stale block device node would replace it silently.
pub async fn move_into_jail(src: &Path, dst: &Path, uid: u32, gid: u32) -> Result<()> {
    if let Err(e) = tokio::fs::remove_file(dst).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
    }
    move_file(src, dst).await.map_err(Error::Io)?;
    chown(dst, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(|source| {
        FcError::Chown {
            path: dst.to_path_buf(),
            source,
        }
    })?;
    Ok(())
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
    let node_path = chroot_root.join("rootfs.ext4");
    mknod_for_jailer(dm_device.as_ref(), &node_path, uid, gid).await?;
    Ok("/rootfs.ext4".to_string())
}

/// Mirror the block device at `device` into the jail as a device node at
/// `node_path`, owned by the jailed uid/gid.
pub async fn mknod_for_jailer(device: &Path, node_path: &Path, uid: u32, gid: u32) -> Result<()> {
    let (major, minor) = blkdev::device_major_minor(device)?;
    // Remove any leftover entry from a previous crash so mknod can succeed
    // (and so we never end up writing into a stale device node).
    if let Err(e) = tokio::fs::remove_file(node_path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
    }
    blkdev::mknod_blkdev(node_path, major, minor)?;
    chown(
        node_path,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(|source| FcError::Chown {
        path: node_path.to_path_buf(),
        source,
    })?;
    Ok(())
}

/// Execute a rendered staging plan into `jail`.
///
/// Creates each destination's parent (handing directories below the root
/// to the jailed uid/gid, as Firecracker writes its own snapshots next to
/// them), then link-or-copies, copies, or mknods each entry.
pub async fn apply(jail: &Jail, plans: &[StagePlan]) -> Result<()> {
    for plan in plans {
        if let Some(parent) = plan.dst.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(Error::Io)?;
            if parent != jail.root {
                chown(
                    parent,
                    Some(Uid::from_raw(jail.uid)),
                    Some(Gid::from_raw(jail.gid)),
                )
                .map_err(|source| FcError::Chown {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        match plan.kind {
            StageKind::LinkOrCopy => {
                link_or_copy_for_jailer(&plan.src, &plan.dst, jail.uid, jail.gid).await?;
            }
            StageKind::Copy => copy_for_jailer(&plan.src, &plan.dst, jail.uid, jail.gid).await?,
            StageKind::BlockNode => {
                mknod_for_jailer(&plan.src, &plan.dst, jail.uid, jail.gid).await?;
            }
            StageKind::Move => move_into_jail(&plan.src, &plan.dst, jail.uid, jail.gid).await?,
            StageKind::Alias => alias_in_jail(&plan.src, &plan.dst, jail.uid, jail.gid).await?,
        }
    }
    Ok(())
}

/// Give a disk that is already inside the jail a second name there: a hard
/// link to the same inode (which keeps its ownership); failing that, a
/// device node for a block device, or a chowned copy.
pub async fn alias_in_jail(src: &Path, dst: &Path, uid: u32, gid: u32) -> Result<()> {
    if let Err(e) = tokio::fs::remove_file(dst).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(Error::Io(e));
    }
    match tokio::fs::hard_link(src, dst).await {
        Ok(()) => return Ok(()),
        Err(e) => {
            warn!(src = %src.display(), dst = %dst.display(), error = %e,
                "hard link failed; aliasing by node or copy");
        }
    }
    let metadata = tokio::fs::metadata(src).await.map_err(Error::Io)?;
    if std::os::unix::fs::FileTypeExt::is_block_device(&metadata.file_type()) {
        mknod_for_jailer(src, dst, uid, gid).await
    } else {
        copy_for_jailer(src, dst, uid, gid).await
    }
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
    tokio::fs::create_dir_all(&snap_in_chroot)
        .await
        .map_err(Error::Io)?;
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
        && tokio::fs::try_exists(mf).await.unwrap_or(false)
    {
        link_or_copy_for_jailer(mf, &snap_in_chroot.join("mem"), uid, gid).await?;
        Some(format!("/snapshots/{}/mem", snapshot.id))
    } else {
        None
    };
    Ok((format!("/snapshots/{}/vmstate", snapshot.id), mem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chroot_root_and_sockets_follow_the_jailer_layout() {
        let root = chroot_root("/opt/fc/firecracker", "/srv/jailer", "box");
        assert_eq!(root, Path::new("/srv/jailer/firecracker/box/root"));
        assert_eq!(
            api_socket_path(&root),
            Path::new("/srv/jailer/firecracker/box/root/run/firecracker.socket")
        );
        assert_eq!(
            vsock_uds_path(&root),
            Path::new("/srv/jailer/firecracker/box/root/run/firecracker.vsock")
        );
        let jail = Jail {
            root: root.clone(),
            uid: 0,
            gid: 0,
        };
        assert_eq!(
            jail.view(&root.join("snapshots/abc/vmstate")).as_deref(),
            Some("/snapshots/abc/vmstate")
        );
        assert_eq!(jail.view(Path::new("/images/vmlinux")), None);
        // A path that names the root on its way past it is not in the
        // jail, however its components read — every decision the jail
        // makes about a host path is this one, so it resolves here.
        assert_eq!(jail.view(&root.join("../../../outside.ext4")), None);
        assert_eq!(
            jail.view(&root.join("snapshots/../rootfs.ext4")).as_deref(),
            Some("/rootfs.ext4")
        );
    }

    #[test]
    fn the_id_budget_is_what_the_longest_socket_leaves_and_never_wraps() {
        let budget = id_budget("/opt/fc/firecracker", "/srv/jailer");
        // The dial-out listener, not the API socket, is what the budget is
        // measured against: it is the longer path, and it is bound before
        // the guest starts.
        assert!(
            "/run/firecracker.vsock_65535".len() > "/run/firecracker.socket".len(),
            "the API socket became the longer path; the budget must follow it"
        );
        assert_eq!(
            budget,
            SUN_PATH - "/srv/jailer/firecracker//root/run/firecracker.vsock_65535".len()
        );
        // An id of exactly the budget fills `sun_path` for that listener
        // and leaves the API socket comfortably inside it.
        let root = chroot_root("/opt/fc/firecracker", "/srv/jailer", &"a".repeat(budget));
        let fits = crate::vsock::listener_socket_path(&vsock_uds_path(&root), 65535);
        assert_eq!(fits.as_os_str().len(), SUN_PATH);
        assert!(api_socket_path(&root).as_os_str().len() < SUN_PATH);

        // A chroot base deep enough spends the whole budget: zero, not a
        // wrap into a length that would look generous and never connect.
        // A temp dir a few levels down is already most of the way there,
        // which is how a test suite meets this before production does.
        let deep = PathBuf::from("/").join("d".repeat(200));
        assert_eq!(id_budget("/opt/fc/firecracker", deep), 0);
    }

    #[tokio::test]
    async fn removing_a_jail_takes_the_whole_per_vm_directory_and_tolerates_its_absence() {
        let dir = tempfile::tempdir().unwrap();
        let per_vm = dir.path().join("jail/firecracker/box");
        let root = per_vm.join("root");
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::write(root.join("rootfs.ext4"), b"disk").unwrap();
        // The jailer's copy of the binary sits beside `root/`, not in it.
        std::fs::write(per_vm.join("firecracker"), b"vmm").unwrap();
        let jail = Jail {
            root,
            uid: 0,
            gid: 0,
        };

        jail.remove().await.unwrap();
        assert!(!per_vm.exists(), "the whole per-vm directory goes");
        assert!(dir.path().join("jail/firecracker").exists(), "and no more");
        jail.remove().await.expect("a vm can end more than once");
    }

    #[tokio::test]
    async fn a_handed_over_file_is_moved_in_and_replaces_what_it_finds() {
        let dir = tempfile::tempdir().unwrap();
        let parked = dir.path().join("parked.ext4");
        std::fs::write(&parked, b"the disk itself").unwrap();
        let root = dir.path().join("jail/firecracker/box/root");
        std::fs::create_dir_all(&root).unwrap();
        // A leftover at the destination from the run that parked it.
        std::fs::write(root.join("rootfs.ext4"), b"stale").unwrap();
        let jail = Jail {
            root: root.clone(),
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        };

        apply(
            &jail,
            &[StagePlan {
                src: parked.clone(),
                dst: root.join("rootfs.ext4"),
                kind: StageKind::Move,
            }],
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(root.join("rootfs.ext4")).unwrap(),
            b"the disk itself"
        );
        assert!(!parked.exists(), "a handed-over disk is moved, not copied");
    }

    #[tokio::test]
    async fn apply_stages_each_plan_under_its_parent_as_the_jail_owner() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(src.join("rootfs.ext4"), b"disk").unwrap();
        std::fs::write(src.join("vmstate"), b"state").unwrap();
        let root = dir.path().join("jail/firecracker/box/root");
        let jail = Jail {
            root: root.clone(),
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
        };
        // A stale entry at a destination is replaced, not written into.
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rootfs.ext4"), b"stale").unwrap();

        apply(
            &jail,
            &[
                StagePlan {
                    src: src.join("vmlinux"),
                    dst: root.join("vmlinux"),
                    kind: StageKind::LinkOrCopy,
                },
                StagePlan {
                    src: src.join("rootfs.ext4"),
                    dst: root.join("rootfs.ext4"),
                    kind: StageKind::Copy,
                },
                StagePlan {
                    src: src.join("vmstate"),
                    dst: root.join("snapshots/abc/vmstate"),
                    kind: StageKind::LinkOrCopy,
                },
            ],
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(root.join("vmlinux")).unwrap(), b"kernel");
        assert_eq!(std::fs::read(root.join("rootfs.ext4")).unwrap(), b"disk");
        assert_eq!(
            std::fs::read(root.join("snapshots/abc/vmstate")).unwrap(),
            b"state"
        );
        // A copy never shares the source inode, whoever the jail runs as.
        use std::os::unix::fs::MetadataExt as _;
        assert_ne!(
            std::fs::metadata(src.join("rootfs.ext4")).unwrap().ino(),
            std::fs::metadata(root.join("rootfs.ext4")).unwrap().ino()
        );

        // An alias is the same inode under a second name, and replaces a
        // stale entry at that name.
        std::fs::create_dir_all(root.join("pool")).unwrap();
        std::fs::write(root.join("pool/slot3.ext4"), b"slot").unwrap();
        std::fs::write(root.join("data.ext4"), b"stale").unwrap();
        apply(
            &jail,
            &[StagePlan {
                src: root.join("pool/slot3.ext4"),
                dst: root.join("data.ext4"),
                kind: StageKind::Alias,
            }],
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(root.join("data.ext4")).unwrap(), b"slot");
        assert_eq!(
            std::fs::metadata(root.join("pool/slot3.ext4"))
                .unwrap()
                .ino(),
            std::fs::metadata(root.join("data.ext4")).unwrap().ino()
        );
    }
}
