//! Crash-safe migrate-then-retire state machine for the ext4 metadata volume.
//!
//! The Linux agent (`agent/linux/metadata_volume.rs`) moves the fsync-hot
//! boltdb metadata directories from the btrfs data volume onto a small ext4
//! volume and bind-mounts them back over their canonical paths. This module
//! owns the on-disk state machine — copy, retire, mountpoint stub — and is
//! kept free of mount syscalls so every crash window stays unit-testable on
//! any host. Design: ../company/engineering/arcbox/plans/ext4-metadata-volume.md.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// What a migration entry is on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory bind-mounted as a whole.
    Dir,
    /// A single file (boltdb) bind-mounted over its canonical path.
    File,
}

/// How [`prepare_entry`] left the volume side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prepared {
    /// Existing btrfs-side content was copied onto the volume.
    Migrated,
    /// No source content existed; the volume entry was created empty.
    Fresh,
    /// The volume entry already existed (nothing copied).
    Existing,
}

/// Suffix of the retired btrfs-side source after a successful migration.
///
/// Renaming the source — rather than leaving it shadowed under the bind — is
/// what prevents a later blank metadata volume (deleted image, recreated by
/// the host) from silently re-migrating stale pre-upgrade state against a
/// data store that has moved on. The renamed copy doubles as a manual
/// recovery artifact for the (unsupported) downgrade path.
pub const RETIRED_SUFFIX: &str = ".pre-ext4";

/// Suffix of an in-progress copy on the volume; never bound, discarded and
/// redone on re-entry.
const PARTIAL_SUFFIX: &str = ".partial";

/// Prepares one metadata entry on the volume and retires its btrfs-side
/// source. Idempotent and crash-safe:
///
/// 1. If `<volume_root>/<name>` is absent: discard any stale `.partial`,
///    then either copy the source into `.partial` and atomically rename it
///    into place, or create the entry empty when no source content exists.
/// 2. If the final entry exists while the source still has content at its
///    canonical path, rename the source to `*.pre-ext4` (also covers a crash
///    between the copy and this retire).
/// 3. Ensure an empty mountpoint stub exists at the canonical path.
///
/// Every interruption re-converges: a torn copy is redone from scratch, a
/// completed copy is never redone, and the retire is retried until it lands.
pub fn prepare_entry(
    volume_root: &Path,
    target: &Path,
    name: &str,
    kind: EntryKind,
) -> io::Result<Prepared> {
    let final_path = volume_root.join(name);
    let partial = volume_root.join(format!("{name}{PARTIAL_SUFFIX}"));

    let prepared = if final_path.symlink_metadata().is_ok() {
        Prepared::Existing
    } else {
        remove_existing(&partial)?;
        if has_content(target, kind) {
            copy_entry(target, &partial, kind)?;
            fs::rename(&partial, &final_path)?;
            // The publish rename MUST be durable before the retire below:
            // the two renames live on different filesystems (volume vs
            // btrfs source), so without this barrier a crash could persist
            // the retire while losing the publish — next boot would then
            // see neither and start empty.
            fs::File::open(volume_root)?.sync_all()?;
            Prepared::Migrated
        } else {
            create_entry(&final_path, kind)?;
            Prepared::Fresh
        }
    };

    if has_content(target, kind) {
        fs::rename(target, free_retired_path(target)?)?;
    }
    ensure_stub(target, kind)?;
    Ok(prepared)
}

/// Whether the canonical source still carries data worth migrating/retiring:
/// a non-empty directory or a non-empty file.
fn has_content(path: &Path, kind: EntryKind) -> bool {
    match kind {
        EntryKind::Dir => fs::read_dir(path).is_ok_and(|mut dir| dir.next().is_some()),
        EntryKind::File => fs::metadata(path).is_ok_and(|meta| meta.len() > 0),
    }
}

fn remove_existing(path: &Path) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn create_entry(path: &Path, kind: EntryKind) -> io::Result<()> {
    match kind {
        EntryKind::Dir => fs::create_dir_all(path),
        EntryKind::File => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map(|_| ())
        }
    }
}

/// Creates the (empty) mountpoint at the canonical path without touching
/// existing content — an existing empty file/dir is reused as the stub.
fn ensure_stub(target: &Path, kind: EntryKind) -> io::Result<()> {
    create_entry(target, kind)
}

fn copy_entry(src: &Path, dst: &Path, kind: EntryKind) -> io::Result<()> {
    match kind {
        EntryKind::Dir => copy_dir_synced(src, dst),
        EntryKind::File => {
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)?;
            }
            copy_file_synced(src, dst)
        }
    }
}

fn copy_dir_synced(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    fs::set_permissions(dst, fs::metadata(src)?.permissions())?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_synced(&entry.path(), &to)?;
        } else if file_type.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, &to)?;
        } else {
            copy_file_synced(&entry.path(), &to)?;
        }
    }
    // Per-file fsync does not contractually persist this directory's
    // entries; sync the dir itself so the published tree can never be
    // durable-but-hollow (replay trusts the final path's existence).
    fs::File::open(dst)?.sync_all()
}

/// `fs::copy` + fsync: the copy must be durable before the rename that
/// publishes it, or a crash could publish a hollow entry.
fn copy_file_synced(src: &Path, dst: &Path) -> io::Result<()> {
    fs::copy(src, dst)?;
    fs::File::open(dst)?.sync_all()
}

/// First free `*.pre-ext4[.N]` sibling for retiring the source. A numbered
/// fallback covers state re-accumulated at the canonical path by boots that
/// ran without the metadata volume.
fn free_retired_path(target: &Path) -> io::Result<PathBuf> {
    let base = path_with_suffix(target, RETIRED_SUFFIX);
    if base.symlink_metadata().is_err() {
        return Ok(base);
    }
    for n in 1..100u32 {
        let candidate = path_with_suffix(target, &format!("{RETIRED_SUFFIX}.{n}"));
        if candidate.symlink_metadata().is_err() {
            return Ok(candidate);
        }
    }
    Err(io::Error::other(format!(
        "no free {RETIRED_SUFFIX} backup name next to {}",
        target.display()
    )))
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let volume = tmp.path().join("volume");
        let data = tmp.path().join("data");
        fs::create_dir_all(&volume).unwrap();
        fs::create_dir_all(&data).unwrap();
        (tmp, volume, data)
    }

    fn seed_dir(dir: &Path) {
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("meta.db"), b"bolt").unwrap();
        fs::write(dir.join("sub/inner.json"), b"{}").unwrap();
    }

    #[test]
    fn fresh_install_creates_empty_entries() {
        let (_tmp, volume, data) = setup();
        let target = data.join("network");

        let out = prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        assert_eq!(out, Prepared::Fresh);
        assert!(volume.join("docker-network").is_dir());
        assert!(target.is_dir(), "mountpoint stub must exist");

        let file_target = data.join("overlayfs/metadata.db");
        let out = prepare_entry(
            &volume,
            &file_target,
            "snapshotter-metadata.db",
            EntryKind::File,
        )
        .unwrap();
        assert_eq!(out, Prepared::Fresh);
        assert_eq!(
            fs::metadata(volume.join("snapshotter-metadata.db"))
                .unwrap()
                .len(),
            0
        );
        assert_eq!(fs::metadata(&file_target).unwrap().len(), 0);
    }

    #[test]
    fn populated_source_is_migrated_and_retired() {
        let (_tmp, volume, data) = setup();
        let target = data.join("network");
        seed_dir(&target);

        let out = prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        assert_eq!(out, Prepared::Migrated);
        let migrated = volume.join("docker-network");
        assert_eq!(fs::read(migrated.join("meta.db")).unwrap(), b"bolt");
        assert_eq!(fs::read(migrated.join("sub/inner.json")).unwrap(), b"{}");
        // Source retired, empty stub in its place.
        assert!(data.join("network.pre-ext4").join("meta.db").exists());
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }

    #[test]
    fn torn_copy_is_discarded_and_redone() {
        let (_tmp, volume, data) = setup();
        let target = data.join("network");
        seed_dir(&target);
        // A crashed previous copy left a partial with garbage.
        fs::create_dir_all(volume.join("docker-network.partial")).unwrap();
        fs::write(volume.join("docker-network.partial/meta.db"), b"torn").unwrap();

        let out = prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        assert_eq!(out, Prepared::Migrated);
        assert!(!volume.join("docker-network.partial").exists());
        assert_eq!(
            fs::read(volume.join("docker-network/meta.db")).unwrap(),
            b"bolt"
        );
    }

    #[test]
    fn crash_between_copy_and_retire_converges() {
        let (_tmp, volume, data) = setup();
        let target = data.join("network");
        seed_dir(&target);
        // The copy landed (final exists) but the retire never ran.
        fs::create_dir_all(volume.join("docker-network")).unwrap();
        fs::write(volume.join("docker-network/meta.db"), b"bolt").unwrap();

        let out = prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        // Nothing re-copied, but the retire and stub landed.
        assert_eq!(out, Prepared::Existing);
        assert!(data.join("network.pre-ext4/meta.db").exists());
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }

    #[test]
    fn replay_after_full_migration_is_a_noop() {
        let (_tmp, volume, data) = setup();
        let target = data.join("network");
        seed_dir(&target);
        prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        let out = prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        assert_eq!(out, Prepared::Existing);
        assert!(
            !data.join("network.pre-ext4.1").exists(),
            "no second backup"
        );
    }

    #[test]
    fn blank_volume_after_retire_starts_fresh_not_stale() {
        let (_tmp, volume, data) = setup();
        let target = data.join("network");
        seed_dir(&target);
        prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        // The metadata image was deleted and recreated blank: volume side
        // empty, retired backup still on btrfs.
        fs::remove_dir_all(volume.join("docker-network")).unwrap();

        let out = prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        // The retired backup must NOT be resurrected — that state predates
        // whatever the data store has since moved on to.
        assert_eq!(out, Prepared::Fresh);
        assert!(
            fs::read_dir(volume.join("docker-network"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn interim_state_retires_under_numbered_backup() {
        let (_tmp, volume, data) = setup();
        let target = data.join("network");
        seed_dir(&target);
        prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        // Boots without the volume re-accumulated state at the canonical path.
        fs::write(target.join("meta.db"), b"interim").unwrap();

        let out = prepare_entry(&volume, &target, "docker-network", EntryKind::Dir).unwrap();

        assert_eq!(out, Prepared::Existing);
        assert_eq!(
            fs::read(data.join("network.pre-ext4.1/meta.db")).unwrap(),
            b"interim"
        );
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }

    #[test]
    fn file_entry_migrates_and_stubs() {
        let (_tmp, volume, data) = setup();
        let target = data.join("overlayfs/metadata.db");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"boltdb-pages").unwrap();
        // A torn file copy is discarded too.
        fs::write(volume.join("snapshotter-metadata.db.partial"), b"torn").unwrap();

        let out =
            prepare_entry(&volume, &target, "snapshotter-metadata.db", EntryKind::File).unwrap();

        assert_eq!(out, Prepared::Migrated);
        assert!(!volume.join("snapshotter-metadata.db.partial").exists());
        assert_eq!(
            fs::read(volume.join("snapshotter-metadata.db")).unwrap(),
            b"boltdb-pages"
        );
        assert_eq!(
            fs::read(data.join("overlayfs/metadata.db.pre-ext4")).unwrap(),
            b"boltdb-pages"
        );
        assert_eq!(fs::metadata(&target).unwrap().len(), 0, "0-byte stub");
    }
}
