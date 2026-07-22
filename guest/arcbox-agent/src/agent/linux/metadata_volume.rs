//! ext4 metadata volume: format, mount, migrate, and bind the fsync-hot
//! boltdb metadata onto a small journaled ext4 disk.
//!
//! Container-start profiling (ABX-496) put ~90 % of fsyncs on these boltdb
//! files, and one fsync costs ~9.5 ms on btrfs vs ~1 ms on ext4 over the
//! same virtio-blk stack — so the hot metadata moves to ext4 while bulk data
//! (layers, blobs, volumes) stays on the compressed btrfs data volume. The
//! crash-safe migration state machine lives in `crate::metadata_migrate`;
//! design and failure policy: internal-docs/plans/ext4-metadata-volume.md.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use arcbox_constants::paths::{CONTAINERD_DATA_MOUNT_POINT, DOCKER_DATA_MOUNT_POINT};

use super::cmdline::docker_metadata_device;
use crate::metadata_migrate::{EntryKind, Prepared, prepare_entry};

/// Mount point of the raw ext4 volume (`/run` is tmpfs, writable).
const METADATA_MOUNT: &str = "/run/arcbox/metadata";
/// Both binaries are baked into the EROFS rootfs (static e2fsprogs).
const MKFS_EXT4: &str = "/sbin/mkfs.ext4";
const E2FSCK: &str = "/sbin/e2fsck";

/// ext4 superblock magic `0xEF53`, little-endian at byte 56 of the
/// superblock (which starts at byte 1024).
const EXT4_MAGIC_OFFSET: u64 = 1024 + 56;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

/// One fsync-hot metadata location: an entry on the volume bound over its
/// canonical btrfs-side path. The set is exactly the profiled hot set —
/// everything else (containers/, volumes/, builder/, trust/) stays on btrfs.
struct Mapping {
    /// Entry name inside the metadata volume.
    name: &'static str,
    /// Canonical path the runtime opens (bind target).
    target: String,
    kind: EntryKind,
}

fn mappings() -> Vec<Mapping> {
    vec![
        Mapping {
            name: "containerd-bolt",
            target: format!("{CONTAINERD_DATA_MOUNT_POINT}/io.containerd.metadata.v1.bolt"),
            kind: EntryKind::Dir,
        },
        // The snapshotter dir also holds snapshots/ (bulk layer data), so
        // only its boltdb is bound — a file bind is safe for bolt, which
        // writes in place and never renames its database file.
        Mapping {
            name: "snapshotter-metadata.db",
            target: format!(
                "{CONTAINERD_DATA_MOUNT_POINT}/io.containerd.snapshotter.v1.overlayfs/metadata.db"
            ),
            kind: EntryKind::File,
        },
        Mapping {
            name: "docker-network",
            target: format!("{DOCKER_DATA_MOUNT_POINT}/network"),
            kind: EntryKind::Dir,
        },
        Mapping {
            name: "docker-image",
            target: format!("{DOCKER_DATA_MOUNT_POINT}/image"),
            kind: EntryKind::Dir,
        },
        Mapping {
            name: "docker-buildkit",
            target: format!("{DOCKER_DATA_MOUNT_POINT}/buildkit"),
            kind: EntryKind::Dir,
        },
    ]
}

/// Mounts the ext4 metadata volume and binds the hot metadata dirs over
/// their btrfs-side paths. Must run after `ensure_data_mount` (targets live
/// on the data subvolumes) and before containerd/dockerd start (their boltdb
/// files must be closed while entries migrate).
///
/// Failure policy (version-skew safe, see the plan doc):
/// - device absent (daemon without the third disk) → `Ok`, btrfs-only boot;
/// - mkfs binary absent AND device blank (older rootfs) → `Ok`, skip;
/// - device present with ext4 but mount/prepare/bind fails → `Err` — booting
///   dockerd against the stale shadowed btrfs state would fork it.
pub(super) fn ensure_metadata_mount() -> Result<String, String> {
    let maps = mappings();
    if maps.iter().all(|m| crate::mount::is_mounted(&m.target)) {
        return Ok("metadata binds already mounted".to_string());
    }

    let device = docker_metadata_device();
    if !wait_for_device(&device) {
        tracing::warn!(device, "metadata device absent; running btrfs-only layout");
        return Ok(format!("metadata device {device} absent; skipped"));
    }

    let mut notes = Vec::new();

    if !has_ext4_superblock(&device) {
        if !Path::new(MKFS_EXT4).exists() {
            // Older rootfs without e2fsprogs and a never-used disk: nothing
            // was ever migrated, so a btrfs-only boot is consistent.
            tracing::warn!("mkfs.ext4 missing and metadata device blank; skipping metadata volume");
            return Ok("metadata volume skipped (no mkfs.ext4)".to_string());
        }
        notes.push(format_ext4(&device)?);
    }

    mount_metadata(&device, &mut notes)?;

    for mapping in &maps {
        if crate::mount::is_mounted(&mapping.target) {
            continue;
        }
        let volume_entry = Path::new(METADATA_MOUNT).join(mapping.name);
        match prepare_entry(
            Path::new(METADATA_MOUNT),
            Path::new(&mapping.target),
            mapping.name,
            mapping.kind,
        ) {
            Ok(Prepared::Migrated) => notes.push(format!("migrated {}", mapping.target)),
            Ok(_) => {}
            Err(e) => return Err(format!("prepare {} failed: {e}", mapping.target)),
        }
        bind(&volume_entry, &mapping.target)?;
    }

    if notes.is_empty() {
        Ok("metadata volume mounted".to_string())
    } else {
        Ok(notes.join("; "))
    }
}

/// Waits up to 5 s for the VirtIO block device node (same budget and
/// rationale as the data-device wait in `btrfs.rs`).
fn wait_for_device(device: &str) -> bool {
    for attempt in 0..50 {
        if Path::new(device).exists() {
            if attempt > 0 {
                tracing::info!(device, attempt, "waited for metadata device");
            }
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

fn has_ext4_superblock(device: &str) -> bool {
    let Ok(mut file) = std::fs::File::open(device) else {
        return false;
    };
    if file.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET)).is_err() {
        return false;
    }
    let mut magic = [0_u8; 2];
    file.read_exact(&mut magic).is_ok() && magic == EXT4_MAGIC
}

fn format_ext4(device: &str) -> Result<String, String> {
    // Explicit feature list so the result is deterministic regardless of
    // any mke2fs.conf; fast_commit targets exactly the small-metadata-commit
    // fsync pattern boltdb produces, lazy init off pays the one-time cost at
    // format instead of trickling background writes into first boot.
    match std::process::Command::new(MKFS_EXT4)
        .args([
            "-F",
            "-t",
            "ext4",
            "-O",
            "has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_nlink,extra_isize,fast_commit",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            "-L",
            "arcbox-meta",
            device,
        ])
        .status()
    {
        Ok(status) if status.success() => Ok(format!("formatted {device} as ext4")),
        Ok(status) => Err(format!(
            "mkfs.ext4 failed on {device} (exit={})",
            status.code().unwrap_or(-1)
        )),
        Err(e) => Err(format!("failed to execute mkfs.ext4: {e}")),
    }
}

/// Mounts the volume; on failure runs `e2fsck -y` once (journal replay is
/// in-kernel — fsck covers the residual corruption class) and retries once.
fn mount_metadata(device: &str, notes: &mut Vec<String>) -> Result<(), String> {
    if crate::mount::is_mounted(METADATA_MOUNT) {
        return Ok(());
    }
    std::fs::create_dir_all(METADATA_MOUNT)
        .map_err(|e| format!("failed to create {METADATA_MOUNT}: {e}"))?;

    if try_mount(device) {
        return Ok(());
    }

    if !Path::new(E2FSCK).exists() {
        return Err(format!(
            "mount {device} on {METADATA_MOUNT} failed and {E2FSCK} is unavailable"
        ));
    }
    // e2fsck exit codes 0/1/2 mean clean or corrected; >=4 is a real failure.
    match std::process::Command::new(E2FSCK)
        .args(["-y", device])
        .status()
    {
        Ok(status) if status.code().is_some_and(|c| c <= 2) => {
            notes.push(format!("e2fsck repaired {device}"));
        }
        Ok(status) => {
            return Err(format!(
                "e2fsck failed on {device} (exit={})",
                status.code().unwrap_or(-1)
            ));
        }
        Err(e) => return Err(format!("failed to execute e2fsck: {e}")),
    }
    if try_mount(device) {
        Ok(())
    } else {
        Err(format!(
            "mount {device} on {METADATA_MOUNT} failed even after e2fsck"
        ))
    }
}

fn try_mount(device: &str) -> bool {
    matches!(
        std::process::Command::new("/bin/busybox")
            .args(["mount", "-t", "ext4", "-o", "noatime", device, METADATA_MOUNT])
            .status(),
        Ok(status) if status.success()
    )
}

fn bind(source: &Path, target: &str) -> Result<(), String> {
    nix::mount::mount(
        Some(source),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| format!("bind {} -> {target} failed: {e}", source.display()))
}
