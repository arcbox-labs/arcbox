mod common;

use arcbox_vm::config::SnapshotType;
use arcbox_vm::snapshot::{SnapshotCatalog, SnapshotDraft};

// ---------------------------------------------------------------------------
// Snapshot persistence
// ---------------------------------------------------------------------------

/// Snapshot metadata written by one SnapshotCatalog instance is readable by a
/// fresh instance pointing to the same directory (tests real file-system I/O).
#[test]
fn snapshot_catalog_persists_across_instances() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_str().unwrap();

    let id = {
        let catalog = SnapshotCatalog::new(data_dir);
        let pending = catalog.begin("vm-persist").unwrap();
        std::fs::write(pending.dir().join("vmstate"), b"vmstate").unwrap();
        pending
            .commit(SnapshotDraft {
                labels: std::collections::HashMap::new(),
                name: Some("checkpoint-1".into()),
                snapshot_type: SnapshotType::Full,
                parent_id: None,
                kernel_path: None,
                rootfs_path: None,
                net_invariant: false,
                geometry: None,
                format: "firecracker/v1".into(),
            })
            .unwrap()
            .id
    }; // catalog is dropped; all state must come from disk

    let catalog2 = SnapshotCatalog::new(data_dir);
    let loaded = catalog2.get("vm-persist", &id).unwrap();
    assert_eq!(loaded.id, id);
    assert_eq!(loaded.name.as_deref(), Some("checkpoint-1"));
    assert_eq!(loaded.snapshot_type, SnapshotType::Full);

    let list = catalog2.list("vm-persist").unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id);
}

// ---------------------------------------------------------------------------
// Block device nodes (Linux, root only)
// ---------------------------------------------------------------------------

/// `device_major_minor` reads the numbers of a real block device and
/// `mknod_blkdev` recreates a node with the same identity — the syscall pair
/// the jailer's rootfs staging relies on, exercised against a live loop
/// device rather than the error paths only. Skips without root or
/// `losetup`; a failure in production degrades silently to a full rootfs
/// copy, so this is the loud check.
#[test]
#[cfg(target_os = "linux")]
fn block_device_numbers_round_trip_through_mknod() {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    use arcbox_vm::snapshot_cow::{device_major_minor, mknod_blkdev};

    if !common::is_root() {
        eprintln!("SKIP block_device_numbers_round_trip_through_mknod — requires root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let backing = dir.path().join("backing.img");
    std::fs::File::create(&backing)
        .unwrap()
        .set_len(4 * 1024 * 1024)
        .unwrap();
    let attached = std::process::Command::new("losetup")
        .args(["-f", "--show"])
        .arg(&backing)
        .output();
    let Ok(output) = attached else {
        eprintln!("SKIP block_device_numbers_round_trip_through_mknod — no losetup");
        return;
    };
    assert!(
        output.status.success(),
        "losetup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let loop_dev = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let result = (|| -> Result<(), String> {
        let (major, minor) = device_major_minor(&loop_dev).map_err(|e| e.to_string())?;
        let node = dir.path().join("rootfs.node");
        mknod_blkdev(&node, major, minor).map_err(|e| e.to_string())?;
        let node_meta = std::fs::metadata(&node).map_err(|e| e.to_string())?;
        let dev_meta = std::fs::metadata(&loop_dev).map_err(|e| e.to_string())?;
        if !node_meta.file_type().is_block_device() {
            return Err("mknod did not create a block device".into());
        }
        if node_meta.rdev() != dev_meta.rdev() {
            return Err(format!(
                "node rdev {:#x} != loop rdev {:#x}",
                node_meta.rdev(),
                dev_meta.rdev()
            ));
        }
        if node_meta.mode() & 0o777 != 0o600 {
            return Err(format!(
                "node mode {:o}, want 600",
                node_meta.mode() & 0o777
            ));
        }
        Ok(())
    })();

    let _ = std::process::Command::new("losetup")
        .args(["-d", &loop_dev])
        .status();
    result.unwrap();
}
