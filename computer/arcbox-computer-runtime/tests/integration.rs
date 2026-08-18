mod common;

use arcbox_computer_runtime::config::SnapshotType;
use arcbox_computer_runtime::snapshot::{SnapshotCatalog, SnapshotDraft};

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

    use arcbox_computer_runtime::snapshot_cow::{device_major_minor, mknod_blkdev};

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

/// The two real userlands, driven through the [`BlockTools`] seam: attach a
/// sparse file, read the device's size, detach, and confirm the kernel saw
/// each step. Unit tests drive shell stand-ins, which prove the argument
/// shapes and nothing about whether the real tools accept them — the option
/// surfaces are exactly what differs between the two implementations, so
/// each needs its own real binary.
#[cfg(target_os = "linux")]
mod block_tools {
    use arcbox_computer_runtime::snapshot_cow::{
        BlockTools, BusyboxBlockTools, UtilLinuxBlockTools,
    };

    use super::common;

    const IMAGE_BYTES: u64 = 4 * 1024 * 1024;

    /// `BusyboxBlockTools` against a real busybox. BusyBox's `losetup` has
    /// no long options, so the applet-driving code cannot be checked with
    /// util-linux — this is the one place the real thing runs. Skips
    /// without root or a busybox (`BUSYBOX`, else `/bin/busybox`); the
    /// `integration` job installs `busybox-static` for it.
    #[test]
    fn busybox_attach_report_and_detach() {
        if !common::is_root() {
            eprintln!("SKIP busybox_attach_report_and_detach — requires root");
            return;
        }
        let busybox = std::env::var("BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
        if !std::path::Path::new(&busybox).exists() {
            eprintln!("SKIP busybox_attach_report_and_detach — no busybox at {busybox}");
            return;
        }
        attach_report_and_detach(&BusyboxBlockTools::new(&busybox));
    }

    /// `UtilLinuxBlockTools` against a stock distro's `/sbin`: the atomic
    /// `losetup -f --show` attach busybox cannot express, plus the
    /// `--version` discovery probe that has to find the real binaries here
    /// and reject a busybox applet elsewhere. Skips without root or a
    /// util-linux userland.
    #[test]
    fn util_linux_attach_report_and_detach() {
        if !common::is_root() {
            eprintln!("SKIP util_linux_attach_report_and_detach — requires root");
            return;
        }
        let tools = match UtilLinuxBlockTools::discover() {
            Ok(tools) => tools,
            Err(e) => {
                eprintln!("SKIP util_linux_attach_report_and_detach — {e}");
                return;
            }
        };
        attach_report_and_detach(&tools);
    }

    fn attach_report_and_detach(tools: &dyn BlockTools) {
        let dir = tempfile::tempdir().unwrap();
        let backing = dir.path().join("backing.img");
        std::fs::File::create(&backing)
            .unwrap()
            .set_len(IMAGE_BYTES)
            .unwrap();

        let device = tools.attach_loop(&backing, false).unwrap();

        let sysfs_backing_file = {
            let index = device
                .strip_prefix("/dev/loop")
                .filter(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()));
            index.map(|index| format!("/sys/block/loop{index}/loop/backing_file"))
        };
        let result = (|| -> Result<(), String> {
            let sysfs_backing_file = sysfs_backing_file
                .as_deref()
                .ok_or_else(|| format!("attach returned {device}, not /dev/loopN"))?;
            let reported = std::fs::read_to_string(sysfs_backing_file)
                .map_err(|e| format!("sysfs backing_file for {device}: {e}"))?;
            let expected = std::fs::canonicalize(&backing).map_err(|e| e.to_string())?;
            if reported.trim() != expected.to_string_lossy() {
                return Err(format!(
                    "{device} backs {:?}, expected {}",
                    reported.trim(),
                    expected.display()
                ));
            }
            let sectors = tools.device_sectors(&device).map_err(|e| e.to_string())?;
            if sectors != IMAGE_BYTES / 512 {
                return Err(format!(
                    "{device} has {sectors} sectors, expected {}",
                    IMAGE_BYTES / 512
                ));
            }
            Ok(())
        })();

        let detached = tools.detach_loop(&device);
        result.unwrap();
        detached.unwrap();

        // `LOOP_CLR_FD` with another opener — udev's blkid probe of the freshly
        // attached device, on a stock distro — only marks the device autoclear
        // and lets the last close release it, so a detach that has "succeeded"
        // can still show the backing file for a moment. Wait for the kernel to
        // actually let go before asserting there is nothing left to detach.
        let sysfs_backing_file = sysfs_backing_file.unwrap();
        let released_by = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::path::Path::new(&sysfs_backing_file).exists() {
            assert!(
                std::time::Instant::now() < released_by,
                "{device} still backs {} five seconds after detach",
                std::fs::read_to_string(&sysfs_backing_file)
                    .unwrap_or_default()
                    .trim()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            tools.detach_loop(&device).is_err(),
            "detaching the released {device} again should fail"
        );
    }
}
