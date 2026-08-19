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

// ---------------------------------------------------------------------------
// Rootfs production (Linux, root only — loop devices and a real mount)
// ---------------------------------------------------------------------------

/// The Computer image path end to end: convert a layer at a capacity and to a
/// path the caller chose, then read the product back through the kernel's own
/// ext4 driver — the view a booting Computer gets. Unit tests cover the
/// conversion, which needs no privilege; the `vm-agent` injection is a loop
/// mount and can only be proven here.
#[cfg(target_os = "linux")]
mod rootfs {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use arcbox_computer_runtime::snapshot_cow::{
        BlockTools, BusyboxBlockTools, UtilLinuxBlockTools,
    };
    use arcbox_computer_runtime::{RootfsBuilder, RootfsPaths, RootfsSource, RootfsSpec};

    use super::common;

    /// Two block groups — small enough that the runner writes it in a
    /// moment, and more than one so the assertion below reads as a capacity
    /// the caller chose rather than a floor. Whole groups are not optional:
    /// any other capacity fails the mount here with `EXT4-fs: bad geometry`.
    const CAPACITY: u64 = 2 * arcbox_computer_runtime::ROOTFS_CAPACITY_GRANULARITY;

    /// Shared with the `block_tools` module: this runner has root, busybox
    /// and loop devices, so a skip here is a failure.
    const REQUIRE: &str = "ARCBOX_REQUIRE_BLOCK_TOOLS";

    fn skipped(test: &str, reason: &str) {
        assert!(
            std::env::var_os(REQUIRE).is_none(),
            "{test}: {reason}, but {REQUIRE} says this host can run it"
        );
        eprintln!("SKIP {test} — {reason}");
    }

    /// A minimal overlay2 chain-id directory standing in for a pulled image.
    fn overlay2_layer(root: &Path) -> PathBuf {
        let layer = root.join("ABCDEF");
        std::fs::create_dir_all(layer.join("diff/etc")).unwrap();
        std::fs::write(layer.join("diff/etc/hostname"), b"computer\n").unwrap();
        std::fs::write(layer.join("link"), "ABCDEF").unwrap();
        layer
    }

    fn builder(vm_agent: &Path, tools: Arc<dyn BlockTools>) -> RootfsBuilder {
        RootfsBuilder::new(
            RootfsPaths {
                vm_agent: vm_agent.to_path_buf(),
                // Neither is read on this path: the product's path comes
                // from the caller, and no busybox userland is built.
                cache_dir: vm_agent.parent().unwrap().join("cache"),
                busybox: "/nonexistent/busybox".into(),
            },
            tools,
        )
    }

    /// Whatever loop tooling this host has: the System VM's busybox by
    /// preference, so the test drives the production shape, else a stock
    /// distro's util-linux. Which of the two accepts which options is
    /// `block_tools`' subject below, not this test's.
    fn block_tools() -> Result<Arc<dyn BlockTools>, String> {
        let busybox = std::env::var("BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
        if Path::new(&busybox).exists() {
            return Ok(Arc::new(BusyboxBlockTools::new(&busybox)));
        }
        match UtilLinuxBlockTools::discover() {
            Ok(tools) => Ok(Arc::new(tools)),
            Err(e) => Err(format!(
                "no busybox at {busybox}, and no util-linux either ({e})"
            )),
        }
    }

    /// Mount `image` read-only and hand its root to `check`, releasing the
    /// mount and the loop device before reporting — a panic inside the
    /// closure would otherwise strand a `/dev/loopN` for the rest of the run.
    fn with_mounted(
        tools: &dyn BlockTools,
        image: &Path,
        check: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<(), String> {
        use nix::mount::{MsFlags, mount, umount};

        let device = tools.attach_loop(image, true).map_err(|e| e.to_string())?;
        let mount_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let mounted = mount(
            Some(device.as_str()),
            mount_dir.path(),
            Some("ext4"),
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("mount {device}: {e}"));

        let result = match mounted {
            Ok(()) => {
                let checked = check(mount_dir.path());
                umount(mount_dir.path())
                    .map_err(|e| format!("umount: {e}"))
                    .and(checked)
            }
            Err(e) => Err(e),
        };
        tools
            .detach_loop(&device)
            .map_err(|e| format!("detach {device}: {e}"))
            .and(result)
    }

    #[tokio::test]
    async fn a_caller_addressed_build_carries_the_boot_convention() {
        const TEST: &str = "a_caller_addressed_build_carries_the_boot_convention";

        if !common::is_root() {
            skipped(TEST, "requires root");
            return;
        }
        let tools = match block_tools() {
            Ok(tools) => tools,
            Err(reason) => {
                skipped(TEST, &reason);
                return;
            }
        };

        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("vm-agent");
        std::fs::write(&staged, b"#!the-staged-agent").unwrap();
        // A path and a capacity of the caller's choosing, in a directory the
        // builder knows nothing about.
        let image = dir.path().join("images/sha256-deadbeef/rootfs.ext4");

        builder(&staged, Arc::clone(&tools))
            .build_rootfs(RootfsSpec {
                source: RootfsSource::Directory(overlay2_layer(dir.path())),
                out: image.clone(),
                size: CAPACITY,
            })
            .await
            .unwrap();

        assert_eq!(
            std::fs::metadata(&image).unwrap().len(),
            CAPACITY,
            "the image must have the capacity the caller asked for"
        );
        with_mounted(&*tools, &image, |root| {
            let agent = root.join("sbin/vm-agent");
            let bytes = std::fs::read(&agent).map_err(|e| format!("read vm-agent: {e}"))?;
            if bytes != b"#!the-staged-agent" {
                return Err(format!("vm-agent holds {} bytes", bytes.len()));
            }
            let mode = std::fs::metadata(&agent)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o755 {
                return Err(format!("vm-agent mode {mode:o}, want 755"));
            }
            let resolv = std::fs::read_link(root.join("etc/resolv.conf"))
                .map_err(|e| format!("read_link resolv.conf: {e}"))?;
            if resolv != Path::new("../run/resolv.conf") {
                return Err(format!("resolv.conf points at {}", resolv.display()));
            }
            // The layer's own contents survive the injection.
            let hostname =
                std::fs::read(root.join("etc/hostname")).map_err(|e| format!("hostname: {e}"))?;
            if hostname != b"computer\n" {
                return Err("the layer's /etc/hostname did not survive".into());
            }
            Ok(())
        })
        .unwrap();

        // The injection is reusable on its own: a second agent reaches an
        // image this builder did not format.
        let replacement = dir.path().join("vm-agent.next");
        std::fs::write(&replacement, b"#!the-next-agent").unwrap();
        builder(&replacement, Arc::clone(&tools))
            .inject_vm_agent(&image)
            .await
            .unwrap();

        with_mounted(&*tools, &image, |root| {
            match std::fs::read(root.join("sbin/vm-agent")) {
                Ok(bytes) if bytes == b"#!the-next-agent" => Ok(()),
                Ok(bytes) => Err(format!("vm-agent holds {} bytes", bytes.len())),
                Err(e) => Err(format!("read vm-agent: {e}")),
            }
        })
        .unwrap();
    }
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

    /// Set by the `integration` job, which installs both userlands: every
    /// skip below then becomes a failure. Without it a regression in the
    /// very code that decides whether to run — `UtilLinuxBlockTools`'s
    /// discovery probe above all — would take its own coverage down with
    /// it and leave CI green.
    const REQUIRE: &str = "ARCBOX_REQUIRE_BLOCK_TOOLS";

    /// Report why `test` cannot run here, or fail when this host promised
    /// it could. The caller returns straight after.
    fn skipped(test: &str, reason: &str) {
        assert!(
            std::env::var_os(REQUIRE).is_none(),
            "{test}: {reason}, but {REQUIRE} says this host has both userlands"
        );
        eprintln!("SKIP {test} — {reason}");
    }

    /// `BusyboxBlockTools` against a real busybox. BusyBox's `losetup` has
    /// no long options, so the applet-driving code cannot be checked with
    /// util-linux — this is the one place the real thing runs. Skips
    /// without root or a busybox (`BUSYBOX`, else `/bin/busybox`); the
    /// `integration` job installs `busybox-static` for it.
    #[test]
    fn busybox_attach_report_and_detach() {
        const TEST: &str = "busybox_attach_report_and_detach";

        if !common::is_root() {
            skipped(TEST, "requires root");
            return;
        }
        let busybox = std::env::var("BUSYBOX").unwrap_or_else(|_| "/bin/busybox".into());
        if !std::path::Path::new(&busybox).exists() {
            skipped(TEST, &format!("no busybox at {busybox}"));
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
        const TEST: &str = "util_linux_attach_report_and_detach";

        if !common::is_root() {
            skipped(TEST, "requires root");
            return;
        }
        let tools = match UtilLinuxBlockTools::discover() {
            Ok(tools) => tools,
            Err(e) => {
                skipped(TEST, &e.to_string());
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
