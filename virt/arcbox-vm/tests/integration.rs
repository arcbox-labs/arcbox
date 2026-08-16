mod common;

use arcbox_vm::config::SnapshotType;
#[cfg(target_os = "linux")]
use arcbox_vm::network::{NetworkAllocation, NetworkManager};
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
// TAP lifecycle (Linux, root only)
// ---------------------------------------------------------------------------

/// NetworkManager creates a real TAP interface on allocation and removes it on
/// release.  Skips if not running as root.
#[test]
#[cfg(target_os = "linux")]
fn tap_lifecycle_via_network_manager() {
    if !common::is_root() {
        eprintln!("SKIP tap_lifecycle_via_network_manager — requires root");
        return;
    }

    // Third octet 10 → TAP name vmtap10<x>, distinct from the other TAP test.
    let mgr = NetworkManager::new("10.0.10.0/28", "10.0.10.1", vec![]).unwrap();
    let alloc = mgr.allocate("itg-tap-lifecycle").unwrap();

    assert!(
        common::iface_exists(&alloc.tap_name),
        "TAP {} should exist after allocate",
        alloc.tap_name
    );

    mgr.release(&alloc);

    assert!(
        !common::iface_exists(&alloc.tap_name),
        "TAP {} should be gone after release",
        alloc.tap_name
    );
}

/// After releasing an allocation the IP re-enters the pool and is assigned on
/// the next call to allocate.  Verifies that the recycled TAP is also cleaned
/// up correctly.  Skips if not running as root.
#[test]
#[cfg(target_os = "linux")]
fn network_ip_returns_to_pool_with_tap() {
    if !common::is_root() {
        eprintln!("SKIP network_ip_returns_to_pool_with_tap — requires root");
        return;
    }

    // Third octet 11 → TAP name vmtap11<x>, distinct from the other TAP test.
    let mgr = NetworkManager::new("10.0.11.0/28", "10.0.11.1", vec![]).unwrap();

    let a1 = mgr.allocate("itg-pool-vm-1").unwrap();
    let first_ip = a1.ip_address;
    mgr.release(&a1);

    let a2 = mgr.allocate("itg-pool-vm-2").unwrap();
    assert_eq!(a2.ip_address, first_ip, "released IP should be reused");

    mgr.release(&a2);
    assert!(
        !common::iface_exists(&a2.tap_name),
        "TAP {} should be gone after final release",
        a2.tap_name
    );
}

// ---------------------------------------------------------------------------
// TAP cleanup guard
// ---------------------------------------------------------------------------

/// RAII guard that releases a TAP allocation on drop, ensuring cleanup even
/// when an assertion panics mid-test.
#[cfg(target_os = "linux")]
struct TapGuard<'a> {
    mgr: &'a NetworkManager,
    alloc: &'a NetworkAllocation,
}

#[cfg(target_os = "linux")]
impl Drop for TapGuard<'_> {
    fn drop(&mut self) {
        self.mgr.release(self.alloc);
    }
}

// ---------------------------------------------------------------------------
// Point-to-point TAP configuration (Linux, root only)
// ---------------------------------------------------------------------------

/// Each TAP gets a point-to-point IP with the gateway as local addr and
/// the sandbox IP as peer, with an explicit /32 host route.
#[test]
#[cfg(target_os = "linux")]
fn tap_has_point_to_point_peer_address() {
    if !common::is_root() {
        eprintln!("SKIP tap_has_point_to_point_peer_address — requires root");
        return;
    }

    let mgr = NetworkManager::new("10.0.12.0/28", "10.0.12.1", vec![]).unwrap();
    let alloc = mgr.allocate("itg-ptp-1").unwrap();
    let guard = TapGuard {
        mgr: &mgr,
        alloc: &alloc,
    };

    // TAP should have the peer address configured.
    let peer = common::get_peer_addr(&alloc.tap_name);
    assert_eq!(
        peer.as_deref(),
        Some(&*alloc.ip_address.to_string()),
        "TAP {} should have peer address {}",
        alloc.tap_name,
        alloc.ip_address
    );

    // Kernel should have a /32 host route to the sandbox IP via this TAP.
    let route_dest = format!("{}/32", alloc.ip_address);
    assert!(
        common::has_route(&route_dest, &alloc.tap_name),
        "expected /32 route to {} via {}",
        alloc.ip_address,
        alloc.tap_name
    );

    // Explicitly drop the guard to trigger release, then verify cleanup.
    drop(guard);

    // Route should be gone after TAP destruction.
    assert!(
        !common::has_route(&route_dest, &alloc.tap_name),
        "route to {} should be removed after release",
        alloc.ip_address
    );
}

/// Multiple TAPs get isolated point-to-point links — each has its own /32
/// route and there is no shared bridge interface.
#[test]
#[cfg(target_os = "linux")]
fn multiple_taps_are_isolated() {
    if !common::is_root() {
        eprintln!("SKIP multiple_taps_are_isolated — requires root");
        return;
    }

    let mgr = NetworkManager::new("10.0.13.0/28", "10.0.13.1", vec![]).unwrap();
    let a1 = mgr.allocate("itg-iso-1").unwrap();
    let _g1 = TapGuard {
        mgr: &mgr,
        alloc: &a1,
    };
    let a2 = mgr.allocate("itg-iso-2").unwrap();
    let _g2 = TapGuard {
        mgr: &mgr,
        alloc: &a2,
    };

    // Both TAPs exist with different IPs.
    assert!(common::iface_exists(&a1.tap_name));
    assert!(common::iface_exists(&a2.tap_name));
    assert_ne!(a1.ip_address, a2.ip_address);

    // Each has its own peer and /32 route.
    assert_eq!(
        common::get_peer_addr(&a1.tap_name).as_deref(),
        Some(&*a1.ip_address.to_string()),
    );
    assert_eq!(
        common::get_peer_addr(&a2.tap_name).as_deref(),
        Some(&*a2.ip_address.to_string()),
    );

    // Neither TAP is attached to a bridge (no "master" in ip link output).
    let out1 = std::process::Command::new("/usr/sbin/ip")
        .args(["link", "show", &a1.tap_name])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&out1.stdout).contains("master"),
        "TAP {} should not be attached to any bridge",
        a1.tap_name
    );
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
