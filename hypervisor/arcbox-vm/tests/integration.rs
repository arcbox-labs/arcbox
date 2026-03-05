mod common;

use std::path::PathBuf;

use arcbox_vm::config::SnapshotType;
use arcbox_vm::snapshot::SnapshotCatalog;

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
        catalog
            .register(
                "vm-persist",
                Some("checkpoint-1".into()),
                SnapshotType::Full,
                PathBuf::from("/tmp/vmstate"),
                None,
                None,
                None,
                None,
            )
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

    use arcbox_vm::network::NetworkManager;

    // Third octet 10 → TAP name vmtap10<x>, distinct from the other TAP test.
    let mgr = NetworkManager::new("", "10.0.10.0/28", "10.0.10.1", vec![]).unwrap();
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

    use arcbox_vm::network::NetworkManager;

    // Third octet 11 → TAP name vmtap11<x>, distinct from the other TAP test.
    let mgr = NetworkManager::new("", "10.0.11.0/28", "10.0.11.1", vec![]).unwrap();

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
