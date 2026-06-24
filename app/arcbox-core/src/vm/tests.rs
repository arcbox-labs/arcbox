use super::*;
use tempfile::TempDir;

fn test_vm_manager() -> (VmManager, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let manager = VmManager::new(temp_dir.path().join("snapshots"));
    (manager, temp_dir)
}

#[test]
fn test_set_guest_cid_updates_vm_config() {
    let (manager, _dir) = test_vm_manager();
    let config = VmConfig {
        guest_cid: None,
        ..Default::default()
    };

    let vm_id = manager.create(config).unwrap();

    manager.set_guest_cid(&vm_id, 7).unwrap();
    assert_eq!(manager.guest_cid_for_test(&vm_id), Some(7));
}

#[test]
fn test_build_vmm_config_includes_guest_cid() {
    let (manager, _dir) = test_vm_manager();
    let config = VmConfig {
        guest_cid: Some(9),
        ..Default::default()
    };

    let vm_id = manager.create(config).unwrap();
    let vmm_config = manager.build_vmm_config_for_test(&vm_id).unwrap();
    assert_eq!(vmm_config.guest_cid, Some(9));
    assert_eq!(
        vmm_config.bridge_nic_mac,
        Some(bridge_nic_mac_for_vm_id(&vm_id))
    );
}

#[test]
fn test_bridge_nic_mac_is_stable_and_locally_administered() {
    let vm_id = VmId::from_string("00112233-4455-6677-8899-aabbccddeeff".to_string());
    let mac = bridge_nic_mac_for_vm_id(&vm_id);

    assert_eq!(mac, "02:00:11:22:33:44");
}

#[test]
fn test_start_failure_rolls_back_to_created() {
    let (manager, _dir) = test_vm_manager();
    let vm_id = manager.create(VmConfig::default()).unwrap();

    let _ = manager.start(&vm_id, None);
    let info = manager.get(&vm_id).expect("vm should still exist");
    assert_eq!(info.state, MachineState::Created);
}
