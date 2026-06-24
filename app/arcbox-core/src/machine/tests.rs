use super::*;
use tempfile::tempdir;

fn test_machine_manager(data_dir: &std::path::Path) -> MachineManager {
    let vm_manager = Arc::new(VmManager::new(data_dir.join("snapshots")));
    MachineManager::new(vm_manager, data_dir.to_path_buf(), None)
}

#[tokio::test]
async fn test_assign_cid_propagates_to_vm_config() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    let name = machine_manager
        .create(MachineConfig {
            name: "cid-test".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let (vm_id, cid) = machine_manager.assign_cid_for_start(&name).unwrap();
    assert_eq!(cid, 3);
    assert_eq!(
        machine_manager.vm_manager.guest_cid_for_test(&vm_id),
        Some(cid)
    );
}

#[test]
fn test_register_mock_machine() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    machine_manager
        .register_mock_machine("test-mock", 42)
        .unwrap();

    let machine = machine_manager
        .get("test-mock")
        .expect("machine should exist");
    assert_eq!(machine.name, "test-mock");
    assert_eq!(machine.cid, Some(42));
    assert_eq!(machine.state, MachineState::Running);
}

#[test]
fn test_register_mock_machine_idempotent() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    machine_manager
        .register_mock_machine("test-idempotent", 10)
        .unwrap();
    machine_manager
        .register_mock_machine("test-idempotent", 20)
        .unwrap();

    let machine = machine_manager.get("test-idempotent").unwrap();
    assert_eq!(machine.cid, Some(10));
}

#[test]
fn test_select_routable_ip_prefers_ipv4() {
    let ips = vec![
        "::1".to_string(),
        "fe80::1".to_string(),
        "2001:db8::10".to_string(),
        "10.0.2.2".to_string(),
    ];
    assert_eq!(select_routable_ip(&ips), Some("10.0.2.2".to_string()));
}

#[test]
fn test_select_routable_ip_falls_back_to_global_ipv6() {
    let ips = vec![
        "::1".to_string(),
        "fe80::2".to_string(),
        "2001:db8::42".to_string(),
    ];
    assert_eq!(select_routable_ip(&ips), Some("2001:db8::42".to_string()));
}

/// Two concurrent `create` calls with the same name must not both succeed.
/// One wins, the other returns `AlreadyExists`, and only one machine is
/// registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_concurrent_same_name_no_duplicate() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = Arc::new(test_machine_manager(temp_dir.path()));

    let name = "race-test";
    let mm1 = machine_manager.clone();
    let mm2 = machine_manager.clone();

    // `create` has no `.await` points, so without a barrier the first-polled
    // task can run to completion before the second is even scheduled.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let b1 = barrier.clone();
    let b2 = barrier.clone();

    let t1 = tokio::spawn(async move {
        b1.wait().await;
        mm1.create(MachineConfig {
            name: name.to_string(),
            ..Default::default()
        })
        .await
    });
    let t2 = tokio::spawn(async move {
        b2.wait().await;
        mm2.create(MachineConfig {
            name: name.to_string(),
            ..Default::default()
        })
        .await
    });

    let r1 = t1.await.unwrap();
    let r2 = t2.await.unwrap();

    let (winner, loser) = match (r1, r2) {
        (Ok(n), Err(e)) | (Err(e), Ok(n)) => (n, e),
        (Ok(_), Ok(_)) => panic!("both creates succeeded — TOCTOU regression"),
        (Err(e1), Err(e2)) => panic!("both creates failed: {e1:?} / {e2:?}"),
    };
    assert_eq!(winner, name);
    match loser {
        CoreError::Common(ref c) if c.is_already_exists() => {}
        other => panic!("loser should be AlreadyExists, got {other:?}"),
    }

    let machines = machine_manager.list();
    assert_eq!(
        machines.len(),
        1,
        "exactly one machine should be registered"
    );
    assert_eq!(machines[0].name, name);
}
