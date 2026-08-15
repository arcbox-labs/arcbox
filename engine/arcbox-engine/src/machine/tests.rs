use super::*;
use tempfile::tempdir;

fn test_machine_manager(data_dir: &std::path::Path) -> MachineManager {
    test_machine_manager_with_bus(data_dir, crate::event::EventBus::new())
}

fn test_machine_manager_with_bus(
    data_dir: &std::path::Path,
    event_bus: crate::event::EventBus,
) -> MachineManager {
    let vm_manager = Arc::new(VmManager::new(data_dir.join("snapshots")));
    MachineManager::new(vm_manager, data_dir.to_path_buf(), None, event_bus)
}

#[tokio::test]
async fn create_publishes_machine_created_for_user_machines_only() {
    use crate::event::{Event, EventBus};

    let temp_dir = tempdir().unwrap();
    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    let manager = test_machine_manager_with_bus(temp_dir.path(), bus);

    manager
        .create(MachineConfig {
            name: "work".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        matches!(rx.try_recv(), Ok(Event::MachineCreated { name }) if name == "work"),
        "creating a user machine must publish MachineCreated"
    );

    // The default System VM's lifecycle events come from its own lifecycle
    // actor; MachineManager must not double-publish for it.
    manager
        .create(MachineConfig {
            name: "default".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        rx.try_recv().is_err(),
        "creating the default machine must not publish from MachineManager"
    );
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

#[tokio::test]
async fn connect_agent_distinguishes_missing_and_stopped_machines() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    let missing = machine_manager
        .connect_agent("missing")
        .err()
        .expect("missing machine must fail");
    assert!(matches!(
        &missing,
        EngineError::Common(arcbox_error::CommonError::NotFound(_))
    ));

    machine_manager
        .create(MachineConfig {
            name: "stopped".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
    let stopped = machine_manager
        .connect_agent("stopped")
        .err()
        .expect("stopped machine must fail");
    assert!(matches!(
        &stopped,
        EngineError::Common(arcbox_error::CommonError::InvalidState(_))
    ));
    assert!(
        stopped
            .to_string()
            .contains("machine 'stopped' is not running")
    );
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
        EngineError::Common(ref c) if c.is_already_exists() => {}
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

#[tokio::test]
async fn test_create_with_shim_assembles_boot_contract() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    let rootfs_img = temp_dir.path().join("rootfs.squashfs");
    std::fs::write(&rootfs_img, b"squash").unwrap();
    let shim_kernel = temp_dir.path().join("kernel");
    let shim_rootfs = temp_dir.path().join("shim.erofs");

    machine_manager
        .create(MachineConfig {
            name: "shimmed".to_string(),
            disk_gb: 1,
            rootfs: Some(MachineRootfs {
                path: rootfs_img.clone(),
                format: "squashfs".to_string(),
                shim: Some(BootShim {
                    kernel: shim_kernel.clone(),
                    rootfs: shim_rootfs.clone(),
                }),
            }),
            ..Default::default()
        })
        .await
        .unwrap();

    let machine = machine_manager.get("shimmed").unwrap();

    // Device contract: vda=shim EROFS ro, vdb=distro rootfs ro, vdc=data rw.
    let devices = &machine.block_devices;
    assert_eq!(devices.len(), 3);
    assert_eq!(devices[0].path, shim_rootfs.to_string_lossy());
    assert!(devices[0].read_only);
    assert_eq!(devices[1].path, rootfs_img.to_string_lossy());
    assert!(devices[1].read_only);
    assert!(devices[2].path.ends_with("data.img"));
    assert!(!devices[2].read_only);

    // The data disk was provisioned sparse at the requested size.
    let data_disk = machine.disk_path.as_ref().unwrap();
    assert_eq!(
        std::fs::metadata(data_disk).unwrap().len(),
        1024 * 1024 * 1024
    );

    // Kernel comes from the shim; cmdline follows the machine-init contract.
    assert_eq!(
        machine.kernel.as_deref(),
        Some(&*shim_kernel.to_string_lossy())
    );
    let cmdline = machine.cmdline.as_deref().unwrap();
    assert!(
        cmdline.contains("root=/dev/vda ro rootfstype=erofs"),
        "{cmdline}"
    );
    assert!(
        cmdline.contains(&format!(
            "init={}",
            arcbox_constants::cmdline::MACHINE_INIT_PATH
        )),
        "{cmdline}"
    );
    assert!(
        cmdline.contains(&format!(
            "{}/dev/vdb",
            arcbox_constants::cmdline::MACHINE_ROOTFS_KEY
        )),
        "{cmdline}"
    );
    assert!(
        cmdline.contains(&format!(
            "{}squashfs",
            arcbox_constants::cmdline::MACHINE_ROOTFS_TYPE_KEY
        )),
        "{cmdline}"
    );
    assert!(
        cmdline.contains(&format!(
            "{}/dev/vdc",
            arcbox_constants::cmdline::MACHINE_DATA_KEY
        )),
        "{cmdline}"
    );
}

#[tokio::test]
async fn test_create_without_shim_boots_rootfs_directly() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    let rootfs_img = temp_dir.path().join("rootfs.squashfs");
    std::fs::write(&rootfs_img, b"squash").unwrap();

    // Without a shim, the rootfs alone cannot boot: an explicit kernel is
    // required (custom-kernel testing path).
    let err = machine_manager
        .create(MachineConfig {
            name: "plain-distro".to_string(),
            disk_gb: 1,
            rootfs: Some(MachineRootfs {
                path: rootfs_img.clone(),
                format: "squashfs".to_string(),
                shim: None,
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("explicit"), "{err}");

    machine_manager
        .create(MachineConfig {
            name: "plain-distro".to_string(),
            disk_gb: 1,
            kernel: Some("/custom/kernel".to_string()),
            rootfs: Some(MachineRootfs {
                path: rootfs_img.clone(),
                format: "squashfs".to_string(),
                shim: None,
            }),
            ..Default::default()
        })
        .await
        .unwrap();

    let machine = machine_manager.get("plain-distro").unwrap();
    let devices = &machine.block_devices;
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].path, rootfs_img.to_string_lossy());
    assert_eq!(machine.kernel.as_deref(), Some("/custom/kernel"));
    let cmdline = machine.cmdline.as_deref().unwrap();
    assert!(
        cmdline.contains("root=/dev/vda ro rootfstype=squashfs"),
        "{cmdline}"
    );
    assert!(!cmdline.contains("init="), "{cmdline}");
}

#[tokio::test]
async fn test_assign_cid_skips_cids_held_by_other_machines() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    machine_manager
        .register_mock_machine("holder-a", 3)
        .unwrap();
    machine_manager
        .register_mock_machine("holder-b", 5)
        .unwrap();

    let name = machine_manager
        .create(MachineConfig {
            name: "fresh".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();

    let (_, cid) = machine_manager.assign_cid_for_start(&name).unwrap();
    assert_eq!(cid, 4, "lowest CID not held by another machine");
}

#[tokio::test]
async fn test_create_with_mounts_extends_cmdline_and_persists() {
    let temp_dir = tempdir().unwrap();
    let machine_manager = test_machine_manager(temp_dir.path());

    let rootfs_img = temp_dir.path().join("rootfs.squashfs");
    std::fs::write(&rootfs_img, b"squash").unwrap();
    let host_share = temp_dir.path().join("share");
    std::fs::create_dir(&host_share).unwrap();

    let shim = BootShim {
        kernel: temp_dir.path().join("kernel"),
        rootfs: temp_dir.path().join("shim.erofs"),
    };
    let mounts = vec![
        MachineMount {
            host_path: host_share.to_string_lossy().into_owned(),
            guest_path: "/work".to_string(),
            read_only: false,
        },
        MachineMount {
            host_path: host_share.to_string_lossy().into_owned(),
            guest_path: "/data".to_string(),
            read_only: true,
        },
    ];

    machine_manager
        .create(MachineConfig {
            name: "mounted".to_string(),
            disk_gb: 1,
            rootfs: Some(MachineRootfs {
                path: rootfs_img.clone(),
                format: "squashfs".to_string(),
                shim: Some(shim.clone()),
            }),
            mounts: mounts.clone(),
            ..Default::default()
        })
        .await
        .unwrap();

    let machine = machine_manager.get("mounted").unwrap();
    let cmdline = machine.cmdline.as_deref().unwrap();
    assert!(
        cmdline.contains(&format!(
            "{}m0=/work,m1=/data:ro",
            arcbox_constants::cmdline::MACHINE_MOUNTS_KEY
        )),
        "{cmdline}"
    );
    assert_eq!(machine.mounts.len(), 2);
    assert_eq!(machine.mounts[1].guest_path, "/data");
    assert!(machine.mounts[1].read_only);

    // Mounts are rejected off the shim path and validated for separators.
    let err = machine_manager
        .create(MachineConfig {
            name: "no-shim-mounts".to_string(),
            mounts: mounts.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("shim"), "{err}");

    let err = machine_manager
        .create(MachineConfig {
            name: "bad-guest-path".to_string(),
            disk_gb: 1,
            rootfs: Some(MachineRootfs {
                path: rootfs_img,
                format: "squashfs".to_string(),
                shim: Some(shim),
            }),
            mounts: vec![MachineMount {
                host_path: host_share.to_string_lossy().into_owned(),
                guest_path: "/with,comma".to_string(),
                read_only: false,
            }],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("','"), "{err}");
}

/// A machine whose distro init is still starting is NOT ready, even though
/// the agent answered and reported a usable address. This is the CORE-66
/// gate: the distro reconfigures the network from scratch after the agent
/// comes up, so an address observed before it settles does not mean the
/// machine is usable.
#[test]
fn readiness_waits_for_the_distro_init_to_settle() {
    let info = arcbox_connect::v1::SystemInfo {
        ip_addresses: vec!["10.0.2.2".to_owned()],
        distro_init_pending: true,
        ..Default::default()
    };
    assert_eq!(readiness_ip(&info, "m", 1), None);
}

#[test]
fn readiness_reports_the_address_once_the_distro_init_has_settled() {
    let info = arcbox_connect::v1::SystemInfo {
        ip_addresses: vec!["10.0.2.2".to_owned()],
        distro_init_pending: false,
        ..Default::default()
    };
    assert_eq!(readiness_ip(&info, "m", 1), Some("10.0.2.2".to_owned()));
}

/// The proto3 default must be the pre-CORE-66 behaviour: an agent that
/// predates the field leaves `distro_init_pending` false, and readiness must
/// proceed exactly as before rather than waiting out the 60 s timeout on a
/// signal that agent will never send.
#[test]
fn an_agent_without_the_field_is_not_treated_as_pending() {
    let decoded = arcbox_connect::v1::SystemInfo::default();
    assert!(!decoded.distro_init_pending);

    let info = arcbox_connect::v1::SystemInfo {
        ip_addresses: vec!["10.0.2.2".to_owned()],
        ..Default::default()
    };
    assert_eq!(readiness_ip(&info, "m", 1), Some("10.0.2.2".to_owned()));
}

/// A settled init with nothing usable to report still is not ready — the
/// gate is additive, it does not replace the address requirement.
#[test]
fn a_settled_init_without_a_usable_address_is_still_not_ready() {
    let info = arcbox_connect::v1::SystemInfo {
        ip_addresses: vec!["127.0.0.1".to_owned()],
        distro_init_pending: false,
        ..Default::default()
    };
    assert_eq!(readiness_ip(&info, "m", 1), None);
}
