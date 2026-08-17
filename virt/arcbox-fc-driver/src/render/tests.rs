//! Pins every path and payload rule of the renderer.

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{
    BootSpec, CacheMode, CheckpointFormat, CheckpointImage, CheckpointKind, ConsoleSpec, DiskSpec,
    Error, IsolationSpec, MacAddr, NicAttachment, NicSpec, RestoreSpec, ShareSpec, VmId, VmSpec,
    VsockSpec,
};
use fc_sdk::types::{DriveCacheType, DriveIoEngine};

use super::*;
use crate::config::FcDriverConfig;

fn config() -> FcDriverConfig {
    let mut config = FcDriverConfig::new("/opt/fc/firecracker");
    config.jailer_binary = Some("/opt/fc/jailer".into());
    config
}

fn jailed(chroot_base: &Path) -> IsolationSpec {
    IsolationSpec::Jailer {
        uid: 1000,
        gid: 1000,
        chroot_base: chroot_base.to_path_buf(),
        netns: None,
        new_pid_ns: false,
        cgroup: None,
    }
}

fn layout(isolation: &IsolationSpec) -> VmLayout {
    VmLayout::new(
        &VmId::new("box").unwrap(),
        isolation,
        &config(),
        Path::new("/run/vms/box"),
    )
    .unwrap()
}

#[test]
fn direct_layout_names_the_runtime_dir_sockets_and_passes_paths_verbatim() {
    let layout = layout(&IsolationSpec::None);
    assert!(layout.jail().is_none());
    assert_eq!(
        layout.api_socket(),
        Path::new("/run/vms/box/firecracker.sock")
    );
    assert_eq!(
        layout.vsock_host_uds(),
        Path::new("/run/vms/box/firecracker.vsock")
    );
    assert_eq!(
        layout.vsock_fc_uds().unwrap(),
        "/run/vms/box/firecracker.vsock"
    );
    assert_eq!(
        layout.vsock_host_view("/run/vms/other/firecracker.vsock"),
        Path::new("/run/vms/other/firecracker.vsock")
    );
    let plan = layout.spawn_plan();
    assert_eq!(plan.api_socket, Path::new("/run/vms/box/firecracker.sock"));
    assert_eq!(plan.vsock_uds, Path::new("/run/vms/box/firecracker.vsock"));
    let SpawnMode::Direct { log, metrics } = plan.mode else {
        panic!("direct spawn");
    };
    assert_eq!(log, Path::new("/run/vms/box/firecracker.log"));
    assert_eq!(metrics, Path::new("/run/vms/box/firecracker.metrics"));

    let mut stage = Vec::new();
    assert_eq!(
        layout
            .place(
                Path::new("/images/vmlinux"),
                "vmlinux",
                StageKind::LinkOrCopy,
                &mut stage
            )
            .unwrap(),
        "/images/vmlinux"
    );
    assert!(stage.is_empty(), "nothing is staged without a jail");
}

#[test]
fn jailer_layout_relativizes_inside_paths_and_stages_outside_ones() {
    let base = PathBuf::from("/srv/jailer");
    let layout = layout(&jailed(&base));
    let root = base.join("firecracker/box/root");
    assert_eq!(layout.jail().unwrap().root, root);
    assert_eq!(layout.api_socket(), root.join("run/firecracker.socket"));
    assert_eq!(layout.vsock_host_uds(), root.join("run/firecracker.vsock"));
    assert_eq!(layout.vsock_fc_uds().unwrap(), "/run/firecracker.vsock");
    assert_eq!(
        layout.vsock_host_view("/run/firecracker.vsock"),
        root.join("run/firecracker.vsock")
    );
    let plan = layout.spawn_plan();
    assert_eq!(plan.api_socket, root.join("run/firecracker.socket"));
    assert_eq!(plan.vsock_uds, root.join("run/firecracker.vsock"));
    let SpawnMode::Jailer {
        isolation,
        jail_root,
    } = plan.mode
    else {
        panic!("jailer spawn");
    };
    assert_eq!(isolation, jailed(&base));
    assert_eq!(jail_root, root);

    let mut stage = Vec::new();
    // Already inside the jail: `/` + relative, nothing staged.
    assert_eq!(
        layout
            .place(
                &root.join("rootfs.ext4"),
                "rootfs.ext4",
                StageKind::Copy,
                &mut stage
            )
            .unwrap(),
        "/rootfs.ext4"
    );
    assert!(stage.is_empty());
    // Outside: staged to `/{name}` by the given kind.
    assert_eq!(
        layout
            .place(
                Path::new("/images/vmlinux"),
                "vmlinux",
                StageKind::LinkOrCopy,
                &mut stage
            )
            .unwrap(),
        "/vmlinux"
    );
    assert_eq!(
        stage,
        vec![StagePlan {
            src: "/images/vmlinux".into(),
            dst: root.join("vmlinux"),
            kind: StageKind::LinkOrCopy,
        }]
    );
}

fn spec(id: &str, isolation: IsolationSpec, rootfs: PathBuf) -> VmSpec {
    VmSpec {
        id: VmId::new(id).unwrap(),
        cpus: 2,
        memory_mib: 512,
        boot: BootSpec::Kernel {
            image: "/images/vmlinux".into(),
            cmdline: "console=ttyS0 ip=1.2.3.4::1.2.3.1:255.255.255.0".into(),
            initrd: None,
        },
        disks: vec![DiskSpec {
            id: "rootfs".into(),
            path: rootfs,
            read_only: false,
            root: true,
            cache: CacheMode::Unsafe,
        }],
        nics: vec![NicSpec {
            id: "eth0".into(),
            mac: MacAddr::new([0x02, 0, 0, 0, 0, 1]),
            attachment: NicAttachment::Tap {
                name: "tap7".into(),
            },
        }],
        vsock: Some(VsockSpec { guest_cid: 3 }),
        shares: vec![],
        console: ConsoleSpec::Off,
        balloon: false,
        entropy: false,
        dirty_tracking: true,
        isolation,
    }
}

fn invalid(result: Result<impl std::fmt::Debug>) -> String {
    match result {
        Err(Error::InvalidSpec(msg)) => msg,
        other => panic!("expected InvalidSpec, got {other:?}"),
    }
}

#[test]
fn direct_mode_passes_paths_verbatim() {
    let plan = fc_config(
        &spec("box", IsolationSpec::None, "/images/rootfs.ext4".into()),
        &config(),
        Path::new("/run/vms/box"),
    )
    .unwrap();
    assert!(plan.stage.is_empty(), "nothing is staged without a jail");
    assert_eq!(plan.boot_source.kernel_image_path, "/images/vmlinux");
    assert_eq!(
        plan.boot_source.boot_args.as_deref(),
        Some("console=ttyS0 ip=1.2.3.4::1.2.3.1:255.255.255.0")
    );
    assert_eq!(
        plan.drives[0].path_on_host.as_deref(),
        Some("/images/rootfs.ext4")
    );
    let vsock = plan.vsock.unwrap();
    assert_eq!(vsock.guest_cid, 3);
    assert_eq!(vsock.uds_path, "/run/vms/box/firecracker.vsock");
    assert_eq!(
        plan.vsock_host_uds.as_deref(),
        Some(Path::new("/run/vms/box/firecracker.vsock"))
    );
}

#[test]
fn machine_config_and_devices_follow_the_spec() {
    let mut s = spec("box", IsolationSpec::None, "/images/rootfs.ext4".into());
    s.entropy = true;
    s.disks.push(DiskSpec {
        id: "data".into(),
        path: "/images/data.ext4".into(),
        read_only: true,
        root: false,
        cache: CacheMode::Writeback,
    });
    let plan = fc_config(&s, &config(), Path::new("/run/vms/box")).unwrap();
    assert_eq!(plan.machine.vcpu_count.get(), 2);
    assert_eq!(plan.machine.mem_size_mib, 512);
    assert!(!plan.machine.smt);
    assert!(plan.machine.track_dirty_pages);
    let root = &plan.drives[0];
    assert!(root.is_root_device);
    assert_eq!(root.is_read_only, Some(false));
    assert!(matches!(root.cache_type, DriveCacheType::Unsafe));
    assert!(matches!(root.io_engine, DriveIoEngine::Sync));
    let data = &plan.drives[1];
    assert_eq!(data.drive_id, "data");
    assert!(!data.is_root_device);
    assert_eq!(data.is_read_only, Some(true));
    assert!(matches!(data.cache_type, DriveCacheType::Writeback));
    let nic = &plan.nics[0];
    assert_eq!(nic.iface_id, "eth0");
    assert_eq!(nic.guest_mac.as_deref(), Some("02:00:00:00:00:01"));
    assert_eq!(nic.host_dev_name, "tap7");
    assert!(plan.entropy.is_some());

    let mut s = spec("box", IsolationSpec::None, "/images/rootfs.ext4".into());
    s.dirty_tracking = false;
    s.vsock = None;
    let plan = fc_config(&s, &config(), Path::new("/run/vms/box")).unwrap();
    assert!(!plan.machine.track_dirty_pages);
    assert!(plan.vsock.is_none() && plan.vsock_host_uds.is_none());
    assert!(plan.entropy.is_none());
}

#[test]
fn jailer_mode_stages_outside_files_and_relativizes_inside_ones() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("jail");
    let root = base.join("firecracker/box/root");
    // A rootfs the caller already put in the jail (a mknod'ed dm device).
    std::fs::create_dir_all(&root).unwrap();
    let inside = root.join("rootfs.ext4");
    std::fs::write(&inside, b"disk").unwrap();
    let outside = dir.path().join("rootfs.ext4");
    std::fs::write(&outside, b"disk").unwrap();

    let plan = fc_config(
        &spec("box", jailed(&base), inside),
        &config(),
        Path::new("/run/vms/box"),
    )
    .unwrap();
    assert_eq!(plan.boot_source.kernel_image_path, "/vmlinux");
    assert_eq!(plan.drives[0].path_on_host.as_deref(), Some("/rootfs.ext4"));
    assert_eq!(
        plan.stage,
        vec![StagePlan {
            src: "/images/vmlinux".into(),
            dst: root.join("vmlinux"),
            kind: StageKind::LinkOrCopy,
        }],
        "the kernel is staged; the in-jail rootfs is not"
    );
    assert_eq!(plan.vsock.unwrap().uds_path, "/run/firecracker.vsock");
    assert_eq!(
        plan.vsock_host_uds.as_deref(),
        Some(root.join("run/firecracker.vsock").as_path())
    );

    // A writable disk outside the jail is copied to /{id}.ext4; a read-only
    // one is link-or-copied.
    let mut s = spec("box", jailed(&base), outside.clone());
    s.disks.push(DiskSpec {
        id: "data".into(),
        path: outside.clone(),
        read_only: true,
        root: false,
        cache: CacheMode::Unsafe,
    });
    let plan = fc_config(&s, &config(), Path::new("/run/vms/box")).unwrap();
    assert_eq!(plan.drives[0].path_on_host.as_deref(), Some("/rootfs.ext4"));
    assert_eq!(plan.drives[1].path_on_host.as_deref(), Some("/data.ext4"));
    assert_eq!(
        plan.stage[1..],
        [
            StagePlan {
                src: outside.clone(),
                dst: root.join("rootfs.ext4"),
                kind: StageKind::Copy,
            },
            StagePlan {
                src: outside,
                dst: root.join("data.ext4"),
                kind: StageKind::LinkOrCopy,
            }
        ]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn jailer_mode_mirrors_a_block_device_as_a_node() {
    use std::os::unix::fs::FileTypeExt as _;
    let Some(device) = std::fs::read_dir("/dev")
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| {
            entry
                .metadata()
                .is_ok_and(|m| m.file_type().is_block_device())
        })
        .map(|entry| entry.path())
    else {
        panic!("no block device under /dev: this host cannot exercise the mknod staging rule");
    };
    let base = PathBuf::from("/srv/jailer");
    let plan = fc_config(
        &spec("box", jailed(&base), device.clone()),
        &config(),
        Path::new("/run/vms/box"),
    )
    .unwrap();
    assert_eq!(plan.drives[0].path_on_host.as_deref(), Some("/rootfs.ext4"));
    assert!(plan.stage.contains(&StagePlan {
        src: device,
        dst: base.join("firecracker/box/root/rootfs.ext4"),
        kind: StageKind::BlockNode,
    }));
}

#[test]
fn a_vm_id_cannot_name_another_jail() {
    // The port allows dots in an id, and the jail is `{base}/{exec}/{id}/root`.
    for id in [".", ".."] {
        let id = VmId::new(id).expect("the port accepts it");
        let error = VmLayout::new(
            &id,
            &jailed(Path::new("/srv/jailer")),
            &config(),
            Path::new("/run/vms/box"),
        );
        assert!(invalid(error).contains("vm id"), "`{id}` is refused");
    }
    // A dot inside a name is not a component of its own.
    assert!(
        VmLayout::new(
            &VmId::new("box.1").unwrap(),
            &jailed(Path::new("/srv/jailer")),
            &config(),
            Path::new("/run/vms/box"),
        )
        .is_ok()
    );
}

#[test]
fn a_disk_id_cannot_reach_out_of_the_jail() {
    let base = PathBuf::from("/srv/jailer");
    for isolation in [IsolationSpec::None, jailed(&base)] {
        let mut s = spec("box", isolation, "/images/rootfs.ext4".into());
        // Staging joins `{id}.ext4` onto the jail root and replaces whatever
        // is there — with a copy, or a device node.
        s.disks[0].id = "../../etc/shadow".into();
        assert!(
            invalid(fc_config(&s, &config(), Path::new("/run/vms/box"))).contains("disk id"),
            "a traversing disk id is refused"
        );
        s.disks[0].id = "nested/name".into();
        assert!(invalid(fc_config(&s, &config(), Path::new("/run/vms/box"))).contains("disk id"));
    }

    // The same guard covers every staged name, whoever supplies it.
    let layout = layout(&jailed(&base));
    let mut stage = Vec::new();
    assert!(
        invalid(layout.place(
            Path::new("/images/vmlinux"),
            "../vmlinux",
            StageKind::LinkOrCopy,
            &mut stage,
        ))
        .contains("inside the jail")
    );
    assert!(stage.is_empty());
}

#[test]
fn what_firecracker_cannot_do_is_refused_before_anything_runs() {
    let base = |mutate: fn(&mut VmSpec)| {
        let mut s = spec("box", IsolationSpec::None, "/images/rootfs.ext4".into());
        mutate(&mut s);
        invalid(fc_config(&s, &config(), Path::new("/run/vms/box")))
    };
    assert!(base(|s| s.console = ConsoleSpec::File("/tmp/c.log".into())).contains("console"));
    assert!(base(|s| s.console = ConsoleSpec::Socket("/tmp/c.sock".into())).contains("console"));
    assert!(
        base(|s| s.shares.push(ShareSpec {
            tag: "src".into(),
            host_path: "/src".into(),
            read_only: false,
        }))
        .contains("shares")
    );
    assert!(base(|s| s.balloon = true).contains("balloon"));
    assert!(
        base(|s| s.boot = BootSpec::Firmware {
            image: "/fw/OVMF.fd".into()
        })
        .contains("kernel"),
    );
    assert!(base(|s| s.nics[0].attachment = NicAttachment::HostNat).contains("TAP"));
    // Spec validation runs first.
    assert!(base(|s| s.cpus = 0).contains("cpus"));
}

fn image(dir: &Path) -> CheckpointImage {
    CheckpointImage {
        dir: dir.to_path_buf(),
        format: CheckpointFormat::new(CHECKPOINT_FORMAT),
        kind: CheckpointKind::Full,
    }
}

fn restore_spec(id: &str, isolation: IsolationSpec, rootfs: PathBuf) -> RestoreSpec {
    let s = spec(id, isolation, rootfs);
    RestoreSpec {
        id: s.id,
        nics: s.nics,
        disks: s.disks,
        isolation: s.isolation,
    }
}

#[test]
fn restore_loads_the_image_and_retargets_nics_onto_the_new_taps() {
    let plan = fc_restore(
        &image(Path::new("/snaps/abc")),
        &restore_spec(
            "box2",
            IsolationSpec::None,
            "/run/vms/box2/rootfs.link".into(),
        ),
        &config(),
        Path::new("/run/vms/box2"),
    )
    .unwrap();
    assert!(plan.stage.is_empty());
    assert_eq!(plan.load.snapshot_path, "/snaps/abc/vmstate");
    assert_eq!(plan.load.mem_file_path.as_deref(), Some("/snaps/abc/mem"));
    // The load leaves the guest frozen until the disks below replace the
    // ones the checkpoint recorded.
    assert_eq!(plan.load.resume_vm, Some(false));
    assert_eq!(plan.load.network_overrides.len(), 1);
    assert_eq!(plan.load.network_overrides[0].iface_id, "eth0");
    assert_eq!(plan.load.network_overrides[0].host_dev_name, "tap7");
    // Without a jail nothing is staged, so the disks reach Firecracker only
    // as the paths to patch onto the loaded drives.
    assert_eq!(plan.drives.len(), 1);
    assert_eq!(plan.drives[0].drive_id, "rootfs");
    assert_eq!(
        plan.drives[0].path_on_host.as_deref(),
        Some("/run/vms/box2/rootfs.link")
    );
}

#[test]
fn restore_stages_the_image_and_disks_into_a_jail_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("jail");
    let root = base.join("firecracker/box2/root");
    let rootfs = dir.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"disk").unwrap();
    let plan = fc_restore(
        &image(Path::new("/snaps/abc")),
        &restore_spec("box2", jailed(&base), rootfs.clone()),
        &config(),
        Path::new("/run/vms/box2"),
    )
    .unwrap();
    assert_eq!(plan.load.snapshot_path, "/snapshots/abc/vmstate");
    assert_eq!(
        plan.load.mem_file_path.as_deref(),
        Some("/snapshots/abc/mem")
    );
    assert_eq!(
        plan.stage,
        vec![
            StagePlan {
                src: "/snaps/abc/vmstate".into(),
                dst: root.join("snapshots/abc/vmstate"),
                kind: StageKind::LinkOrCopy,
            },
            StagePlan {
                src: "/snaps/abc/mem".into(),
                dst: root.join("snapshots/abc/mem"),
                kind: StageKind::LinkOrCopy,
            },
            StagePlan {
                src: rootfs,
                dst: root.join("rootfs.ext4"),
                kind: StageKind::Copy,
            },
        ]
    );
    assert_eq!(plan.drives[0].path_on_host.as_deref(), Some("/rootfs.ext4"));

    // An image the caller already staged into the jail is loaded in place.
    let staged = root.join("snapshots/abc");
    let plan = fc_restore(
        &image(&staged),
        &restore_spec("box2", jailed(&base), root.join("rootfs.ext4")),
        &config(),
        Path::new("/run/vms/box2"),
    )
    .unwrap();
    assert!(plan.stage.is_empty());
    assert_eq!(plan.load.snapshot_path, "/snapshots/abc/vmstate");
    assert_eq!(plan.drives[0].path_on_host.as_deref(), Some("/rootfs.ext4"));

    // A disk the caller placed in the jail somewhere else than the canonical
    // name is named where it is: the drive is patched, not staged.
    let elsewhere = root.join("pool/slot3.ext4");
    let plan = fc_restore(
        &image(&staged),
        &restore_spec("box2", jailed(&base), elsewhere),
        &config(),
        Path::new("/run/vms/box2"),
    )
    .unwrap();
    assert!(plan.stage.is_empty());
    assert_eq!(
        plan.drives[0].path_on_host.as_deref(),
        Some("/pool/slot3.ext4")
    );
}

#[test]
fn restore_refuses_foreign_and_diff_images() {
    let mut foreign = image(Path::new("/snaps/abc"));
    foreign.format = CheckpointFormat::new("fake/v1");
    let spec = restore_spec("box2", IsolationSpec::None, "/x".into());
    match fc_restore(&foreign, &spec, &config(), Path::new("/run/vms/box2")) {
        Err(Error::ForeignCheckpoint(format)) => assert_eq!(format.as_str(), "fake/v1"),
        other => panic!("expected ForeignCheckpoint, got {other:?}"),
    }
    let mut diff = image(Path::new("/snaps/abc"));
    diff.kind = CheckpointKind::Diff;
    assert!(
        invalid(fc_restore(
            &diff,
            &spec,
            &config(),
            Path::new("/run/vms/box2")
        ))
        .contains("diff")
    );
    let mut spec = spec;
    spec.nics[0].attachment = NicAttachment::HostNat;
    assert!(
        invalid(fc_restore(
            &image(Path::new("/snaps/abc")),
            &spec,
            &config(),
            Path::new("/run/vms/box2")
        ))
        .contains("TAP")
    );
}
