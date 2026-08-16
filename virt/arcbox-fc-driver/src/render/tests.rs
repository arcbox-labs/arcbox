//! Pins every path and payload rule of the renderer.

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{IsolationSpec, VmId};

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
    let plan = layout.spawn_plan();
    assert_eq!(plan.api_socket, Path::new("/run/vms/box/firecracker.sock"));
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
    let plan = layout.spawn_plan();
    assert_eq!(plan.api_socket, root.join("run/firecracker.socket"));
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
