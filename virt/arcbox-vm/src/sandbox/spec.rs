//! The VM spec a sandbox boots or restores onto, as the driver port sees
//! it.
//!
//! One place renders every device the manager asks for — the root disk, the
//! single NIC, vsock, the kernel cmdline — so a boot and a restore of the
//! same sandbox cannot drift apart in what they hand the driver.

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{
    BootSpec, CacheMode, ConsoleSpec, DiskSpec, IsolationSpec, NicAttachment, NicSpec, RestoreSpec,
    VmId, VmSpec, VsockSpec,
};

use crate::boot_proto::KernelIpParam;
use crate::error::{Result, VmmError};
use crate::network::NetworkAllocation;
use crate::sandbox::SandboxSpec;

/// The boot recipe as the driver port sees it.
///
/// `kernel` and `rootfs` are the paths the VMM must open — in jailer mode
/// already staged inside the jail, so the driver finds them there and
/// stages nothing itself. Every sandbox boots the identical fixed identity
/// (CORE-81) unless the caller pinned its own `ip=`: the pool IP stays a
/// host-side property of the TAP, so snapshots taken from this guest are
/// network-agnostic and restore with zero guest-side work. The guest-side
/// vm-agent parses the `ip=` parameter back via `KernelIpParam::from_str`
/// to derive the DNS nameserver.
pub(super) fn build_vm_spec(
    id: &str,
    spec: &SandboxSpec,
    net_alloc: Option<&NetworkAllocation>,
    kernel: PathBuf,
    rootfs: PathBuf,
    isolation: IsolationSpec,
) -> Result<VmSpec> {
    let cmdline = if net_alloc.is_some() && !spec.boot_args.contains("ip=") {
        let ip_param = KernelIpParam {
            client: crate::network::invariant::GUEST_IP,
            gateway: crate::network::invariant::GUEST_GATEWAY,
            netmask: crate::network::invariant::GUEST_NETMASK,
        };
        format!("{} {ip_param}", spec.boot_args)
    } else {
        spec.boot_args.clone()
    };
    Ok(VmSpec {
        id: VmId::new(id)?,
        cpus: spec.vcpus.max(1),
        memory_mib: u32::try_from(spec.memory_mib).map_err(|_| {
            VmmError::Config(format!(
                "memory_mib {} exceeds what a VM spec can carry",
                spec.memory_mib
            ))
        })?,
        boot: BootSpec::Kernel {
            image: kernel,
            cmdline,
            initrd: None,
        },
        disks: vec![rootfs_disk(rootfs)],
        nics: net_alloc.map(nic_spec).transpose()?.into_iter().collect(),
        // CID 3 is the conventional guest CID; each VMM is isolated so the
        // same CID is safe across concurrent sandboxes.
        vsock: Some(VsockSpec { guest_cid: 3 }),
        shares: Vec::new(),
        console: ConsoleSpec::Off,
        balloon: false,
        entropy: false,
        // Dirty-page tracking so checkpointing is always available.
        dirty_tracking: true,
        isolation,
    })
}

/// The root disk: writable, `Unsafe` host caching, id `rootfs` — the name a
/// checkpoint of this driver records for it, which a restore must reuse.
pub(super) fn rootfs_disk(path: PathBuf) -> DiskSpec {
    DiskSpec {
        id: "rootfs".into(),
        path,
        read_only: false,
        root: true,
        cache: CacheMode::Unsafe,
    }
}

/// The guest's one NIC, `eth0`, on the allocation's TAP with its MAC.
pub(super) fn nic_spec(net: &NetworkAllocation) -> Result<NicSpec> {
    Ok(NicSpec {
        id: "eth0".into(),
        mac: net.mac_address.parse().map_err(VmmError::from)?,
        attachment: NicAttachment::Tap {
            name: net.tap_name.clone(),
        },
    })
}

/// What a restore may change about the checkpointed VM: its identity
/// (`owner`, the id the jail is keyed by), the fresh TAP, and the disk it
/// runs on — the rootfs staged into the owner's jail.
pub(super) fn restore_spec(
    owner: &str,
    chroot: &Path,
    net_alloc: Option<&NetworkAllocation>,
    isolation: IsolationSpec,
) -> Result<RestoreSpec> {
    Ok(RestoreSpec {
        id: VmId::new(owner)?,
        nics: net_alloc.map(nic_spec).transpose()?.into_iter().collect(),
        disks: vec![rootfs_disk(chroot.join("rootfs.ext4"))],
        isolation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation() -> NetworkAllocation {
        NetworkAllocation {
            tap_name: "vmtap0-7".into(),
            ip_address: "172.20.0.7".parse().unwrap(),
            prefix_len: 16,
            gateway: "172.20.0.1".parse().unwrap(),
            mac_address: "02:fc:00:00:00:07".into(),
            dns_servers: vec![],
            cleanup_token: String::new(),
        }
    }

    /// The spec the driver boots: the invariant `ip=` identity baked into
    /// the cmdline (unless the caller pinned one), the geometry with at
    /// least one vCPU, one writable root disk, `eth0` on the TAP, vsock
    /// CID 3, dirty tracking on — and nothing the sandbox never had.
    #[test]
    fn boot_spec_bakes_the_invariant_identity_and_the_fixed_devices() {
        let spec = SandboxSpec {
            boot_args: "console=ttyS0".into(),
            vcpus: 0,
            memory_mib: 512,
            ..SandboxSpec::default()
        };
        let vm = build_vm_spec(
            "box",
            &spec,
            Some(&allocation()),
            PathBuf::from("/jail/vmlinux"),
            PathBuf::from("/jail/rootfs.ext4"),
            IsolationSpec::None,
        )
        .unwrap();
        assert_eq!(vm.id.as_str(), "box");
        assert_eq!((vm.cpus, vm.memory_mib), (1, 512));
        let BootSpec::Kernel { image, cmdline, .. } = &vm.boot else {
            panic!("a direct kernel boot");
        };
        assert_eq!(image, Path::new("/jail/vmlinux"));
        assert!(cmdline.starts_with("console=ttyS0 ip="), "{cmdline}");
        assert!(
            cmdline.contains(&crate::network::invariant::GUEST_IP.to_string()),
            "{cmdline}"
        );
        assert_eq!(vm.disks.len(), 1);
        assert!(vm.disks[0].root && !vm.disks[0].read_only);
        assert_eq!(vm.disks[0].path, Path::new("/jail/rootfs.ext4"));
        assert_eq!(vm.nics.len(), 1);
        assert_eq!(vm.nics[0].mac.to_string(), "02:fc:00:00:00:07");
        assert_eq!(
            vm.nics[0].attachment,
            NicAttachment::Tap {
                name: "vmtap0-7".into()
            }
        );
        assert_eq!(vm.vsock.map(|v| v.guest_cid), Some(3));
        assert!(vm.dirty_tracking && !vm.balloon && !vm.entropy);
        assert_eq!(vm.console, ConsoleSpec::Off);
        vm.validate()
            .expect("the driver accepts what the manager builds");

        // A caller-pinned `ip=` is kept verbatim; no network means no NIC
        // and no `ip=` at all.
        let pinned = SandboxSpec {
            boot_args: "ip=10.0.0.2::10.0.0.1:255.255.255.0".into(),
            ..spec.clone()
        };
        let vm = build_vm_spec(
            "box",
            &pinned,
            Some(&allocation()),
            "/k".into(),
            "/r".into(),
            IsolationSpec::None,
        )
        .unwrap();
        let BootSpec::Kernel { cmdline, .. } = &vm.boot else {
            unreachable!()
        };
        assert_eq!(cmdline, &pinned.boot_args);
        let vm = build_vm_spec(
            "box",
            &spec,
            None,
            "/k".into(),
            "/r".into(),
            IsolationSpec::None,
        )
        .unwrap();
        assert!(vm.nics.is_empty());
        let BootSpec::Kernel { cmdline, .. } = &vm.boot else {
            unreachable!()
        };
        assert_eq!(cmdline, "console=ttyS0");
    }
}
