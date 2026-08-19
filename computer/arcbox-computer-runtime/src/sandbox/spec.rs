//! The VM spec a sandbox boots or restores onto, as the driver port sees
//! it.
//!
//! One place renders every device the manager asks for — the root disk, the
//! single NIC, vsock, the kernel cmdline — so a boot and a restore of the
//! same sandbox cannot drift apart in what they hand the driver.

use std::path::PathBuf;

use arcbox_vm_driver::{
    BootSpec, CacheMode, ConsoleSpec, DiskSpec, IsolationSpec, NicSpec, RestoreSpec, VmId, VmSpec,
    VsockSpec,
};

use crate::boot_proto::KernelIpParam;
use crate::error::{ComputerError, Result};
use crate::sandbox::{NetworkAttachment, SandboxSpec, ipv4, netmask};

/// The boot recipe as the driver port sees it.
///
/// `kernel` and `rootfs` are the paths the VMM must open — in jailer mode
/// already staged inside the jail, so the driver finds them there and
/// stages nothing itself.
///
/// `net` is what the guest network handed back when it activated this
/// sandbox's lease — the one NIC a sandbox ever has plus the addressing a
/// guest on it sees — or none when the sandbox is networkless. The `ip=`
/// parameter is that identity, not a constant: under the TAP network's
/// invariant identity (CORE-81) every sandbox boots the same fixed
/// address, the pool address stays a host-side property of the interface,
/// and snapshots are network-agnostic — but that is one adapter's answer,
/// and a guest booted with another adapter's NIC must be told that
/// adapter's addressing. A caller who pinned its own `ip=` keeps it. The
/// guest-side vm-agent parses the parameter back via
/// `KernelIpParam::from_str` to derive the DNS nameserver.
pub fn build_vm_spec(
    id: &str,
    spec: &SandboxSpec,
    net: Option<&NetworkAttachment>,
    kernel: PathBuf,
    rootfs: PathBuf,
    isolation: IsolationSpec,
) -> Result<VmSpec> {
    let cmdline = match net {
        Some(net) if !spec.boot_args.contains("ip=") => {
            let ip_param = KernelIpParam {
                client: ipv4(net.identity.ip)?,
                gateway: ipv4(net.identity.gateway)?,
                netmask: netmask(net.identity.prefix_len),
            };
            format!("{} {ip_param}", spec.boot_args)
        }
        _ => spec.boot_args.clone(),
    };
    Ok(VmSpec {
        id: VmId::new(id)?,
        cpus: spec.vcpus.max(1),
        memory_mib: u32::try_from(spec.memory_mib).map_err(|_| {
            ComputerError::Config(format!(
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
        nics: net.map(|net| net.nic.clone()).into_iter().collect(),
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

/// The id the root disk carries, everywhere it is named.
///
/// One constant because two things must agree on it: the spec a boot or a
/// restore hands the driver, and the [`Staging::stage_disk`] call that put
/// the disk where that spec points. A driver stages a disk under a name it
/// makes from this id and records that name in its checkpoints, so a disk
/// staged under one id and specced under another is a checkpoint that will
/// not restore.
///
/// [`Staging::stage_disk`]: arcbox_vm_driver::Staging::stage_disk
pub const ROOTFS_DISK_ID: &str = "rootfs";

/// The root disk: writable, `Unsafe` host caching, id [`ROOTFS_DISK_ID`] —
/// the name a checkpoint of this driver records for it, which a restore
/// must reuse.
pub(super) fn rootfs_disk(path: PathBuf) -> DiskSpec {
    DiskSpec {
        id: ROOTFS_DISK_ID.into(),
        path,
        read_only: false,
        root: true,
        cache: CacheMode::Unsafe,
    }
}

/// What a restore may change about the checkpointed VM: its identity
/// (`owner`, the id its resources are keyed by), the fresh NIC the guest
/// network activated, and the disk it runs on — wherever staging said that
/// disk now is.
pub fn restore_spec(
    owner: &str,
    rootfs: PathBuf,
    nic: Option<NicSpec>,
    isolation: IsolationSpec,
) -> Result<RestoreSpec> {
    Ok(RestoreSpec {
        id: VmId::new(owner)?,
        nics: nic.into_iter().collect(),
        disks: vec![rootfs_disk(rootfs)],
        isolation,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use arcbox_vm_driver::NicAttachment;
    use arcbox_vm_driver::net::{NetworkIdentity, NetworkLease};

    use super::*;

    /// The fixed invariant addressing a guest on the System VM's TAP
    /// network is told to use — `arcbox-tap-net`'s `invariant::GUEST_*`,
    /// written out because these fixtures stand in for *a* guest network,
    /// not for that one: nothing in this module names an adapter, and the
    /// identity production reads comes from the port's `NetworkIdentity`.
    const GUEST_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(169, 254, 100, 2);
    const GUEST_GATEWAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(169, 254, 100, 1);
    const GUEST_PREFIX_LEN: u8 = 30;
    const GUEST_NETMASK: std::net::Ipv4Addr = std::net::Ipv4Addr::new(255, 255, 255, 252);

    /// What a guest network hands back from activating a lease: the NIC,
    /// and the fixed invariant addressing above.
    fn attachment() -> NetworkAttachment {
        NetworkAttachment {
            lease: NetworkLease {
                vm: VmId::new("box").unwrap(),
                ip: "172.20.0.7".parse().unwrap(),
                prefix_len: 16,
                gateway: "172.20.0.1".parse().unwrap(),
                mac: "02:fc:00:00:00:07".parse().unwrap(),
                cleanup_token: "gen-1".into(),
            },
            nic: NicSpec {
                id: "eth0".into(),
                mac: "02:fc:00:00:00:07".parse().unwrap(),
                attachment: NicAttachment::Tap {
                    name: "vmtap0-7".into(),
                },
            },
            identity: NetworkIdentity {
                ip: GUEST_IP.into(),
                prefix_len: GUEST_PREFIX_LEN,
                gateway: GUEST_GATEWAY.into(),
                dns: vec![GUEST_GATEWAY.into()],
                mac: "02:fc:00:00:00:07".parse().unwrap(),
            },
            invariant_identity: true,
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
            Some(&attachment()),
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
        // The whole `ip=` comes from the network's identity, netmask
        // included: the TAP network's /30 renders as the fixed netmask its
        // guests have always booted with.
        assert!(cmdline.contains(&GUEST_IP.to_string()), "{cmdline}");
        assert!(cmdline.contains(&GUEST_NETMASK.to_string()), "{cmdline}");
        assert_eq!(netmask(GUEST_PREFIX_LEN), GUEST_NETMASK);
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
            Some(&attachment()),
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
