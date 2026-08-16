//! From the port's specs to what Firecracker is told.
//!
//! Two pure decisions live here and nowhere else: which API payloads a
//! [`VmSpec`] becomes, and which path Firecracker sees for every host
//! file. Without a jail, paths pass through verbatim. Under the
//! jailer, Firecracker is chrooted into
//! `{chroot_base}/{firecracker binary name}/{id}/root` and every path it
//! is told is chroot-relative: a host path already under the jail is passed
//! as `/` + its relative part; anything else is staged in first — the
//! kernel to `/vmlinux`, a disk `id` to `/{id}.ext4`, a checkpoint to
//! `/snapshots/{image dir name}/{vmstate,mem}` — and named by where it
//! landed. [`VmLayout`] is that map; [`fc_config`] uses it to produce a
//! boot plan (the restore renderer follows), and [`jail::apply`] executes
//! the staging half.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use arcbox_vm_driver::{
    BootSpec, CacheMode, ConsoleSpec, DiskSpec, Error, IsolationSpec, NicAttachment, NicSpec,
    Result, VmId, VmSpec,
};
use fc_sdk::types::{
    BootSource, Drive, DriveCacheType, DriveIoEngine, EntropyDevice, MachineConfiguration,
    NetworkInterface, Vsock,
};

use crate::NAME;
use crate::config::FcDriverConfig;
use crate::error::FcError;
use crate::jail;

mod plan;
#[cfg(test)]
mod tests;

pub use plan::{FcPlan, FcRestorePlan, SpawnMode, SpawnPlan, StageKind, StagePlan};

pub use crate::jail::Jail;

/// The vsock socket name, in the runtime dir (direct) or `run/` (jail).
const VSOCK_NAME: &str = "firecracker.vsock";

/// Where a VM's files live from the host's and Firecracker's points of
/// view: the runtime dir, the jail if any, and the sockets in them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLayout {
    id: VmId,
    runtime_dir: PathBuf,
    isolation: IsolationSpec,
    jail: Option<Jail>,
}

impl VmLayout {
    /// The layout of VM `id` confined by `isolation`, with `runtime_dir` as
    /// its private scratch space.
    pub fn new(
        id: &VmId,
        isolation: &IsolationSpec,
        config: &FcDriverConfig,
        runtime_dir: &Path,
    ) -> Result<Self> {
        let jail = match isolation {
            IsolationSpec::None => None,
            IsolationSpec::Jailer {
                uid,
                gid,
                chroot_base,
                ..
            } => Some(Jail {
                root: jail::chroot_root(&config.firecracker_binary, chroot_base, id.as_str()),
                uid: *uid,
                gid: *gid,
            }),
            other => {
                return Err(Error::InvalidSpec(format!(
                    "{NAME}: unsupported isolation {other:?}"
                )));
            }
        };
        Ok(Self {
            id: id.clone(),
            runtime_dir: runtime_dir.to_path_buf(),
            isolation: isolation.clone(),
            jail,
        })
    }

    /// The VM.
    pub fn id(&self) -> &VmId {
        &self.id
    }

    /// The per-VM scratch directory the driver was given.
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// The confinement the layout was built for.
    pub fn isolation(&self) -> &IsolationSpec {
        &self.isolation
    }

    /// The jail, when the VM runs under the jailer.
    pub fn jail(&self) -> Option<&Jail> {
        self.jail.as_ref()
    }

    /// The Firecracker API socket, as the host connects to it.
    pub fn api_socket(&self) -> PathBuf {
        match &self.jail {
            Some(jail) => jail::api_socket_path(&jail.root),
            None => self.runtime_dir.join("firecracker.sock"),
        }
    }

    /// The hybrid-vsock Unix socket, as the host dials it.
    pub fn vsock_host_uds(&self) -> PathBuf {
        match &self.jail {
            Some(jail) => jail::vsock_uds_path(&jail.root),
            None => self.runtime_dir.join(VSOCK_NAME),
        }
    }

    /// The hybrid-vsock Unix socket, as Firecracker is told to bind it.
    pub fn vsock_fc_uds(&self) -> Result<String> {
        match &self.jail {
            Some(_) => Ok(jail::VSOCK_UDS_IN_JAIL.to_owned()),
            None => utf8(&self.runtime_dir.join(VSOCK_NAME)),
        }
    }

    /// The process to spawn for this VM.
    pub fn spawn_plan(&self) -> SpawnPlan {
        let mode = match &self.jail {
            Some(jail) => SpawnMode::Jailer {
                isolation: self.isolation.clone(),
                jail_root: jail.root.clone(),
            },
            None => SpawnMode::Direct {
                log: self.runtime_dir.join("firecracker.log"),
                metrics: self.runtime_dir.join("firecracker.metrics"),
            },
        };
        SpawnPlan {
            id: self.id.clone(),
            api_socket: self.api_socket(),
            mode,
        }
    }

    /// The path Firecracker is told for `host`, and the staging that makes
    /// it true: verbatim without a jail; `/` + relative when already inside
    /// the jail; otherwise staged to `/{in_jail}` by `kind`.
    pub fn place(
        &self,
        host: &Path,
        in_jail: &str,
        kind: StageKind,
        stage: &mut Vec<StagePlan>,
    ) -> Result<String> {
        let Some(jail) = &self.jail else {
            return utf8(host);
        };
        if let Some(view) = jail.view(host) {
            return Ok(view);
        }
        stage.push(StagePlan {
            src: host.to_path_buf(),
            dst: jail.root.join(in_jail),
            kind,
        });
        Ok(format!("/{in_jail}"))
    }
}

/// Renders a boot: the API payloads for `spec` and the files a jail needs
/// staged first.
///
/// Refuses, with [`Error::InvalidSpec`], what Firecracker cannot do or this
/// driver does not expose: firmware and macOS boots, non-TAP NICs, console
/// files and sockets, virtiofs shares, the balloon.
pub fn fc_config(spec: &VmSpec, config: &FcDriverConfig, runtime_dir: &Path) -> Result<FcPlan> {
    spec.validate()?;
    let layout = VmLayout::new(&spec.id, &spec.isolation, config, runtime_dir)?;
    if spec.console != ConsoleSpec::Off {
        return Err(unsupported(
            "console output is not exposed; use ConsoleSpec::Off",
        ));
    }
    if !spec.shares.is_empty() {
        return Err(unsupported("virtiofs shares are not available"));
    }
    if spec.balloon {
        return Err(unsupported("the balloon is not exposed"));
    }

    let mut stage = Vec::new();
    let boot_source = match &spec.boot {
        BootSpec::Kernel {
            image,
            cmdline,
            initrd,
        } => BootSource {
            kernel_image_path: layout.place(image, "vmlinux", StageKind::LinkOrCopy, &mut stage)?,
            boot_args: Some(cmdline.clone()),
            initrd_path: initrd
                .as_deref()
                .map(|initrd| layout.place(initrd, "initrd", StageKind::LinkOrCopy, &mut stage))
                .transpose()?,
        },
        other => {
            return Err(unsupported(&format!(
                "only direct kernel boots are supported, not {other:?}"
            )));
        }
    };
    let drives = spec
        .disks
        .iter()
        .map(|disk| drive(&layout, disk, &mut stage))
        .collect::<Result<Vec<_>>>()?;
    let nics = spec
        .nics
        .iter()
        .map(network_interface)
        .collect::<Result<Vec<_>>>()?;
    let vsock = spec
        .vsock
        .map(|vsock| {
            Ok::<_, Error>(Vsock {
                guest_cid: i64::from(vsock.guest_cid),
                uds_path: layout.vsock_fc_uds()?,
                vsock_id: None,
            })
        })
        .transpose()?;
    Ok(FcPlan {
        stage,
        boot_source,
        machine: MachineConfiguration {
            vcpu_count: NonZeroU64::new(u64::from(spec.cpus))
                .ok_or_else(|| Error::InvalidSpec("cpus must be at least 1".into()))?,
            mem_size_mib: i64::from(spec.memory_mib),
            smt: false,
            track_dirty_pages: spec.dirty_tracking,
            cpu_template: None,
            huge_pages: None,
        },
        drives,
        nics,
        vsock_host_uds: vsock.is_some().then(|| layout.vsock_host_uds()),
        vsock,
        entropy: spec.entropy.then_some(EntropyDevice { rate_limiter: None }),
    })
}

fn drive(layout: &VmLayout, disk: &DiskSpec, stage: &mut Vec<StagePlan>) -> Result<Drive> {
    let kind = match &layout.jail {
        // Verbatim, or already inside the jail: nothing is staged.
        None => StageKind::Copy,
        Some(jail) if jail.view(&disk.path).is_some() => StageKind::Copy,
        Some(_) if is_block_device(&disk.path)? => StageKind::BlockNode,
        Some(_) if disk.read_only => StageKind::LinkOrCopy,
        Some(_) => StageKind::Copy,
    };
    let path_on_host = layout.place(&disk.path, &format!("{}.ext4", disk.id), kind, stage)?;
    Ok(Drive {
        drive_id: disk.id.clone(),
        path_on_host: Some(path_on_host),
        is_root_device: disk.root,
        is_read_only: Some(disk.read_only),
        partuuid: None,
        cache_type: match disk.cache {
            CacheMode::Unsafe => DriveCacheType::Unsafe,
            CacheMode::Writeback => DriveCacheType::Writeback,
        },
        rate_limiter: None,
        io_engine: DriveIoEngine::Sync,
        socket: None,
    })
}

fn network_interface(nic: &NicSpec) -> Result<NetworkInterface> {
    Ok(NetworkInterface {
        iface_id: nic.id.clone(),
        guest_mac: Some(nic.mac.to_string()),
        host_dev_name: tap_name(nic)?,
        rx_rate_limiter: None,
        tx_rate_limiter: None,
    })
}

fn tap_name(nic: &NicSpec) -> Result<String> {
    match &nic.attachment {
        NicAttachment::Tap { name } => Ok(name.clone()),
        other => Err(unsupported(&format!(
            "nic `{}`: only TAP attachments are supported, not {other:?}",
            nic.id
        ))),
    }
}

fn is_block_device(path: &Path) -> Result<bool> {
    use std::os::unix::fs::FileTypeExt as _;
    let metadata = std::fs::metadata(path).map_err(|source| FcError::Stat {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(metadata.file_type().is_block_device())
}

fn utf8(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidSpec(format!("{NAME}: path {} is not UTF-8", path.display())))
}

fn unsupported(what: &str) -> Error {
    Error::InvalidSpec(format!("{NAME}: {what}"))
}
