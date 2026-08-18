//! From the port's specs to what Firecracker is told.
//!
//! Two pure decisions live here and nowhere else: which API payloads a
//! [`VmSpec`] / [`RestoreSpec`] becomes, and which path Firecracker sees for
//! every host file. Without a jail, paths pass through verbatim. Under the
//! jailer, Firecracker is chrooted into
//! `{chroot_base}/{firecracker binary name}/{id}/root` and every path it
//! is told is chroot-relative: a host path already under the jail is passed
//! as `/` + its relative part; anything else is staged in first — the
//! kernel to `/vmlinux`, a disk `id` to `/{id}.ext4`, a checkpoint to
//! `/snapshots/{image dir name}/{vmstate,mem}` — and named by where it
//! landed. [`VmLayout`] is that map; [`fc_config`] and [`fc_restore`] use it
//! to produce plans, and [`jail::apply`] executes the staging half.

use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use arcbox_vm_driver::{
    BootSpec, CacheMode, CheckpointImage, CheckpointKind, ConsoleSpec, DiskSpec, Error,
    IsolationSpec, NicAttachment, NicSpec, RestoreSpec, Result, VmId, VmSpec,
};
use fc_sdk::types::{
    BootSource, Drive, DriveCacheType, DriveIoEngine, EntropyDevice, MachineConfiguration,
    NetworkInterface, NetworkOverride, SnapshotLoadParams, Vsock,
};

use crate::config::FcDriverConfig;
use crate::error::FcError;
use crate::jail;
use crate::{CHECKPOINT_FORMAT, NAME};

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
        // The id is a directory name here — the jail is `{base}/{exec}/{id}/
        // root` — so `.` and `..` would name another VM's jail, or the base
        // itself. The port refuses them at the id; a layout is built from
        // whatever id it is handed, so the same rule is checked here too.
        if !is_plain_component(id.as_str()) {
            return Err(unsupported(&format!("vm id `{id}` must be a plain name")));
        }
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

    /// The host view of a path Firecracker reports (`GET /vm/config` after
    /// a restore or on adopt — a vsock socket it bound, a disk it opened):
    /// jail-relative under a jail, verbatim otherwise.
    pub fn host_view(&self, fc_path: &str) -> PathBuf {
        match &self.jail {
            Some(jail) => jail.root.join(fc_path.trim_start_matches('/')),
            None => PathBuf::from(fc_path),
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
            vsock_uds: self.vsock_host_uds(),
            mode,
        }
    }

    /// The path Firecracker is told for `host`, and the staging that makes
    /// it true: verbatim without a jail; `/` + relative when already inside
    /// the jail; otherwise staged to `/{in_jail}` by `kind`.
    ///
    /// `in_jail` must be a relative path of plain components — parts of it
    /// come from the spec (a disk `id`), and staging writes, replaces, and
    /// mknods at the destination, so a `..` in it would reach a host file
    /// outside the jail.
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
        if !is_inside_jail(in_jail) {
            return Err(unsupported(&format!(
                "`{in_jail}` does not name a path inside the jail"
            )));
        }
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

    /// The host path `in_jail` names inside the jail, or `None` when the VM
    /// has none.
    ///
    /// The read-only counterpart of [`place`](Self::place), for asking
    /// about a file already staged rather than bringing one in — and it
    /// holds `in_jail` to the same rule, because a caller that can name a
    /// staged file can otherwise name one outside the jail and move it.
    pub fn jail_path(&self, in_jail: &str) -> Result<Option<PathBuf>> {
        let Some(jail) = &self.jail else {
            return Ok(None);
        };
        if !is_inside_jail(in_jail) {
            return Err(unsupported(&format!(
                "`{in_jail}` does not name a path inside the jail"
            )));
        }
        Ok(Some(jail.root.join(in_jail)))
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
            kernel_image_path: layout.place(
                image,
                KERNEL_FILE,
                StageKind::LinkOrCopy,
                &mut stage,
            )?,
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

/// Renders a restore of `image` under `spec`.
///
/// The plan carries the files a jail needs staged, the `PUT /snapshot/load`
/// payload with the image's NICs retargeted onto `spec.nics`, and the disks
/// as Firecracker must see them once the image is loaded.
///
/// Refuses a format this driver did not write
/// ([`Error::ForeignCheckpoint`]), a diff image, and a spec without jailer
/// isolation ([`Error::InvalidSpec`], see [`require_jailed_restore`]).
/// A snapshot load reopens the disk paths the checkpoint recorded — inside
/// the new jail, where the plan stages this restore's disks under the same
/// names, `/{id}.ext4`, aliasing a disk that already sits in the jail
/// elsewhere ([`FcRestorePlan::aliases`]) — so the load is rendered paused
/// and the caller points each drive at [`FcRestorePlan::drives`] before
/// resuming and drops the aliases.
pub fn fc_restore(
    image: &CheckpointImage,
    spec: &RestoreSpec,
    config: &FcDriverConfig,
    runtime_dir: &Path,
) -> Result<FcRestorePlan> {
    if image.format.as_str() != CHECKPOINT_FORMAT {
        return Err(Error::ForeignCheckpoint(image.format.clone()));
    }
    if image.kind != CheckpointKind::Full {
        return Err(unsupported("diff checkpoints are not restored"));
    }
    require_jailed_restore(&spec.isolation)?;
    let layout = VmLayout::new(&spec.id, &spec.isolation, config, runtime_dir)?;
    let name = image
        .dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::InvalidSpec(format!(
                "checkpoint dir {} has no usable name",
                image.dir.display()
            ))
        })?;
    let mut stage = Vec::new();
    let dir = checkpoint_dir(name);
    let snapshot_path = layout.place(
        &image.dir.join("vmstate"),
        &format!("{dir}/vmstate"),
        StageKind::LinkOrCopy,
        &mut stage,
    )?;
    let mem_file_path = layout.place(
        &image.dir.join("mem"),
        &format!("{dir}/mem"),
        StageKind::LinkOrCopy,
        &mut stage,
    )?;
    let mut aliases = Vec::new();
    let drives = spec
        .disks
        .iter()
        .map(|disk| {
            let drive = drive(&layout, disk, &mut stage)?;
            // The load reopens each drive at the name the checkpoint
            // recorded — `/{id}.ext4`, where this driver stages a disk. A
            // disk that already sits in the jail under another name gets
            // that name too, for the load; the drive is then pointed at the
            // disk itself and the alias goes.
            if let Some(jail) = &layout.jail
                && let Some(view) = jail.view(&disk.path)
                && view != recorded_name(disk)
            {
                let alias = jail.root.join(recorded_file(disk));
                stage.push(StagePlan {
                    src: disk.path.clone(),
                    dst: alias.clone(),
                    kind: StageKind::Alias,
                });
                aliases.push(alias);
            }
            Ok(drive)
        })
        .collect::<Result<Vec<_>>>()?;
    let network_overrides = spec
        .nics
        .iter()
        .map(|nic| {
            Ok(NetworkOverride {
                iface_id: nic.id.clone(),
                host_dev_name: tap_name(nic)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(FcRestorePlan {
        stage,
        load: SnapshotLoadParams {
            snapshot_path,
            mem_file_path: Some(mem_file_path),
            mem_backend: None,
            enable_diff_snapshots: None,
            track_dirty_pages: None,
            // The guest stays frozen until its disks are reattached.
            resume_vm: Some(false),
            network_overrides,
        },
        drives,
        aliases,
    })
}

/// The file the kernel is staged as inside the jail.
pub const KERNEL_FILE: &str = "vmlinux";

/// The file a disk with this id is staged as inside the jail, and so the
/// name a checkpoint of this driver records for it: `{id}.ext4`.
///
/// Shared with [`Staging::stage_disk`](arcbox_vm_driver::Staging::stage_disk):
/// a disk staged ahead of a boot must land where rendering that boot would
/// have put it, or the render stages a second copy of it beside the first.
pub fn disk_file(id: &str) -> String {
    format!("{id}.ext4")
}

/// The directory a checkpoint whose image dir is named `name` is staged
/// into inside the jail.
///
/// Shared with
/// [`Staging::stage_checkpoint`](arcbox_vm_driver::Staging::stage_checkpoint)
/// for the same reason as [`disk_file`], and here it is load-bearing
/// twice: a warm pool stages an image into a slot long before the restore
/// that loads it renders the same paths.
pub fn checkpoint_dir(name: &str) -> String {
    format!("snapshots/{name}")
}

/// The file a disk is staged as inside the jail, and so the name a
/// checkpoint of this driver records for it.
fn recorded_file(disk: &DiskSpec) -> String {
    disk_file(&disk.id)
}

/// [`recorded_file`] as Firecracker names it: `/{id}.ext4`.
fn recorded_name(disk: &DiskSpec) -> String {
    format!("/{}", recorded_file(disk))
}

/// Checkpoints are a jailer-mode capability.
///
/// `PUT /snapshot/load` reopens every drive at the path the checkpoint
/// recorded, with no override, so a restored VM can be given other disks
/// only where that path is private to it — inside a per-VM chroot, where
/// this driver stages them under the recorded names. Without a jail the
/// recorded paths are the source VM's own host paths, shared with it, and a
/// restore is refused.
pub fn require_jailed_restore(isolation: &IsolationSpec) -> Result<()> {
    match isolation {
        IsolationSpec::Jailer { .. } => Ok(()),
        _ => Err(unsupported(
            "restore needs jailer isolation: Firecracker reopens the recorded drive paths on load",
        )),
    }
}

fn drive(layout: &VmLayout, disk: &DiskSpec, stage: &mut Vec<StagePlan>) -> Result<Drive> {
    // The id names a Firecracker device (`PUT /drives/{id}`, and the URL a
    // restore patches) and, under a jail, the file the disk is staged as.
    if !is_plain_component(&disk.id) {
        return Err(unsupported(&format!(
            "disk id `{}` must be a plain name",
            disk.id
        )));
    }
    let kind = match &layout.jail {
        // Verbatim, or already inside the jail: nothing is staged.
        None => StageKind::Copy,
        Some(jail) if jail.view(&disk.path).is_some() => StageKind::Copy,
        Some(_) if is_block_device(&disk.path)? => StageKind::BlockNode,
        Some(_) if disk.read_only => StageKind::LinkOrCopy,
        Some(_) => StageKind::Copy,
    };
    let path_on_host = layout.place(&disk.path, &recorded_file(disk), kind, stage)?;
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

/// True when `name` is one plain path component: no separator, no `.` or
/// `..`, no root, nothing a jail-relative path may not be made of.
fn is_plain_component(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

/// True when `path` is relative and made only of plain components, so
/// joining it onto the jail root lands inside the jail.
fn is_inside_jail(path: &str) -> bool {
    let mut components = Path::new(path).components().peekable();
    components.peek().is_some()
        && components.all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Whether `path` is a block device — the one thing rendering cannot decide
/// from the spec alone.
///
/// A `stat` inside an otherwise pure function, deliberately: rendering is
/// synchronous so its rules can be unit-tested as values, and moving the
/// probe into the staging executor would move a path decision out of this
/// module, which is the one place they are made.
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
