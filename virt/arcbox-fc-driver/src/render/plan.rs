//! What a render produces: the process to spawn, the files to stage, and
//! the API payloads to send.

use std::path::PathBuf;

use arcbox_vm_driver::{IsolationSpec, VmId};
use fc_sdk::types::{
    BootSource, Drive, EntropyDevice, MachineConfiguration, NetworkInterface, SnapshotLoadParams,
    Vsock,
};

/// The process a VM runs on, decided before any spec is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnPlan {
    /// The VM.
    pub id: VmId,
    /// The API socket the spawned process answers on, as the host sees it.
    pub api_socket: PathBuf,
    /// The vsock Unix socket the VM will bind, as the host sees it; a stale
    /// one from an earlier VM in the same place is cleared before the spawn.
    pub vsock_uds: PathBuf,
    /// Direct or jailed.
    pub mode: SpawnMode,
}

/// How the VMM process is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnMode {
    /// `firecracker` run directly by the caller.
    Direct {
        /// Firecracker's log file, pre-created before the spawn.
        log: PathBuf,
        /// Firecracker's metrics file, pre-created before the spawn.
        metrics: PathBuf,
    },
    /// `jailer` confining `firecracker` into a chroot.
    Jailer {
        /// The confinement, always [`IsolationSpec::Jailer`].
        isolation: IsolationSpec,
        /// The chroot root the jailer will create.
        jail_root: PathBuf,
    },
}

/// One host file to bring into the jail before Firecracker is told about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagePlan {
    /// The file on the host.
    pub src: PathBuf,
    /// Where it lands inside the jail (a host path under the jail root).
    pub dst: PathBuf,
    /// How it gets there.
    pub kind: StageKind,
}

/// How a host file is mirrored into the jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    /// Hard link when the jail runs as root, a chowned copy otherwise — for
    /// files Firecracker only reads (kernel, initrd, vmstate, mem, a
    /// read-only disk).
    LinkOrCopy,
    /// A private, chowned copy — for a writable regular file Firecracker
    /// will write guest blocks into.
    Copy,
    /// A device node with the source's major/minor — for a block device
    /// (a device-mapper rootfs).
    BlockNode,
}

/// Everything a boot needs after the process is up.
#[derive(Debug, Clone)]
pub struct FcPlan {
    /// Files to stage into the jail first (empty without a jail).
    pub stage: Vec<StagePlan>,
    /// `PUT /boot-source`.
    pub boot_source: BootSource,
    /// `PUT /machine-config`.
    pub machine: MachineConfiguration,
    /// `PUT /drives/{id}`, in bus order.
    pub drives: Vec<Drive>,
    /// `PUT /network-interfaces/{id}`, in bus order.
    pub nics: Vec<NetworkInterface>,
    /// `PUT /vsock`, when the spec asked for one.
    pub vsock: Option<Vsock>,
    /// `PUT /entropy`, when the spec asked for one.
    pub entropy: Option<EntropyDevice>,
    /// The vsock Unix socket as the host dials it, when there is a vsock.
    pub vsock_host_uds: Option<PathBuf>,
}

/// Everything a restore needs after the process is up.
///
/// Which devices the restored VM has — a vsock, and where its Unix socket
/// is bound — is the image's to say, not the plan's: Firecracker re-creates
/// the vsock at the path the checkpoint recorded, so the driver reads it
/// back from `GET /vm/config` after the load.
#[derive(Debug, Clone)]
pub struct FcRestorePlan {
    /// Files to stage into the jail first (empty without a jail).
    pub stage: Vec<StagePlan>,
    /// `PUT /snapshot/load`.
    pub load: SnapshotLoadParams,
}
