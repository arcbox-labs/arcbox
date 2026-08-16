//! From the port's specs to what Firecracker is told.
//!
//! One decision lives here and nowhere else: which path Firecracker sees
//! for every host file. Without a jail, paths pass through verbatim. Under
//! the jailer, Firecracker is chrooted into
//! `{chroot_base}/{firecracker binary name}/{id}/root` and every path it
//! is told is chroot-relative: a host path already under the jail is passed
//! as `/` + its relative part; anything else is staged in first and named
//! by where it landed. [`VmLayout`] is that map; the renderers that use it
//! to produce an [`FcPlan`] / [`FcRestorePlan`] follow, and
//! [`jail::apply`] executes the staging half.

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{Error, IsolationSpec, Result, VmId};

use crate::NAME;
use crate::config::FcDriverConfig;
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

fn utf8(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::InvalidSpec(format!("{NAME}: path {} is not UTF-8", path.display())))
}
