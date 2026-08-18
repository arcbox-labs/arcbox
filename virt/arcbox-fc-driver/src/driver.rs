//! [`FcDriver`]: the port's [`VmDriver`] for Firecracker, with `Prepare`
//! and `Adopt`.

use std::path::Path;
use std::sync::Arc;

use arcbox_vm_driver::{
    Adopt, CheckpointImage, DriverCapabilities, Error, IsolationSpec, NestedVirt, Prepare,
    PreparedVm, RestoreSpec, Result, VmDriver, VmHandle, VmId, VmRecord, VmSpec,
};
use async_trait::async_trait;

use crate::config::FcDriverConfig;
use crate::prepared::FcPrepared;
use crate::render;
use crate::{CHECKPOINT_FORMAT, NAME, adopt, discover, jail};

/// The Firecracker adapter.
///
/// `boot` and `restore` are exactly prepare-then-boot / prepare-then-restore
/// on a fresh [`FcPrepared`]; a failure on the way drops the prepared VM,
/// which kills the process it spawned.
pub struct FcDriver {
    config: Arc<FcDriverConfig>,
}

impl FcDriver {
    /// A driver over `config`.
    pub fn new(config: FcDriverConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// The node-wide config this driver runs with.
    pub fn config(&self) -> &FcDriverConfig {
        &self.config
    }

    async fn prepare_vm(
        &self,
        id: &VmId,
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> Result<FcPrepared> {
        FcPrepared::spawn(Arc::clone(&self.config), id, isolation, runtime_dir).await
    }
}

#[async_trait]
impl VmDriver for FcDriver {
    fn name(&self) -> &'static str {
        NAME
    }

    /// Checkpoints are claimed only with a jailer configured: a restore is
    /// possible only inside a per-VM chroot
    /// ([`render::require_jailed_restore`]), and a driver that cannot
    /// restore does not claim to checkpoint.
    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities {
            vsock: true,
            vsock_listen: true,
            checkpoint: self.config.jailer_binary.is_some(),
            diff_checkpoint: false,
            adopt: true,
            prepare: true,
            staging: true,
            balloon: false,
            console: false,
            debug: false,
            nested_virt: nested_virt(),
        }
    }

    async fn boot(&self, spec: VmSpec, runtime_dir: &Path) -> Result<Box<dyn VmHandle>> {
        spec.validate()?;
        let prepared = self
            .prepare_vm(&spec.id, &spec.isolation, runtime_dir)
            .await?;
        prepared.boot(spec).await
    }

    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
        runtime_dir: &Path,
    ) -> Result<Box<dyn VmHandle>> {
        // Refuse a foreign image, and a restore outside a jail, before
        // spawning anything.
        if image.format.as_str() != CHECKPOINT_FORMAT {
            return Err(Error::ForeignCheckpoint(image.format.clone()));
        }
        render::require_jailed_restore(&spec.isolation)?;
        let prepared = self
            .prepare_vm(&spec.id, &spec.isolation, runtime_dir)
            .await?;
        prepared.restore(image, spec).await
    }

    fn adopt(&self) -> Option<&dyn Adopt> {
        Some(self)
    }

    fn prepare(&self) -> Option<&dyn Prepare> {
        Some(self)
    }

    /// Under the jailer, what the longest socket path in the jail leaves
    /// for the id ([`jail::id_budget`]) — so a longer chroot base or a
    /// longer binary name tightens the budget rather than silently
    /// reintroducing the connect timeout it exists to prevent.
    ///
    /// Nothing bounds the id in direct mode — not because the id stays out
    /// of the path (the sockets live in the caller's `runtime_dir`, which
    /// may well be named after it), but because an over-long path there
    /// announces itself: Firecracker binds the same absolute path the host
    /// connects to, so the kernel raises `ENAMETOOLONG` at bind and names
    /// the path it could not bind. The jail's budget exists for the
    /// asymmetry direct mode does not have — a name short inside the chroot
    /// and long outside it, which binds cleanly and fails only on the
    /// host's `connect`. An isolation this driver cannot run at all is
    /// refused when its layout is built, not here.
    fn id_budget(&self, isolation: &IsolationSpec) -> Option<usize> {
        match isolation {
            IsolationSpec::Jailer { chroot_base, .. } => Some(jail::id_budget(
                &self.config.firecracker_binary,
                chroot_base,
            )),
            _ => None,
        }
    }
}

#[async_trait]
impl Prepare for FcDriver {
    async fn prepare(
        &self,
        id: &VmId,
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> Result<Box<dyn PreparedVm>> {
        Ok(Box::new(self.prepare_vm(id, isolation, runtime_dir).await?))
    }
}

#[async_trait]
impl Adopt for FcDriver {
    /// Finds the VMM `record` names — the recorded pid when it is still a
    /// Firecracker, else a `/proc` scan by `--id`, `--api-sock`, or a
    /// jail root ending in `{firecracker binary name}/{id}/root` — and
    /// rebuilds a handle over it, its exit tracked by probing. The API is
    /// reconnected best-effort within [`adopt::API_TIMEOUT`]: a VMM that
    /// answers yields the full [`FcHandle`](crate::FcHandle) with its
    /// devices and paused state read back; one whose socket is missing,
    /// wedged, or closes yields an [`FcProcessHandle`](crate::FcProcessHandle)
    /// that can be killed, observed, and detached, and nothing else. A
    /// verified process is never left unadoptable by its API.
    async fn adopt(&self, record: &VmRecord) -> Result<Option<Box<dyn VmHandle>>> {
        match discover::find(&self.config, record) {
            Some(found) => Ok(Some(
                adopt::rebuild(&self.config, found, record, adopt::API_TIMEOUT).await?,
            )),
            None => Ok(None),
        }
    }
}

/// Whether guests may run their own hypervisor: KVM's `nested` module
/// parameter on Linux; nowhere else, since Firecracker needs KVM.
fn nested_virt() -> NestedVirt {
    #[cfg(target_os = "linux")]
    {
        for module in ["kvm_intel", "kvm_amd"] {
            let path = format!("/sys/module/{module}/parameters/nested");
            if let Ok(value) = std::fs::read_to_string(&path) {
                let value = value.trim();
                return if value == "Y" || value == "1" {
                    NestedVirt::supported()
                } else {
                    NestedVirt::unsupported(format!("{path} is {value}"))
                };
            }
        }
        NestedVirt::unsupported(
            "no /sys/module/kvm_{intel,amd}/parameters/nested: kvm not loaded, or not an x86 host",
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        NestedVirt::unsupported("Firecracker needs Linux KVM")
    }
}

#[cfg(test)]
mod tests {
    use arcbox_vm_driver::{
        BootSpec, CheckpointFormat, CheckpointKind, ConsoleSpec, IsolationSpec,
    };

    use super::*;

    /// A driver whose binary does not exist: anything that reaches a spawn
    /// fails loudly, so these tests prove what is refused before one.
    fn driver() -> FcDriver {
        FcDriver::new(FcDriverConfig::new(
            "/nonexistent/arcbox-fc-driver/firecracker",
        ))
    }

    #[test]
    fn capabilities_name_what_this_adapter_claims() {
        let driver = driver();
        assert_eq!(driver.name(), "firecracker");
        let caps = driver.capabilities();
        assert!(caps.vsock && caps.vsock_listen);
        assert!(caps.adopt && caps.prepare && caps.staging);
        assert!(!caps.diff_checkpoint && !caps.balloon && !caps.console && !caps.debug);
        assert!(VmDriver::adopt(&driver).is_some() && VmDriver::prepare(&driver).is_some());
        // Checkpoints go with the jailer: without one nothing could be
        // restored, so nothing is claimed.
        assert!(!caps.checkpoint);
        let mut config = FcDriverConfig::new("/nonexistent/arcbox-fc-driver/firecracker");
        config.jailer_binary = Some("/nonexistent/arcbox-fc-driver/jailer".into());
        assert!(FcDriver::new(config).capabilities().checkpoint);
    }

    #[test]
    fn the_id_budget_is_the_jails_and_direct_mode_has_none() {
        let driver = driver();
        // Nothing in a direct-mode VM's paths carries the id.
        assert_eq!(driver.id_budget(&IsolationSpec::None), None);

        let jailed = |chroot_base: &str| IsolationSpec::Jailer {
            uid: 0,
            gid: 0,
            chroot_base: chroot_base.into(),
            netns: None,
            new_pid_ns: false,
            cgroup: None,
        };
        assert_eq!(
            driver.id_budget(&jailed("/srv/jailer")),
            Some(crate::jail::id_budget(
                "/nonexistent/arcbox-fc-driver/firecracker",
                "/srv/jailer"
            ))
        );
        // A deeper base is a tighter budget, and a deep enough one leaves
        // nothing: the caller must refuse every id rather than mint one.
        assert!(
            driver.id_budget(&jailed("/srv/jailer/nested/deeper"))
                < driver.id_budget(&jailed("/srv/jailer"))
        );
        assert_eq!(
            driver.id_budget(&jailed(&format!("/{}", "d".repeat(200)))),
            Some(0)
        );
    }

    #[tokio::test]
    async fn invalid_specs_and_foreign_images_are_refused_before_a_spawn() {
        let driver = driver();
        let dir = tempfile::tempdir().unwrap();
        let spec = VmSpec {
            id: VmId::new("box").unwrap(),
            cpus: 0,
            memory_mib: 128,
            boot: BootSpec::Kernel {
                image: "/vmlinux".into(),
                cmdline: String::new(),
                initrd: None,
            },
            disks: vec![],
            nics: vec![],
            vsock: None,
            shares: vec![],
            console: ConsoleSpec::Off,
            balloon: false,
            entropy: false,
            dirty_tracking: false,
            isolation: IsolationSpec::None,
        };
        assert!(matches!(
            driver.boot(spec, dir.path()).await,
            Err(Error::InvalidSpec(_))
        ));
        let image = CheckpointImage {
            dir: dir.path().to_path_buf(),
            format: CheckpointFormat::new("other/v1"),
            kind: CheckpointKind::Full,
        };
        let restore = RestoreSpec {
            id: VmId::new("box").unwrap(),
            nics: vec![],
            disks: vec![],
            isolation: IsolationSpec::None,
        };
        assert!(matches!(
            driver.restore(&image, restore.clone(), dir.path()).await,
            Err(Error::ForeignCheckpoint(_))
        ));
        // A restore outside a jail is refused before a spawn too.
        let own = CheckpointImage {
            format: CheckpointFormat::new(CHECKPOINT_FORMAT),
            ..image
        };
        assert!(matches!(
            driver.restore(&own, restore, dir.path()).await,
            Err(Error::InvalidSpec(msg)) if msg.contains("jailer isolation")
        ));
        assert!(
            !dir.path().join("firecracker.log").exists(),
            "nothing was spawned"
        );
    }
}
