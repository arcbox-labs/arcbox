//! [`FcPrepared`]: a spawned Firecracker waiting for a spec — the port's
//! [`PreparedVm`].

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arcbox_vm_driver::{
    CheckpointImage, Error, ExitStatus, IsolationSpec, PreparedVm, ProcessRecord, RestoreSpec,
    Result, Staging, VmHandle, VmId, VmRecord, VmSpec, VmState, VsockListen, VsockListener,
};
use async_trait::async_trait;
use fc_sdk::VmBuilder;

use crate::config::FcDriverConfig;
use crate::error::FcError;
use crate::handle::FcHandle;
use crate::listener::VsockEndpoint;
use crate::process::FcProcess;
use crate::render::{self, VmLayout};
use crate::staging::JailStaging;
use crate::{NAME, api, jail, listener, spawn};

/// A spawned VMM process with its API socket up and nothing loaded yet.
///
/// Dropping it kills the process unless a `boot` or `restore` succeeded,
/// after which the returned handle owns it (and shares the guard).
pub struct FcPrepared {
    config: Arc<FcDriverConfig>,
    /// The area this VM's files are brought into, and the layout that
    /// names every path in it. Shared in shape — not in value — with the
    /// handle a boot returns, which builds its own from the same layout.
    staging: JailStaging,
    process: Arc<FcProcess>,
    record: VmRecord,
    /// Where guest dial-outs land: the layout's vsock socket, until a
    /// restore learns where the checkpoint had it and moves it. Listeners
    /// bound before the boot or restore follow.
    vsock: VsockEndpoint,
    /// A boot or restore succeeded.
    consumed: AtomicBool,
    /// Serializes `boot` / `restore` so at most one can succeed.
    launch: tokio::sync::Mutex<()>,
}

impl FcPrepared {
    /// Spawn the VMM for `id` under `isolation` with `runtime_dir` as its
    /// scratch space, and wait for its API socket.
    ///
    /// The scratch space and, under the jailer, the chroot base the jail
    /// is rooted at are created here — idempotently, at the point this
    /// driver first needs them. They are this adapter's own layout, so a
    /// composer never has to know a driver wants a directory made.
    pub async fn spawn(
        config: Arc<FcDriverConfig>,
        id: &VmId,
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> Result<Self> {
        let layout = VmLayout::new(id, isolation, &config, runtime_dir)?;
        tokio::fs::create_dir_all(runtime_dir).await?;
        if let IsolationSpec::Jailer { chroot_base, .. } = isolation {
            tokio::fs::create_dir_all(chroot_base).await?;
        }
        let plan = layout.spawn_plan();
        let spawned = async {
            let child = spawn::spawn(&plan, &config).await?;
            debug_assert_eq!(
                child.socket_path(),
                plan.api_socket,
                "the layout and fc-sdk agree on the API socket"
            );
            let process = Arc::new(FcProcess::spawn(child, plan.api_socket.clone())?);
            let record = VmRecord {
                id: id.clone(),
                driver: NAME.to_owned(),
                runtime_dir: runtime_dir.to_path_buf(),
                process: Some(ProcessRecord {
                    pid: process.pid(),
                    api_socket: Some(plan.api_socket.clone()),
                }),
            };
            let vsock = VsockEndpoint::new(layout.vsock_host_uds());
            Ok(Self {
                config: Arc::clone(&config),
                staging: JailStaging::new(layout.clone()),
                process,
                record,
                vsock,
                consumed: AtomicBool::new(false),
                launch: tokio::sync::Mutex::new(()),
            })
        }
        .await;
        if spawned.is_err()
            && let Some(jail) = layout.jail()
        {
            // The jailer makes the chroot before it execs, so a spawn that
            // failed after that point leaves one standing with no grip to
            // discard it. The area goes with the failure exactly as it goes
            // with a discard — best-effort, because the spawn's own error
            // is the one worth reporting.
            if let Err(error) = jail.remove().await {
                tracing::warn!(vm = %id, error = %error,
                    "the jail of a vmm that failed to spawn could not be removed");
            }
        }
        spawned
    }

    fn require_unused(&self) -> Result<()> {
        if let Some(status) = self.process.exit_status() {
            return Err(Error::WrongState {
                id: self.record.id.clone(),
                state: VmState::Exited(status),
                expected: "a prepared vm that was not discarded",
            });
        }
        if self.consumed.load(Ordering::Acquire) {
            return Err(Error::WrongState {
                id: self.record.id.clone(),
                state: VmState::Running,
                expected: "a prepared vm that was not booted yet",
            });
        }
        Ok(())
    }

    fn require_same_identity(&self, id: &VmId, isolation: &IsolationSpec) -> Result<()> {
        if *id != self.record.id {
            return Err(Error::InvalidSpec(format!(
                "spec id {id} does not match the prepared vm {}",
                self.record.id
            )));
        }
        if *isolation != *self.layout().isolation() {
            return Err(Error::InvalidSpec(format!(
                "spec isolation does not match what vm {} was prepared with",
                self.record.id
            )));
        }
        Ok(())
    }

    /// Where this VM's files live: the jail, the runtime dir, the sockets.
    fn layout(&self) -> &VmLayout {
        self.staging.layout()
    }

    fn handle(&self, client: fc_sdk::Client, has_vsock: bool) -> FcHandle {
        self.consumed.store(true, Ordering::Release);
        FcHandle::new(
            Arc::clone(&self.process),
            client,
            self.layout().clone(),
            self.record.clone(),
            has_vsock.then(|| self.vsock.clone()),
            false,
        )
    }
}

impl Drop for FcPrepared {
    fn drop(&mut self) {
        if !self.consumed.load(Ordering::Acquire) {
            self.process.kill_now();
        }
    }
}

#[async_trait]
impl PreparedVm for FcPrepared {
    fn id(&self) -> &VmId {
        &self.record.id
    }

    fn record(&self) -> VmRecord {
        self.record.clone()
    }

    fn alive(&self) -> bool {
        self.process.alive()
    }

    fn vsock_listener(&self) -> Option<&dyn VsockListen> {
        Some(self)
    }

    fn staging(&self) -> Option<&dyn Staging> {
        Some(&self.staging)
    }

    async fn boot(&self, spec: VmSpec) -> Result<Box<dyn VmHandle>> {
        let _launch = self.launch.lock().await;
        self.require_unused()?;
        self.require_same_identity(&spec.id, &spec.isolation)?;
        let plan = render::fc_config(&spec, &self.config, self.layout().runtime_dir())?;
        if let Some(jail) = self.layout().jail() {
            jail::apply(jail, &plan.stage).await?;
        }
        let mut builder = VmBuilder::new(self.process.api_socket())
            .boot_source(plan.boot_source)
            .machine_config(plan.machine);
        for drive in plan.drives {
            builder = builder.drive(drive);
        }
        for nic in plan.nics {
            builder = builder.network_interface(nic);
        }
        if let Some(vsock) = plan.vsock {
            builder = builder.vsock(vsock);
        }
        if let Some(entropy) = plan.entropy {
            builder = builder.entropy(entropy);
        }
        let vm = builder.start().await.map_err(FcError::Api)?;
        Ok(Box::new(
            self.handle(vm.into_client(), plan.vsock_host_uds.is_some()),
        ))
    }

    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
    ) -> Result<Box<dyn VmHandle>> {
        let _launch = self.launch.lock().await;
        self.require_unused()?;
        self.require_same_identity(&spec.id, &spec.isolation)?;
        let plan = render::fc_restore(image, &spec, &self.config, self.layout().runtime_dir())?;
        if let Some(jail) = self.layout().jail() {
            jail::apply(jail, &plan.stage).await?;
        }
        let vm = fc_sdk::restore(self.process.api_socket(), plan.load)
            .await
            .map_err(FcError::Api)?;
        let client = vm.into_client();
        // The image, not the spec, decides which devices the VM has, and it
        // names them at the paths the checkpoint recorded — so both the
        // disks and the vsock socket are read back rather than assumed.
        let loaded = api::vm_config(&client).await?;
        reattach_disks(&client, &loaded.drives, &plan.drives).await?;
        // The drives now name the disks themselves; the second names staged
        // for the load are not needed any more.
        for alias in &plan.aliases {
            if let Err(e) = tokio::fs::remove_file(alias).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(vm = %self.record.id, alias = %alias.display(), error = %e,
                    "a disk alias staged for the load could not be removed");
            }
        }
        // Firecracker rebound the vsock where the checkpoint recorded it;
        // listeners bound on this prepared VM move there before the guest
        // can dial out.
        let has_vsock = loaded.vsock.is_some();
        if let Some(vsock) = loaded.vsock {
            self.vsock
                .relocate(self.layout().host_view(&vsock.uds_path));
        }
        // The load left the guest frozen so it could not touch a stale disk;
        // it runs from here.
        api::resume(&client).await?;
        Ok(Box::new(self.handle(client, has_vsock)))
    }

    /// Kills the VMM, and the jail goes with it.
    ///
    /// This grip made the area — the jailer built the chroot for the
    /// process this discards — so it is the grip that takes it away, and
    /// with it every file staged in. A caller that wants something out of
    /// there takes it out first, through
    /// [`Staging::unstage_disk`]; that is what the paused computer's
    /// copy-mode rootfs does. Reporting a removal failure rather than
    /// swallowing it is deliberate: the caller keeps its grip and can
    /// retry, and both halves are idempotent.
    async fn discard(&self) -> Result<ExitStatus> {
        let status = self.process.kill().await?;
        if let Some(jail) = self.layout().jail() {
            jail.remove().await?;
        }
        Ok(status)
    }
}

/// Point every drive of a freshly loaded image at the path this restore
/// gives it, skipping the ones the image already names.
///
/// A checkpoint records each disk's path, and a restore's disks are never
/// at those paths — a fresh copy-on-write device, a per-VM copy, a jail of
/// its own. The VM is still paused here, so the swap happens before the
/// guest reads a block from the disk it was checkpointed on.
async fn reattach_disks(
    client: &fc_sdk::Client,
    loaded: &[fc_sdk::types::Drive],
    wanted: &[fc_sdk::types::Drive],
) -> Result<()> {
    for drive in wanted {
        let recorded = loaded
            .iter()
            .find(|loaded| loaded.drive_id == drive.drive_id)
            .ok_or_else(|| {
                Error::InvalidSpec(format!(
                    "{NAME}: the checkpoint has no disk `{}`",
                    drive.drive_id
                ))
            })?;
        if recorded.path_on_host != drive.path_on_host {
            let path = drive.path_on_host.as_deref().ok_or_else(|| {
                Error::InvalidSpec(format!("{NAME}: disk `{}` has no path", drive.drive_id))
            })?;
            api::update_drive(client, &drive.drive_id, path).await?;
        }
    }
    Ok(())
}

#[async_trait]
impl VsockListen for FcPrepared {
    /// Bound next to the layout's vsock socket, where a boot puts the
    /// device; a restore moves the endpoint to the recorded path before
    /// the guest resumes and the listener follows.
    async fn listen(&self, port: u32) -> Result<Box<dyn VsockListener>> {
        listener::bind(self.layout(), &self.vsock, &self.process, port)
    }
}

#[cfg(test)]
mod tests {
    use fc_sdk::types::{DriveCacheType, DriveIoEngine};

    use super::*;

    /// The jailer's chroot base is this driver's own layout, so the driver
    /// makes it rather than expecting a composer to. Asserted on a spawn
    /// that fails afterwards, because the directory has to exist by the
    /// time the jailer is executed.
    #[tokio::test]
    async fn a_jailed_spawn_creates_the_chroot_base() {
        let dir = tempfile::tempdir().unwrap();
        let chroot_base = dir.path().join("srv").join("jailer");
        let mut config = FcDriverConfig::new(dir.path().join("firecracker"));
        config.jailer_binary = Some(dir.path().join("no-such-jailer"));

        let spawned = FcPrepared::spawn(
            Arc::new(config),
            &VmId::new("boxy").unwrap(),
            &IsolationSpec::Jailer {
                uid: 0,
                gid: 0,
                chroot_base: chroot_base.clone(),
                netns: None,
                new_pid_ns: false,
                cgroup: None,
            },
            &dir.path().join("run"),
        )
        .await;

        assert!(spawned.is_err(), "there is no jailer to exec");
        assert!(chroot_base.is_dir(), "the base is made before the exec");
    }

    fn drive(id: &str, path: &str) -> fc_sdk::types::Drive {
        fc_sdk::types::Drive {
            drive_id: id.to_owned(),
            path_on_host: Some(path.to_owned()),
            is_root_device: true,
            is_read_only: Some(false),
            partuuid: None,
            cache_type: DriveCacheType::Unsafe,
            rate_limiter: None,
            io_engine: DriveIoEngine::Sync,
            socket: None,
        }
    }

    /// A client on a socket nobody answers on: any call it makes fails, so
    /// a call that does not happen is provable.
    fn unreachable_client() -> fc_sdk::Client {
        fc_sdk::connection::connect("/nonexistent/arcbox-fc-driver/api.sock")
    }

    #[tokio::test]
    async fn a_disk_the_image_already_names_is_not_patched() {
        reattach_disks(
            &unreachable_client(),
            &[drive("rootfs", "/rootfs.ext4")],
            &[drive("rootfs", "/rootfs.ext4")],
        )
        .await
        .expect("no call is made for a path the image already names");
    }

    #[tokio::test]
    async fn a_disk_at_a_new_path_is_patched_and_an_unknown_one_is_refused() {
        // The patch is attempted — against a socket nobody answers on, so it
        // fails as a driver error rather than being skipped.
        let patched = reattach_disks(
            &unreachable_client(),
            &[drive("rootfs", "/rootfs.ext4")],
            &[drive("rootfs", "/restored.ext4")],
        )
        .await;
        assert!(matches!(patched, Err(Error::Driver { .. })), "{patched:?}");

        let unknown = reattach_disks(
            &unreachable_client(),
            &[drive("rootfs", "/rootfs.ext4")],
            &[drive("data", "/data.ext4")],
        )
        .await;
        match unknown {
            Err(Error::InvalidSpec(message)) => assert!(message.contains("data"), "{message}"),
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }
}
