//! [`FcPrepared`]: a spawned Firecracker waiting for a spec — the port's
//! [`PreparedVm`].

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arcbox_vm_driver::{
    CheckpointImage, Error, ExitStatus, IsolationSpec, PreparedVm, ProcessRecord, RestoreSpec,
    Result, VmHandle, VmId, VmRecord, VmSpec, VmState, VsockListen, VsockListener,
};
use async_trait::async_trait;
use fc_sdk::VmBuilder;

use crate::config::FcDriverConfig;
use crate::error::FcError;
use crate::handle::FcHandle;
use crate::process::FcProcess;
use crate::render::{self, VmLayout};
use crate::{NAME, api, jail, listener, spawn};

/// A spawned VMM process with its API socket up and nothing loaded yet.
///
/// Dropping it kills the process unless a `boot` or `restore` succeeded,
/// after which the returned handle owns it (and shares the guard).
pub struct FcPrepared {
    config: Arc<FcDriverConfig>,
    layout: VmLayout,
    process: Arc<FcProcess>,
    record: VmRecord,
    /// A boot or restore succeeded.
    consumed: AtomicBool,
    /// Serializes `boot` / `restore` so at most one can succeed.
    launch: tokio::sync::Mutex<()>,
}

impl FcPrepared {
    /// Spawn the VMM for `id` under `isolation` with `runtime_dir` as its
    /// scratch space, and wait for its API socket.
    pub async fn spawn(
        config: Arc<FcDriverConfig>,
        id: &VmId,
        isolation: &IsolationSpec,
        runtime_dir: &Path,
    ) -> Result<Self> {
        let layout = VmLayout::new(id, isolation, &config, runtime_dir)?;
        tokio::fs::create_dir_all(runtime_dir).await?;
        let plan = layout.spawn_plan();
        let child = spawn::spawn(&plan, &config).await?;
        let process = Arc::new(FcProcess::spawn(child, plan.api_socket.clone())?);
        let record = VmRecord {
            id: id.clone(),
            driver: NAME.to_owned(),
            runtime_dir: runtime_dir.to_path_buf(),
            process: Some(ProcessRecord {
                pid: process.pid(),
                api_socket: Some(plan.api_socket),
            }),
        };
        Ok(Self {
            config,
            layout,
            process,
            record,
            consumed: AtomicBool::new(false),
            launch: tokio::sync::Mutex::new(()),
        })
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
        if *isolation != *self.layout.isolation() {
            return Err(Error::InvalidSpec(format!(
                "spec isolation does not match what vm {} was prepared with",
                self.record.id
            )));
        }
        Ok(())
    }

    fn handle(&self, client: fc_sdk::Client, vsock_uds: Option<std::path::PathBuf>) -> FcHandle {
        self.consumed.store(true, Ordering::Release);
        FcHandle::new(
            Arc::clone(&self.process),
            client,
            self.layout.clone(),
            self.record.clone(),
            vsock_uds,
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

    async fn boot(&self, spec: VmSpec) -> Result<Box<dyn VmHandle>> {
        let _launch = self.launch.lock().await;
        self.require_unused()?;
        self.require_same_identity(&spec.id, &spec.isolation)?;
        let plan = render::fc_config(&spec, &self.config, self.layout.runtime_dir())?;
        if let Some(jail) = self.layout.jail() {
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
        Ok(Box::new(self.handle(vm.into_client(), plan.vsock_host_uds)))
    }

    async fn restore(
        &self,
        image: &CheckpointImage,
        spec: RestoreSpec,
    ) -> Result<Box<dyn VmHandle>> {
        let _launch = self.launch.lock().await;
        self.require_unused()?;
        self.require_same_identity(&spec.id, &spec.isolation)?;
        let plan = render::fc_restore(image, &spec, &self.config, self.layout.runtime_dir())?;
        if let Some(jail) = self.layout.jail() {
            jail::apply(jail, &plan.stage).await?;
        }
        let vm = fc_sdk::restore(self.process.api_socket(), plan.load)
            .await
            .map_err(FcError::Api)?;
        let client = vm.into_client();
        // The image, not the spec, decides which devices the VM has.
        let has_vsock = api::vm_config(&client).await?.vsock.is_some();
        Ok(Box::new(
            self.handle(client, has_vsock.then_some(plan.vsock_host_uds)),
        ))
    }

    async fn discard(&self) -> Result<ExitStatus> {
        Ok(self.process.kill().await?)
    }
}

#[async_trait]
impl VsockListen for FcPrepared {
    async fn listen(&self, port: u32) -> Result<Box<dyn VsockListener>> {
        listener::bind(&self.layout, &self.process, port)
    }
}
