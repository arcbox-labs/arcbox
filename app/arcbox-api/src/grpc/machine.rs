//! Machine service gRPC implementation.

use std::pin::Pin;

use arcbox_core::ExecSessionInput;
use arcbox_core::machine_image;
use arcbox_grpc::v1::machine_service_server;
use arcbox_protocol::v1::{
    CreateMachineRequest, CreateMachineResponse, Empty, InspectMachineRequest, ListMachinesRequest,
    ListMachinesResponse, MachineAgentRequest, MachineExecInput, MachineExecOutput,
    MachineExecRequest, MachineInfo, MachineNetwork, MachinePingResponse, MachineSummary,
    MachineSystemInfo, RemoveMachineRequest, StartMachineRequest, StopMachineRequest,
    machine_exec_input,
};
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tonic::{Request, Response, Status};

use super::{SharedRuntime, SharedRuntimeExt};

/// The NAT gateway every machine's primary interface routes through; it also
/// serves DNS (same literal the guest agent's DHCP path documents).
const NAT_GATEWAY: &str = "10.0.2.1";

/// Converts a chrono timestamp to the wire `Timestamp`.
fn timestamp(t: chrono::DateTime<chrono::Utc>) -> arcbox_protocol::v1::Timestamp {
    arcbox_protocol::v1::Timestamp {
        seconds: t.timestamp(),
        nanos: i32::try_from(t.timestamp_subsec_nanos()).unwrap_or(0),
    }
}

/// Machine service implementation.
pub struct MachineServiceImpl {
    runtime: SharedRuntime,
}

impl MachineServiceImpl {
    /// Creates a new machine service with a deferred runtime.
    #[must_use]
    pub fn new(runtime: SharedRuntime) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl machine_service_server::MachineService for MachineServiceImpl {
    async fn create(
        &self,
        request: Request<CreateMachineRequest>,
    ) -> Result<Response<CreateMachineResponse>, Status> {
        let req = request.into_inner();
        let runtime = self.runtime.ready()?;

        // Convert bytes to MB for internal config.
        let memory_mb = req.memory / (1024 * 1024);
        let disk_gb = req.disk_size / (1024 * 1024 * 1024);

        // Distro machines boot a published rootfs image: resolve and pull it
        // (a cached image is a no-op) before registering the machine.
        let rootfs = if req.distro.is_empty() {
            None
        } else {
            let arch = if req.arch.is_empty() {
                machine_image::host_image_arch().to_string()
            } else {
                machine_image::image_arch(&req.arch).to_string()
            };
            let selector = machine_image::ImageSelector::Distro {
                distro: req.distro.clone(),
                release: (!req.version.is_empty()).then(|| req.version.clone()),
                arch,
            };
            let image = runtime
                .machine_image_manager()
                .pull(&selector, |done, total| {
                    tracing::debug!(machine = %req.name, done, total, "machine image pull");
                })
                .await
                .map_err(|e| match &e {
                    arcbox_core::error::CoreError::Common(c) if c.is_not_found() => {
                        Status::not_found(e.to_string())
                    }
                    _ => Status::internal(e.to_string()),
                })?;
            tracing::info!(
                machine = %req.name,
                image = %format!("{}@{}", image.manifest.name, image.manifest.version),
                "machine image ready"
            );

            // Resolve the boot shim (kernel + EROFS with
            // /sbin/arcbox-machine-init) from the same boot-assets cache the
            // daemon populates for the System VM; a warm cache is a no-op.
            let shim = async {
                let provider = arcbox_core::boot_assets::BootAssetProvider::new(
                    runtime.config().data_dir.join("boot"),
                )?;
                let assets = provider.get_assets().await?;
                Ok::<_, arcbox_core::error::CoreError>(arcbox_core::machine::BootShim {
                    kernel: assets.kernel,
                    rootfs: assets.rootfs_image,
                })
            }
            .await
            .map_err(|e| Status::internal(format!("resolve boot shim: {e}")))?;

            Some(arcbox_core::machine::MachineRootfs {
                path: image.rootfs_path(),
                format: image.manifest.rootfs.format,
                shim: Some(shim),
            })
        };

        let config = arcbox_core::machine::MachineConfig {
            name: req.name.clone(),
            // 0 on the wire means "use the daemon-configured default".
            cpus: if req.cpus == 0 {
                runtime.config().vm.effective_cpus()
            } else {
                req.cpus
            },
            memory_mb,
            disk_gb,
            kernel: if req.kernel.is_empty() {
                None
            } else {
                Some(req.kernel)
            },
            cmdline: if req.cmdline.is_empty() {
                None
            } else {
                Some(req.cmdline)
            },
            distro: if req.distro.is_empty() {
                None
            } else {
                Some(req.distro)
            },
            distro_version: if req.version.is_empty() {
                None
            } else {
                Some(req.version)
            },
            block_devices: Vec::new(),
            rootfs,
            backend: arcbox_core::VmBackend::default(),
            enable_rosetta: false,
        };

        runtime
            .machine_manager()
            .create(config)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateMachineResponse { id: req.name }))
    }

    async fn start(
        &self,
        request: Request<StartMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let id = request.into_inner().id;
        let runtime = self.runtime.ready()?;

        runtime
            .machine_manager()
            .start(&id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn stop(&self, request: Request<StopMachineRequest>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let runtime = self.runtime.ready()?;
        let manager = std::sync::Arc::clone(runtime.machine_manager());

        // Graceful stop (guest ACPI) with a force fallback, unless the caller
        // asked for an immediate force stop. Both are synchronous VM calls
        // that can block up to the shutdown window; keep them off the async
        // workers.
        let force = req.force;
        let id = req.id;
        tokio::task::spawn_blocking(move || {
            if force {
                return manager.stop(&id);
            }
            match manager.graceful_stop(
                &id,
                std::time::Duration::from_secs(
                    arcbox_constants::timeouts::HOST_SHUTDOWN_TIMEOUT_SECS,
                ),
            ) {
                Ok(true) => Ok(()),
                Ok(false) => {
                    tracing::warn!(machine = %id, "graceful stop timed out; force stopping");
                    manager.stop(&id)
                }
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(|e| Status::internal(format!("stop task panicked: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let runtime = self.runtime.ready()?;

        runtime
            .machine_manager()
            .remove(&req.id, req.force)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn list(
        &self,
        _request: Request<ListMachinesRequest>,
    ) -> Result<Response<ListMachinesResponse>, Status> {
        let runtime = self.runtime.ready()?;

        let summaries: Vec<MachineSummary> = runtime
            .machine_manager()
            .list()
            .into_iter()
            .map(|m| MachineSummary {
                id: m.name.clone(),
                name: m.name,
                state: format!("{:?}", m.state).to_lowercase(),
                cpus: m.cpus,
                memory: m.memory_mb * 1024 * 1024,
                disk_size: m.disk_gb * 1024 * 1024 * 1024,
                ip_address: m.ip_address.unwrap_or_default(),
                created: m.created_at.timestamp(),
                distro: m.distro.unwrap_or_default(),
                distro_version: m.distro_version.unwrap_or_default(),
            })
            .collect();

        Ok(Response::new(ListMachinesResponse {
            machines: summaries,
        }))
    }

    async fn inspect(
        &self,
        request: Request<InspectMachineRequest>,
    ) -> Result<Response<MachineInfo>, Status> {
        let id = request.into_inner().id;
        let runtime = self.runtime.ready()?;

        let machine = runtime
            .machine_manager()
            .get(&id)
            .ok_or_else(|| Status::not_found("machine not found"))?;

        Ok(Response::new(MachineInfo {
            id: machine.name.clone(),
            name: machine.name,
            state: format!("{:?}", machine.state).to_lowercase(),
            hardware: Some(arcbox_protocol::v1::MachineHardware {
                cpus: machine.cpus,
                memory: machine.memory_mb * 1024 * 1024,
                arch: std::env::consts::ARCH.to_string(),
            }),
            network: Some(MachineNetwork {
                // Gateway/DNS only exist once the guest has an address; both
                // are the NAT gateway (which also serves DNS — the same
                // topology the agent's DHCP path configures).
                gateway: machine
                    .ip_address
                    .as_ref()
                    .map(|_| NAT_GATEWAY.to_string())
                    .unwrap_or_default(),
                dns_servers: machine
                    .ip_address
                    .as_ref()
                    .map(|_| vec![NAT_GATEWAY.to_string()])
                    .unwrap_or_default(),
                ip_address: machine.ip_address.clone().unwrap_or_default(),
                mac_address: String::new(),
                bridge_mac_address: arcbox_core::vm::bridge_nic_mac_for_vm_id(&machine.vm_id),
            }),
            storage: Some(arcbox_protocol::v1::MachineStorage {
                disk_size: machine.disk_gb * 1024 * 1024 * 1024,
                disk_format: "raw".to_string(),
                disk_path: machine
                    .disk_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            }),
            os: Some(arcbox_protocol::v1::MachineOs {
                distro: machine
                    .distro
                    .clone()
                    .unwrap_or_else(|| "linux".to_string()),
                version: machine.distro_version.clone().unwrap_or_default(),
                kernel: machine.kernel.unwrap_or_default(),
            }),
            created: Some(timestamp(machine.created_at)),
            started_at: machine.started_at.map(timestamp),
            mounts: vec![],
        }))
    }

    async fn ping(
        &self,
        request: Request<MachineAgentRequest>,
    ) -> Result<Response<MachinePingResponse>, Status> {
        let id = request.into_inner().id;

        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&id)
            .map_err(|e| Status::internal(e.to_string()))?;
        let response = agent
            .ping()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(MachinePingResponse {
            message: response.message,
            version: response.version,
        }))
    }

    async fn get_system_info(
        &self,
        request: Request<MachineAgentRequest>,
    ) -> Result<Response<MachineSystemInfo>, Status> {
        let id = request.into_inner().id;

        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&id)
            .map_err(|e| Status::internal(e.to_string()))?;
        let info = agent
            .get_system_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(MachineSystemInfo {
            kernel_version: info.kernel_version,
            os_name: info.os_name,
            os_version: info.os_version,
            arch: info.arch,
            total_memory: info.total_memory,
            available_memory: info.available_memory,
            cpu_count: info.cpu_count,
            load_average: info.load_average,
            hostname: info.hostname,
            uptime: info.uptime,
            ip_addresses: info.ip_addresses,
        }))
    }

    async fn compact_disk(
        &self,
        request: Request<MachineAgentRequest>,
    ) -> Result<Response<Empty>, Status> {
        let id = request.into_inner().id;

        // Trigger an immediate fstrim in the guest. The discards flow through
        // virtio-blk, which punches holes in the host data image, shrinking its
        // physical footprint. The caller measures host usage before/after.
        //
        // If fstrim fails in the guest, the agent replies with a generic error
        // response, so `disk_trim()` surfaces it as an `Err` here — no need to
        // inspect the result text.
        let mut agent = self
            .runtime
            .ready()?
            .get_agent(&id)
            .map_err(|e| Status::internal(e.to_string()))?;
        let resp = agent
            .disk_trim()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        tracing::debug!(machine = %id, result = %resp.result, "disk compact: fstrim done");

        Ok(Response::new(Empty {}))
    }

    type ExecStream =
        Pin<Box<dyn Stream<Item = Result<MachineExecOutput, Status>> + Send + 'static>>;

    /// Runs a command in the machine root via the guest agent, streaming
    /// stdout/stderr frames and a final exit-code frame.
    ///
    /// Non-interactive: the agent rejects `tty` requests until the bidi exec
    /// session lands. Streaming requires the async agent transport (VZ);
    /// the HV blocking transport shares the sandbox-streaming limitation.
    async fn exec(
        &self,
        request: Request<MachineExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let req = request.into_inner();
        let agent = self
            .runtime
            .ready()?
            .get_agent(&req.id)
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut rx = agent
            .machine_exec(req)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let stream = async_stream::stream! {
            while let Some(item) = rx.recv().await {
                match item {
                    Ok(output) => {
                        let done = output.done;
                        yield Ok(output);
                        if done {
                            break;
                        }
                    }
                    Err(arcbox_core::error::CoreError::Agent { code: 400, message }) => {
                        yield Err(Status::invalid_argument(message));
                        break;
                    }
                    Err(e) => {
                        yield Err(Status::internal(e.to_string()));
                        break;
                    }
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn ssh_info(
        &self,
        _request: Request<arcbox_protocol::v1::SshInfoRequest>,
    ) -> Result<Response<arcbox_protocol::v1::SshInfoResponse>, Status> {
        // TODO: Implement SSH info.
        Err(Status::unimplemented("ssh_info not implemented"))
    }

    type ExecSessionStream =
        Pin<Box<dyn Stream<Item = Result<MachineExecOutput, Status>> + Send + 'static>>;

    /// Interactive machine exec: a bidi PTY session bridged to the agent's
    /// machine-exec frames. The first client message must carry Init; stdin
    /// and resize messages follow on the same stream.
    async fn exec_session(
        &self,
        request: Request<tonic::Streaming<MachineExecInput>>,
    ) -> Result<Response<Self::ExecSessionStream>, Status> {
        let mut stream = request.into_inner();

        let first = stream.next().await.ok_or_else(|| {
            Status::invalid_argument("exec session: stream closed before Init message")
        })??;
        let exec_req = match first.payload {
            Some(machine_exec_input::Payload::Init(req)) => req,
            _ => {
                return Err(Status::invalid_argument(
                    "exec session: first message must be Init",
                ));
            }
        };

        let agent = self
            .runtime
            .ready()?
            .get_agent(&exec_req.id)
            .map_err(|e| Status::internal(e.to_string()))?;

        // Feed remaining gRPC input (stdin + TTY resizes) into a channel for
        // the core layer. Stream end sends the empty-stdin EOF sentinel.
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            while let Some(Ok(input)) = stream.next().await {
                let msg = match input.payload {
                    Some(machine_exec_input::Payload::Stdin(data)) => ExecSessionInput::Stdin(data),
                    Some(machine_exec_input::Payload::Resize(size)) => ExecSessionInput::Resize {
                        width: u16::try_from(size.width).unwrap_or(u16::MAX),
                        height: u16::try_from(size.height).unwrap_or(u16::MAX),
                    },
                    _ => continue,
                };
                if in_tx.send(msg).await.is_err() {
                    return;
                }
            }
            let _ = in_tx.send(ExecSessionInput::Stdin(Vec::new())).await;
        });

        let mut out_rx = agent
            .machine_exec_session(exec_req, in_rx)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let out_stream = async_stream::stream! {
            while let Some(item) = out_rx.recv().await {
                match item {
                    Ok(output) => {
                        let done = output.done;
                        yield Ok(output);
                        if done {
                            break;
                        }
                    }
                    Err(arcbox_core::error::CoreError::Agent { code: 400, message }) => {
                        yield Err(Status::invalid_argument(message));
                        break;
                    }
                    Err(e) => {
                        yield Err(Status::internal(e.to_string()));
                        break;
                    }
                }
            }
        };
        Ok(Response::new(Box::pin(out_stream)))
    }
}
