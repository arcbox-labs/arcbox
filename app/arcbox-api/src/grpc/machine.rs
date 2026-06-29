//! Machine service gRPC implementation.

use std::pin::Pin;

use arcbox_grpc::v1::machine_service_server;
use arcbox_protocol::v1::{
    CreateMachineRequest, CreateMachineResponse, Empty, InspectMachineRequest, ListMachinesRequest,
    ListMachinesResponse, MacImageListResponse, MacImagePullRequest, MacImageRemoveRequest,
    MacImageSummary, MachineAgentRequest, MachineExecOutput, MachineExecRequest, MachineInfo,
    MachineNetwork, MachinePingResponse, MachineSummary, MachineSystemInfo, RemoveMachineRequest,
    StartMachineRequest, StopMachineRequest,
};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use super::{SharedRuntime, SharedRuntimeExt};

/// Drives a `!Send` macOS VM future to completion on a dedicated blocking thread.
///
/// Virtualization.framework operations hold ObjC handles (and the VM's dispatch
/// queue) across await and are not `Send`, but tonic requires handler futures to be
/// `Send`. Running the future via a transient current-thread runtime inside
/// `spawn_blocking` keeps that `!Send` state off the gRPC worker threads; the booted
/// VM (which is `Send + Sync`) outlives the transient runtime.
#[cfg(target_os = "macos")]
async fn run_macos_blocking<T, Fut, F>(f: F) -> Result<T, Status>
where
    T: Send + 'static,
    Fut: std::future::Future<Output = arcbox_core::Result<T>>,
    F: FnOnce() -> Fut + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Status::internal(format!("macOS runtime: {e}")))?
            .block_on(f())
            .map_err(|e| Status::internal(e.to_string()))
    })
    .await
    .map_err(|e| Status::internal(format!("macOS task join: {e}")))?
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

        if req.guest_os == "macos" {
            #[cfg(target_os = "macos")]
            {
                self.runtime
                    .ready()?
                    .mac_machine_manager()
                    .create(arcbox_core::MacMachineConfig {
                        name: req.name.clone(),
                        image: req.macos_image,
                        cpus: req.cpus,
                        memory_mib: req.memory / (1024 * 1024),
                    })
                    .map_err(|e| Status::internal(e.to_string()))?;
                return Ok(Response::new(CreateMachineResponse { id: req.name }));
            }
            #[cfg(not(target_os = "macos"))]
            return Err(Status::unimplemented(
                "macOS guests require an Apple Silicon host",
            ));
        }

        // Convert bytes to MB for internal config.
        let memory_mb = req.memory / (1024 * 1024);
        let disk_gb = req.disk_size / (1024 * 1024 * 1024);

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

        #[cfg(target_os = "macos")]
        if runtime.mac_machine_manager().get(&id).is_some() {
            let mgr = std::sync::Arc::clone(runtime.mac_machine_manager());
            let name = id.clone();
            run_macos_blocking(move || async move { mgr.start(&name).await }).await?;
            return Ok(Response::new(Empty {}));
        }

        runtime
            .machine_manager()
            .start(&id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn stop(&self, request: Request<StopMachineRequest>) -> Result<Response<Empty>, Status> {
        let id = request.into_inner().id;
        let runtime = self.runtime.ready()?;

        #[cfg(target_os = "macos")]
        if runtime.mac_machine_manager().get(&id).is_some() {
            let mgr = std::sync::Arc::clone(runtime.mac_machine_manager());
            let name = id.clone();
            run_macos_blocking(move || async move { mgr.stop(&name).await }).await?;
            return Ok(Response::new(Empty {}));
        }

        runtime
            .machine_manager()
            .stop(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let runtime = self.runtime.ready()?;

        #[cfg(target_os = "macos")]
        if runtime.mac_machine_manager().get(&req.id).is_some() {
            let mgr = std::sync::Arc::clone(runtime.mac_machine_manager());
            let name = req.id.clone();
            let force = req.force;
            run_macos_blocking(move || async move { mgr.remove(&name, force).await }).await?;
            return Ok(Response::new(Empty {}));
        }

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

        #[cfg(target_os = "macos")]
        let mac: Vec<MachineSummary> = runtime
            .mac_machine_manager()
            .list()
            .into_iter()
            .map(|m| MachineSummary {
                id: m.name.clone(),
                name: m.name,
                state: format!("{:?}", m.state).to_lowercase(),
                cpus: m.cpus,
                memory: m.memory_mib * 1024 * 1024,
                disk_size: 0,
                ip_address: String::new(),
                created: m.created_at.timestamp(),
                guest_os: "macos".to_string(),
            })
            .collect();
        #[cfg(not(target_os = "macos"))]
        let mac: Vec<MachineSummary> = Vec::new();

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
                guest_os: "linux".to_string(),
            })
            .chain(mac)
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

        #[cfg(target_os = "macos")]
        if let Some(machine) = runtime.mac_machine_manager().get(&id) {
            return Ok(Response::new(MachineInfo {
                id: machine.name.clone(),
                name: machine.name,
                state: format!("{:?}", machine.state).to_lowercase(),
                hardware: Some(arcbox_protocol::v1::MachineHardware {
                    cpus: machine.cpus,
                    memory: machine.memory_mib * 1024 * 1024,
                    arch: std::env::consts::ARCH.to_string(),
                }),
                network: None,
                storage: None,
                os: Some(arcbox_protocol::v1::MachineOs {
                    distro: "macos".to_string(),
                    version: machine.image,
                    kernel: String::new(),
                }),
                created: None,
                started_at: None,
                mounts: vec![],
            }));
        }

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
                ip_address: machine.ip_address.clone().unwrap_or_default(),
                gateway: String::new(),
                mac_address: String::new(),
                dns_servers: vec![],
                bridge_mac_address: arcbox_core::vm::bridge_nic_mac_for_vm_id(&machine.vm_id),
            }),
            storage: Some(arcbox_protocol::v1::MachineStorage {
                disk_size: machine.disk_gb * 1024 * 1024 * 1024,
                disk_format: "raw".to_string(),
                disk_path: String::new(),
            }),
            os: Some(arcbox_protocol::v1::MachineOs {
                distro: machine
                    .distro
                    .clone()
                    .unwrap_or_else(|| "linux".to_string()),
                version: machine.distro_version.clone().unwrap_or_default(),
                kernel: machine.kernel.unwrap_or_default(),
            }),
            created: None,
            started_at: None,
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

    async fn exec(
        &self,
        _request: Request<MachineExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        Err(Status::unimplemented(
            "machine exec is no longer supported by guest agent RPC",
        ))
    }

    async fn ssh_info(
        &self,
        _request: Request<arcbox_protocol::v1::SshInfoRequest>,
    ) -> Result<Response<arcbox_protocol::v1::SshInfoResponse>, Status> {
        // TODO: Implement SSH info.
        Err(Status::unimplemented("ssh_info not implemented"))
    }

    async fn mac_image_pull(
        &self,
        request: Request<MacImagePullRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        #[cfg(target_os = "macos")]
        {
            let mgr = std::sync::Arc::clone(self.runtime.ready()?.mac_machine_manager());
            let name = req.name.clone();
            let ipsw = req.ipsw_path.clone();
            let disk_gb = (req.disk_size / (1024 * 1024 * 1024)).max(64);
            run_macos_blocking(move || async move {
                let mut last = String::new();
                mgr.images()
                    .install_from_ipsw(std::path::Path::new(&ipsw), &name, disk_gb, |frac| {
                        let pct = format!("{:.0}", frac * 100.0);
                        if pct != last {
                            tracing::info!("macOS image install: {pct}%");
                            last = pct;
                        }
                    })
                    .await
            })
            .await?;
            Ok(Response::new(Empty {}))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = req;
            Err(Status::unimplemented(
                "macOS images require an Apple Silicon host",
            ))
        }
    }

    async fn mac_image_list(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<MacImageListResponse>, Status> {
        #[cfg(target_os = "macos")]
        let images: Vec<MacImageSummary> = self
            .runtime
            .ready()?
            .mac_machine_manager()
            .images()
            .list()
            .into_iter()
            .map(|i| MacImageSummary {
                name: i.meta.name,
                minimum_cpu_count: i.meta.minimum_cpu_count,
                minimum_memory_mib: i.meta.minimum_memory_mib,
                disk_gb: i.meta.disk_gb,
                created: i.meta.created_at.timestamp(),
                source: i.meta.source.unwrap_or_default(),
            })
            .collect();
        #[cfg(not(target_os = "macos"))]
        let images: Vec<MacImageSummary> = Vec::new();

        Ok(Response::new(MacImageListResponse { images }))
    }

    async fn mac_image_remove(
        &self,
        request: Request<MacImageRemoveRequest>,
    ) -> Result<Response<Empty>, Status> {
        let name = request.into_inner().name;
        #[cfg(target_os = "macos")]
        {
            self.runtime
                .ready()?
                .mac_machine_manager()
                .images()
                .remove(&name)
                .map_err(|e| Status::internal(e.to_string()))?;
            Ok(Response::new(Empty {}))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = name;
            Err(Status::unimplemented(
                "macOS images require an Apple Silicon host",
            ))
        }
    }
}
