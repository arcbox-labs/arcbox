//! gRPC service implementations.
//!
//! This module implements the gRPC services defined in arcbox-protocol.
//! All types are imported from arcbox_protocol::v1, and service traits
//! are from arcbox_grpc::v1.

use arcbox_core::Runtime;
use arcbox_grpc::v1::machine_service_server;
use arcbox_protocol::v1::{
    CreateMachineRequest, CreateMachineResponse, Empty, InspectMachineRequest,
    ListMachinesRequest, ListMachinesResponse, MachineAgentRequest, MachineExecOutput,
    MachineExecRequest, MachineInfo, MachineNetwork, MachinePingResponse, MachineSummary,
    MachineSystemInfo, RemoveMachineRequest, StartMachineRequest, StopMachineRequest,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

// =============================================================================
// Machine Service
// =============================================================================

/// Machine service implementation.
pub struct MachineServiceImpl {
    runtime: Arc<Runtime>,
}

impl MachineServiceImpl {
    /// Creates a new machine service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
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

        // Convert bytes to MB for internal config.
        let memory_mb = req.memory / (1024 * 1024);
        let disk_gb = req.disk_size / (1024 * 1024 * 1024);

        let config = arcbox_core::machine::MachineConfig {
            name: req.name.clone(),
            cpus: req.cpus,
            memory_mb,
            disk_gb,
            kernel: if req.kernel.is_empty() {
                None
            } else {
                Some(req.kernel)
            },
            initrd: if req.initrd.is_empty() {
                None
            } else {
                Some(req.initrd)
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
        };

        self.runtime
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

        self.runtime
            .machine_manager()
            .start(&id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn stop(&self, request: Request<StopMachineRequest>) -> Result<Response<Empty>, Status> {
        let id = request.into_inner().id;

        self.runtime
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

        self.runtime
            .machine_manager()
            .remove(&req.id, req.force)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn list(
        &self,
        _request: Request<ListMachinesRequest>,
    ) -> Result<Response<ListMachinesResponse>, Status> {
        let machines = self.runtime.machine_manager().list();

        let summaries: Vec<_> = machines
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

        let machine = self
            .runtime
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
                kernel: machine.kernel.clone().unwrap_or_default(),
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

    type ExecStream =
        Pin<Box<dyn Stream<Item = Result<MachineExecOutput, Status>> + Send + 'static>>;

    async fn exec(
        &self,
        request: Request<MachineExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let req = request.into_inner();
        let machine_name = req.id;

        // Build exec request for agent.
        let agent_req = arcbox_protocol::v1::AgentExecRequest {
            container_id: String::new(),
            cmd: req.cmd,
            env: req.env,
            working_dir: req.working_dir,
            user: req.user,
            tty: req.tty,
        };

        let mut agent = self
            .runtime
            .get_agent(&machine_name)
            .map_err(|e| Status::internal(format!("machine error: {e}")))?;

        let stream = async_stream::try_stream! {
            let output = agent
                .exec(agent_req)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            if !output.data.is_empty() {
                yield MachineExecOutput {
                    stream: output.stream.clone(),
                    data: output.data.clone(),
                    exit_code: 0,
                    done: false,
                };
            }

            yield MachineExecOutput {
                stream: String::new(),
                data: Vec::new(),
                exit_code: output.exit_code,
                done: true,
            };
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn ssh_info(
        &self,
        request: Request<arcbox_protocol::v1::SshInfoRequest>,
    ) -> Result<Response<arcbox_protocol::v1::SshInfoResponse>, Status> {
        // TODO: Implement SSH info.
        Err(Status::unimplemented("ssh_info not implemented"))
    }
}

