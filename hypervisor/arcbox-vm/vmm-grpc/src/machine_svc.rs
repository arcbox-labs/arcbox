use std::sync::Arc;

use tonic::{Request, Response, Status};

use vmm_core::{VmmManager, config::VmSpec};

use crate::proto::arcbox::{
    machine_service_server::MachineService, CreateMachineRequest, CreateMachineResponse,
    InspectMachineRequest, ListMachinesRequest, ListMachinesResponse, MachineAgentRequest,
    MachineExecOutput, MachineExecRequest, MachineInfo, MachineHardware, MachineNetwork,
    MachineStorage, MachinePingResponse, MachineSystemInfo, MachineSummary, RemoveMachineRequest,
    SshInfoRequest, SshInfoResponse, StartMachineRequest, StopMachineRequest,
};
use crate::proto::arcbox::Empty;

/// Implementation of `arcbox.v1.MachineService` backed by [`VmmManager`].
pub struct MachineServiceImpl {
    manager: Arc<VmmManager>,
}

impl MachineServiceImpl {
    pub fn new(manager: Arc<VmmManager>) -> Self {
        Self { manager }
    }
}

#[tonic::async_trait]
impl MachineService for MachineServiceImpl {
    /// Create and boot a new VM.
    async fn create(
        &self,
        request: Request<CreateMachineRequest>,
    ) -> Result<Response<CreateMachineResponse>, Status> {
        let req = request.into_inner();
        let spec = VmSpec {
            name: req.name.clone(),
            vcpus: if req.cpus > 0 { req.cpus as u64 } else { 1 },
            memory_mib: if req.memory > 0 {
                req.memory / (1024 * 1024)
            } else {
                512
            },
            kernel: if req.kernel.is_empty() {
                self.manager_config_kernel()
            } else {
                req.kernel.clone()
            },
            rootfs: String::new(), // Provisioned via distro/version resolution (future)
            boot_args: if req.cmdline.is_empty() {
                "console=ttyS0 reboot=k panic=1 pci=off".into()
            } else {
                req.cmdline.clone()
            },
            disk_size: if req.disk_size > 0 {
                Some(req.disk_size)
            } else {
                None
            },
            ssh_public_key: if req.ssh_public_key.is_empty() {
                None
            } else {
                Some(req.ssh_public_key)
            },
        };

        let id = self
            .manager
            .create_vm(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateMachineResponse { id }))
    }

    /// Start a stopped VM.
    async fn start(
        &self,
        request: Request<StartMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .start_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Stop a running VM.
    async fn stop(
        &self,
        request: Request<StopMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .stop_vm(&req.id, req.force)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Remove a VM.
    async fn remove(
        &self,
        request: Request<RemoveMachineRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .remove_vm(&req.id, req.force)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// List VMs.
    async fn list(
        &self,
        request: Request<ListMachinesRequest>,
    ) -> Result<Response<ListMachinesResponse>, Status> {
        let req = request.into_inner();
        let vms = self
            .manager
            .list_vms(req.all)
            .map_err(|e| Status::internal(e.to_string()))?;

        let machines = vms
            .into_iter()
            .map(|s| MachineSummary {
                id: s.id,
                name: s.name,
                state: s.state.to_string(),
                cpus: s.vcpus as u32,
                memory: s.memory_mib * 1024 * 1024,
                disk_size: 0,
                ip_address: s.ip_address.unwrap_or_default(),
                created: s.created_at.timestamp(),
            })
            .collect();

        Ok(Response::new(ListMachinesResponse { machines }))
    }

    /// Inspect a VM.
    async fn inspect(
        &self,
        request: Request<InspectMachineRequest>,
    ) -> Result<Response<MachineInfo>, Status> {
        let req = request.into_inner();
        let info = self
            .manager
            .inspect_vm(&req.id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let net = info.network.as_ref();
        Ok(Response::new(MachineInfo {
            id: info.id.clone(),
            name: info.name,
            state: info.state.to_string(),
            hardware: Some(MachineHardware {
                cpus: info.spec.vcpus as u32,
                memory: info.spec.memory_mib * 1024 * 1024,
                arch: std::env::consts::ARCH.into(),
            }),
            network: Some(MachineNetwork {
                ip_address: net.map(|n| n.ip_address.to_string()).unwrap_or_default(),
                gateway: net.map(|n| n.gateway.to_string()).unwrap_or_default(),
                mac_address: net.map(|n| n.mac_address.clone()).unwrap_or_default(),
                dns_servers: net
                    .map(|n| n.dns_servers.clone())
                    .unwrap_or_default(),
            }),
            storage: Some(MachineStorage {
                disk_size: info.spec.disk_size.unwrap_or(0),
                disk_format: "ext4".into(),
                disk_path: info.spec.rootfs.clone(),
            }),
            os: None,
            created: Some(crate::timestamp(info.created_at)),
            started_at: info.started_at.map(crate::timestamp),
            mounts: vec![],
        }))
    }

    /// Guest agent ping (not yet implemented — vsock future work).
    async fn ping(
        &self,
        _request: Request<MachineAgentRequest>,
    ) -> Result<Response<MachinePingResponse>, Status> {
        Err(Status::unimplemented("vsock agent not yet implemented"))
    }

    /// Guest system info (not yet implemented — vsock future work).
    async fn get_system_info(
        &self,
        _request: Request<MachineAgentRequest>,
    ) -> Result<Response<MachineSystemInfo>, Status> {
        Err(Status::unimplemented("vsock agent not yet implemented"))
    }

    type ExecStream = tokio_stream::wrappers::ReceiverStream<Result<MachineExecOutput, Status>>;

    /// Exec in guest (not yet implemented — vsock future work).
    async fn exec(
        &self,
        _request: Request<MachineExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        Err(Status::unimplemented("vsock agent not yet implemented"))
    }

    /// SSH connection info.
    async fn ssh_info(
        &self,
        request: Request<SshInfoRequest>,
    ) -> Result<Response<SshInfoResponse>, Status> {
        let req = request.into_inner();
        let info = self
            .manager
            .inspect_vm(&req.id)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let ip = info
            .network
            .as_ref()
            .map(|n| n.ip_address.to_string())
            .unwrap_or_default();

        Ok(Response::new(SshInfoResponse {
            host: ip.clone(),
            port: 22,
            user: "root".into(),
            identity_file: String::new(),
            command: format!("ssh root@{ip}"),
        }))
    }

}

impl MachineServiceImpl {
    fn manager_config_kernel(&self) -> String {
        // Fall back to empty string so VmmManager uses its configured default.
        String::new()
    }
}
