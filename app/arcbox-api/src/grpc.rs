//! gRPC service implementations.
//!
//! This module implements the gRPC services defined in arcbox-protocol.
//! All types are imported from arcbox_protocol::v1, and service traits
//! are from arcbox_grpc::v1.

use arcbox_container::{ContainerConfig, ContainerId, ContainerState};
use arcbox_core::Runtime;
use arcbox_grpc::v1::{
    container_service_server, image_service_server, machine_service_server, network_service_server,
    system_service_server,
};
use arcbox_image::{ImagePuller, ImageRef, RegistryClient};
use arcbox_protocol::v1::{
    ContainerInfo, ContainerState as ProtoContainerState, ContainerSummary, CreateContainerRequest,
    CreateContainerResponse, CreateMachineRequest, CreateMachineResponse, CreateNetworkRequest,
    CreateNetworkResponse, Empty, ExecOutput, GetInfoRequest, GetInfoResponse, GetVersionRequest,
    GetVersionResponse, ImageInfo, ImageSummary, InspectContainerRequest, InspectImageRequest,
    InspectMachineRequest, InspectNetworkRequest, ListContainersRequest, ListContainersResponse,
    ListImagesRequest, ListImagesResponse, ListMachinesRequest, ListMachinesResponse,
    ListNetworksRequest, ListNetworksResponse, LogEntry, LogsRequest, MachineAgentRequest,
    MachineExecOutput, MachineExecRequest, MachineInfo, MachineNetwork, MachinePingResponse,
    MachineSummary, MachineSystemInfo, NetworkInfo, NetworkSummary, PullImageRequest, PullProgress,
    RemoveContainerRequest, RemoveImageRequest, RemoveImageResponse, RemoveMachineRequest,
    RemoveNetworkRequest, StartContainerRequest, StartMachineRequest, StopContainerRequest,
    StopMachineRequest, SystemPingRequest, SystemPingResponse, TagImageRequest,
    WaitContainerRequest, WaitContainerResponse,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

// =============================================================================
// Container Service
// =============================================================================

/// Container service implementation.
pub struct ContainerServiceImpl {
    runtime: Arc<Runtime>,
}

impl ContainerServiceImpl {
    /// Creates a new container service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl container_service_server::ContainerService for ContainerServiceImpl {
    async fn create(
        &self,
        request: Request<CreateContainerRequest>,
    ) -> Result<Response<CreateContainerResponse>, Status> {
        let req = request.into_inner();

        let config = ContainerConfig {
            name: if req.name.is_empty() {
                None
            } else {
                Some(req.name)
            },
            image: req.image,
            cmd: req.cmd,
            entrypoint: req.entrypoint,
            env: req.env,
            working_dir: if req.working_dir.is_empty() {
                None
            } else {
                Some(req.working_dir)
            },
            user: if req.user.is_empty() {
                None
            } else {
                Some(req.user)
            },
            labels: req.labels,
            ..Default::default()
        };

        let id = self
            .runtime
            .container_manager()
            .create(config)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateContainerResponse {
            id: id.to_string(),
            warnings: vec![],
        }))
    }

    async fn start(
        &self,
        request: Request<StartContainerRequest>,
    ) -> Result<Response<Empty>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        let container = self
            .runtime
            .container_manager()
            .get(&id)
            .ok_or_else(|| Status::not_found("container not found"))?;

        let machine_name = container
            .machine_name
            .clone()
            .unwrap_or_else(|| self.runtime.default_machine_name().to_string());

        self.runtime
            .start_container(&machine_name, &id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn stop(
        &self,
        request: Request<StopContainerRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let id = ContainerId::from_string(req.id);
        let timeout = req.timeout;

        self.runtime
            .container_manager()
            .stop(&id, timeout)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn kill(
        &self,
        request: Request<arcbox_protocol::v1::KillContainerRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let id = ContainerId::from_string(req.id);

        // Kill with SIGKILL by default.
        self.runtime
            .container_manager()
            .stop(&id, 0)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn remove(
        &self,
        request: Request<RemoveContainerRequest>,
    ) -> Result<Response<Empty>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        self.runtime
            .container_manager()
            .remove(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn list(
        &self,
        request: Request<ListContainersRequest>,
    ) -> Result<Response<ListContainersResponse>, Status> {
        let req = request.into_inner();

        let containers = self.runtime.container_manager().list();

        // Filter based on 'all' flag (only running if not all).
        let filtered: Vec<_> = containers
            .into_iter()
            .filter(|c| req.all || c.state == ContainerState::Running)
            .take(if req.limit > 0 {
                req.limit as usize
            } else {
                usize::MAX
            })
            .map(|c| ContainerSummary {
                id: c.id.to_string(),
                names: vec![c.name],
                image: c.image.clone(),
                image_id: String::new(),
                command: String::new(),
                created: c.created.timestamp(),
                state: format_container_state(&c.state),
                status: format_container_status(&c.state, c.exit_code),
                ports: vec![],
                labels: std::collections::HashMap::new(),
                size_rw: 0,
                size_root_fs: 0,
            })
            .collect();

        Ok(Response::new(ListContainersResponse {
            containers: filtered,
        }))
    }

    async fn inspect(
        &self,
        request: Request<InspectContainerRequest>,
    ) -> Result<Response<ContainerInfo>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        let container = self
            .runtime
            .container_manager()
            .get(&id)
            .ok_or_else(|| Status::not_found("container not found"))?;

        Ok(Response::new(ContainerInfo {
            id: container.id.to_string(),
            name: container.name,
            created: None, // TODO: convert DateTime to Timestamp
            path: String::new(),
            args: vec![],
            state: Some(ProtoContainerState {
                status: format_container_state(&container.state),
                running: container.state == ContainerState::Running,
                paused: container.state == ContainerState::Paused,
                restarting: container.state == ContainerState::Restarting,
                oom_killed: false,
                dead: container.state == ContainerState::Dead,
                pid: 0,
                exit_code: container.exit_code.unwrap_or(0),
                error: String::new(),
                started_at: container
                    .started_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
                finished_at: container
                    .finished_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
            }),
            image: container.image,
            config: None,
            network_settings: None,
            mounts: vec![],
        }))
    }

    type LogsStream = Pin<Box<dyn Stream<Item = Result<LogEntry, Status>> + Send + 'static>>;

    async fn logs(
        &self,
        request: Request<LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let req = request.into_inner();
        let container_id = ContainerId::from_string(&req.container_id);

        // Get container to find its machine.
        let container = self
            .runtime
            .container_manager()
            .get(&container_id)
            .ok_or_else(|| Status::not_found("container not found"))?;

        let machine_name = container
            .machine_name
            .unwrap_or_else(|| self.runtime.default_machine_name().to_string());

        let runtime = Arc::clone(&self.runtime);
        let follow = req.follow;
        let stdout = req.stdout;
        let stderr = req.stderr;
        let since = req.since;
        let until = req.until;
        let timestamps = req.timestamps;
        let tail = req.tail.parse::<i64>().unwrap_or(0);

        let stream = async_stream::try_stream! {
            if follow {
                let mut log_stream = runtime
                    .container_logs_stream(
                        &machine_name,
                        &container_id.to_string(),
                        stdout,
                        stderr,
                        since,
                        until,
                        timestamps,
                        tail,
                    )
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;

                use tokio_stream::StreamExt;
                while let Some(result) = log_stream.next().await {
                    match result {
                        Ok(entry) => {
                            yield LogEntry {
                                stream: entry.stream,
                                message: entry.message,
                                timestamp: None, // TODO: convert to Timestamp
                            };
                        }
                        Err(e) => {
                            Err(Status::internal(e.to_string()))?;
                        }
                    }
                }
            } else {
                let entry = runtime
                    .container_logs(
                        &machine_name,
                        &container_id.to_string(),
                        false,
                        stdout,
                        stderr,
                        since,
                        until,
                        timestamps,
                        tail,
                    )
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;

                yield LogEntry {
                    stream: entry.stream,
                    message: entry.message,
                    timestamp: None,
                };
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn exec_create(
        &self,
        request: Request<arcbox_protocol::v1::ExecCreateRequest>,
    ) -> Result<Response<arcbox_protocol::v1::ExecCreateResponse>, Status> {
        // Simplified exec create - just return an ID.
        let req = request.into_inner();
        let exec_id = format!("exec-{}", uuid::Uuid::new_v4());
        Ok(Response::new(arcbox_protocol::v1::ExecCreateResponse {
            id: exec_id,
        }))
    }

    type ExecStartStream = Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    async fn exec_start(
        &self,
        request: Request<arcbox_protocol::v1::ExecStartRequest>,
    ) -> Result<Response<Self::ExecStartStream>, Status> {
        let req = request.into_inner();

        // Return empty stream for now.
        let stream = async_stream::try_stream! {
            yield ExecOutput {
                stream: "stdout".to_string(),
                data: Vec::new(),
            };
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type AttachStream = Pin<
        Box<dyn Stream<Item = Result<arcbox_protocol::v1::AttachOutput, Status>> + Send + 'static>,
    >;

    async fn attach(
        &self,
        request: Request<tonic::Streaming<arcbox_protocol::v1::AttachInput>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        // Return empty stream for now.
        let stream = async_stream::try_stream! {
            yield arcbox_protocol::v1::AttachOutput {
                stream: "stdout".to_string(),
                data: Vec::new(),
            };
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn wait(
        &self,
        request: Request<WaitContainerRequest>,
    ) -> Result<Response<WaitContainerResponse>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        match self.runtime.container_manager().wait_async(&id).await {
            Ok(exit_code) => Ok(Response::new(WaitContainerResponse {
                status_code: i64::from(exit_code),
                error: String::new(),
            })),
            Err(e) => {
                let error_str = e.to_string();
                if error_str.contains("not found") {
                    Err(Status::not_found(error_str))
                } else {
                    Err(Status::internal(error_str))
                }
            }
        }
    }

    async fn pause(
        &self,
        request: Request<arcbox_protocol::v1::PauseContainerRequest>,
    ) -> Result<Response<Empty>, Status> {
        // TODO: Implement pause.
        Err(Status::unimplemented("pause not implemented"))
    }

    async fn unpause(
        &self,
        request: Request<arcbox_protocol::v1::UnpauseContainerRequest>,
    ) -> Result<Response<Empty>, Status> {
        // TODO: Implement unpause.
        Err(Status::unimplemented("unpause not implemented"))
    }

    async fn stats(
        &self,
        request: Request<arcbox_protocol::v1::ContainerStatsRequest>,
    ) -> Result<Response<arcbox_protocol::v1::ContainerStatsResponse>, Status> {
        // TODO: Implement stats.
        Err(Status::unimplemented("stats not implemented"))
    }

    async fn top(
        &self,
        request: Request<arcbox_protocol::v1::ContainerTopRequest>,
    ) -> Result<Response<arcbox_protocol::v1::ContainerTopResponse>, Status> {
        // TODO: Implement top.
        Err(Status::unimplemented("top not implemented"))
    }
}

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

// =============================================================================
// Image Service
// =============================================================================

/// Channel-based pull progress reporter for gRPC streaming.
struct ChannelPullProgress {
    tx: tokio::sync::mpsc::Sender<Result<PullProgress, Status>>,
}

impl ChannelPullProgress {
    fn new(tx: tokio::sync::mpsc::Sender<Result<PullProgress, Status>>) -> Self {
        Self { tx }
    }

    fn short_digest(digest: &str) -> String {
        let s = digest.strip_prefix("sha256:").unwrap_or(digest);
        s[..12.min(s.len())].to_string()
    }
}

impl arcbox_image::PullProgress for ChannelPullProgress {
    fn layer_start(&self, digest: &str, size: u64) {
        let short = Self::short_digest(digest);
        let tx = self.tx.clone();
        let _ = tx.try_send(Ok(PullProgress {
            id: digest.to_string(),
            status: format!("Downloading {short}"),
            progress: String::new(),
            current: 0,
            total: size as i64,
        }));
    }

    fn layer_progress(&self, digest: &str, downloaded: u64, total: u64) {
        let short = Self::short_digest(digest);
        let tx = self.tx.clone();
        let _ = tx.try_send(Ok(PullProgress {
            id: digest.to_string(),
            status: format!("Downloading {short}"),
            progress: format!("{downloaded}/{total}"),
            current: downloaded as i64,
            total: total as i64,
        }));
    }

    fn layer_complete(&self, digest: &str) {
        let short = Self::short_digest(digest);
        let tx = self.tx.clone();
        let _ = tx.try_send(Ok(PullProgress {
            id: digest.to_string(),
            status: format!("Downloaded {short}"),
            progress: "complete".to_string(),
            current: 0,
            total: 0,
        }));
    }

    fn complete(&self, image_id: &str) {
        let tx = self.tx.clone();
        let _ = tx.try_send(Ok(PullProgress {
            id: image_id.to_string(),
            status: "Pull complete".to_string(),
            progress: String::new(),
            current: 0,
            total: 0,
        }));
    }
}

/// Image service implementation.
pub struct ImageServiceImpl {
    runtime: Arc<Runtime>,
}

impl ImageServiceImpl {
    /// Creates a new image service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl image_service_server::ImageService for ImageServiceImpl {
    type PullStream = Pin<Box<dyn Stream<Item = Result<PullProgress, Status>> + Send + 'static>>;

    async fn pull(
        &self,
        request: Request<PullImageRequest>,
    ) -> Result<Response<Self::PullStream>, Status> {
        let req = request.into_inner();

        let image_ref = ImageRef::parse(&req.reference)
            .ok_or_else(|| Status::invalid_argument("invalid image reference"))?;

        let store = self.runtime.image_store().clone();
        let registry = image_ref.registry.clone();

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<PullProgress, Status>>(32);
        let progress = ChannelPullProgress::new(tx.clone());

        tokio::spawn(async move {
            let client = RegistryClient::new(&registry);
            let puller = ImagePuller::new(store, client).with_progress(progress);

            match puller.pull(&image_ref).await {
                Ok(image_id) => {
                    let _ = tx
                        .send(Ok(PullProgress {
                            id: image_id,
                            status: "Pull complete".to_string(),
                            progress: String::new(),
                            current: 0,
                            total: 0,
                        }))
                        .await;
                }
                Err(e) => {
                    let _ = tx
                        .send(Ok(PullProgress {
                            id: String::new(),
                            status: format!("Error: {}", e),
                            progress: String::new(),
                            current: 0,
                            total: 0,
                        }))
                        .await;
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    type PushStream = Pin<
        Box<dyn Stream<Item = Result<arcbox_protocol::v1::PushProgress, Status>> + Send + 'static>,
    >;

    async fn push(
        &self,
        request: Request<arcbox_protocol::v1::PushImageRequest>,
    ) -> Result<Response<Self::PushStream>, Status> {
        // TODO: Implement push.
        Err(Status::unimplemented("push not implemented"))
    }

    async fn list(
        &self,
        _request: Request<ListImagesRequest>,
    ) -> Result<Response<ListImagesResponse>, Status> {
        let images = self.runtime.image_store().list();

        let summaries: Vec<_> = images
            .into_iter()
            .map(|img| ImageSummary {
                id: img.id.clone(),
                repo_tags: vec![img.reference.full_name()],
                repo_digests: vec![],
                created: img.created.timestamp(),
                size: img.size as i64,
                virtual_size: img.size as i64,
                containers: 0,
                labels: std::collections::HashMap::new(),
            })
            .collect();

        Ok(Response::new(ListImagesResponse { images: summaries }))
    }

    async fn inspect(
        &self,
        request: Request<InspectImageRequest>,
    ) -> Result<Response<ImageInfo>, Status> {
        let req = request.into_inner();

        // InspectImageRequest uses 'id' field, not 'reference'.
        let image_ref = ImageRef::parse(&req.id)
            .ok_or_else(|| Status::invalid_argument("invalid image reference"))?;

        let image = self
            .runtime
            .image_store()
            .get(&image_ref)
            .ok_or_else(|| Status::not_found("image not found"))?;

        Ok(Response::new(ImageInfo {
            id: image.id.clone(),
            repo_tags: vec![image.reference.full_name()],
            repo_digests: vec![],
            parent: String::new(),
            comment: String::new(),
            created: image.created.to_rfc3339(),
            author: String::new(),
            architecture: std::env::consts::ARCH.to_string(),
            os: "linux".to_string(),
            os_version: String::new(),
            size: image.size as i64,
            virtual_size: image.size as i64,
            config: None,
            root_fs: None,
        }))
    }

    async fn remove(
        &self,
        request: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        let req = request.into_inner();

        // RemoveImageRequest uses 'id' field, not 'reference'.
        let image_ref = ImageRef::parse(&req.id)
            .ok_or_else(|| Status::invalid_argument("invalid image reference"))?;

        self.runtime
            .image_store()
            .remove(&image_ref)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RemoveImageResponse {
            deleted: vec![req.id],
            untagged: vec![],
        }))
    }

    async fn tag(&self, request: Request<TagImageRequest>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();

        let source = ImageRef::parse(&req.source)
            .ok_or_else(|| Status::invalid_argument("invalid source reference"))?;

        let target_str = if req.tag.is_empty() {
            format!("{}:latest", req.repo)
        } else {
            format!("{}:{}", req.repo, req.tag)
        };
        let target = ImageRef::parse(&target_str)
            .ok_or_else(|| Status::invalid_argument("invalid target reference"))?;

        self.runtime
            .image_store()
            .tag(&source, &target)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    type BuildStream = Pin<
        Box<dyn Stream<Item = Result<arcbox_protocol::v1::BuildProgress, Status>> + Send + 'static>,
    >;

    async fn build(
        &self,
        request: Request<tonic::Streaming<arcbox_protocol::v1::BuildContext>>,
    ) -> Result<Response<Self::BuildStream>, Status> {
        // TODO: Implement build.
        Err(Status::unimplemented("build not implemented"))
    }

    async fn exists(
        &self,
        request: Request<arcbox_protocol::v1::ExistsImageRequest>,
    ) -> Result<Response<arcbox_protocol::v1::ExistsImageResponse>, Status> {
        let req = request.into_inner();

        // ExistsImageRequest uses 'reference' field.
        let image_ref = ImageRef::parse(&req.reference)
            .ok_or_else(|| Status::invalid_argument("invalid image reference"))?;

        let image = self.runtime.image_store().get(&image_ref);
        let (exists, id) = match image {
            Some(img) => (true, img.id.clone()),
            None => (false, String::new()),
        };

        Ok(Response::new(arcbox_protocol::v1::ExistsImageResponse {
            exists,
            id,
        }))
    }
}

// =============================================================================
// System Service
// =============================================================================

/// System service implementation.
pub struct SystemServiceImpl {
    runtime: Arc<Runtime>,
}

impl SystemServiceImpl {
    /// Creates a new system service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl system_service_server::SystemService for SystemServiceImpl {
    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        let containers = self.runtime.container_manager().list();
        let images = self.runtime.image_store().list();
        let machines = self.runtime.machine_manager().list();

        let running = containers
            .iter()
            .filter(|c| c.state == ContainerState::Running)
            .count() as i64;
        let paused = containers
            .iter()
            .filter(|c| c.state == ContainerState::Paused)
            .count() as i64;
        let stopped = containers.len() as i64 - running - paused;

        let machines_running = machines
            .iter()
            .filter(|m| m.state == arcbox_core::machine::MachineState::Running)
            .count() as i64;

        Ok(Response::new(GetInfoResponse {
            containers: containers.len() as i64,
            containers_running: running,
            containers_paused: paused,
            containers_stopped: stopped,
            images: images.len() as i64,
            machines: machines.len() as i64,
            machines_running,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            mem_total: total_memory(),
            ncpu: num_cpus(),
            data_dir: self.runtime.config().data_dir.to_string_lossy().to_string(),
            kernel_version: String::new(),
            os_type: std::env::consts::OS.to_string(),
            logging_driver: "json-file".to_string(),
            storage_driver: "overlay2".to_string(),
        }))
    }

    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: "1.0.0".to_string(),
            min_api_version: "1.0.0".to_string(),
            git_commit: option_env!("ARCBOX_GIT_COMMIT")
                .unwrap_or("unknown")
                .to_string(),
            build_time: option_env!("ARCBOX_BUILD_TIME")
                .unwrap_or("unknown")
                .to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            go_version: String::new(), // N/A for Rust
        }))
    }

    async fn ping(
        &self,
        _request: Request<SystemPingRequest>,
    ) -> Result<Response<SystemPingResponse>, Status> {
        Ok(Response::new(SystemPingResponse {
            api_version: "1.0.0".to_string(),
            build_version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    type EventsStream =
        Pin<Box<dyn Stream<Item = Result<arcbox_protocol::v1::Event, Status>> + Send + 'static>>;

    async fn events(
        &self,
        request: Request<arcbox_protocol::v1::EventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        // TODO: Implement events stream.
        Err(Status::unimplemented("events not implemented"))
    }

    async fn prune(
        &self,
        request: Request<arcbox_protocol::v1::PruneRequest>,
    ) -> Result<Response<arcbox_protocol::v1::PruneResponse>, Status> {
        // TODO: Implement prune.
        Err(Status::unimplemented("prune not implemented"))
    }
}

// =============================================================================
// Network Service
// =============================================================================

/// Network service implementation.
pub struct NetworkServiceImpl {
    runtime: Arc<Runtime>,
}

impl NetworkServiceImpl {
    /// Creates a new network service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

#[tonic::async_trait]
impl network_service_server::NetworkService for NetworkServiceImpl {
    async fn create(
        &self,
        request: Request<CreateNetworkRequest>,
    ) -> Result<Response<CreateNetworkResponse>, Status> {
        let req = request.into_inner();

        let driver = if req.driver.is_empty() {
            None
        } else {
            Some(req.driver.as_str())
        };

        let id = self
            .runtime
            .network_manager()
            .create_network(&req.name, driver, req.labels)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateNetworkResponse {
            id,
            warnings: vec![],
        }))
    }

    async fn remove(
        &self,
        request: Request<RemoveNetworkRequest>,
    ) -> Result<Response<Empty>, Status> {
        let id = request.into_inner().id;

        self.runtime
            .network_manager()
            .remove_network(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(Empty {}))
    }

    async fn list(
        &self,
        _request: Request<ListNetworksRequest>,
    ) -> Result<Response<ListNetworksResponse>, Status> {
        let networks = self.runtime.network_manager().list_networks();

        let summaries: Vec<_> = networks
            .into_iter()
            .map(|n| NetworkSummary {
                id: n.id,
                name: n.name,
                driver: n.driver,
                scope: n.scope,
                created: n.created.to_rfc3339(),
                internal: n.internal,
                attachable: n.attachable,
                labels: n.labels,
            })
            .collect();

        Ok(Response::new(ListNetworksResponse {
            networks: summaries,
        }))
    }

    async fn inspect(
        &self,
        request: Request<InspectNetworkRequest>,
    ) -> Result<Response<NetworkInfo>, Status> {
        let id = request.into_inner().id;

        let network = self
            .runtime
            .network_manager()
            .get_network(&id)
            .ok_or_else(|| Status::not_found("network not found"))?;

        Ok(Response::new(NetworkInfo {
            id: network.id,
            name: network.name,
            driver: network.driver,
            scope: network.scope,
            created: network.created.to_rfc3339(),
            internal: network.internal,
            attachable: network.attachable,
            labels: network.labels,
            ipam: None,
            containers: std::collections::HashMap::new(),
            options: std::collections::HashMap::new(),
        }))
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Formats a container status string.
fn format_container_status(state: &ContainerState, exit_code: Option<i32>) -> String {
    match state {
        ContainerState::Created => "Created".to_string(),
        ContainerState::Starting => "Created".to_string(),
        ContainerState::Running => "Up".to_string(),
        ContainerState::Paused => "Paused".to_string(),
        ContainerState::Restarting => "Restarting".to_string(),
        ContainerState::Exited => {
            format!("Exited ({})", exit_code.unwrap_or(0))
        }
        ContainerState::Removing => "Removing".to_string(),
        ContainerState::Dead => "Dead".to_string(),
    }
}

fn format_container_state(state: &ContainerState) -> String {
    match state {
        ContainerState::Starting => "created".to_string(),
        _ => state.to_string(),
    }
}

/// Returns the number of CPUs.
fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(1)
}

/// Returns total system memory in bytes.
fn total_memory() -> i64 {
    #[cfg(target_os = "macos")]
    {
        let mut size: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        let mut mib = [libc::CTL_HW, libc::HW_MEMSIZE];

        // SAFETY: sysctl is called with valid parameters.
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                std::ptr::addr_of_mut!(size).cast::<libc::c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };

        if ret == 0 { size as i64 } else { 0 }
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;

        fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|line| line.starts_with("MemTotal:"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<i64>().ok())
                    })
            })
            .map(|kb| kb * 1024)
            .unwrap_or(0)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}
