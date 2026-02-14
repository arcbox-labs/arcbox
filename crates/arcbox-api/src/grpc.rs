//! gRPC service implementations.

use crate::generated::{
    ContainerLogsRequest, ContainerState as ProtoContainerState, ContainerSummary,
    CreateContainerRequest, CreateContainerResponse, CreateMachineRequest, CreateMachineResponse,
    CreateNetworkRequest, CreateNetworkResponse, ExecContainerRequest, ExecMachineRequest,
    ExecOutput, GetInfoRequest, GetInfoResponse, GetVersionRequest, GetVersionResponse,
    InspectContainerRequest, InspectContainerResponse, InspectImageRequest, InspectImageResponse,
    InspectMachineRequest, InspectMachineResponse, InspectNetworkRequest, InspectNetworkResponse,
    ListContainersRequest, ListContainersResponse, ListImagesRequest, ListImagesResponse,
    ListMachinesRequest, ListMachinesResponse, ListNetworksRequest, ListNetworksResponse, LogEntry,
    MachineSummary, Mount, NetworkSummary, PingRequest, PingResponse, PortBinding,
    PullImageRequest, PullProgress, RemoveContainerRequest, RemoveContainerResponse,
    RemoveImageRequest, RemoveImageResponse, RemoveMachineRequest, RemoveMachineResponse,
    RemoveNetworkRequest, RemoveNetworkResponse, ShellInput, ShellOutput, StartContainerRequest,
    StartContainerResponse, StartMachineRequest, StartMachineResponse, StopContainerRequest,
    StopContainerResponse, StopMachineRequest, StopMachineResponse, TagImageRequest,
    TagImageResponse, WaitContainerRequest, WaitContainerResponse, container_service_server,
    image_service_server, machine_service_server, network_service_server, system_service_server,
};
use arcbox_container::{ContainerConfig, ContainerId, ContainerState};
use arcbox_core::Runtime;
use arcbox_image::{ImagePuller, ImageRef, RegistryClient};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

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
    async fn create_container(
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

    async fn start_container(
        &self,
        request: Request<StartContainerRequest>,
    ) -> Result<Response<StartContainerResponse>, Status> {
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

        Ok(Response::new(StartContainerResponse {}))
    }

    async fn stop_container(
        &self,
        request: Request<StopContainerRequest>,
    ) -> Result<Response<StopContainerResponse>, Status> {
        let req = request.into_inner();
        let id = ContainerId::from_string(req.id);
        let timeout = req.timeout;

        self.runtime
            .container_manager()
            .stop(&id, timeout)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(StopContainerResponse {}))
    }

    async fn remove_container(
        &self,
        request: Request<RemoveContainerRequest>,
    ) -> Result<Response<RemoveContainerResponse>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        self.runtime
            .container_manager()
            .remove(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RemoveContainerResponse {}))
    }

    async fn list_containers(
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
                name: c.name,
                image: c.image,
                state: format_container_state(&c.state),
                status: format_container_status(&c.state, c.exit_code),
                created: c.created.timestamp(),
                ports: vec![],
                labels: std::collections::HashMap::new(),
            })
            .collect();

        Ok(Response::new(ListContainersResponse {
            containers: filtered,
        }))
    }

    async fn inspect_container(
        &self,
        request: Request<InspectContainerRequest>,
    ) -> Result<Response<InspectContainerResponse>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        let container = self
            .runtime
            .container_manager()
            .get(&id)
            .ok_or_else(|| Status::not_found("container not found"))?;

        // Extract config fields if available
        let (cmd, entrypoint, env, working_dir, mounts, ports, labels) =
            if let Some(ref config) = container.config {
                (
                    config.cmd.clone(),
                    config.entrypoint.clone(),
                    config.env.clone(),
                    config.working_dir.clone().unwrap_or_default(),
                    config
                        .volumes
                        .iter()
                        .map(|v| Mount {
                            source: v.source.clone(),
                            target: v.target.clone(),
                            r#type: "bind".to_string(),
                            readonly: v.read_only,
                        })
                        .collect(),
                    // Parse exposed ports in format "port/protocol" to PortBinding
                    config
                        .exposed_ports
                        .iter()
                        .filter_map(|p| {
                            let parts: Vec<&str> = p.split('/').collect();
                            parts.first().and_then(|port_str| {
                                port_str.parse::<u32>().ok().map(|port| PortBinding {
                                    container_port: port,
                                    host_port: port,
                                    protocol: parts.get(1).unwrap_or(&"tcp").to_string(),
                                    host_ip: String::new(),
                                })
                            })
                        })
                        .collect(),
                    config.labels.clone(),
                )
            } else {
                (
                    vec![],
                    vec![],
                    std::collections::HashMap::new(),
                    String::new(),
                    vec![],
                    vec![],
                    std::collections::HashMap::new(),
                )
            };

        Ok(Response::new(InspectContainerResponse {
            id: container.id.to_string(),
            name: container.name,
            image: container.image,
            created: container.created.timestamp(),
            state: Some(ProtoContainerState {
                status: format_container_state(&container.state),
                running: container.state == ContainerState::Running,
                paused: container.state == ContainerState::Paused,
                restarting: container.state == ContainerState::Restarting,
                dead: container.state == ContainerState::Dead,
                pid: 0, // PID is managed by guest agent, not tracked on host
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
            cmd,
            entrypoint,
            env,
            working_dir,
            mounts,
            ports,
            labels,
        }))
    }

    async fn wait_container(
        &self,
        request: Request<WaitContainerRequest>,
    ) -> Result<Response<WaitContainerResponse>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        // Wait for container to exit asynchronously.
        // Uses broadcast channel to efficiently wait for state changes.
        match self.runtime.container_manager().wait_async(&id).await {
            Ok(exit_code) => Ok(Response::new(WaitContainerResponse {
                status_code: i64::from(exit_code),
                error: String::new(),
            })),
            Err(e) => {
                // Check if it's a not-found error
                let error_str = e.to_string();
                if error_str.contains("not found") {
                    Err(Status::not_found(error_str))
                } else {
                    Err(Status::internal(error_str))
                }
            }
        }
    }

    type ContainerLogsStream =
        Pin<Box<dyn Stream<Item = Result<LogEntry, Status>> + Send + 'static>>;

    async fn container_logs(
        &self,
        request: Request<ContainerLogsRequest>,
    ) -> Result<Response<Self::ContainerLogsStream>, Status> {
        let req = request.into_inner();
        let container_id = ContainerId::from_string(&req.id);

        // Get container to find its machine.
        let container = self
            .runtime
            .container_manager()
            .get(&container_id)
            .ok_or_else(|| Status::not_found("container not found"))?;

        let machine_name = container
            .machine_name
            .unwrap_or_else(|| self.runtime.default_machine_name().to_string());

        // Create a streaming response.
        let runtime = Arc::clone(&self.runtime);
        let follow = req.follow;
        let stdout = req.stdout;
        let stderr = req.stderr;
        let since = req.since;
        let until = req.until;
        let timestamps = req.timestamps;
        let tail = req.tail;

        let stream = async_stream::try_stream! {
            if follow {
                // Use streaming logs.
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
                                timestamp: entry.timestamp,
                                stream: entry.stream,
                                data: entry.data,
                            };
                        }
                        Err(e) => {
                            Err(Status::internal(e.to_string()))?;
                        }
                    }
                }
            } else {
                // Get logs once.
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
                    timestamp: entry.timestamp,
                    stream: entry.stream,
                    data: entry.data,
                };
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type ExecContainerStream =
        Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    async fn exec_container(
        &self,
        request: Request<ExecContainerRequest>,
    ) -> Result<Response<Self::ExecContainerStream>, Status> {
        let req = request.into_inner();
        let container_id = ContainerId::from_string(&req.id);

        // Get container to find its machine.
        let container = self
            .runtime
            .container_manager()
            .get(&container_id)
            .ok_or_else(|| Status::not_found("container not found"))?;

        let machine_name = container
            .machine_name
            .unwrap_or_else(|| self.runtime.default_machine_name().to_string());

        // Get CID for the machine.
        let cid = self
            .runtime
            .machine_manager()
            .get_cid(&machine_name)
            .ok_or_else(|| Status::internal("machine has no CID"))?;

        // Build exec request for agent.
        let agent_req = arcbox_protocol::agent::ExecRequest {
            container_id: req.id.clone(),
            cmd: req.cmd,
            env: req.env,
            working_dir: req.working_dir,
            user: req.user,
            tty: req.tty,
        };

        let agent_pool = Arc::clone(self.runtime.agent_pool());

        let stream = async_stream::try_stream! {
            let agent = agent_pool.get(cid).await;
            let mut agent = agent.write().await;

            let output = agent
                .exec(agent_req)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            // Yield output data if present.
            if !output.data.is_empty() {
                yield ExecOutput {
                    stream: output.stream.clone(),
                    data: output.data.clone(),
                    exit_code: 0,
                    done: false,
                };
            }

            // Final message with exit code.
            yield ExecOutput {
                stream: String::new(),
                data: Vec::new(),
                exit_code: output.exit_code,
                done: true,
            };
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

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
    async fn create_machine(
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
        };

        self.runtime
            .machine_manager()
            .create(config)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateMachineResponse { id: req.name }))
    }

    async fn start_machine(
        &self,
        request: Request<StartMachineRequest>,
    ) -> Result<Response<StartMachineResponse>, Status> {
        let id = request.into_inner().id;

        self.runtime
            .machine_manager()
            .start(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(StartMachineResponse {}))
    }

    async fn stop_machine(
        &self,
        request: Request<StopMachineRequest>,
    ) -> Result<Response<StopMachineResponse>, Status> {
        let id = request.into_inner().id;

        self.runtime
            .machine_manager()
            .stop(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(StopMachineResponse {}))
    }

    async fn remove_machine(
        &self,
        request: Request<RemoveMachineRequest>,
    ) -> Result<Response<RemoveMachineResponse>, Status> {
        let req = request.into_inner();

        self.runtime
            .machine_manager()
            .remove(&req.id, req.force)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RemoveMachineResponse {}))
    }

    async fn list_machines(
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
                created: m.created_at.timestamp(),
            })
            .collect();

        Ok(Response::new(ListMachinesResponse {
            machines: summaries,
        }))
    }

    async fn inspect_machine(
        &self,
        request: Request<InspectMachineRequest>,
    ) -> Result<Response<InspectMachineResponse>, Status> {
        let id = request.into_inner().id;

        let machine = self
            .runtime
            .machine_manager()
            .get(&id)
            .ok_or_else(|| Status::not_found("machine not found"))?;

        Ok(Response::new(InspectMachineResponse {
            id: machine.name.clone(),
            name: machine.name,
            state: format!("{:?}", machine.state).to_lowercase(),
            cpus: machine.cpus,
            memory: machine.memory_mb * 1024 * 1024,
            disk_size: machine.disk_gb * 1024 * 1024 * 1024,
            created: machine.created_at.timestamp(),
            kernel: machine.kernel.unwrap_or_default(),
            initrd: machine.initrd.unwrap_or_default(),
            cmdline: machine.cmdline.unwrap_or_default(),
            cid: machine.cid.unwrap_or(0),
        }))
    }

    type ExecMachineStream =
        Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    async fn exec_machine(
        &self,
        request: Request<ExecMachineRequest>,
    ) -> Result<Response<Self::ExecMachineStream>, Status> {
        let req = request.into_inner();
        let machine_name = req.id;

        // Get CID for the machine.
        let cid = self
            .runtime
            .machine_manager()
            .get_cid(&machine_name)
            .ok_or_else(|| Status::not_found("machine not found or not running"))?;

        // Build exec request for agent (empty container_id for VM-level exec).
        let agent_req = arcbox_protocol::agent::ExecRequest {
            container_id: String::new(), // Empty = run in VM namespace, not in a container
            cmd: req.cmd,
            env: req.env,
            working_dir: req.working_dir,
            user: req.user,
            tty: req.tty,
        };

        let agent_pool = Arc::clone(self.runtime.agent_pool());

        let stream = async_stream::try_stream! {
            let agent = agent_pool.get(cid).await;
            let mut agent = agent.write().await;

            let output = agent
                .exec(agent_req)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            // Yield output data if present.
            if !output.data.is_empty() {
                yield ExecOutput {
                    stream: output.stream.clone(),
                    data: output.data.clone(),
                    exit_code: 0,
                    done: false,
                };
            }

            // Final message with exit code.
            yield ExecOutput {
                stream: String::new(),
                data: Vec::new(),
                exit_code: output.exit_code,
                done: true,
            };
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type ShellMachineStream =
        Pin<Box<dyn Stream<Item = Result<ShellOutput, Status>> + Send + 'static>>;

    async fn shell_machine(
        &self,
        request: Request<tonic::Streaming<ShellInput>>,
    ) -> Result<Response<Self::ShellMachineStream>, Status> {
        let machine_name = {
            // Extract machine name from metadata (the client should send it).
            request
                .metadata()
                .get("machine-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
                .ok_or_else(|| Status::invalid_argument("missing machine-id header"))?
        };

        // Get CID for the machine.
        let cid = self
            .runtime
            .machine_manager()
            .get_cid(&machine_name)
            .ok_or_else(|| Status::not_found("machine not found or not running"))?;

        let agent_pool = Arc::clone(self.runtime.agent_pool());
        let mut input_stream = request.into_inner();

        let stream = async_stream::try_stream! {
            let agent = agent_pool.get(cid).await;
            let mut agent = agent.write().await;

            // Start a shell session - use exec with /bin/sh.
            let shell_req = arcbox_protocol::agent::ExecRequest {
                container_id: String::new(),
                cmd: vec!["/bin/sh".to_string()],
                env: std::collections::HashMap::new(),
                working_dir: String::new(),
                user: String::new(),
                tty: true,
            };

            let output = agent
                .exec(shell_req)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            // Yield initial output.
            yield ShellOutput {
                data: output.data,
                exit_code: output.exit_code,
                done: output.done,
            };

            // Process input from client (simplified - in a real implementation,
            // we'd need bidirectional streaming to the agent).
            use tokio_stream::StreamExt;
            while let Some(result) = input_stream.next().await {
                match result {
                    Ok(_input) => {
                        // In a full implementation, we'd send input to the agent
                        // and yield output back. For now, we just acknowledge.
                        // This requires a more complex bidirectional protocol with the agent.
                    }
                    Err(e) => {
                        Err(Status::internal(format!("input stream error: {}", e)))?;
                    }
                }
            }

            // Final output when stream ends.
            yield ShellOutput {
                data: Vec::new(),
                exit_code: 0,
                done: true,
            };
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

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
            status: format!("Downloading {short}"),
            id: digest.to_string(),
            progress: format!("0/{size}"),
            error: String::new(),
        }));
    }

    fn layer_progress(&self, digest: &str, downloaded: u64, total: u64) {
        let short = Self::short_digest(digest);
        let tx = self.tx.clone();
        let _ = tx.try_send(Ok(PullProgress {
            status: format!("Downloading {short}"),
            id: digest.to_string(),
            progress: format!("{downloaded}/{total}"),
            error: String::new(),
        }));
    }

    fn layer_complete(&self, digest: &str) {
        let short = Self::short_digest(digest);
        let tx = self.tx.clone();
        let _ = tx.try_send(Ok(PullProgress {
            status: format!("Downloaded {short}"),
            id: digest.to_string(),
            progress: "complete".to_string(),
            error: String::new(),
        }));
    }

    fn complete(&self, image_id: &str) {
        let tx = self.tx.clone();
        let _ = tx.try_send(Ok(PullProgress {
            status: "Pull complete".to_string(),
            id: image_id.to_string(),
            progress: String::new(),
            error: String::new(),
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
    type PullImageStream =
        Pin<Box<dyn Stream<Item = Result<PullProgress, Status>> + Send + 'static>>;

    async fn pull_image(
        &self,
        request: Request<PullImageRequest>,
    ) -> Result<Response<Self::PullImageStream>, Status> {
        let req = request.into_inner();

        let image_ref = ImageRef::parse(&req.reference)
            .ok_or_else(|| Status::invalid_argument("invalid image reference"))?;

        let store = self.runtime.image_store().clone();
        let registry = image_ref.registry.clone();

        // Create a channel to send progress updates.
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<PullProgress, Status>>(32);

        // Create channel-based progress reporter.
        let progress = ChannelPullProgress::new(tx.clone());

        // Spawn the pull task.
        tokio::spawn(async move {
            let client = RegistryClient::new(&registry);
            let puller = ImagePuller::new(store, client).with_progress(progress);

            match puller.pull(&image_ref).await {
                Ok(image_id) => {
                    let _ = tx
                        .send(Ok(PullProgress {
                            status: "Pull complete".to_string(),
                            id: image_id,
                            progress: String::new(),
                            error: String::new(),
                        }))
                        .await;
                }
                Err(e) => {
                    let _ = tx
                        .send(Ok(PullProgress {
                            status: "Error".to_string(),
                            id: String::new(),
                            progress: String::new(),
                            error: e.to_string(),
                        }))
                        .await;
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn remove_image(
        &self,
        request: Request<RemoveImageRequest>,
    ) -> Result<Response<RemoveImageResponse>, Status> {
        let req = request.into_inner();

        let image_ref = ImageRef::parse(&req.reference)
            .ok_or_else(|| Status::invalid_argument("invalid image reference"))?;

        self.runtime
            .image_store()
            .remove(&image_ref)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RemoveImageResponse {
            untagged: vec![],
            deleted: vec![req.reference],
        }))
    }

    async fn list_images(
        &self,
        _request: Request<ListImagesRequest>,
    ) -> Result<Response<ListImagesResponse>, Status> {
        let images = self.runtime.image_store().list();

        let summaries: Vec<_> = images
            .into_iter()
            .map(|img| crate::generated::ImageSummary {
                id: img.id.clone(),
                repo_tags: vec![img.reference.full_name()],
                repo_digests: vec![],
                created: img.created.timestamp(),
                size: img.size as i64,
                labels: std::collections::HashMap::new(),
            })
            .collect();

        Ok(Response::new(ListImagesResponse { images: summaries }))
    }

    async fn inspect_image(
        &self,
        request: Request<InspectImageRequest>,
    ) -> Result<Response<InspectImageResponse>, Status> {
        let req = request.into_inner();

        let image_ref = ImageRef::parse(&req.reference)
            .ok_or_else(|| Status::invalid_argument("invalid image reference"))?;

        let image = self
            .runtime
            .image_store()
            .get(&image_ref)
            .ok_or_else(|| Status::not_found("image not found"))?;

        Ok(Response::new(InspectImageResponse {
            id: image.id.clone(),
            repo_tags: vec![image.reference.full_name()],
            repo_digests: vec![],
            parent: String::new(),
            comment: String::new(),
            created: image.created.timestamp(),
            author: String::new(),
            architecture: String::new(),
            os: "linux".to_string(),
            size: image.size as i64,
            cmd: vec![],
            entrypoint: vec![],
            env: std::collections::HashMap::new(),
            working_dir: String::new(),
            labels: std::collections::HashMap::new(),
        }))
    }

    async fn tag_image(
        &self,
        request: Request<TagImageRequest>,
    ) -> Result<Response<TagImageResponse>, Status> {
        let req = request.into_inner();

        let source = ImageRef::parse(&req.source)
            .ok_or_else(|| Status::invalid_argument("invalid source reference"))?;

        // Construct target from repo:tag
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

        Ok(Response::new(TagImageResponse {}))
    }
}

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
        }))
    }

    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: "1.0.0".to_string(),
            git_commit: option_env!("ARCBOX_GIT_COMMIT")
                .unwrap_or("unknown")
                .to_string(),
            build_time: option_env!("ARCBOX_BUILD_TIME")
                .unwrap_or("unknown")
                .to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        }))
    }

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse {
            api_version: "1.0.0".to_string(),
        }))
    }
}

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
    async fn create_network(
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

        Ok(Response::new(CreateNetworkResponse { id }))
    }

    async fn remove_network(
        &self,
        request: Request<RemoveNetworkRequest>,
    ) -> Result<Response<RemoveNetworkResponse>, Status> {
        let id = request.into_inner().id;

        self.runtime
            .network_manager()
            .remove_network(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RemoveNetworkResponse {}))
    }

    async fn list_networks(
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

    async fn inspect_network(
        &self,
        request: Request<InspectNetworkRequest>,
    ) -> Result<Response<InspectNetworkResponse>, Status> {
        let id = request.into_inner().id;

        let network = self
            .runtime
            .network_manager()
            .get_network(&id)
            .ok_or_else(|| Status::not_found("network not found"))?;

        Ok(Response::new(InspectNetworkResponse {
            id: network.id,
            name: network.name,
            driver: network.driver,
            scope: network.scope,
            created: network.created.to_rfc3339(),
            internal: network.internal,
            attachable: network.attachable,
            labels: network.labels,
            containers: std::collections::HashMap::new(),
        }))
    }
}

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
