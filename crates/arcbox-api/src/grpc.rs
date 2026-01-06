//! gRPC service implementations.

use crate::generated::{
    container_service_server, image_service_server, machine_service_server, system_service_server,
    ContainerLogsRequest, ContainerState as ProtoContainerState, ContainerSummary,
    CreateContainerRequest, CreateContainerResponse, CreateMachineRequest, CreateMachineResponse,
    ExecContainerRequest, ExecMachineRequest, ExecOutput, GetInfoRequest, GetInfoResponse,
    GetVersionRequest, GetVersionResponse, InspectContainerRequest, InspectContainerResponse,
    InspectImageRequest, InspectImageResponse, InspectMachineRequest, InspectMachineResponse,
    ListContainersRequest, ListContainersResponse, ListImagesRequest, ListImagesResponse,
    ListMachinesRequest, ListMachinesResponse, LogEntry, MachineSummary, PingRequest, PingResponse,
    PullImageRequest, PullProgress, RemoveContainerRequest, RemoveContainerResponse,
    RemoveImageRequest, RemoveImageResponse, RemoveMachineRequest, RemoveMachineResponse,
    ShellInput, ShellOutput, StartContainerRequest, StartContainerResponse, StartMachineRequest,
    StartMachineResponse, StopContainerRequest, StopContainerResponse, StopMachineRequest,
    StopMachineResponse, TagImageRequest, TagImageResponse, WaitContainerRequest,
    WaitContainerResponse,
};
use arcbox_container::{ContainerConfig, ContainerId, ContainerState};
use arcbox_core::Runtime;
use arcbox_image::ImageRef;
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

        self.runtime
            .container_manager()
            .start(&id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(StartContainerResponse {}))
    }

    async fn stop_container(
        &self,
        request: Request<StopContainerRequest>,
    ) -> Result<Response<StopContainerResponse>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        self.runtime
            .container_manager()
            .stop(&id)
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
                state: c.state.to_string(),
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

        Ok(Response::new(InspectContainerResponse {
            id: container.id.to_string(),
            name: container.name,
            image: container.image,
            created: container.created.timestamp(),
            state: Some(ProtoContainerState {
                status: container.state.to_string(),
                running: container.state == ContainerState::Running,
                paused: container.state == ContainerState::Paused,
                restarting: container.state == ContainerState::Restarting,
                dead: container.state == ContainerState::Dead,
                pid: 0,
                exit_code: container.exit_code.unwrap_or(0),
                error: String::new(),
                started_at: container
                    .started_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
                finished_at: String::new(),
            }),
            cmd: vec![],
            entrypoint: vec![],
            env: std::collections::HashMap::new(),
            working_dir: String::new(),
            mounts: vec![],
            ports: vec![],
            labels: std::collections::HashMap::new(),
        }))
    }

    async fn wait_container(
        &self,
        request: Request<WaitContainerRequest>,
    ) -> Result<Response<WaitContainerResponse>, Status> {
        let id = ContainerId::from_string(request.into_inner().id);

        // Wait for container to exit.
        // Note: This is a simplified implementation. A full implementation
        // would use async channels to wait for state changes.
        let exit_code = self.runtime.container_manager().wait(&id).unwrap_or(0);

        Ok(Response::new(WaitContainerResponse {
            status_code: i64::from(exit_code),
            error: String::new(),
        }))
    }

    type ContainerLogsStream =
        Pin<Box<dyn Stream<Item = Result<LogEntry, Status>> + Send + 'static>>;

    async fn container_logs(
        &self,
        _request: Request<ContainerLogsRequest>,
    ) -> Result<Response<Self::ContainerLogsStream>, Status> {
        // TODO: Implement log streaming via agent.
        let stream = async_stream::stream! {
            yield Err(Status::unimplemented("container logs not yet implemented"));
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type ExecContainerStream =
        Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    async fn exec_container(
        &self,
        _request: Request<ExecContainerRequest>,
    ) -> Result<Response<Self::ExecContainerStream>, Status> {
        // TODO: Implement exec via agent.
        let stream = async_stream::stream! {
            yield Err(Status::unimplemented("exec not yet implemented"));
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
                created: 0, // TODO: Add created timestamp to MachineInfo
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
            created: 0, // TODO: Add created timestamp
            kernel: String::new(),
            initrd: String::new(),
            cmdline: String::new(),
            cid: 0, // TODO: Add CID for vsock
        }))
    }

    type ExecMachineStream =
        Pin<Box<dyn Stream<Item = Result<ExecOutput, Status>> + Send + 'static>>;

    async fn exec_machine(
        &self,
        _request: Request<ExecMachineRequest>,
    ) -> Result<Response<Self::ExecMachineStream>, Status> {
        // TODO: Implement exec via agent.
        let stream = async_stream::stream! {
            yield Err(Status::unimplemented("machine exec not yet implemented"));
        };

        Ok(Response::new(Box::pin(stream)))
    }

    type ShellMachineStream =
        Pin<Box<dyn Stream<Item = Result<ShellOutput, Status>> + Send + 'static>>;

    async fn shell_machine(
        &self,
        _request: Request<tonic::Streaming<ShellInput>>,
    ) -> Result<Response<Self::ShellMachineStream>, Status> {
        // TODO: Implement interactive shell via agent.
        let stream = async_stream::stream! {
            yield Err(Status::unimplemented("machine shell not yet implemented"));
        };

        Ok(Response::new(Box::pin(stream)))
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
        let _req = request.into_inner();

        // TODO: Implement actual image pull with progress streaming.
        let stream = async_stream::stream! {
            yield Ok(PullProgress {
                status: "Pulling image...".to_string(),
                id: String::new(),
                progress: String::new(),
                error: String::new(),
            });
            yield Ok(PullProgress {
                status: "Pull complete".to_string(),
                id: String::new(),
                progress: String::new(),
                error: String::new(),
            });
        };

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
            data_dir: self
                .runtime
                .config()
                .data_dir
                .to_string_lossy()
                .to_string(),
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

    async fn ping(
        &self,
        _request: Request<PingRequest>,
    ) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse {
            api_version: "1.0.0".to_string(),
        }))
    }
}

/// Formats a container status string.
fn format_container_status(state: &ContainerState, exit_code: Option<i32>) -> String {
    match state {
        ContainerState::Created => "Created".to_string(),
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

        if ret == 0 {
            size as i64
        } else {
            0
        }
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
