//! ArcBox runtime.

use crate::agent_client::AgentPool;
use crate::boot_assets::BootAssetManifest;
use crate::config::Config;
use crate::container_backend::{DynContainerBackend, create_backend};
use crate::error::{CoreError, Result};
use crate::event::EventBus;
use crate::machine::{MachineManager, MachineState};
use crate::vm::VmManager;
use crate::vm_lifecycle::{DEFAULT_MACHINE_NAME, VmLifecycleConfig, VmLifecycleManager};
use arcbox_container::{
    ContainerConfig, ContainerId, ContainerManager, ExecManager, VolumeManager,
};
use arcbox_image::{ImageError, ImagePuller, ImageRef, ImageStore, RegistryClient};
use arcbox_net::{
    NetworkManager,
    port_forward::{PortForwardRule, PortForwarder},
};
use arcbox_protocol::Mount;
use arcbox_protocol::agent::{
    AttachInput, AttachOutput, AttachRequest, CreateContainerRequest, LogEntry, LogsRequest,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Component, Path};
use std::sync::{Arc, RwLock};
use tokio::sync::RwLock as TokioRwLock;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// ArcBox runtime.
///
/// The main entry point for the ArcBox system, managing all components.
/// Default guest VM IP address in NAT network.
const DEFAULT_GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 64, 2);
const REQUIRED_RUNTIME_ASSETS: [&str; 3] = ["dockerd", "containerd", "youki"];

fn ensure_container_network_files(rootfs: &Path) -> Result<()> {
    let etc_dir = rootfs.join("etc");
    std::fs::create_dir_all(&etc_dir).map_err(|e| {
        CoreError::config(format!(
            "failed to create container etc directory '{}': {}",
            etc_dir.display(),
            e
        ))
    })?;

    let resolv_conf = etc_dir.join("resolv.conf");
    if !resolv_conf.exists() {
        std::fs::write(&resolv_conf, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n").map_err(|e| {
            CoreError::config(format!(
                "failed to write container resolv.conf '{}': {}",
                resolv_conf.display(),
                e
            ))
        })?;
    }

    Ok(())
}

fn ensure_container_working_dir(rootfs: &Path, working_dir: &str) -> Result<()> {
    if working_dir.is_empty() {
        return Ok(());
    }

    let relative = if let Ok(stripped) = Path::new(working_dir).strip_prefix("/") {
        stripped
    } else {
        Path::new(working_dir)
    };
    let host_workdir = rootfs.join(relative);
    if let Ok(meta) = std::fs::symlink_metadata(&host_workdir) {
        if meta.file_type().is_symlink() {
            if let Ok(target) = std::fs::read_link(&host_workdir) {
                let target_path = if target.is_absolute() {
                    let target_relative = target
                        .strip_prefix("/")
                        .map(|p| p.to_path_buf())
                        .unwrap_or(target.clone());
                    rootfs.join(target_relative)
                } else {
                    host_workdir
                        .parent()
                        .unwrap_or(rootfs)
                        .join(target.as_path())
                };
                std::fs::create_dir_all(&target_path).map_err(|e| {
                    CoreError::config(format!(
                        "failed to create container symlinked working directory '{}': {}",
                        target_path.display(),
                        e
                    ))
                })?;
                return Ok(());
            }
        }
    }

    std::fs::create_dir_all(&host_workdir).map_err(|e| {
        CoreError::config(format!(
            "failed to create container working directory '{}': {}",
            host_workdir.display(),
            e
        ))
    })?;

    Ok(())
}

fn shell_quote(input: &str) -> String {
    if input.is_empty() {
        return "''".to_string();
    }
    let escaped = input.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

fn validate_bundled_runtime_manifest(manifest: &BootAssetManifest, cache_dir: &Path) -> Result<()> {
    let mut missing = Vec::new();

    for required in REQUIRED_RUNTIME_ASSETS {
        let Some(entry) = manifest
            .runtime_assets
            .iter()
            .find(|item| item.name == required)
        else {
            missing.push(required);
            continue;
        };

        if entry
            .version
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(CoreError::config(format!(
                "boot manifest runtime asset '{}' is missing version",
                required
            )));
        }
        let expected_sha = entry.sha256.as_deref().unwrap_or_default().trim();
        if expected_sha.is_empty() {
            return Err(CoreError::config(format!(
                "boot manifest runtime asset '{}' is missing sha256",
                required
            )));
        }

        let relative_path = Path::new(&entry.path);
        if relative_path.as_os_str().is_empty()
            || relative_path.is_absolute()
            || relative_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(CoreError::config(format!(
                "boot manifest runtime asset '{}' has invalid path '{}'",
                required, entry.path
            )));
        }

        let runtime_path = cache_dir.join(relative_path);
        if !runtime_path.exists() {
            return Err(CoreError::config(format!(
                "boot runtime asset '{}' missing from cache: {}",
                required,
                runtime_path.display()
            )));
        }

        let bytes = std::fs::read(&runtime_path).map_err(|e| {
            CoreError::config(format!(
                "failed to read boot runtime asset '{}': {}",
                runtime_path.display(),
                e
            ))
        })?;
        let actual_sha = format!("{:x}", Sha256::digest(&bytes));
        if actual_sha != expected_sha {
            return Err(CoreError::config(format!(
                "boot runtime asset '{}' checksum mismatch: expected {}, got {}",
                required, expected_sha, actual_sha
            )));
        }
    }

    if !missing.is_empty() {
        return Err(CoreError::config(format!(
            "boot manifest runtime_assets missing required entries: {}",
            missing.join(", ")
        )));
    }

    Ok(())
}

pub struct Runtime {
    /// Configuration.
    config: Config,
    /// Event bus.
    event_bus: EventBus,
    /// VM manager.
    vm_manager: Arc<VmManager>,
    /// Machine manager.
    machine_manager: Arc<MachineManager>,
    /// VM lifecycle manager (automatic VM management).
    vm_lifecycle: Arc<VmLifecycleManager>,
    /// Selected container backend implementation.
    container_backend: DynContainerBackend,
    /// Container manager.
    container_manager: Arc<ContainerManager>,
    /// Image store.
    image_store: Arc<ImageStore>,
    /// Volume manager.
    volume_manager: Arc<RwLock<VolumeManager>>,
    /// Network manager.
    network_manager: Arc<NetworkManager>,
    /// Exec manager.
    exec_manager: Arc<ExecManager>,
    /// Agent connection pool.
    agent_pool: Arc<AgentPool>,
    /// Port forwarders for each container (keyed by container ID).
    port_forwarders: Arc<TokioRwLock<HashMap<String, PortForwarder>>>,
}

impl Runtime {
    /// Creates a new runtime with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the image store cannot be created.
    pub fn new(config: Config) -> Result<Self> {
        Self::with_vm_lifecycle_config(config, VmLifecycleConfig::default())
    }

    /// Creates a new runtime with custom VM lifecycle configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the image store cannot be created.
    pub fn with_vm_lifecycle_config(
        config: Config,
        mut vm_lifecycle_config: VmLifecycleConfig,
    ) -> Result<Self> {
        if matches!(
            config.container.backend,
            crate::config::ContainerBackendMode::GuestDocker
        ) {
            vm_lifecycle_config.guest_docker_vsock_port =
                Some(config.container.guest_docker_vsock_port);
        }

        let event_bus = EventBus::new();
        let vm_manager = Arc::new(VmManager::new());
        let machine_manager = Arc::new(MachineManager::new(
            VmManager::new(),
            config.data_dir.clone(),
        ));

        // Create VM lifecycle manager with the machine manager
        let vm_lifecycle = Arc::new(VmLifecycleManager::new(
            machine_manager.clone(),
            event_bus.clone(),
            config.data_dir.clone(),
            vm_lifecycle_config,
        ));
        let container_backend = create_backend(
            &config.container,
            Arc::clone(&vm_lifecycle),
            Arc::clone(&machine_manager),
            DEFAULT_MACHINE_NAME,
        );

        let container_manager = Arc::new(ContainerManager::new());
        let image_store = Arc::new(ImageStore::new(config.data_dir.join("images"))?);
        let volume_manager = Arc::new(RwLock::new(VolumeManager::new(
            config.data_dir.join("volumes"),
        )));
        let network_manager = Arc::new(NetworkManager::new(arcbox_net::NetConfig::default()));
        let exec_manager = Arc::new(ExecManager::new());
        let agent_pool = Arc::new(AgentPool::new());

        Ok(Self {
            config,
            event_bus,
            vm_manager,
            machine_manager,
            vm_lifecycle,
            container_backend,
            container_manager,
            image_store,
            volume_manager,
            network_manager,
            exec_manager,
            agent_pool,
            port_forwarders: Arc::new(TokioRwLock::new(HashMap::new())),
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the event bus.
    #[must_use]
    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Returns the VM manager.
    #[must_use]
    pub fn vm_manager(&self) -> &Arc<VmManager> {
        &self.vm_manager
    }

    /// Returns the machine manager.
    #[must_use]
    pub fn machine_manager(&self) -> &Arc<MachineManager> {
        &self.machine_manager
    }

    /// Returns the container manager.
    #[must_use]
    pub fn container_manager(&self) -> &Arc<ContainerManager> {
        &self.container_manager
    }

    /// Returns the image store.
    #[must_use]
    pub fn image_store(&self) -> &Arc<ImageStore> {
        &self.image_store
    }

    /// Returns the volume manager.
    #[must_use]
    pub fn volume_manager(&self) -> &Arc<RwLock<VolumeManager>> {
        &self.volume_manager
    }

    /// Returns the network manager.
    #[must_use]
    pub fn network_manager(&self) -> &Arc<NetworkManager> {
        &self.network_manager
    }

    /// Returns the exec manager.
    #[must_use]
    pub fn exec_manager(&self) -> &Arc<ExecManager> {
        &self.exec_manager
    }

    /// Returns the agent connection pool.
    #[must_use]
    pub fn agent_pool(&self) -> &Arc<AgentPool> {
        &self.agent_pool
    }

    /// Returns the VM lifecycle manager.
    #[must_use]
    pub fn vm_lifecycle(&self) -> &Arc<VmLifecycleManager> {
        &self.vm_lifecycle
    }

    /// Returns the selected container backend implementation.
    #[must_use]
    pub fn container_backend(&self) -> &DynContainerBackend {
        &self.container_backend
    }

    /// Returns true when the active backend delegates to guest Docker.
    #[must_use]
    pub fn is_guest_docker(&self) -> bool {
        self.container_backend.mode() == crate::config::ContainerBackendMode::GuestDocker
    }

    /// Returns the configured guest Docker vsock port.
    #[must_use]
    pub fn guest_docker_vsock_port(&self) -> u32 {
        self.config.container.guest_docker_vsock_port
    }

    /// Sends an HTTP GET request to the guest Docker daemon via vsock and
    /// returns the raw response body bytes.
    ///
    /// This is used by Docker API handlers to proxy read-only queries
    /// (list, inspect) directly to the guest Docker, making it the single
    /// source of truth for container runtime state.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM is not running or the request fails.
    /// Returns `(http_status_code, body)` so callers can propagate the
    /// upstream status faithfully (e.g. 404 for missing containers).
    pub async fn guest_docker_get(&self, path: &str) -> Result<(u16, bytes::Bytes)> {
        use std::os::fd::FromRawFd;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let port = self.config.container.guest_docker_vsock_port;
        let fd = self
            .machine_manager
            .connect_vsock_port(DEFAULT_MACHINE_NAME, port)?;

        // Wrap the raw fd into an async TcpStream-like handle.
        // SAFETY: fd is a valid, newly-opened vsock file descriptor.
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true).map_err(|e| {
            CoreError::Machine(format!("failed to set vsock fd non-blocking: {}", e))
        })?;
        let stream = tokio::net::TcpStream::from_std(std_stream)
            .map_err(|e| CoreError::Machine(format!("failed to wrap vsock fd: {}", e)))?;

        let (mut reader, mut writer) = tokio::io::split(stream);

        // Send a minimal HTTP/1.1 GET request.
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        writer
            .write_all(request.as_bytes())
            .await
            .map_err(|e| CoreError::Machine(format!("failed to write to guest docker: {}", e)))?;

        // Read the full response.
        let mut buf = Vec::with_capacity(8192);
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(|e| CoreError::Machine(format!("failed to read from guest docker: {}", e)))?;

        // Parse HTTP status code from the status line ("HTTP/1.1 200 OK\r\n").
        let status_line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(0);
        let status_code = std::str::from_utf8(&buf[..status_line_end])
            .ok()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(502);

        // Split headers from body at the first \r\n\r\n boundary.
        let body_start = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .unwrap_or(0);

        Ok((status_code, bytes::Bytes::from(buf[body_start..].to_vec())))
    }

    /// Ensures the default VM is running and ready for container operations.
    ///
    /// This is the main entry point for automatic VM lifecycle management.
    /// If the VM is not running, it will be created and started automatically.
    /// This method is idempotent and safe to call multiple times.
    ///
    /// Returns the vsock CID of the running VM.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be started or becomes unhealthy.
    pub async fn ensure_vm_ready(&self) -> Result<u32> {
        self.container_backend.ensure_ready().await
    }

    /// Returns the default machine name used for automatic VM lifecycle.
    #[must_use]
    pub fn default_machine_name(&self) -> &'static str {
        DEFAULT_MACHINE_NAME
    }

    /// Gets an agent client for a machine.
    ///
    /// On macOS, this uses the hypervisor layer to establish vsock connections.
    /// On Linux, it creates a direct AF_VSOCK connection.
    ///
    /// # Errors
    /// Returns an error if the machine is not found or connection fails.
    #[cfg(target_os = "macos")]
    pub fn get_agent(&self, machine_name: &str) -> Result<crate::agent_client::AgentClient> {
        self.machine_manager.connect_agent(machine_name)
    }

    /// Gets an agent client for a machine (Linux version).
    #[cfg(target_os = "linux")]
    pub fn get_agent(&self, machine_name: &str) -> Result<crate::agent_client::AgentClient> {
        self.machine_manager.connect_agent(machine_name)
    }

    /// Initializes the runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn init(&self) -> Result<()> {
        // Create data directories
        tokio::fs::create_dir_all(&self.config.data_dir).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("vms")).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("machines")).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("images")).await?;
        tokio::fs::create_dir_all(self.config.data_dir.join("volumes")).await?;

        if matches!(
            self.config.container.backend,
            crate::config::ContainerBackendMode::GuestDocker
        ) && matches!(
            self.config.container.provision,
            crate::config::ContainerProvisionMode::BundledAssets
        ) {
            let boot_assets = self.vm_lifecycle.boot_assets().get_assets().await?;
            let manifest = boot_assets.manifest.as_ref().ok_or_else(|| {
                CoreError::config(
                    "guest_docker + bundled_assets requires boot manifest with runtime_assets",
                )
            })?;
            let cache_dir = self.vm_lifecycle.boot_assets().config().version_cache_dir();
            validate_bundled_runtime_manifest(manifest, &cache_dir)?;
        }

        tracing::info!(
            backend = self.container_backend.name(),
            "ArcBox runtime initialized"
        );
        Ok(())
    }

    /// Shuts down the runtime gracefully.
    ///
    /// This performs the following in order:
    /// 1. Stop all running containers
    /// 2. Shutdown VM lifecycle manager (handles default VM)
    /// 3. Stop any remaining machines/VMs
    /// 4. Clean up network resources
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("ArcBox runtime shutting down");

        // 1. Stop all running containers.
        let containers = self.container_manager.list();
        for container in containers {
            if container.state == arcbox_container::ContainerState::Running {
                tracing::debug!("Stopping container {}", container.id);
                if let Some(machine_name) = &container.machine_name {
                    // Try to stop via agent (with timeout).
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        self.stop_container(machine_name, &container.id, 5),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            tracing::info!("Container {} stopped", container.id);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Failed to stop container {}: {}", container.id, e);
                        }
                        Err(_) => {
                            tracing::warn!("Timeout stopping container {}", container.id);
                        }
                    }
                }
            }
        }

        // 2. Shutdown VM lifecycle manager (gracefully stops default VM).
        if let Err(e) = self.vm_lifecycle.shutdown().await {
            tracing::warn!("Failed to shutdown VM lifecycle manager: {}", e);
        }

        // 3. Stop any remaining machines/VMs (non-default VMs).
        let machines = self.machine_manager.list();
        for machine in machines {
            if machine.state == MachineState::Running && machine.name != DEFAULT_MACHINE_NAME {
                tracing::debug!("Stopping machine {}", machine.name);
                match self.machine_manager.stop(&machine.name) {
                    Ok(()) => {
                        tracing::info!("Machine {} stopped", machine.name);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to stop machine {}: {}", machine.name, e);
                    }
                }
            }
        }

        // 4. Stop network manager.
        if let Err(e) = self.network_manager.stop() {
            tracing::warn!("Failed to stop network manager: {}", e);
        }

        tracing::info!("ArcBox runtime shutdown complete");
        Ok(())
    }

    /// Shuts down the runtime forcefully.
    ///
    /// Skips graceful container/VM shutdown and immediately cleans up.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown_force(&self) -> Result<()> {
        tracing::warn!("ArcBox runtime force shutdown");

        // Force stop VM lifecycle manager (immediate VM termination).
        if let Err(e) = self.vm_lifecycle.force_stop().await {
            tracing::warn!("Failed to force stop VM lifecycle manager: {}", e);
        }

        // Force stop any remaining machines (non-default VMs).
        let machines = self.machine_manager.list();
        for machine in machines {
            if machine.state == MachineState::Running && machine.name != DEFAULT_MACHINE_NAME {
                tracing::debug!("Force stopping machine {}", machine.name);
                let _ = self.machine_manager.stop(&machine.name);
            }
        }

        // Stop network manager.
        let _ = self.network_manager.stop();

        tracing::info!("ArcBox runtime force shutdown complete");
        Ok(())
    }

    // =========================================================================
    // Container operations (coordinating ContainerManager + Agent)
    // =========================================================================

    /// Creates and starts a container in a machine.
    ///
    /// This coordinates between the host-side ContainerManager (metadata) and
    /// the guest Agent (actual container execution).
    ///
    /// # Errors
    ///
    /// Returns an error if container creation fails.
    pub async fn create_container(
        &self,
        machine_name: &str,
        config: ContainerConfig,
    ) -> Result<ContainerId> {
        // Check machine exists and is running
        let machine = self
            .machine_manager
            .get(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::invalid_state(format!(
                "machine '{}' is not running",
                machine_name
            )));
        }

        let cid = machine
            .cid
            .ok_or_else(|| CoreError::Machine("machine has no CID assigned".to_string()))?;

        // Create container in local state first
        let container_id = self.container_manager.create(config.clone())?;

        // Update container with machine name
        let machine_name_clone = machine_name.to_string();
        self.container_manager.update(&container_id, |container| {
            container.machine_name = Some(machine_name_clone);
        })?;

        // Extract image to create rootfs
        let image_ref = ImageRef::parse(&config.image).ok_or_else(|| {
            CoreError::config(format!("invalid image reference: {}", config.image))
        })?;

        // Check if image exists locally, if not, pull it automatically (Docker-like UX).
        if let Err(e) = self.image_store.get_image_config(&image_ref) {
            if !e.is_not_found() {
                return Err(e.into());
            }
            tracing::info!(
                "Image {} not found locally, pulling from registry...",
                config.image
            );
            let client = RegistryClient::new(&image_ref.registry);
            let puller = ImagePuller::new(self.image_store.clone(), client);
            puller.pull(&image_ref).await?;
            tracing::info!("Successfully pulled image {}", config.image);
        }

        // Get image config for default entrypoint/cmd
        let image_config = self.image_store.get_image_config(&image_ref)?;
        let image_container_config = &image_config.config;
        let container_working_dir = config
            .working_dir
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                image_container_config
                    .working_dir
                    .clone()
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "/".to_string());

        // Prepare container rootfs by extracting image layers
        let host_rootfs = self
            .image_store
            .prepare_container_rootfs(&container_id.to_string(), &image_ref)?;
        ensure_container_network_files(&host_rootfs)?;
        ensure_container_working_dir(&host_rootfs, &container_working_dir)?;

        tracing::info!(
            "Prepared rootfs for container {}: {}",
            container_id,
            host_rootfs.display()
        );

        // Calculate guest-side rootfs path
        // The VirtioFS share "arcbox" maps data_dir to /arcbox in guest
        // So containers/{id}/rootfs on host becomes /arcbox/containers/{id}/rootfs in guest
        let guest_rootfs = format!("/arcbox/containers/{}/rootfs", container_id);

        // Convert volume mounts to protocol Mount type with path translation.
        // Host paths under data_dir are translated to /arcbox/... in guest.
        // Host paths under home directory are translated to /host-home/... in guest.
        let data_dir_str = self.config.data_dir.to_string_lossy().to_string();
        let home_dir_str = dirs::home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let mounts: Vec<Mount> = config
            .volumes
            .iter()
            .map(|v| {
                // Translate host path to guest-accessible path.
                // Priority: data_dir first, then home directory
                let guest_source = if v.source.starts_with(&data_dir_str) {
                    v.source.replacen(&data_dir_str, "/arcbox", 1)
                } else if !home_dir_str.is_empty() && v.source.starts_with(&home_dir_str) {
                    v.source.replacen(&home_dir_str, "/host-home", 1)
                } else {
                    // For paths outside both data_dir and home, keep as-is.
                    tracing::warn!(
                        "Volume source '{}' is outside data_dir and home, mount may fail",
                        v.source
                    );
                    v.source.clone()
                };
                Mount {
                    source: guest_source,
                    target: v.target.clone(),
                    r#type: "bind".to_string(),
                    readonly: v.read_only,
                }
            })
            .collect();

        // Use config values if provided, otherwise fall back to image defaults.
        let entrypoint = if config.entrypoint.is_empty() {
            image_container_config
                .entrypoint
                .clone()
                .unwrap_or_default()
        } else {
            config.entrypoint.clone()
        };
        let cmd = if config.cmd.is_empty() {
            image_container_config.cmd.clone().unwrap_or_default()
        } else {
            config.cmd.clone()
        };
        let mut env = HashMap::new();
        if let Some(image_env) = &image_container_config.env {
            for item in image_env {
                if let Some((key, value)) = item.split_once('=') {
                    env.insert(key.to_string(), value.to_string());
                } else {
                    env.insert(item.clone(), String::new());
                }
            }
        }
        env.extend(config.env.clone());
        if !env.contains_key("PATH") {
            env.insert(
                "PATH".to_string(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            );
        }

        let mut request_entrypoint = entrypoint;
        let mut request_cmd = cmd;
        let mut request_working_dir = container_working_dir;
        if request_working_dir != "/" {
            let mut full_cmd = request_entrypoint.clone();
            full_cmd.extend(request_cmd.clone());
            if !full_cmd.is_empty() {
                let quoted_cmd = full_cmd
                    .iter()
                    .map(|part| shell_quote(part))
                    .collect::<Vec<_>>()
                    .join(" ");
                let quoted_workdir = shell_quote(&request_working_dir);
                let script = format!(
                    "mkdir -p {wd} && cd {wd} && exec {cmd}",
                    wd = quoted_workdir,
                    cmd = quoted_cmd
                );
                request_entrypoint = vec!["/bin/sh".to_string(), "-c".to_string()];
                request_cmd = vec![script];
                request_working_dir = "/".to_string();
            }
        }

        tracing::debug!(
            "Container {} entrypoint={:?}, cmd={:?}",
            container_id,
            request_entrypoint,
            request_cmd
        );

        let req = CreateContainerRequest {
            name: config.name.clone().unwrap_or_default(),
            image: config.image.clone(),
            cmd: request_cmd,
            entrypoint: request_entrypoint,
            env,
            working_dir: request_working_dir,
            user: config.user.clone().unwrap_or_default(),
            mounts,
            tty: config.tty.unwrap_or(false),
            open_stdin: config.open_stdin.unwrap_or(false),
            rootfs: guest_rootfs,
            id: container_id.to_string(),
        };

        // Send create request to agent
        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.create_container(req).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.create_container(req).await?;
        }

        tracing::info!(
            "Created container {} in machine '{}'",
            container_id,
            machine_name
        );

        Ok(container_id)
    }

    /// Starts a container in a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be started.
    pub async fn start_container(
        &self,
        machine_name: &str,
        container_id: &ContainerId,
    ) -> Result<bool> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let start_outcome = self.container_manager.begin_start(container_id)?;
        let start_ticket = match start_outcome {
            arcbox_container::StartOutcome::Started(ticket) => Some(ticket),
            arcbox_container::StartOutcome::AlreadyRunning
            | arcbox_container::StartOutcome::AlreadyStarting => {
                return Ok(false);
            }
        };

        // Send start request to agent
        let container_id_str = container_id.to_string();
        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            if let Err(e) = agent.start_container(&container_id_str).await {
                if let Some(ticket) = start_ticket {
                    let _ = self.container_manager.fail_start(container_id, ticket);
                }
                return Err(e.into());
            }
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            if let Err(e) = agent.start_container(&container_id_str).await {
                if let Some(ticket) = start_ticket {
                    let _ = self.container_manager.fail_start(container_id, ticket);
                }
                return Err(e.into());
            }
        }

        // Update local state after successful agent call
        self.container_manager.finish_start(container_id)?;

        // Start port forwarding if configured.
        self.start_port_forwarding(machine_name, container_id)
            .await?;

        tracing::info!(
            "Started container {} in machine '{}'",
            container_id,
            machine_name
        );

        Ok(true)
    }

    /// Gets the VM's IP address by executing a command in the guest.
    ///
    /// Returns the first IPv4 address found on a non-loopback interface.
    /// Retries a few times if network is not yet configured.
    async fn get_guest_ip(&self, machine_name: &str) -> Result<Ipv4Addr> {
        const MAX_RETRIES: u32 = 5;
        const RETRY_DELAY_MS: u64 = 500;

        for attempt in 0..MAX_RETRIES {
            // Try to get IP address from the VM using cat /var/log/network.log
            // which is written by the init script after network configuration.
            // Also try ip addr as a fallback.
            let output = self
                .exec_machine(
                    machine_name,
                    vec![
                        "/bin/busybox".to_string(),
                        "cat".to_string(),
                        "/var/log/network.log".to_string(),
                    ],
                    std::collections::HashMap::new(),
                    String::new(),
                    String::new(),
                    false,
                )
                .await?;

            let stdout = String::from_utf8_lossy(&output.data);
            tracing::debug!(
                "network log (attempt {}): exit_code={}, output={:?}",
                attempt + 1,
                output.exit_code,
                stdout
            );

            // Parse the output to find an IP address.
            // network.log format: "Network configured: eth0 -> 192.168.64.2/24"
            // or: "No network interface found"
            for line in stdout.lines() {
                let line = line.trim();

                // network.log format: "Network configured: eth0 -> 192.168.64.2/24"
                if line.contains("Network configured:") && line.contains(" -> ") {
                    if let Some(ip_part) = line.split(" -> ").nth(1) {
                        // Remove CIDR notation if present
                        let ip_str = ip_part.split('/').next().unwrap_or(ip_part);
                        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                            tracing::info!("Discovered guest IP from network.log: {}", ip);
                            return Ok(ip);
                        }
                    }
                }

                // ip addr format: "inet 192.168.64.2/24 ..."
                if line.starts_with("inet ") && !line.contains("127.0.0.1") {
                    if let Some(ip_cidr) = line.strip_prefix("inet ") {
                        if let Some(ip_str) = ip_cidr.split('/').next() {
                            let ip_str = ip_str.split_whitespace().next().unwrap_or(ip_str);
                            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                tracing::info!("Discovered guest IP: {}", ip);
                                return Ok(ip);
                            }
                        }
                    }
                }

                // ifconfig format: "inet addr:192.168.64.2 ..."
                if line.contains("inet addr:") && !line.contains("127.0.0.1") {
                    if let Some(addr_part) = line.split("inet addr:").nth(1) {
                        if let Some(ip_str) = addr_part.split_whitespace().next() {
                            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                tracing::info!("Discovered guest IP: {}", ip);
                                return Ok(ip);
                            }
                        }
                    }
                }
            }

            // No IP found yet, wait and retry if not last attempt.
            if attempt < MAX_RETRIES - 1 {
                tracing::debug!(
                    "Guest IP not found on attempt {}, retrying in {}ms",
                    attempt + 1,
                    RETRY_DELAY_MS
                );
                tokio::time::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS)).await;
            }
        }

        tracing::warn!(
            "Could not discover guest IP after {} attempts, using default {}",
            MAX_RETRIES,
            DEFAULT_GUEST_IP
        );
        Ok(DEFAULT_GUEST_IP)
    }

    /// Starts port forwarding for a container based on its configuration.
    async fn start_port_forwarding(
        &self,
        machine_name: &str,
        container_id: &ContainerId,
    ) -> Result<()> {
        let container = self
            .container_manager
            .get(container_id)
            .ok_or_else(|| CoreError::not_found(container_id.to_string()))?;

        let port_bindings = match &container.config {
            Some(cfg) if !cfg.port_bindings.is_empty() => &cfg.port_bindings,
            _ => return Ok(()), // No port bindings configured
        };

        // Get the actual guest IP address.
        let guest_ip = self.get_guest_ip(machine_name).await?;

        let mut forwarder = PortForwarder::new();

        for binding in port_bindings {
            // Determine host IP to bind (0.0.0.0 if not specified)
            let host_ip: Ipv4Addr = if binding.host_ip.is_empty() || binding.host_ip == "0.0.0.0" {
                Ipv4Addr::UNSPECIFIED
            } else {
                binding.host_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
            };

            let host_addr = SocketAddr::V4(SocketAddrV4::new(host_ip, binding.host_port));
            let guest_addr = SocketAddr::V4(SocketAddrV4::new(guest_ip, binding.container_port));

            let rule = match binding.protocol.to_lowercase().as_str() {
                "udp" => PortForwardRule::udp(host_addr, guest_addr),
                _ => PortForwardRule::tcp(host_addr, guest_addr),
            };

            forwarder.add_rule(rule);
            tracing::info!(
                "Port forward rule added: {} -> {} ({})",
                host_addr,
                guest_addr,
                binding.protocol
            );
        }

        // Start all forwarders.
        forwarder.start().await?;

        // Store the forwarder.
        let mut forwarders = self.port_forwarders.write().await;
        forwarders.insert(container_id.to_string(), forwarder);

        Ok(())
    }

    /// Stops port forwarding for a container.
    async fn stop_port_forwarding(&self, container_id: &ContainerId) {
        let mut forwarders = self.port_forwarders.write().await;
        if let Some(mut forwarder) = forwarders.remove(&container_id.to_string()) {
            forwarder.stop().await;
            tracing::debug!("Stopped port forwarding for container {}", container_id);
        }
    }

    /// Stops a container in a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be stopped.
    pub async fn stop_container(
        &self,
        machine_name: &str,
        container_id: &ContainerId,
        timeout: u32,
    ) -> Result<()> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        // Send stop request to agent first
        let container_id_str = container_id.to_string();
        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.stop_container(&container_id_str, timeout).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.stop_container(&container_id_str, timeout).await?;
        }

        // Stop port forwarding first.
        self.stop_port_forwarding(container_id).await;

        // Update local state after successful agent call
        self.container_manager.stop(container_id, timeout).await?;

        tracing::info!(
            "Stopped container {} in machine '{}'",
            container_id,
            machine_name
        );

        Ok(())
    }

    /// Waits for a container to finish and returns its exit code.
    ///
    /// # Errors
    ///
    /// Returns an error if the wait operation fails.
    pub async fn wait_container(&self, machine_name: &str, container_id: &str) -> Result<i32> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let exit_code = {
            #[cfg(target_os = "macos")]
            {
                let mut agent = self.machine_manager.connect_agent(machine_name)?;
                agent.wait_container(container_id).await?
            }
            #[cfg(target_os = "linux")]
            {
                let agent = self.agent_pool.get(cid).await;
                let mut agent = agent.write().await;
                agent.wait_container(container_id).await?
            }
        };

        tracing::debug!(
            "Container {} exited with code {} in machine '{}'",
            container_id,
            exit_code,
            machine_name
        );

        Ok(exit_code)
    }

    /// Removes a container from a machine.
    ///
    /// When `force` is true and the container is running, the container is
    /// killed via the agent before removal. This ensures:
    /// - The guest-side process is terminated cleanly.
    /// - Host-side state transitions to Exited so waiters are unblocked.
    /// - Port forwarding and rootfs are cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be removed.
    pub async fn remove_container(
        &self,
        machine_name: &str,
        container_id: &ContainerId,
        force: bool,
    ) -> Result<()> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        // Send remove request to agent.
        let container_id_str = container_id.to_string();
        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.remove_container(&container_id_str, force).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.remove_container(&container_id_str, force).await?;
        }

        // Stop port forwarding if any.
        self.stop_port_forwarding(container_id).await;

        // Update local state. remove_force handles the Exited transition
        // and waiter notification for active containers.
        if force {
            self.container_manager.remove_force(container_id)?;
        } else {
            self.container_manager.remove(container_id)?;
        }

        // Clean up container rootfs so the same name/ID can be reused.
        if let Err(e) = self.image_store.remove_container_rootfs(&container_id_str) {
            tracing::warn!(
                "Failed to clean up rootfs for container {}: {}",
                container_id,
                e
            );
        }

        tracing::info!(
            "Removed container {} from machine '{}'",
            container_id,
            machine_name
        );

        Ok(())
    }

    /// Lists containers in a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the list operation fails.
    pub async fn list_containers_in_machine(
        &self,
        machine_name: &str,
        all: bool,
    ) -> Result<Vec<arcbox_protocol::agent::ContainerInfo>> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let response = {
            #[cfg(target_os = "macos")]
            {
                let mut agent = self.machine_manager.connect_agent(machine_name)?;
                agent.list_containers(all).await?
            }
            #[cfg(target_os = "linux")]
            {
                let agent = self.agent_pool.get(cid).await;
                let mut agent = agent.write().await;
                agent.list_containers(all).await?
            }
        };

        Ok(response.containers)
    }

    /// Gets container logs from a machine.
    ///
    /// # Errors
    ///
    /// Returns an error if the logs cannot be retrieved.
    pub async fn container_logs(
        &self,
        machine_name: &str,
        container_id: &str,
        follow: bool,
        stdout: bool,
        stderr: bool,
        since: i64,
        until: i64,
        timestamps: bool,
        tail: i64,
    ) -> Result<LogEntry> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let req = LogsRequest {
            container_id: container_id.to_string(),
            follow,
            stdout,
            stderr,
            since,
            until,
            timestamps,
            tail,
        };

        let response = {
            #[cfg(target_os = "macos")]
            {
                let mut agent = self.machine_manager.connect_agent(machine_name)?;
                agent.logs(req).await?
            }
            #[cfg(target_os = "linux")]
            {
                let agent = self.agent_pool.get(cid).await;
                let mut agent = agent.write().await;
                agent.logs(req).await?
            }
        };

        Ok(response)
    }

    /// Gets container logs as a stream from a machine.
    ///
    /// This is used for `follow=true` mode to stream logs continuously.
    ///
    /// # Errors
    ///
    /// Returns an error if the logs stream cannot be established.
    pub async fn container_logs_stream(
        &self,
        machine_name: &str,
        container_id: &str,
        stdout: bool,
        stderr: bool,
        since: i64,
        until: i64,
        timestamps: bool,
        tail: i64,
    ) -> Result<ReceiverStream<Result<LogEntry>>> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let req = LogsRequest {
            container_id: container_id.to_string(),
            follow: true, // Always true for streaming
            stdout,
            stderr,
            since,
            until,
            timestamps,
            tail,
        };

        let stream = {
            #[cfg(target_os = "macos")]
            {
                let mut agent = self.machine_manager.connect_agent(machine_name)?;
                agent.logs_stream(req).await?
            }
            #[cfg(target_os = "linux")]
            {
                let agent = self.agent_pool.get(cid).await;
                let mut agent = agent.write().await;
                agent.logs_stream(req).await?
            }
        };

        Ok(stream)
    }

    /// Attaches to a running container for interactive I/O.
    ///
    /// Returns a stream of outputs and a sender for stdin/resize messages.
    pub async fn container_attach(
        &self,
        machine_name: &str,
        container_id: &str,
        exec_id: Option<String>,
        attach_stdin: bool,
        attach_stdout: bool,
        attach_stderr: bool,
        tty_width: u32,
        tty_height: u32,
    ) -> Result<(
        ReceiverStream<Result<AttachOutput>>,
        mpsc::Sender<AttachInput>,
    )> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let req = AttachRequest {
            container_id: container_id.to_string(),
            attach_stdin,
            attach_stdout,
            attach_stderr,
            tty_width,
            tty_height,
            exec_id: exec_id.unwrap_or_default(),
        };

        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent
                .attach_stream(req)
                .await
                .map_err(|e| CoreError::Machine(e.to_string()))
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent
                .attach_stream(req)
                .await
                .map_err(|e| CoreError::Machine(e.to_string()))
        }
    }

    /// Attaches to an exec session using the same attach stream pipeline.
    pub async fn exec_attach(
        &self,
        machine_name: &str,
        exec_id: &str,
        attach_stdin: bool,
        attach_stdout: bool,
        attach_stderr: bool,
        tty_width: u32,
        tty_height: u32,
    ) -> Result<(
        ReceiverStream<Result<AttachOutput>>,
        mpsc::Sender<AttachInput>,
    )> {
        self.container_attach(
            machine_name,
            "",
            Some(exec_id.to_string()),
            attach_stdin,
            attach_stdout,
            attach_stderr,
            tty_width,
            tty_height,
        )
        .await
    }

    /// Starts an exec session in the guest VM (streaming-ready).
    pub async fn exec_start_streaming(
        &self,
        machine_name: &str,
        exec_id: &str,
        container_id: &str,
        cmd: Vec<String>,
        env: std::collections::HashMap<String, String>,
        working_dir: Option<String>,
        user: Option<String>,
        tty: bool,
        detach: bool,
        tty_width: u32,
        tty_height: u32,
    ) -> Result<u32> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let req = arcbox_protocol::agent::ExecStartRequest {
            exec_id: exec_id.to_string(),
            container_id: container_id.to_string(),
            cmd,
            env,
            working_dir: working_dir.unwrap_or_default(),
            user: user.unwrap_or_default(),
            tty,
            detach,
            tty_width,
            tty_height,
        };

        let resp = {
            #[cfg(target_os = "macos")]
            {
                let mut agent = self.machine_manager.connect_agent(machine_name)?;
                agent.exec_start(req).await?
            }
            #[cfg(target_os = "linux")]
            {
                let agent = self.agent_pool.get(cid).await;
                let mut agent = agent.write().await;
                agent.exec_start(req).await?
            }
        };

        Ok(resp.pid)
    }

    /// Resizes an exec session PTY.
    pub async fn exec_resize(
        &self,
        machine_name: &str,
        exec_id: &str,
        width: u32,
        height: u32,
    ) -> Result<()> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let req = arcbox_protocol::agent::ExecResizeRequest {
            exec_id: exec_id.to_string(),
            width,
            height,
        };

        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.exec_resize(req).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.exec_resize(req).await?;
        }

        Ok(())
    }

    /// Kills a container in a machine with a signal.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be killed.
    pub async fn kill_container(
        &self,
        machine_name: &str,
        container_id: &ContainerId,
        signal: &str,
    ) -> Result<()> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        // Send stop request to agent with 0 timeout (immediate kill).
        // Note: The agent protocol doesn't have a dedicated kill RPC,
        // so we use stop with timeout=0 for SIGKILL behavior.
        let timeout = if signal == "SIGKILL" || signal == "9" {
            0 // Immediate termination
        } else {
            1 // Brief timeout for SIGTERM
        };

        let container_id_str = container_id.to_string();
        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.kill_container(&container_id_str, signal).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.kill_container(&container_id_str, signal).await?;
        }

        // Stop port forwarding.
        self.stop_port_forwarding(container_id).await;

        // Update local state after successful agent call.
        self.container_manager.kill(container_id, signal).await?;

        tracing::info!(
            "Killed container {} in machine '{}' with signal {}",
            container_id,
            machine_name,
            signal
        );

        Ok(())
    }

    /// Pauses a container.
    ///
    /// Sends SIGSTOP to suspend all processes in the container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be paused.
    pub async fn pause_container(
        &self,
        machine_name: &str,
        container_id: &ContainerId,
    ) -> Result<()> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let container_id_str = container_id.to_string();

        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.pause_container(&container_id_str).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.pause_container(&container_id_str).await?;
        }

        // Update local state after successful agent call.
        self.container_manager.update(container_id, |c| {
            c.state = arcbox_container::state::ContainerState::Paused;
        })?;

        tracing::info!(
            "Paused container {} in machine '{}'",
            container_id,
            machine_name
        );

        Ok(())
    }

    /// Unpauses a container.
    ///
    /// Sends SIGCONT to resume all processes in the container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be unpaused.
    pub async fn unpause_container(
        &self,
        machine_name: &str,
        container_id: &ContainerId,
    ) -> Result<()> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let container_id_str = container_id.to_string();

        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.unpause_container(&container_id_str).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.unpause_container(&container_id_str).await?;
        }

        // Update local state after successful agent call.
        self.container_manager.update(container_id, |c| {
            c.state = arcbox_container::state::ContainerState::Running;
        })?;

        tracing::info!(
            "Unpaused container {} in machine '{}'",
            container_id,
            machine_name
        );

        Ok(())
    }

    /// Gets container statistics (CPU, memory, I/O).
    ///
    /// # Errors
    ///
    /// Returns an error if stats cannot be retrieved.
    pub async fn container_stats(
        &self,
        machine_name: &str,
        container_id: &str,
    ) -> Result<arcbox_protocol::container::ContainerStatsResponse> {
        let _cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent
                .container_stats(container_id)
                .await
                .map_err(Into::into)
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(_cid).await;
            let mut agent = agent.write().await;
            agent
                .container_stats(container_id)
                .await
                .map_err(Into::into)
        }
    }

    /// Gets the process list for a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the process list cannot be retrieved.
    pub async fn container_top(
        &self,
        machine_name: &str,
        container_id: &str,
        ps_args: &str,
    ) -> Result<arcbox_protocol::container::ContainerTopResponse> {
        let _cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent
                .container_top(container_id, ps_args)
                .await
                .map_err(Into::into)
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(_cid).await;
            let mut agent = agent.write().await;
            agent
                .container_top(container_id, ps_args)
                .await
                .map_err(Into::into)
        }
    }

    // =========================================================================
    // Exec operations (coordinating ExecManager + Agent)
    // =========================================================================

    /// Executes a command in a container.
    ///
    /// This is the main exec entry point that coordinates between
    /// ExecManager (local metadata) and Agent (actual execution).
    ///
    /// # Errors
    ///
    /// Returns an error if execution fails.
    pub async fn exec_container(
        &self,
        machine_name: &str,
        container_id: &str,
        cmd: Vec<String>,
        env: std::collections::HashMap<String, String>,
        working_dir: String,
        user: String,
        tty: bool,
    ) -> Result<arcbox_protocol::agent::ExecOutput> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        let req = arcbox_protocol::agent::ExecRequest {
            container_id: container_id.to_string(),
            cmd,
            env,
            working_dir,
            user,
            tty,
        };

        let output = {
            #[cfg(target_os = "macos")]
            {
                let mut agent = self.machine_manager.connect_agent(machine_name)?;
                agent.exec(req).await?
            }
            #[cfg(target_os = "linux")]
            {
                let agent = self.agent_pool.get(cid).await;
                let mut agent = agent.write().await;
                agent.exec(req).await?
            }
        };

        tracing::debug!(
            "Executed command in container {} (machine '{}'), exit_code: {}",
            container_id,
            machine_name,
            output.exit_code
        );

        Ok(output)
    }

    /// Executes a command in the VM (not in a container).
    ///
    /// # Errors
    ///
    /// Returns an error if execution fails.
    pub async fn exec_machine(
        &self,
        machine_name: &str,
        cmd: Vec<String>,
        env: std::collections::HashMap<String, String>,
        working_dir: String,
        user: String,
        tty: bool,
    ) -> Result<arcbox_protocol::agent::ExecOutput> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::not_found(machine_name.to_string()))?;

        // Empty container_id means execute in VM namespace.
        let req = arcbox_protocol::agent::ExecRequest {
            container_id: String::new(),
            cmd,
            env,
            working_dir,
            user,
            tty,
        };

        let output = {
            #[cfg(target_os = "macos")]
            {
                let mut agent = self.machine_manager.connect_agent(machine_name)?;
                agent.exec(req).await?
            }
            #[cfg(target_os = "linux")]
            {
                let agent = self.agent_pool.get(cid).await;
                let mut agent = agent.write().await;
                agent.exec(req).await?
            }
        };

        tracing::debug!(
            "Executed command in machine '{}', exit_code: {}",
            machine_name,
            output.exit_code
        );

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::validate_bundled_runtime_manifest;
    use crate::boot_assets::{BootAssetManifest, RuntimeAssetManifestEntry};
    use sha2::{Digest, Sha256};

    fn runtime_entry(name: &str, content: &[u8]) -> RuntimeAssetManifestEntry {
        RuntimeAssetManifestEntry {
            name: name.to_string(),
            path: format!("runtime/bin/{}", name),
            version: Some("test-version".to_string()),
            sha256: Some(format!("{:x}", Sha256::digest(content))),
        }
    }

    #[test]
    fn test_validate_bundled_runtime_manifest_ok() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_dir = temp_dir.path().join("runtime/bin");
        std::fs::create_dir_all(&runtime_dir).unwrap();

        std::fs::write(runtime_dir.join("dockerd"), b"dockerd-bin").unwrap();
        std::fs::write(runtime_dir.join("containerd"), b"containerd-bin").unwrap();
        std::fs::write(runtime_dir.join("youki"), b"youki-bin").unwrap();

        let manifest = BootAssetManifest {
            schema_version: 1,
            asset_version: "test".to_string(),
            arch: "arm64".to_string(),
            kernel_commit: None,
            agent_commit: None,
            built_at: None,
            kernel_cmdline: None,
            runtime_assets: vec![
                runtime_entry("dockerd", b"dockerd-bin"),
                runtime_entry("containerd", b"containerd-bin"),
                runtime_entry("youki", b"youki-bin"),
            ],
        };

        let result = validate_bundled_runtime_manifest(&manifest, temp_dir.path());
        assert!(
            result.is_ok(),
            "expected validation success, got {:?}",
            result
        );
    }

    #[test]
    fn test_validate_bundled_runtime_manifest_missing_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let runtime_dir = temp_dir.path().join("runtime/bin");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        std::fs::write(runtime_dir.join("dockerd"), b"dockerd-bin").unwrap();
        std::fs::write(runtime_dir.join("containerd"), b"containerd-bin").unwrap();

        let manifest = BootAssetManifest {
            schema_version: 1,
            asset_version: "test".to_string(),
            arch: "arm64".to_string(),
            kernel_commit: None,
            agent_commit: None,
            built_at: None,
            kernel_cmdline: None,
            runtime_assets: vec![
                runtime_entry("dockerd", b"dockerd-bin"),
                runtime_entry("containerd", b"containerd-bin"),
            ],
        };

        let err = validate_bundled_runtime_manifest(&manifest, temp_dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("runtime_assets missing required entries"),
            "unexpected error: {}",
            err
        );
    }
}
