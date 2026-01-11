//! ArcBox runtime.

use crate::agent_client::AgentPool;
use crate::config::Config;
use crate::error::{CoreError, Result};
use crate::event::EventBus;
use crate::machine::{MachineManager, MachineState};
use crate::vm::VmManager;
use crate::vm_lifecycle::{VmLifecycleConfig, VmLifecycleManager, DEFAULT_MACHINE_NAME};
use arcbox_container::{ContainerConfig, ContainerId, ContainerManager, ContainerState, ExecManager, VolumeManager};
use arcbox_image::{ImageRef, ImageStore};
use arcbox_net::NetworkManager;
use arcbox_protocol::agent::{CreateContainerRequest, LogEntry, LogsRequest};
use arcbox_protocol::Mount;
use tokio_stream::wrappers::ReceiverStream;
use std::sync::{Arc, RwLock};

/// ArcBox runtime.
///
/// The main entry point for the ArcBox system, managing all components.
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
        vm_lifecycle_config: VmLifecycleConfig,
    ) -> Result<Self> {
        let event_bus = EventBus::new();
        let vm_manager = Arc::new(VmManager::new());
        let machine_manager = Arc::new(MachineManager::new(VmManager::new(), config.data_dir.clone()));

        // Create VM lifecycle manager with the machine manager
        let vm_lifecycle = Arc::new(VmLifecycleManager::new(
            machine_manager.clone(),
            config.data_dir.clone(),
            vm_lifecycle_config,
        ));

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
            container_manager,
            image_store,
            volume_manager,
            network_manager,
            exec_manager,
            agent_pool,
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
        self.vm_lifecycle.ensure_ready().await
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

        tracing::info!("ArcBox runtime initialized");
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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

        if machine.state != MachineState::Running {
            return Err(CoreError::InvalidState(format!(
                "machine '{}' is not running",
                machine_name
            )));
        }

        let cid = machine.cid.ok_or_else(|| {
            CoreError::Machine("machine has no CID assigned".to_string())
        })?;

        // Create container in local state first
        let container_id = self.container_manager.create(config.clone())?;

        // Update container with machine name
        let machine_name_clone = machine_name.to_string();
        self.container_manager.update(&container_id, |container| {
            container.machine_name = Some(machine_name_clone);
        })?;

        // Extract image to create rootfs
        let image_ref = ImageRef::parse(&config.image).ok_or_else(|| {
            CoreError::Config(format!("invalid image reference: {}", config.image))
        })?;

        // Prepare container rootfs by extracting image layers
        let host_rootfs = self
            .image_store
            .prepare_container_rootfs(&container_id.to_string(), &image_ref)?;

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
        let data_dir_str = self.config.data_dir.to_string_lossy();
        let mounts: Vec<Mount> = config
            .volumes
            .iter()
            .map(|v| {
                // Translate host path to guest-accessible path.
                // If source is under data_dir, map to /arcbox/...
                let guest_source = if v.source.starts_with(data_dir_str.as_ref()) {
                    v.source.replacen(data_dir_str.as_ref(), "/arcbox", 1)
                } else {
                    // For paths outside data_dir, keep as-is.
                    // TODO: Add VirtioFS share for home directory to support arbitrary paths.
                    tracing::warn!(
                        "Volume source '{}' is outside data_dir, mount may fail",
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

        let req = CreateContainerRequest {
            name: config.name.clone().unwrap_or_default(),
            image: config.image.clone(),
            cmd: config.cmd.clone(),
            entrypoint: config.entrypoint.clone(),
            env: config.env.clone(),
            working_dir: config.working_dir.clone().unwrap_or_default(),
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
    ) -> Result<()> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

        // Send start request to agent
        let container_id_str = container_id.to_string();
        #[cfg(target_os = "macos")]
        {
            let mut agent = self.machine_manager.connect_agent(machine_name)?;
            agent.start_container(&container_id_str).await?;
        }
        #[cfg(target_os = "linux")]
        {
            let agent = self.agent_pool.get(cid).await;
            let mut agent = agent.write().await;
            agent.start_container(&container_id_str).await?;
        }

        // Update local state after successful agent call
        self.container_manager.start(container_id).await?;

        tracing::info!(
            "Started container {} in machine '{}'",
            container_id,
            machine_name
        );

        Ok(())
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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
    pub async fn wait_container(
        &self,
        machine_name: &str,
        container_id: &str,
    ) -> Result<i32> {
        let cid = self
            .machine_manager
            .get_cid(machine_name)
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

        // Send remove request to agent first
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

        // Update local state
        self.container_manager.remove(container_id)?;

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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
            .ok_or_else(|| CoreError::NotFound(machine_name.to_string()))?;

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
