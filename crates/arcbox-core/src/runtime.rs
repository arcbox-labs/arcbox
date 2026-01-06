//! ArcBox runtime.

use crate::agent_client::AgentPool;
use crate::config::Config;
use crate::error::{CoreError, Result};
use crate::event::EventBus;
use crate::machine::{MachineManager, MachineState};
use crate::vm::VmManager;
use arcbox_container::{ContainerConfig, ContainerId, ContainerManager, ContainerState, ExecManager, VolumeManager};
use arcbox_image::ImageStore;
use arcbox_net::NetworkManager;
use arcbox_protocol::agent::{CreateContainerRequest, LogEntry, LogsRequest};
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
        let event_bus = EventBus::new();
        let vm_manager = Arc::new(VmManager::new());
        let machine_manager = Arc::new(MachineManager::new(VmManager::new(), config.data_dir.clone()));
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

    /// Shuts down the runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("ArcBox runtime shutting down");
        // TODO: Stop all VMs and containers
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
        if let Some(mut container) = self.container_manager.get(&container_id) {
            container.machine_name = Some(machine_name.to_string());
            // Note: ContainerManager doesn't have an update method, so we'd need to add one
            // For now, we'll rely on the agent communication for actual container state
        }

        // Send create request to agent
        let agent = self.agent_pool.get(cid).await;
        let mut agent = agent.write().await;

        let req = CreateContainerRequest {
            name: config.name.clone().unwrap_or_default(),
            image: config.image.clone(),
            cmd: config.cmd.clone(),
            entrypoint: config.entrypoint.clone(),
            env: config.env.clone(),
            working_dir: config.working_dir.clone().unwrap_or_default(),
            user: config.user.clone().unwrap_or_default(),
            mounts: vec![],
            tty: false,
        };

        agent.create_container(req).await?;

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

        // Update local state
        self.container_manager.start(container_id)?;

        // Send start request to agent
        let agent = self.agent_pool.get(cid).await;
        let mut agent = agent.write().await;
        agent.start_container(&container_id.to_string()).await?;

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
        let agent = self.agent_pool.get(cid).await;
        let mut agent = agent.write().await;
        agent.stop_container(&container_id.to_string(), timeout).await?;

        // Update local state
        self.container_manager.stop(container_id)?;

        tracing::info!(
            "Stopped container {} in machine '{}'",
            container_id,
            machine_name
        );

        Ok(())
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
        let agent = self.agent_pool.get(cid).await;
        let mut agent = agent.write().await;
        agent.remove_container(&container_id.to_string(), force).await?;

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

        let agent = self.agent_pool.get(cid).await;
        let mut agent = agent.write().await;
        let response = agent.list_containers(all).await?;

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

        let agent = self.agent_pool.get(cid).await;
        let mut agent = agent.write().await;

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

        let response = agent.logs(req).await?;

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

        let agent = self.agent_pool.get(cid).await;
        let mut agent = agent.write().await;

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

        let stream = agent.logs_stream(req).await?;

        Ok(stream)
    }
}
