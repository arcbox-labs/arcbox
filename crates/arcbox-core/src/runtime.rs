//! ArcBox runtime.

use crate::agent_client::AgentPool;
use crate::config::Config;
use crate::error::Result;
use crate::event::EventBus;
use crate::machine::MachineManager;
use crate::vm::VmManager;
use arcbox_container::{ContainerManager, ExecManager, VolumeManager};
use arcbox_image::ImageStore;
use arcbox_net::NetworkManager;
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
}
