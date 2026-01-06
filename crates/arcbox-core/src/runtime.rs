//! ArcBox runtime.

use crate::agent_client::AgentPool;
use crate::config::Config;
use crate::error::Result;
use crate::event::EventBus;
use crate::machine::MachineManager;
use crate::vm::VmManager;
use arcbox_container::ContainerManager;
use arcbox_image::ImageStore;
use std::sync::Arc;

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
        let agent_pool = Arc::new(AgentPool::new());

        Ok(Self {
            config,
            event_bus,
            vm_manager,
            machine_manager,
            container_manager,
            image_store,
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
