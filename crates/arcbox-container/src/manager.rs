//! Container manager.

use crate::{
    config::ContainerConfig,
    error::{ContainerError, Result},
    state::{Container, ContainerId, ContainerState},
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

/// Trait for agent communication.
///
/// This trait abstracts the communication with the guest VM agent,
/// allowing different implementations (real vsock, mock for testing).
#[async_trait]
pub trait AgentConnection: Send + Sync {
    /// Starts a container in the guest VM.
    async fn start_container(&self, id: &str) -> std::result::Result<(), String>;

    /// Stops a container in the guest VM.
    async fn stop_container(&self, id: &str, timeout: u32) -> std::result::Result<(), String>;

    /// Kills a container in the guest VM with a signal.
    async fn kill_container(&self, id: &str, signal: &str) -> std::result::Result<(), String>;
}

/// Container manager.
///
/// Manages container lifecycle and state.
pub struct ContainerManager {
    containers: RwLock<HashMap<ContainerId, Container>>,
    /// Channel to notify waiters when a container exits.
    /// Sends (container_id, exit_code).
    exit_sender: broadcast::Sender<(ContainerId, i32)>,
    /// Agent connection for communicating with guest VM.
    agent: Option<Arc<dyn AgentConnection>>,
}

impl ContainerManager {
    /// Creates a new container manager.
    #[must_use]
    pub fn new() -> Self {
        // Create broadcast channel with reasonable capacity.
        let (exit_sender, _) = broadcast::channel(256);

        Self {
            containers: RwLock::new(HashMap::new()),
            exit_sender,
            agent: None,
        }
    }

    /// Creates a new container manager with an agent connection.
    #[must_use]
    pub fn with_agent(agent: Arc<dyn AgentConnection>) -> Self {
        let (exit_sender, _) = broadcast::channel(256);

        Self {
            containers: RwLock::new(HashMap::new()),
            exit_sender,
            agent: Some(agent),
        }
    }

    /// Sets the agent connection.
    pub fn set_agent(&mut self, agent: Arc<dyn AgentConnection>) {
        self.agent = Some(agent);
    }

    /// Creates a new container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be created.
    pub fn create(&self, config: ContainerConfig) -> Result<ContainerId> {
        let name = config
            .name
            .clone()
            .unwrap_or_else(|| format!("container_{}", uuid::Uuid::new_v4()));

        let container = Container::new(name, &config.image);
        let id = container.id.clone();

        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        containers.insert(id.clone(), container);
        Ok(id)
    }

    /// Starts a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be started.
    pub async fn start(&self, id: &ContainerId) -> Result<()> {
        // First validate state (holding lock briefly).
        {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

            if container.state != ContainerState::Created
                && container.state != ContainerState::Exited
            {
                return Err(ContainerError::InvalidState(format!(
                    "cannot start from state {}",
                    container.state
                )));
            }
        }

        // Send start command to agent if connected.
        if let Some(ref agent) = self.agent {
            agent.start_container(id.as_str()).await.map_err(|e| {
                ContainerError::Runtime(format!("agent start failed: {}", e))
            })?;
        }

        // Update local state after successful agent call.
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

        container.state = ContainerState::Running;
        container.started_at = Some(chrono::Utc::now());
        Ok(())
    }

    /// Stops a container.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    /// * `timeout` - Timeout in seconds before force kill
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be stopped.
    pub async fn stop(&self, id: &ContainerId, timeout: u32) -> Result<()> {
        // First validate state (holding lock briefly).
        {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

            if container.state != ContainerState::Running {
                return Err(ContainerError::InvalidState(format!(
                    "cannot stop from state {}",
                    container.state
                )));
            }
        }

        // Send stop command to agent if connected.
        if let Some(ref agent) = self.agent {
            agent.stop_container(id.as_str(), timeout).await.map_err(|e| {
                ContainerError::Runtime(format!("agent stop failed: {}", e))
            })?;
        }

        // Update local state after successful agent call.
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

        container.state = ContainerState::Exited;
        container.exit_code = Some(0);
        container.finished_at = Some(chrono::Utc::now());
        Ok(())
    }

    /// Kills a container with a signal.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be killed.
    pub async fn kill(&self, id: &ContainerId, signal: &str) -> Result<()> {
        // First validate state (holding lock briefly).
        {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

            if container.state != ContainerState::Running {
                return Err(ContainerError::InvalidState(format!(
                    "cannot kill container in state {}",
                    container.state
                )));
            }
        }

        // Send kill command to agent if connected.
        if let Some(ref agent) = self.agent {
            agent.kill_container(id.as_str(), signal).await.map_err(|e| {
                ContainerError::Runtime(format!("agent kill failed: {}", e))
            })?;
        }

        // Update local state after successful agent call.
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

        container.state = ContainerState::Exited;
        // SIGKILL (9) -> 137, SIGTERM (15) -> 143
        container.exit_code = Some(if signal == "SIGKILL" || signal == "9" {
            137
        } else {
            143
        });
        container.finished_at = Some(chrono::Utc::now());
        Ok(())
    }

    /// Restarts a container.
    ///
    /// # Arguments
    ///
    /// * `id` - Container ID
    /// * `timeout` - Timeout in seconds for stop operation
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be restarted.
    pub async fn restart(&self, id: &ContainerId, timeout: u32) -> Result<()> {
        // Check if container is running (holding lock briefly).
        let is_running = {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

            container.state == ContainerState::Running
        };

        // Stop if running (lock is released before await).
        if is_running {
            self.stop(id, timeout).await?;
        }

        // Reset state to allow restart.
        {
            let mut containers = self
                .containers
                .write()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            if let Some(c) = containers.get_mut(id) {
                c.state = ContainerState::Created;
                c.exit_code = None;
            }
        }

        // Start the container.
        self.start(id).await
    }

    /// Checks if a container has already exited and returns its exit code.
    ///
    /// Returns `None` if the container is still running or not found.
    #[must_use]
    pub fn wait(&self, id: &ContainerId) -> Option<i32> {
        let containers = self.containers.read().ok()?;
        let container = containers.get(id)?;

        match container.state {
            ContainerState::Exited | ContainerState::Dead => container.exit_code,
            _ => None,
        }
    }

    /// Asynchronously waits for a container to exit.
    ///
    /// Returns the exit code when the container exits. If the container
    /// has already exited, returns immediately.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or if waiting fails.
    pub async fn wait_async(&self, id: &ContainerId) -> Result<i32> {
        // First check if already exited.
        {
            let containers = self.containers.read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers.get(id)
                .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

            match container.state {
                ContainerState::Exited | ContainerState::Dead => {
                    return Ok(container.exit_code.unwrap_or(0));
                }
                _ => {}
            }
        }

        // Subscribe to exit notifications.
        let mut receiver = self.exit_sender.subscribe();
        let target_id = id.clone();

        // Wait for the container to exit.
        loop {
            // Check again in case it exited between our check and subscribe.
            {
                let containers = self.containers.read()
                    .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

                if let Some(container) = containers.get(&target_id) {
                    match container.state {
                        ContainerState::Exited | ContainerState::Dead => {
                            return Ok(container.exit_code.unwrap_or(0));
                        }
                        _ => {}
                    }
                } else {
                    return Err(ContainerError::NotFound(target_id.to_string()));
                }
            }

            // Wait for next exit notification.
            match receiver.recv().await {
                Ok((exited_id, exit_code)) => {
                    if exited_id == target_id {
                        return Ok(exit_code);
                    }
                    // Not our container, keep waiting.
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // We missed some messages, check state again.
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(ContainerError::Runtime("exit channel closed".to_string()));
                }
            }
        }
    }

    /// Notifies waiters that a container has exited.
    ///
    /// This should be called when the container state changes to Exited or Dead.
    pub fn notify_exit(&self, id: &ContainerId, exit_code: i32) {
        // Update container state.
        if let Ok(mut containers) = self.containers.write() {
            if let Some(container) = containers.get_mut(id) {
                container.state = ContainerState::Exited;
                container.exit_code = Some(exit_code);
                container.finished_at = Some(chrono::Utc::now());
            }
        }

        // Notify waiters (ignore if no one is listening).
        let _ = self.exit_sender.send((id.clone(), exit_code));
    }

    /// Removes a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be removed.
    pub fn remove(&self, id: &ContainerId) -> Result<()> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get(id)
            .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

        if container.state == ContainerState::Running {
            return Err(ContainerError::InvalidState(
                "cannot remove running container".to_string(),
            ));
        }

        containers.remove(id);
        Ok(())
    }

    /// Gets container information.
    #[must_use]
    pub fn get(&self, id: &ContainerId) -> Option<Container> {
        self.containers.read().ok()?.get(id).cloned()
    }

    /// Lists all containers.
    #[must_use]
    pub fn list(&self) -> Vec<Container> {
        self.containers
            .read()
            .map(|c| c.values().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for ContainerManager {
    fn default() -> Self {
        Self::new()
    }
}
