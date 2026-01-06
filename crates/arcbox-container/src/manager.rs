//! Container manager.

use crate::{
    config::ContainerConfig,
    error::{ContainerError, Result},
    state::{Container, ContainerId, ContainerState},
};
use std::collections::HashMap;
use std::sync::RwLock;

/// Container manager.
///
/// Manages container lifecycle and state.
pub struct ContainerManager {
    containers: RwLock<HashMap<ContainerId, Container>>,
}

impl ContainerManager {
    /// Creates a new container manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            containers: RwLock::new(HashMap::new()),
        }
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
    pub fn start(&self, id: &ContainerId) -> Result<()> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

        if container.state != ContainerState::Created
            && container.state != ContainerState::Exited
        {
            return Err(ContainerError::InvalidState(format!(
                "cannot start from state {}",
                container.state
            )));
        }

        // TODO: Send start command to arcbox-agent
        container.state = ContainerState::Running;
        container.started_at = Some(chrono::Utc::now());
        Ok(())
    }

    /// Stops a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be stopped.
    pub fn stop(&self, id: &ContainerId) -> Result<()> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

        if container.state != ContainerState::Running {
            return Err(ContainerError::InvalidState(format!(
                "cannot stop from state {}",
                container.state
            )));
        }

        // TODO: Send stop command to arcbox-agent
        container.state = ContainerState::Exited;
        container.exit_code = Some(0);
        Ok(())
    }

    /// Kills a container with a signal.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be killed.
    pub fn kill(&self, id: &ContainerId, signal: &str) -> Result<()> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

        if container.state != ContainerState::Running {
            return Err(ContainerError::InvalidState(format!(
                "cannot kill container in state {}",
                container.state
            )));
        }

        // TODO: Send kill signal to arcbox-agent
        container.state = ContainerState::Exited;
        // SIGKILL (9) -> 137, SIGTERM (15) -> 143
        container.exit_code = Some(if signal == "SIGKILL" || signal == "9" {
            137
        } else {
            143
        });
        Ok(())
    }

    /// Restarts a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be restarted.
    pub fn restart(&self, id: &ContainerId) -> Result<()> {
        // First stop if running.
        {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::NotFound(id.to_string()))?;

            if container.state == ContainerState::Running {
                drop(containers);
                self.stop(id)?;
            }
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
        self.start(id)
    }

    /// Waits for a container to exit and returns its exit code.
    ///
    /// Note: This is a simplified implementation that returns immediately
    /// if the container is not running. A full implementation would use
    /// async channels to wait for state changes.
    #[must_use]
    pub fn wait(&self, id: &ContainerId) -> Option<i32> {
        let containers = self.containers.read().ok()?;
        let container = containers.get(id)?;

        match container.state {
            ContainerState::Exited | ContainerState::Dead => container.exit_code,
            _ => None,
        }
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
