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

    /// Waits for a container to exit in the guest VM.
    ///
    /// Returns the exit code when the container exits.
    async fn wait_container(&self, id: &str) -> std::result::Result<i32, String>;
}

/// Container manager.
///
/// Manages container lifecycle and state.
pub struct ContainerManager {
    containers: RwLock<HashMap<ContainerId, Container>>,
    /// Channel to notify waiters when a container exits.
    /// Sends (container_id, exit_code).
    exit_sender: broadcast::Sender<(ContainerId, i32)>,
    /// Channel to notify waiters when container state changes.
    /// Sends (container_id, new_state).
    state_sender: broadcast::Sender<(ContainerId, ContainerState)>,
    /// Agent connection for communicating with guest VM.
    agent: Option<Arc<dyn AgentConnection>>,
}

/// Snapshot for rolling back a start transition.
#[derive(Debug)]
pub struct StartTicket {
    prev_state: ContainerState,
    prev_started_at: Option<chrono::DateTime<chrono::Utc>>,
    prev_finished_at: Option<chrono::DateTime<chrono::Utc>>,
    prev_exit_code: Option<i32>,
}

/// Result of a start transition attempt.
#[derive(Debug)]
pub enum StartOutcome {
    /// Transitioned to Starting; caller should invoke the agent.
    Started(StartTicket),
    /// Container is already running.
    AlreadyRunning,
    /// Container start is already in progress.
    AlreadyStarting,
}

impl ContainerManager {
    /// Creates a new container manager.
    #[must_use]
    pub fn new() -> Self {
        // Create broadcast channels with reasonable capacity.
        let (exit_sender, _) = broadcast::channel(256);
        let (state_sender, _) = broadcast::channel(256);

        Self {
            containers: RwLock::new(HashMap::new()),
            exit_sender,
            state_sender,
            agent: None,
        }
    }

    /// Creates a new container manager with an agent connection.
    #[must_use]
    pub fn with_agent(agent: Arc<dyn AgentConnection>) -> Self {
        let (exit_sender, _) = broadcast::channel(256);
        let (state_sender, _) = broadcast::channel(256);

        Self {
            containers: RwLock::new(HashMap::new()),
            exit_sender,
            state_sender,
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

        // Use with_config to store the full configuration (including port_bindings).
        let container = Container::with_config(name, config);
        let id = container.id.clone();

        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        containers.insert(id.clone(), container);
        Ok(id)
    }

    /// Updates a container in the manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or lock is poisoned.
    pub fn update(&self, id: &ContainerId, f: impl FnOnce(&mut Container)) -> Result<()> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

        f(container);
        Ok(())
    }

    /// Starts a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container cannot be started.
    pub async fn start(&self, id: &ContainerId) -> Result<()> {
        match self.begin_start(id)? {
            StartOutcome::Started(_ticket) => {
                self.finish_start(id)?;
            }
            StartOutcome::AlreadyRunning | StartOutcome::AlreadyStarting => {}
        }
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
                .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

            if container.state != ContainerState::Running {
                return Err(ContainerError::invalid_state(format!(
                    "cannot stop from state {}",
                    container.state
                )));
            }
        }

        // Send stop command to agent if connected.
        if let Some(ref agent) = self.agent {
            agent
                .stop_container(id.as_str(), timeout)
                .await
                .map_err(|e| ContainerError::Runtime(format!("agent stop failed: {}", e)))?;
        }

        // Update local state after successful agent call.
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

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
                .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

            if container.state != ContainerState::Running {
                return Err(ContainerError::invalid_state(format!(
                    "cannot kill container in state {}",
                    container.state
                )));
            }
        }

        // Send kill command to agent if connected.
        if let Some(ref agent) = self.agent {
            agent
                .kill_container(id.as_str(), signal)
                .await
                .map_err(|e| ContainerError::Runtime(format!("agent kill failed: {}", e)))?;
        }

        // Update local state after successful agent call.
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

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
        // Check current state (holding lock briefly).
        let state = {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

            container.state
        };

        if state == ContainerState::Starting {
            return Err(ContainerError::invalid_state(
                "cannot restart while starting".to_string(),
            ));
        }

        // Stop if running (lock is released before await).
        if state == ContainerState::Running {
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

    /// Marks a container as starting, returning the previous state snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is in an invalid state.
    pub fn begin_start(&self, id: &ContainerId) -> Result<StartOutcome> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

        match container.state {
            ContainerState::Created | ContainerState::Exited => {
                let ticket = StartTicket {
                    prev_state: container.state,
                    prev_started_at: container.started_at,
                    prev_finished_at: container.finished_at,
                    prev_exit_code: container.exit_code,
                };
                container.state = ContainerState::Starting;
                container.started_at = None;
                container.finished_at = None;
                container.exit_code = None;
                Ok(StartOutcome::Started(ticket))
            }
            ContainerState::Running => Ok(StartOutcome::AlreadyRunning),
            ContainerState::Starting => Ok(StartOutcome::AlreadyStarting),
            _ => Err(ContainerError::invalid_state(format!(
                "cannot start from state {}",
                container.state
            ))),
        }
    }

    /// Marks a container as running after a successful start.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found.
    pub fn finish_start(&self, id: &ContainerId) -> Result<()> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

        container.state = ContainerState::Running;
        container.started_at = Some(chrono::Utc::now());
        container.finished_at = None;
        container.exit_code = None;

        // Notify state change waiters.
        let _ = self
            .state_sender
            .send((id.clone(), ContainerState::Running));

        Ok(())
    }

    /// Restores container state if a start attempt fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found.
    pub fn fail_start(&self, id: &ContainerId, ticket: StartTicket) -> Result<()> {
        let mut containers = self
            .containers
            .write()
            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

        let container = containers
            .get_mut(id)
            .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

        container.state = ticket.prev_state;
        container.started_at = ticket.prev_started_at;
        container.finished_at = ticket.prev_finished_at;
        container.exit_code = ticket.prev_exit_code;
        Ok(())
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
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

            match container.state {
                ContainerState::Exited | ContainerState::Dead => {
                    return Ok(container.exit_code.unwrap_or(0));
                }
                _ => {}
            }
        }

        // If we have an agent, ask it to wait for the container.
        // This is the primary mechanism for knowing when a container exits.
        if let Some(ref agent) = self.agent {
            let exit_code = agent
                .wait_container(&id.to_string())
                .await
                .map_err(|e| ContainerError::Runtime(format!("agent wait failed: {}", e)))?;

            // Update container state.
            self.notify_exit(id, exit_code);

            return Ok(exit_code);
        }

        // Fallback: subscribe to exit notifications (for testing or if agent is unavailable).
        let mut receiver = self.exit_sender.subscribe();
        let target_id = id.clone();

        // Wait for the container to exit.
        loop {
            // Check again in case it exited between our check and subscribe.
            {
                let containers = self
                    .containers
                    .read()
                    .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

                if let Some(container) = containers.get(&target_id) {
                    match container.state {
                        ContainerState::Exited | ContainerState::Dead => {
                            return Ok(container.exit_code.unwrap_or(0));
                        }
                        _ => {}
                    }
                } else {
                    return Err(ContainerError::not_found(target_id.to_string()));
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

        // Notify state change waiters.
        let _ = self.state_sender.send((id.clone(), ContainerState::Exited));
        // Notify exit waiters (ignore if no one is listening).
        let _ = self.exit_sender.send((id.clone(), exit_code));
    }

    /// Waits for a container to reach Running or Exited state.
    ///
    /// This is useful for attach operations that need to wait for the container
    /// to be ready before attaching to its streams.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or if waiting times out.
    pub async fn wait_for_running_or_exited(
        &self,
        id: &ContainerId,
        timeout: std::time::Duration,
    ) -> Result<ContainerState> {
        use tokio::time::timeout as tokio_timeout;

        // First check current state.
        {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            let container = containers
                .get(id)
                .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

            match container.state {
                ContainerState::Running | ContainerState::Exited | ContainerState::Dead => {
                    return Ok(container.state);
                }
                _ => {}
            }
        }

        // Subscribe to state changes before checking again to avoid race.
        let mut receiver = self.state_sender.subscribe();
        let target_id = id.clone();

        // Check again after subscribing.
        {
            let containers = self
                .containers
                .read()
                .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;

            if let Some(container) = containers.get(&target_id) {
                match container.state {
                    ContainerState::Running | ContainerState::Exited | ContainerState::Dead => {
                        return Ok(container.state);
                    }
                    _ => {}
                }
            } else {
                return Err(ContainerError::not_found(target_id.to_string()));
            }
        }

        // Wait for state change with timeout.
        let wait_future = async {
            loop {
                match receiver.recv().await {
                    Ok((changed_id, new_state)) => {
                        if changed_id == target_id {
                            match new_state {
                                ContainerState::Running
                                | ContainerState::Exited
                                | ContainerState::Dead => {
                                    return Ok(new_state);
                                }
                                _ => continue,
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Missed some messages, check current state.
                        let containers = self
                            .containers
                            .read()
                            .map_err(|_| ContainerError::Runtime("lock poisoned".to_string()))?;
                        if let Some(container) = containers.get(&target_id) {
                            match container.state {
                                ContainerState::Running
                                | ContainerState::Exited
                                | ContainerState::Dead => {
                                    return Ok(container.state);
                                }
                                _ => continue,
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(ContainerError::Runtime(
                            "state change channel closed".to_string(),
                        ));
                    }
                }
            }
        };

        match tokio_timeout(timeout, wait_future).await {
            Ok(result) => result,
            Err(_) => Err(ContainerError::Runtime(format!(
                "timeout waiting for container {} to start",
                id
            ))),
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
            .ok_or_else(|| ContainerError::not_found(id.to_string()))?;

        if matches!(
            container.state,
            ContainerState::Running | ContainerState::Starting
        ) {
            return Err(ContainerError::invalid_state(
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

    /// Resolves a container by ID prefix or name.
    ///
    /// This method supports Docker-compatible container resolution:
    /// - Full container ID (12 hex characters)
    /// - ID prefix (minimum 3 characters for uniqueness)
    /// - Container name (exact match)
    ///
    /// Returns None if no container matches or if the prefix is ambiguous.
    #[must_use]
    pub fn resolve(&self, id_or_name: &str) -> Option<Container> {
        let containers = self.containers.read().ok()?;

        // First, try exact ID match.
        let container_id = ContainerId::from_string(id_or_name);
        if let Some(container) = containers.get(&container_id) {
            return Some(container.clone());
        }

        // Try name match.
        for container in containers.values() {
            if container.name == id_or_name {
                return Some(container.clone());
            }
        }

        // Try ID prefix match (minimum 3 characters for safety).
        if id_or_name.len() >= 3 {
            let mut matches: Vec<&Container> = containers
                .values()
                .filter(|c| c.id.as_str().starts_with(id_or_name))
                .collect();

            if matches.len() == 1 {
                return Some(matches.remove(0).clone());
            }
        }

        None
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn start_is_atomic_and_blocks_concurrent_start() {
        let manager = ContainerManager::new();

        let mut config = ContainerConfig::default();
        config.image = "alpine".to_string();
        let id = manager.create(config).unwrap();

        let outcome = manager.begin_start(&id).unwrap();
        assert!(matches!(outcome, StartOutcome::Started(_)));
        let state = manager.get(&id).unwrap().state;
        assert_eq!(state, ContainerState::Starting);

        let second = manager.begin_start(&id).unwrap();
        assert!(matches!(second, StartOutcome::AlreadyStarting));

        manager.finish_start(&id).unwrap();
        assert_eq!(manager.get(&id).unwrap().state, ContainerState::Running);
    }
}
