//! Exec instance management.
//!
//! Manages exec instances for running commands inside containers.

use crate::state::ContainerId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Exec instance ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecId(String);

impl ExecId {
    /// Creates a new exec ID.
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string().replace('-', ""))
    }

    /// Creates an exec ID from a string.
    #[must_use]
    pub fn from_string(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl Default for ExecId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ExecId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Exec instance configuration.
#[derive(Debug, Clone)]
pub struct ExecConfig {
    /// Container ID.
    pub container_id: ContainerId,
    /// Command to run.
    pub cmd: Vec<String>,
    /// Environment variables.
    pub env: Vec<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Attach stdin.
    pub attach_stdin: bool,
    /// Attach stdout.
    pub attach_stdout: bool,
    /// Attach stderr.
    pub attach_stderr: bool,
    /// Allocate a TTY.
    pub tty: bool,
    /// Run as user.
    pub user: Option<String>,
    /// Privileged mode.
    pub privileged: bool,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            container_id: ContainerId::from_string(""),
            cmd: vec![],
            env: vec![],
            working_dir: None,
            attach_stdin: false,
            attach_stdout: true,
            attach_stderr: true,
            tty: false,
            user: None,
            privileged: false,
        }
    }
}

/// Exec instance state.
#[derive(Debug, Clone)]
pub struct ExecInstance {
    /// Exec ID.
    pub id: ExecId,
    /// Configuration.
    pub config: ExecConfig,
    /// Whether the exec is running.
    pub running: bool,
    /// Exit code (if completed).
    pub exit_code: Option<i32>,
    /// Process ID (if running).
    pub pid: Option<u32>,
    /// Created timestamp.
    pub created: DateTime<Utc>,
}

impl ExecInstance {
    /// Creates a new exec instance.
    #[must_use]
    pub fn new(config: ExecConfig) -> Self {
        Self {
            id: ExecId::new(),
            config,
            running: false,
            exit_code: None,
            pid: None,
            created: Utc::now(),
        }
    }
}

/// Exec start request for agent communication.
#[derive(Debug, Clone)]
pub struct ExecStartParams {
    /// Exec ID.
    pub exec_id: String,
    /// Container ID.
    pub container_id: String,
    /// Command to execute.
    pub cmd: Vec<String>,
    /// Environment variables.
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// User to run as.
    pub user: Option<String>,
    /// Allocate TTY.
    pub tty: bool,
    /// Detach mode.
    pub detach: bool,
    /// Initial TTY width.
    pub tty_width: u32,
    /// Initial TTY height.
    pub tty_height: u32,
}

/// Exec start result from agent.
#[derive(Debug, Clone)]
pub struct ExecStartResult {
    /// Process ID in guest.
    pub pid: u32,
    /// Standard output (if not detached and not TTY).
    pub stdout: Vec<u8>,
    /// Standard error (if not detached and not TTY).
    pub stderr: Vec<u8>,
    /// Exit code (if not detached).
    pub exit_code: Option<i32>,
}

/// Trait for exec agent communication.
///
/// Abstracts communication with the guest VM agent for exec operations.
#[async_trait]
pub trait ExecAgentConnection: Send + Sync {
    /// Starts an exec instance in the guest VM.
    async fn exec_start(&self, params: ExecStartParams) -> Result<ExecStartResult, String>;

    /// Resizes an exec instance's TTY.
    async fn exec_resize(
        &self,
        exec_id: &str,
        width: u32,
        height: u32,
    ) -> Result<(), String>;
}

/// Exec manager.
pub struct ExecManager {
    /// Exec instances by ID.
    execs: RwLock<HashMap<String, ExecInstance>>,
    /// Agent connection for exec operations.
    agent: Option<Arc<dyn ExecAgentConnection>>,
}

impl ExecManager {
    /// Creates a new exec manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            execs: RwLock::new(HashMap::new()),
            agent: None,
        }
    }

    /// Creates a new exec manager with an agent connection.
    #[must_use]
    pub fn with_agent(agent: Arc<dyn ExecAgentConnection>) -> Self {
        Self {
            execs: RwLock::new(HashMap::new()),
            agent: Some(agent),
        }
    }

    /// Sets the agent connection.
    pub fn set_agent(&mut self, agent: Arc<dyn ExecAgentConnection>) {
        self.agent = Some(agent);
    }

    /// Creates a new exec instance.
    #[must_use]
    pub fn create(&self, config: ExecConfig) -> ExecId {
        let exec = ExecInstance::new(config);
        let id = exec.id.clone();

        let mut execs = self.execs.write().unwrap();
        execs.insert(id.to_string(), exec);

        id
    }

    /// Gets an exec instance by ID.
    #[must_use]
    pub fn get(&self, id: &ExecId) -> Option<ExecInstance> {
        self.execs.read().ok()?.get(&id.to_string()).cloned()
    }

    /// Starts an exec instance.
    ///
    /// Sends an ExecStartRequest to the agent and waits for completion.
    /// If detach=true, returns immediately after the process starts.
    ///
    /// # Arguments
    ///
    /// * `id` - The exec instance ID
    /// * `detach` - If true, run in background and return immediately
    /// * `tty_width` - Initial TTY width (if TTY mode)
    /// * `tty_height` - Initial TTY height (if TTY mode)
    ///
    /// # Errors
    ///
    /// Returns an error if the exec cannot be started.
    pub async fn start(
        &self,
        id: &ExecId,
        detach: bool,
        tty_width: u32,
        tty_height: u32,
    ) -> crate::Result<ExecStartResult> {
        // First validate state and get config (holding lock briefly).
        let (config, exec_id_str) = {
            let mut execs = self
                .execs
                .write()
                .map_err(|_| crate::ContainerError::Runtime("lock poisoned".to_string()))?;

            let exec = execs
                .get_mut(&id.to_string())
                .ok_or_else(|| crate::ContainerError::NotFound(id.to_string()))?;

            if exec.running {
                return Err(crate::ContainerError::InvalidState(
                    "exec is already running".to_string(),
                ));
            }

            exec.running = true;
            (exec.config.clone(), exec.id.to_string())
        };

        // Build the exec start params.
        let params = ExecStartParams {
            exec_id: exec_id_str.clone(),
            container_id: config.container_id.to_string(),
            cmd: config.cmd.clone(),
            env: config
                .env
                .iter()
                .filter_map(|s| {
                    let parts: Vec<&str> = s.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect(),
            working_dir: config.working_dir.clone(),
            user: config.user.clone(),
            tty: config.tty,
            detach,
            tty_width,
            tty_height,
        };

        // Send request to agent if connected.
        let result = if let Some(ref agent) = self.agent {
            agent.exec_start(params).await.map_err(|e| {
                crate::ContainerError::Runtime(format!("agent exec_start failed: {}", e))
            })?
        } else {
            // No agent - return empty result (for testing without VM).
            ExecStartResult {
                pid: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: Some(0),
            }
        };

        // Update local state after agent call.
        {
            let mut execs = self
                .execs
                .write()
                .map_err(|_| crate::ContainerError::Runtime("lock poisoned".to_string()))?;

            if let Some(exec) = execs.get_mut(&exec_id_str) {
                exec.pid = Some(result.pid);

                if let Some(exit_code) = result.exit_code {
                    // Process has exited.
                    exec.running = false;
                    exec.exit_code = Some(exit_code);
                }
                // If detached, process is still running (no exit_code yet).
            }
        }

        Ok(result)
    }

    /// Resizes the exec TTY.
    ///
    /// Sends a resize request to the agent to update the PTY window size.
    ///
    /// # Errors
    ///
    /// Returns an error if the resize fails.
    pub async fn resize(&self, id: &ExecId, width: u32, height: u32) -> crate::Result<()> {
        // Validate exec exists and has TTY.
        {
            let execs = self
                .execs
                .read()
                .map_err(|_| crate::ContainerError::Runtime("lock poisoned".to_string()))?;

            let exec = execs
                .get(&id.to_string())
                .ok_or_else(|| crate::ContainerError::NotFound(id.to_string()))?;

            if !exec.config.tty {
                return Err(crate::ContainerError::InvalidState(
                    "exec does not have a TTY".to_string(),
                ));
            }

            if !exec.running {
                return Err(crate::ContainerError::InvalidState(
                    "exec is not running".to_string(),
                ));
            }
        }

        // Send resize to agent if connected.
        if let Some(ref agent) = self.agent {
            agent
                .exec_resize(&id.to_string(), width, height)
                .await
                .map_err(|e| {
                    crate::ContainerError::Runtime(format!("agent exec_resize failed: {}", e))
                })?;
        }

        Ok(())
    }

    /// Marks an exec instance as completed.
    ///
    /// Called when the agent notifies that an exec process has exited.
    pub fn notify_exit(&self, id: &ExecId, exit_code: i32) {
        if let Ok(mut execs) = self.execs.write() {
            if let Some(exec) = execs.get_mut(&id.to_string()) {
                exec.running = false;
                exec.exit_code = Some(exit_code);
            }
        }
    }

    /// Lists all exec instances for a container.
    #[must_use]
    pub fn list_for_container(&self, container_id: &ContainerId) -> Vec<ExecInstance> {
        self.execs
            .read()
            .map(|execs| {
                execs
                    .values()
                    .filter(|e| e.config.container_id == *container_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for ExecManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_exec() {
        let manager = ExecManager::new();
        let config = ExecConfig {
            container_id: ContainerId::from_string("test-container"),
            cmd: vec!["ls".to_string(), "-la".to_string()],
            ..Default::default()
        };

        let id = manager.create(config);
        let exec = manager.get(&id).unwrap();

        assert_eq!(exec.config.cmd, vec!["ls", "-la"]);
        assert!(!exec.running);
        assert!(exec.exit_code.is_none());
    }

    #[tokio::test]
    async fn test_start_exec() {
        let manager = ExecManager::new();
        let config = ExecConfig {
            container_id: ContainerId::from_string("test-container"),
            cmd: vec!["echo".to_string(), "hello".to_string()],
            ..Default::default()
        };

        let id = manager.create(config);
        // Default width/height for non-TTY mode.
        let result = manager.start(&id, false, 80, 24).await.unwrap();

        let exec = manager.get(&id).unwrap();
        assert!(!exec.running);
        assert_eq!(exec.exit_code, Some(0));
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_start_exec_detached() {
        let manager = ExecManager::new();
        let config = ExecConfig {
            container_id: ContainerId::from_string("test-container"),
            cmd: vec!["sleep".to_string(), "10".to_string()],
            ..Default::default()
        };

        let id = manager.create(config);
        // Without agent, detach mode still returns immediately with exit_code=0.
        let result = manager.start(&id, true, 80, 24).await.unwrap();

        // Without agent, it returns exit_code=0 immediately.
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_resize_without_tty() {
        let manager = ExecManager::new();
        let config = ExecConfig {
            container_id: ContainerId::from_string("test-container"),
            cmd: vec!["echo".to_string(), "hello".to_string()],
            tty: false,
            ..Default::default()
        };

        let id = manager.create(config);

        // Resize should fail because exec doesn't have TTY.
        let result = manager.resize(&id, 100, 40).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_notify_exit() {
        let manager = ExecManager::new();
        let config = ExecConfig {
            container_id: ContainerId::from_string("test-container"),
            cmd: vec!["sleep".to_string(), "10".to_string()],
            ..Default::default()
        };

        let id = manager.create(config);

        // Manually set running state.
        {
            let mut execs = manager.execs.write().unwrap();
            if let Some(exec) = execs.get_mut(&id.to_string()) {
                exec.running = true;
                exec.pid = Some(12345);
            }
        }

        // Notify exit.
        manager.notify_exit(&id, 42);

        let exec = manager.get(&id).unwrap();
        assert!(!exec.running);
        assert_eq!(exec.exit_code, Some(42));
    }
}
