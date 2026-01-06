//! Exec instance management.
//!
//! Manages exec instances for running commands inside containers.

use crate::state::ContainerId;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::RwLock;

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

/// Exec manager.
pub struct ExecManager {
    /// Exec instances by ID.
    execs: RwLock<HashMap<String, ExecInstance>>,
}

impl ExecManager {
    /// Creates a new exec manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            execs: RwLock::new(HashMap::new()),
        }
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
    /// # Errors
    ///
    /// Returns an error if the exec cannot be started.
    pub fn start(&self, id: &ExecId) -> crate::Result<()> {
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
        // TODO: Actually start the exec via agent communication
        // For now, immediately mark as completed
        exec.running = false;
        exec.exit_code = Some(0);

        Ok(())
    }

    /// Resizes the exec TTY.
    ///
    /// # Errors
    ///
    /// Returns an error if the resize fails.
    pub fn resize(&self, id: &ExecId, _height: u32, _width: u32) -> crate::Result<()> {
        let execs = self
            .execs
            .read()
            .map_err(|_| crate::ContainerError::Runtime("lock poisoned".to_string()))?;

        if !execs.contains_key(&id.to_string()) {
            return Err(crate::ContainerError::NotFound(id.to_string()));
        }

        // TODO: Resize TTY via agent communication
        Ok(())
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

    #[test]
    fn test_start_exec() {
        let manager = ExecManager::new();
        let config = ExecConfig {
            container_id: ContainerId::from_string("test-container"),
            cmd: vec!["echo".to_string(), "hello".to_string()],
            ..Default::default()
        };

        let id = manager.create(config);
        manager.start(&id).unwrap();

        let exec = manager.get(&id).unwrap();
        assert!(!exec.running);
        assert_eq!(exec.exit_code, Some(0));
    }
}
