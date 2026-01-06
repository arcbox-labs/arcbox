//! Container management in guest.
//!
//! This module manages container lifecycle within the guest VM.
//! It handles container creation, starting, stopping, and removal.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// Container state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    /// Container has been created but not started.
    Created,
    /// Container is running.
    Running,
    /// Container has stopped.
    Stopped,
}

impl ContainerState {
    /// Returns the string representation of the state.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// Container handle containing all container metadata.
#[derive(Debug, Clone)]
pub struct ContainerHandle {
    /// Unique container ID.
    pub id: String,
    /// Container name.
    pub name: String,
    /// Image reference.
    pub image: String,
    /// Command to run.
    pub command: Vec<String>,
    /// Environment variables.
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub working_dir: String,
    /// Current state.
    pub state: ContainerState,
    /// Process ID (if running).
    pub pid: Option<u32>,
    /// Exit code (if stopped).
    pub exit_code: Option<i32>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Running process handle.
struct ProcessHandle {
    /// The child process.
    child: Child,
}

/// Container runtime managing all containers.
pub struct ContainerRuntime {
    /// Container metadata indexed by ID.
    containers: HashMap<String, ContainerHandle>,
    /// Running process handles indexed by container ID.
    processes: Mutex<HashMap<String, ProcessHandle>>,
}

impl ContainerRuntime {
    /// Creates a new container runtime.
    #[must_use]
    pub fn new() -> Self {
        Self {
            containers: HashMap::new(),
            processes: Mutex::new(HashMap::new()),
        }
    }

    /// Adds a container to the runtime.
    pub fn add_container(&mut self, handle: ContainerHandle) {
        tracing::info!(
            "Adding container: id={}, name={}, image={}",
            handle.id,
            handle.name,
            handle.image
        );
        self.containers.insert(handle.id.clone(), handle);
    }

    /// Gets a container by ID.
    #[must_use]
    pub fn get_container(&self, id: &str) -> Option<&ContainerHandle> {
        self.containers.get(id)
    }

    /// Gets a mutable container by ID.
    pub fn get_container_mut(&mut self, id: &str) -> Option<&mut ContainerHandle> {
        self.containers.get_mut(id)
    }

    /// Lists all containers.
    ///
    /// If `all` is false, only running containers are returned.
    #[must_use]
    pub fn list_containers(&self, all: bool) -> Vec<ContainerHandle> {
        self.containers
            .values()
            .filter(|c| all || c.state == ContainerState::Running)
            .cloned()
            .collect()
    }

    /// Starts a container.
    pub async fn start_container(&mut self, id: &str) -> Result<()> {
        let container = self
            .containers
            .get_mut(id)
            .context("container not found")?;

        if container.state == ContainerState::Running {
            anyhow::bail!("container is already running");
        }

        if container.command.is_empty() {
            anyhow::bail!("container has no command");
        }

        tracing::info!(
            "Starting container {}: cmd={:?}, workdir={}",
            id,
            container.command,
            container.working_dir
        );

        // Build the command
        let mut cmd = Command::new(&container.command[0]);
        cmd.args(&container.command[1..]);
        cmd.current_dir(&container.working_dir);

        // Set environment variables
        for (key, value) in &container.env {
            cmd.env(key, value);
        }

        // Configure stdio
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Spawn the process
        let child = cmd.spawn().context("failed to spawn container process")?;
        let pid = child.id();

        // Update container state
        container.state = ContainerState::Running;
        container.pid = pid;
        container.exit_code = None;

        // Store the process handle
        if let Some(pid) = pid {
            tracing::info!("Container {} started with PID {}", id, pid);
        }

        let mut processes = self.processes.lock().await;
        processes.insert(id.to_string(), ProcessHandle { child });

        Ok(())
    }

    /// Stops a container.
    pub async fn stop_container(&mut self, id: &str, timeout_secs: u32) -> Result<()> {
        let container = self
            .containers
            .get_mut(id)
            .context("container not found")?;

        if container.state != ContainerState::Running {
            anyhow::bail!("container is not running");
        }

        let pid = container.pid.context("container has no PID")?;

        tracing::info!(
            "Stopping container {} (PID {}) with timeout {}s",
            id,
            pid,
            timeout_secs
        );

        // Send SIGTERM first
        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let nix_pid = Pid::from_raw(pid as i32);
            if let Err(e) = kill(nix_pid, Signal::SIGTERM) {
                tracing::warn!("Failed to send SIGTERM to {}: {}", pid, e);
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // On non-Linux, use libc directly
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }

        // Wait for the process to exit with timeout
        let mut processes = self.processes.lock().await;
        if let Some(process_handle) = processes.get_mut(id) {
            let timeout = tokio::time::Duration::from_secs(timeout_secs.into());
            let result = tokio::time::timeout(timeout, process_handle.child.wait()).await;

            match result {
                Ok(Ok(status)) => {
                    container.exit_code = status.code();
                    tracing::info!(
                        "Container {} exited with code {:?}",
                        id,
                        container.exit_code
                    );
                }
                Ok(Err(e)) => {
                    tracing::warn!("Error waiting for container {}: {}", id, e);
                }
                Err(_) => {
                    // Timeout - send SIGKILL
                    tracing::warn!(
                        "Container {} did not stop after {}s, sending SIGKILL",
                        id,
                        timeout_secs
                    );

                    #[cfg(target_os = "linux")]
                    {
                        use nix::sys::signal::{kill, Signal};
                        use nix::unistd::Pid;

                        let nix_pid = Pid::from_raw(pid as i32);
                        let _ = kill(nix_pid, Signal::SIGKILL);
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGKILL);
                        }
                    }

                    // Wait briefly for SIGKILL to take effect
                    let _ = tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        process_handle.child.wait(),
                    )
                    .await;
                }
            }
        }

        // Update state
        container.state = ContainerState::Stopped;
        container.pid = None;

        // Remove from process map
        processes.remove(id);

        Ok(())
    }

    /// Removes a container.
    pub async fn remove_container(&mut self, id: &str, force: bool) -> Result<()> {
        let container = self.containers.get(id).context("container not found")?;

        if container.state == ContainerState::Running {
            if force {
                // Force stop first
                self.stop_container(id, 10).await?;
            } else {
                anyhow::bail!("cannot remove running container (use force=true)");
            }
        }

        tracing::info!("Removing container {}", id);
        self.containers.remove(id);

        Ok(())
    }

    /// Waits for a container to exit and returns its exit code.
    pub async fn wait_container(&mut self, id: &str) -> Result<i32> {
        let container = self.containers.get(id).context("container not found")?;

        if container.state == ContainerState::Stopped {
            return Ok(container.exit_code.unwrap_or(-1));
        }

        if container.state != ContainerState::Running {
            anyhow::bail!("container is not running");
        }

        let mut processes = self.processes.lock().await;
        if let Some(process_handle) = processes.get_mut(id) {
            let status = process_handle.child.wait().await?;
            let exit_code = status.code().unwrap_or(-1);

            // Update container state
            drop(processes); // Release lock before getting mutable reference
            if let Some(container) = self.containers.get_mut(id) {
                container.state = ContainerState::Stopped;
                container.exit_code = Some(exit_code);
                container.pid = None;
            }

            return Ok(exit_code);
        }

        anyhow::bail!("container process not found")
    }
}

impl Default for ContainerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_container(id: &str, cmd: Vec<String>) -> ContainerHandle {
        ContainerHandle {
            id: id.to_string(),
            name: format!("test-{}", id),
            image: "test:latest".to_string(),
            command: cmd,
            env: vec![],
            working_dir: "/".to_string(),
            state: ContainerState::Created,
            pid: None,
            exit_code: None,
            created_at: Utc::now(),
        }
    }

    fn create_test_container_with_env(
        id: &str,
        cmd: Vec<String>,
        env: Vec<(String, String)>,
    ) -> ContainerHandle {
        ContainerHandle {
            id: id.to_string(),
            name: format!("test-{}", id),
            image: "test:latest".to_string(),
            command: cmd,
            env,
            working_dir: "/".to_string(),
            state: ContainerState::Created,
            pid: None,
            exit_code: None,
            created_at: Utc::now(),
        }
    }

    // =========================================================================
    // ContainerState Tests
    // =========================================================================

    #[test]
    fn test_container_state_as_str() {
        assert_eq!(ContainerState::Created.as_str(), "created");
        assert_eq!(ContainerState::Running.as_str(), "running");
        assert_eq!(ContainerState::Stopped.as_str(), "stopped");
    }

    #[test]
    fn test_container_state_equality() {
        assert_eq!(ContainerState::Created, ContainerState::Created);
        assert_ne!(ContainerState::Created, ContainerState::Running);
        assert_ne!(ContainerState::Running, ContainerState::Stopped);
    }

    // =========================================================================
    // ContainerRuntime Basic Tests
    // =========================================================================

    #[test]
    fn test_container_runtime_new() {
        let runtime = ContainerRuntime::new();
        assert!(runtime.list_containers(true).is_empty());
    }

    #[test]
    fn test_container_runtime_default() {
        let runtime = ContainerRuntime::default();
        assert!(runtime.list_containers(true).is_empty());
    }

    #[test]
    fn test_container_runtime_add_list() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container("test1", vec!["echo".to_string()]);
        runtime.add_container(container);

        let list = runtime.list_containers(true);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "test1");

        // Running filter should return empty for created containers
        let running = runtime.list_containers(false);
        assert!(running.is_empty());
    }

    #[test]
    fn test_container_runtime_add_multiple() {
        let mut runtime = ContainerRuntime::new();

        runtime.add_container(create_test_container("c1", vec!["echo".to_string()]));
        runtime.add_container(create_test_container("c2", vec!["echo".to_string()]));
        runtime.add_container(create_test_container("c3", vec!["echo".to_string()]));

        let list = runtime.list_containers(true);
        assert_eq!(list.len(), 3);

        let ids: Vec<&str> = list.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"c1"));
        assert!(ids.contains(&"c2"));
        assert!(ids.contains(&"c3"));
    }

    #[test]
    fn test_container_runtime_get_container() {
        let mut runtime = ContainerRuntime::new();

        runtime.add_container(create_test_container("test1", vec!["echo".to_string()]));

        let container = runtime.get_container("test1");
        assert!(container.is_some());
        assert_eq!(container.unwrap().id, "test1");

        let nonexistent = runtime.get_container("nonexistent");
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_container_runtime_get_container_mut() {
        let mut runtime = ContainerRuntime::new();

        runtime.add_container(create_test_container("test1", vec!["echo".to_string()]));

        // Modify the container
        {
            let container = runtime.get_container_mut("test1").unwrap();
            container.name = "modified-name".to_string();
        }

        // Verify modification persisted
        let container = runtime.get_container("test1").unwrap();
        assert_eq!(container.name, "modified-name");
    }

    // =========================================================================
    // Container Lifecycle Tests
    // =========================================================================

    #[tokio::test]
    async fn test_container_lifecycle() {
        let mut runtime = ContainerRuntime::new();

        // Add a container that runs a quick command
        let container = create_test_container(
            "lifecycle-test",
            vec!["echo".to_string(), "hello".to_string()],
        );
        runtime.add_container(container);

        // Start it
        runtime.start_container("lifecycle-test").await.unwrap();

        let container = runtime.get_container("lifecycle-test").unwrap();
        assert_eq!(container.state, ContainerState::Running);

        // Wait for it to complete
        let exit_code = runtime.wait_container("lifecycle-test").await.unwrap();
        assert_eq!(exit_code, 0);

        let container = runtime.get_container("lifecycle-test").unwrap();
        assert_eq!(container.state, ContainerState::Stopped);

        // Remove it
        runtime
            .remove_container("lifecycle-test", false)
            .await
            .unwrap();

        assert!(runtime.get_container("lifecycle-test").is_none());
    }

    #[tokio::test]
    async fn test_start_container_sets_pid() {
        let mut runtime = ContainerRuntime::new();

        // Use sleep to keep the process alive long enough to check PID
        let container = create_test_container(
            "pid-test",
            vec!["sleep".to_string(), "0.1".to_string()],
        );
        runtime.add_container(container);

        runtime.start_container("pid-test").await.unwrap();

        let container = runtime.get_container("pid-test").unwrap();
        assert!(container.pid.is_some());
        assert!(container.pid.unwrap() > 0);

        // Clean up
        let _ = runtime.wait_container("pid-test").await;
    }

    #[tokio::test]
    async fn test_start_nonexistent_container() {
        let mut runtime = ContainerRuntime::new();

        let result = runtime.start_container("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_start_already_running_container() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container(
            "double-start",
            vec!["sleep".to_string(), "1".to_string()],
        );
        runtime.add_container(container);

        // Start once
        runtime.start_container("double-start").await.unwrap();

        // Try to start again
        let result = runtime.start_container("double-start").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already running"));

        // Clean up
        let _ = runtime.stop_container("double-start", 1).await;
    }

    #[tokio::test]
    async fn test_start_container_with_no_command() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container("empty-cmd", vec![]);
        runtime.add_container(container);

        let result = runtime.start_container("empty-cmd").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no command"));
    }

    #[tokio::test]
    async fn test_container_with_nonzero_exit_code() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container(
            "exit-code-test",
            vec!["sh".to_string(), "-c".to_string(), "exit 42".to_string()],
        );
        runtime.add_container(container);

        runtime.start_container("exit-code-test").await.unwrap();
        let exit_code = runtime.wait_container("exit-code-test").await.unwrap();

        assert_eq!(exit_code, 42);

        let container = runtime.get_container("exit-code-test").unwrap();
        assert_eq!(container.exit_code, Some(42));
    }

    #[tokio::test]
    async fn test_container_with_environment_variables() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container_with_env(
            "env-test",
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "exit $((MY_VAR + 10))".to_string(),
            ],
            vec![("MY_VAR".to_string(), "5".to_string())],
        );
        runtime.add_container(container);

        runtime.start_container("env-test").await.unwrap();
        let exit_code = runtime.wait_container("env-test").await.unwrap();

        // 5 + 10 = 15
        assert_eq!(exit_code, 15);
    }

    // =========================================================================
    // Stop Container Tests
    // =========================================================================

    #[tokio::test]
    async fn test_stop_running_container() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container(
            "stop-test",
            vec!["sleep".to_string(), "60".to_string()],
        );
        runtime.add_container(container);

        runtime.start_container("stop-test").await.unwrap();

        // Verify it's running
        let container = runtime.get_container("stop-test").unwrap();
        assert_eq!(container.state, ContainerState::Running);

        // Stop it
        runtime.stop_container("stop-test", 5).await.unwrap();

        let container = runtime.get_container("stop-test").unwrap();
        assert_eq!(container.state, ContainerState::Stopped);
        assert!(container.pid.is_none());
    }

    #[tokio::test]
    async fn test_stop_nonexistent_container() {
        let mut runtime = ContainerRuntime::new();

        let result = runtime.stop_container("nonexistent", 5).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_stop_not_running_container() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container("not-running", vec!["echo".to_string()]);
        runtime.add_container(container);

        let result = runtime.stop_container("not-running", 5).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not running"));
    }

    // =========================================================================
    // Remove Container Tests
    // =========================================================================

    #[tokio::test]
    async fn test_remove_stopped_container() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container("remove-test", vec!["echo".to_string()]);
        runtime.add_container(container);

        runtime.start_container("remove-test").await.unwrap();
        let _ = runtime.wait_container("remove-test").await;

        // Now remove it
        runtime.remove_container("remove-test", false).await.unwrap();

        assert!(runtime.get_container("remove-test").is_none());
    }

    #[tokio::test]
    async fn test_remove_running_container_without_force() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container(
            "force-remove",
            vec!["sleep".to_string(), "60".to_string()],
        );
        runtime.add_container(container);

        runtime.start_container("force-remove").await.unwrap();

        // Try to remove without force
        let result = runtime.remove_container("force-remove", false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("running"));

        // Clean up
        let _ = runtime.stop_container("force-remove", 1).await;
    }

    #[tokio::test]
    async fn test_remove_running_container_with_force() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container(
            "force-remove",
            vec!["sleep".to_string(), "60".to_string()],
        );
        runtime.add_container(container);

        runtime.start_container("force-remove").await.unwrap();

        // Remove with force
        runtime.remove_container("force-remove", true).await.unwrap();

        assert!(runtime.get_container("force-remove").is_none());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_container() {
        let mut runtime = ContainerRuntime::new();

        let result = runtime.remove_container("nonexistent", false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // =========================================================================
    // Wait Container Tests
    // =========================================================================

    #[tokio::test]
    async fn test_wait_already_stopped_container() {
        let mut runtime = ContainerRuntime::new();

        let mut container = create_test_container("wait-stopped", vec!["echo".to_string()]);
        container.state = ContainerState::Stopped;
        container.exit_code = Some(123);
        runtime.add_container(container);

        let exit_code = runtime.wait_container("wait-stopped").await.unwrap();
        assert_eq!(exit_code, 123);
    }

    #[tokio::test]
    async fn test_wait_nonexistent_container() {
        let mut runtime = ContainerRuntime::new();

        let result = runtime.wait_container("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_wait_created_container() {
        let mut runtime = ContainerRuntime::new();

        let container = create_test_container("wait-created", vec!["echo".to_string()]);
        runtime.add_container(container);

        // Container is Created, not Running, so wait should fail
        let result = runtime.wait_container("wait-created").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not running"));
    }

    // =========================================================================
    // List Containers Filter Tests
    // =========================================================================

    #[tokio::test]
    async fn test_list_containers_filter_running() {
        let mut runtime = ContainerRuntime::new();

        // Add two containers, start only one
        runtime.add_container(create_test_container(
            "running",
            vec!["sleep".to_string(), "60".to_string()],
        ));
        runtime.add_container(create_test_container("created", vec!["echo".to_string()]));

        runtime.start_container("running").await.unwrap();

        // List all
        let all = runtime.list_containers(true);
        assert_eq!(all.len(), 2);

        // List running only
        let running = runtime.list_containers(false);
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].id, "running");

        // Clean up
        let _ = runtime.stop_container("running", 1).await;
    }

    // =========================================================================
    // ContainerHandle Tests
    // =========================================================================

    #[test]
    fn test_container_handle_clone() {
        let container = create_test_container("clone-test", vec!["echo".to_string()]);
        let cloned = container.clone();

        assert_eq!(cloned.id, container.id);
        assert_eq!(cloned.name, container.name);
        assert_eq!(cloned.image, container.image);
        assert_eq!(cloned.command, container.command);
        assert_eq!(cloned.state, container.state);
    }
}
