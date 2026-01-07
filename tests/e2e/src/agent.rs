//! Agent client utilities for E2E tests.
//!
//! Provides direct communication with the guest agent for testing.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Agent client for test operations.
pub struct AgentClient<'a> {
    /// Path to arcbox binary.
    binary: &'a Path,
    /// Socket path for daemon communication.
    socket: &'a Path,
    /// Machine name.
    machine: &'a str,
}

impl<'a> AgentClient<'a> {
    /// Creates a new agent client.
    pub fn new(binary: &'a Path, socket: &'a Path, machine: &'a str) -> Self {
        Self {
            binary,
            socket,
            machine,
        }
    }

    /// Pings the agent.
    pub fn ping(&self) -> Result<Duration> {
        let start = std::time::Instant::now();

        let output = Command::new(self.binary)
            .arg("machine")
            .arg("ping")
            .arg(self.machine)
            .arg("--socket")
            .arg(self.socket)
            .output()
            .context("failed to ping agent")?;

        let elapsed = start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ping failed: {}", stderr);
        }

        Ok(elapsed)
    }

    /// Lists containers in the guest.
    pub fn list_containers(&self, all: bool) -> Result<Vec<ContainerInfo>> {
        let mut cmd = Command::new(self.binary);
        cmd.arg("ps")
            .arg("--machine")
            .arg(self.machine)
            .arg("--socket")
            .arg(self.socket)
            .arg("--format")
            .arg("json");

        if all {
            cmd.arg("-a");
        }

        let output = cmd.output().context("failed to list containers")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ps failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON array of containers
        // For now, return empty vec if parsing fails
        Ok(parse_container_list(&stdout).unwrap_or_default())
    }

    /// Creates a container.
    pub fn create_container(&self, image: &str, name: Option<&str>, cmd: &[&str]) -> Result<String> {
        let mut args = vec!["create"];

        if let Some(n) = name {
            args.push("--name");
            args.push(n);
        }

        args.push("--machine");
        args.push(self.machine);
        args.push(image);
        args.extend(cmd);

        let output = self.run_arcbox(&args)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("create failed: {}", stderr);
        }

        // Return container ID from stdout
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Starts a container.
    pub fn start_container(&self, container: &str) -> Result<()> {
        let output = self.run_arcbox(&["start", "--machine", self.machine, container])?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("start failed: {}", stderr);
        }

        Ok(())
    }

    /// Stops a container.
    pub fn stop_container(&self, container: &str, timeout: Option<u32>) -> Result<()> {
        let timeout_str = timeout.unwrap_or(10).to_string();
        let output = self.run_arcbox(&[
            "stop",
            "--machine",
            self.machine,
            "-t",
            &timeout_str,
            container,
        ])?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("stop failed: {}", stderr);
        }

        Ok(())
    }

    /// Removes a container.
    pub fn remove_container(&self, container: &str, force: bool) -> Result<()> {
        let mut args = vec!["rm", "--machine", self.machine];
        if force {
            args.push("-f");
        }
        args.push(container);

        let output = self.run_arcbox(&args)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("rm failed: {}", stderr);
        }

        Ok(())
    }

    /// Runs a container (create + start + wait).
    pub fn run_container(
        &self,
        image: &str,
        cmd: &[&str],
        options: &RunOptions,
    ) -> Result<RunResult> {
        let mut args = vec!["run"];

        if options.remove {
            args.push("--rm");
        }
        if options.detach {
            args.push("-d");
        }
        if let Some(ref name) = options.name {
            args.push("--name");
            args.push(name);
        }

        args.push("--machine");
        args.push(self.machine);
        args.push(image);
        args.extend(cmd);

        let output = self.run_arcbox(&args)?;

        Ok(RunResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Executes a command in a running container.
    pub fn exec_container(&self, container: &str, cmd: &[&str]) -> Result<ExecResult> {
        let mut args = vec!["exec", "--machine", self.machine, container];
        args.extend(cmd);

        let output = self.run_arcbox(&args)?;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Gets container logs.
    pub fn logs(&self, container: &str, options: &LogOptions) -> Result<String> {
        let tail_str = options.tail.map(|n| n.to_string());
        let mut args = vec!["logs", "--machine", self.machine];

        if options.follow {
            args.push("-f");
        }
        if let Some(ref n) = tail_str {
            args.push("--tail");
            args.push(n);
        }

        args.push(container);

        let output = self.run_arcbox(&args)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("logs failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Runs an arcbox command.
    fn run_arcbox(&self, args: &[&str]) -> Result<std::process::Output> {
        let mut cmd = Command::new(self.binary);
        cmd.args(args)
            .arg("--socket")
            .arg(self.socket);

        cmd.output().context("failed to run arcbox command")
    }
}

/// Container information.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Container ID.
    pub id: String,
    /// Container name.
    pub name: String,
    /// Image name.
    pub image: String,
    /// Container status.
    pub status: String,
    /// Container state.
    pub state: ContainerState,
}

/// Container state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Stopped,
    Unknown,
}

/// Options for running a container.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Remove container after exit.
    pub remove: bool,
    /// Run in detached mode.
    pub detach: bool,
    /// Container name.
    pub name: Option<String>,
    /// Enable TTY.
    pub tty: bool,
    /// Keep stdin open.
    pub interactive: bool,
}

/// Result of running a container.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Exit code.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl RunResult {
    /// Returns true if the container exited successfully.
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Result of executing in a container.
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Exit code.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl ExecResult {
    /// Returns true if the command succeeded.
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Options for getting logs.
#[derive(Debug, Clone, Default)]
pub struct LogOptions {
    /// Follow log output.
    pub follow: bool,
    /// Number of lines to tail.
    pub tail: Option<u32>,
}

/// Parses container list from JSON output.
fn parse_container_list(json: &str) -> Option<Vec<ContainerInfo>> {
    // Simple parsing - in production would use serde_json
    let mut containers = Vec::new();

    // Look for container entries
    for line in json.lines() {
        let line = line.trim();
        if line.contains("\"id\"") {
            // Extract basic info - simplified
            if let Some(id) = extract_json_string(line, "id") {
                containers.push(ContainerInfo {
                    id,
                    name: extract_json_string(line, "name").unwrap_or_default(),
                    image: extract_json_string(line, "image").unwrap_or_default(),
                    status: extract_json_string(line, "status").unwrap_or_default(),
                    state: ContainerState::Unknown,
                });
            }
        }
    }

    Some(containers)
}

/// Extracts a string value from JSON.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    if let Some(start) = json.find(&pattern) {
        let start = start + pattern.len();
        if let Some(end) = json[start..].find('"') {
            return Some(json[start..start + end].to_string());
        }
    }
    None
}
