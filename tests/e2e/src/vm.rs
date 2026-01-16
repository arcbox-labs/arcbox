//! VM controller for E2E tests.
//!
//! Provides utilities for managing VM state during tests.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// VM controller for test operations.
pub struct VmController<'a> {
    /// Path to arcbox binary.
    binary: &'a Path,
    /// Socket path for daemon communication.
    socket: &'a Path,
    /// Machine name.
    machine: &'a str,
}

impl<'a> VmController<'a> {
    /// Creates a new VM controller.
    pub fn new(binary: &'a Path, socket: &'a Path, machine: &'a str) -> Self {
        Self {
            binary,
            socket,
            machine,
        }
    }

    /// Gets the machine status.
    pub fn status(&self) -> Result<MachineStatus> {
        let output = Command::new(self.binary)
            .arg("machine")
            .arg("inspect")
            .arg(self.machine)
            .arg("--socket")
            .arg(self.socket)
            .arg("--format")
            .arg("json")
            .output()
            .context("failed to get machine status")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") {
                return Ok(MachineStatus::NotFound);
            }
            anyhow::bail!("machine inspect failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse JSON response
        if stdout.contains("\"state\":\"running\"") {
            Ok(MachineStatus::Running)
        } else if stdout.contains("\"state\":\"stopped\"") {
            Ok(MachineStatus::Stopped)
        } else if stdout.contains("\"state\":\"created\"") {
            Ok(MachineStatus::Created)
        } else {
            Ok(MachineStatus::Unknown)
        }
    }

    /// Checks if the machine is running.
    pub fn is_running(&self) -> Result<bool> {
        Ok(matches!(self.status()?, MachineStatus::Running))
    }

    /// Gets system info from the guest agent.
    pub fn get_system_info(&self) -> Result<GuestSystemInfo> {
        let output = Command::new(self.binary)
            .arg("machine")
            .arg("info")
            .arg(self.machine)
            .arg("--socket")
            .arg(self.socket)
            .output()
            .context("failed to get system info")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("machine info failed: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse basic info from output
        Ok(GuestSystemInfo {
            kernel_version: extract_field(&stdout, "kernel").unwrap_or_default(),
            hostname: extract_field(&stdout, "hostname").unwrap_or_default(),
            cpu_count: extract_field(&stdout, "cpus")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            memory_total: extract_field(&stdout, "memory")
                .and_then(|s| parse_memory(&s))
                .unwrap_or(0),
        })
    }

    /// Executes a command in the guest VM.
    pub fn exec(&self, command: &[&str]) -> Result<ExecResult> {
        let mut cmd = Command::new(self.binary);
        cmd.arg("machine")
            .arg("exec")
            .arg(self.machine)
            .arg("--socket")
            .arg(self.socket)
            .arg("--");

        for arg in command {
            cmd.arg(arg);
        }

        let output = cmd.output().context("failed to exec in guest")?;

        Ok(ExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Machine status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineStatus {
    /// Machine not found.
    NotFound,
    /// Machine created but not started.
    Created,
    /// Machine is running.
    Running,
    /// Machine is stopped.
    Stopped,
    /// Unknown status.
    Unknown,
}

/// Guest system information.
#[derive(Debug, Clone)]
pub struct GuestSystemInfo {
    /// Kernel version.
    pub kernel_version: String,
    /// Hostname.
    pub hostname: String,
    /// CPU count.
    pub cpu_count: u32,
    /// Total memory in bytes.
    pub memory_total: u64,
}

/// Result of executing a command in the guest.
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
    /// Returns true if the command succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Extracts a field value from command output.
fn extract_field(output: &str, field: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with(field) {
            if let Some(idx) = line.find(':') {
                return Some(line[idx + 1..].trim().to_string());
            }
        }
    }
    None
}

/// Parses memory string (e.g., "1024 MB") to bytes.
fn parse_memory(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.ends_with("GB") || s.ends_with("G") {
        let num: u64 = s
            .trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse()
            .ok()?;
        Some(num * 1024 * 1024 * 1024)
    } else if s.ends_with("MB") || s.ends_with("M") {
        let num: u64 = s
            .trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse()
            .ok()?;
        Some(num * 1024 * 1024)
    } else if s.ends_with("KB") || s.ends_with("K") {
        let num: u64 = s
            .trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse()
            .ok()?;
        Some(num * 1024)
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory() {
        assert_eq!(parse_memory("1024"), Some(1024));
        assert_eq!(parse_memory("1024 MB"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_memory("2G"), Some(2 * 1024 * 1024 * 1024));
    }
}
