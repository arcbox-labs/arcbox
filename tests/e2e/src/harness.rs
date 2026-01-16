//! Test harness for managing E2E test environment.
//!
//! The harness manages:
//! - Temporary data directory for each test
//! - Daemon process lifecycle
//! - VM lifecycle
//! - Cleanup after tests

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tempfile::TempDir;

/// Test configuration.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Path to the arcbox binary.
    pub arcbox_binary: PathBuf,
    /// Path to the kernel image.
    pub kernel_path: PathBuf,
    /// Path to the initramfs.
    pub initramfs_path: PathBuf,
    /// Number of CPUs for the VM.
    pub cpus: u32,
    /// Memory in MB for the VM.
    pub memory_mb: u64,
    /// Timeout for operations.
    pub timeout: Duration,
    /// Enable verbose logging.
    pub verbose: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        Self {
            arcbox_binary: project_root.join("target/debug/arcbox"),
            kernel_path: project_root.join("tests/resources/Image-arm64"),
            initramfs_path: project_root.join("tests/resources/initramfs-arcbox"),
            cpus: 2,
            memory_mb: 1024,
            timeout: Duration::from_secs(60),
            verbose: std::env::var("E2E_VERBOSE").is_ok(),
        }
    }
}

impl TestConfig {
    /// Creates a release build configuration.
    pub fn release() -> Self {
        let mut config = Self::default();
        config.arcbox_binary = config
            .arcbox_binary
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("release/arcbox");
        config
    }

    /// Validates that all required files exist.
    pub fn validate(&self) -> Result<()> {
        if !self.arcbox_binary.exists() {
            anyhow::bail!(
                "arcbox binary not found at {}. Run `cargo build` first.",
                self.arcbox_binary.display()
            );
        }
        if !self.kernel_path.exists() {
            anyhow::bail!(
                "kernel not found at {}. Run `tests/resources/download-kernel.sh` first.",
                self.kernel_path.display()
            );
        }
        if !self.initramfs_path.exists() {
            anyhow::bail!(
                "initramfs not found at {}. Run `tests/resources/build-initramfs.sh` first.",
                self.initramfs_path.display()
            );
        }
        Ok(())
    }
}

/// Test harness for E2E tests.
///
/// Manages the lifecycle of test resources including:
/// - Temporary data directory
/// - Daemon process
/// - Machine/VM instances
pub struct TestHarness {
    /// Test configuration.
    pub config: TestConfig,
    /// Temporary data directory.
    data_dir: TempDir,
    /// Daemon process handle.
    daemon: Option<Child>,
    /// Flag indicating if cleanup should be skipped (for debugging).
    skip_cleanup: Arc<AtomicBool>,
    /// Machine name for this test.
    machine_name: String,
}

impl TestHarness {
    /// Creates a new test harness with the given configuration.
    pub fn new(config: TestConfig) -> Result<Self> {
        config.validate()?;

        let data_dir = TempDir::new().context("failed to create temp directory")?;
        let machine_name = format!("test-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());

        if config.verbose {
            tracing::info!(
                "Created test harness: data_dir={}, machine={}",
                data_dir.path().display(),
                machine_name
            );
        }

        Ok(Self {
            config,
            data_dir,
            daemon: None,
            skip_cleanup: Arc::new(AtomicBool::new(false)),
            machine_name,
        })
    }

    /// Creates a test harness with default configuration.
    pub fn with_defaults() -> Result<Self> {
        Self::new(TestConfig::default())
    }

    /// Returns the data directory path.
    pub fn data_dir(&self) -> &Path {
        self.data_dir.path()
    }

    /// Returns the machine name for this test.
    pub fn machine_name(&self) -> &str {
        &self.machine_name
    }

    /// Returns the socket path for the daemon (Docker API).
    pub fn socket_path(&self) -> PathBuf {
        self.data_dir.path().join("arcbox.sock")
    }

    /// Returns the gRPC socket path for the daemon.
    pub fn grpc_socket_path(&self) -> PathBuf {
        self.data_dir.path().join("arcbox-grpc.sock")
    }

    /// Starts the daemon process.
    pub async fn start_daemon(&mut self) -> Result<()> {
        if self.daemon.is_some() {
            anyhow::bail!("daemon is already running");
        }

        let socket_path = self.socket_path();

        let mut cmd = Command::new(&self.config.arcbox_binary);
        cmd.arg("daemon")
            .arg("--socket")
            .arg(&socket_path)
            .arg("--grpc-socket")
            .arg(self.grpc_socket_path())
            .arg("--data-dir")
            .arg(self.data_dir.path())
            .arg("--kernel")
            .arg(&self.config.kernel_path)
            .arg("--initramfs")
            .arg(&self.config.initramfs_path)
            .env(
                "RUST_LOG",
                if self.config.verbose { "debug" } else { "warn" },
            )
            .stdin(Stdio::null())
            .stdout(if self.config.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stderr(if self.config.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            });

        let child = cmd.spawn().context("failed to start daemon")?;

        self.daemon = Some(child);

        // Wait for socket to appear
        let start = std::time::Instant::now();
        while !socket_path.exists() {
            if start.elapsed() > Duration::from_secs(10) {
                anyhow::bail!("timeout waiting for daemon socket");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if self.config.verbose {
            tracing::info!("Daemon started, socket at {}", socket_path.display());
        }

        Ok(())
    }

    /// Stops the daemon process.
    pub fn stop_daemon(&mut self) -> Result<()> {
        if let Some(mut child) = self.daemon.take() {
            // Send SIGTERM
            #[cfg(unix)]
            {
                use nix::sys::signal::{Signal, kill};
                use nix::unistd::Pid;

                let pid = child.id();
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
            }

            // Wait for graceful shutdown
            let _ = child.wait();

            if self.config.verbose {
                tracing::info!("Daemon stopped");
            }
        }
        Ok(())
    }

    /// Creates a machine for testing.
    ///
    /// Uses custom kernel/initramfs paths from TestConfig for E2E testing.
    pub async fn create_machine(&self) -> Result<()> {
        let output = Command::new(&self.config.arcbox_binary)
            .arg("--socket")
            .arg(self.socket_path())
            .arg("machine")
            .arg("create")
            .arg(&self.machine_name)
            .arg("--cpus")
            .arg(self.config.cpus.to_string())
            .arg("--memory")
            .arg(self.config.memory_mb.to_string())
            .arg("--kernel")
            .arg(&self.config.kernel_path)
            .arg("--initrd")
            .arg(&self.config.initramfs_path)
            .output()
            .context("failed to create machine")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("machine create failed: {}", stderr);
        }

        if self.config.verbose {
            tracing::info!("Machine '{}' created", self.machine_name);
        }

        Ok(())
    }

    /// Starts the machine.
    pub async fn start_machine(&self) -> Result<()> {
        let output = Command::new(&self.config.arcbox_binary)
            .arg("--socket")
            .arg(self.socket_path())
            .arg("machine")
            .arg("start")
            .arg(&self.machine_name)
            .output()
            .context("failed to start machine")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("machine start failed: {}", stderr);
        }

        if self.config.verbose {
            tracing::info!("Machine '{}' started", self.machine_name);
        }

        Ok(())
    }

    /// Stops the machine.
    pub async fn stop_machine(&self) -> Result<()> {
        let output = Command::new(&self.config.arcbox_binary)
            .arg("--socket")
            .arg(self.socket_path())
            .arg("machine")
            .arg("stop")
            .arg(&self.machine_name)
            .output()
            .context("failed to stop machine")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail if already stopped
            if !stderr.contains("not running") {
                anyhow::bail!("machine stop failed: {}", stderr);
            }
        }

        if self.config.verbose {
            tracing::info!("Machine '{}' stopped", self.machine_name);
        }

        Ok(())
    }

    /// Waits for the agent to become ready.
    pub async fn wait_for_agent(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + self.config.timeout;

        while tokio::time::Instant::now() < deadline {
            let output = Command::new(&self.config.arcbox_binary)
                .arg("--socket")
                .arg(self.socket_path())
                .arg("machine")
                .arg("ping")
                .arg(&self.machine_name)
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    if self.config.verbose {
                        tracing::info!("Agent is ready");
                    }
                    return Ok(());
                }
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        anyhow::bail!("timeout waiting for agent")
    }

    /// Runs an arcbox command and returns its output.
    pub fn run_command(&self, args: &[&str]) -> Result<std::process::Output> {
        let mut cmd = Command::new(&self.config.arcbox_binary);
        cmd.arg("--socket").arg(self.socket_path()).args(args);

        cmd.output().context("failed to run command")
    }

    /// Runs an arcbox command and asserts it succeeds.
    pub fn run_command_success(&self, args: &[&str]) -> Result<String> {
        let output = self.run_command(args)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("command {:?} failed: {}", args, stderr);
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Skips cleanup on drop (useful for debugging failed tests).
    pub fn skip_cleanup(&self) {
        self.skip_cleanup.store(true, Ordering::SeqCst);
    }

    /// Sets up a complete test environment (daemon with auto-managed VM).
    ///
    /// The daemon automatically creates and starts the default VM when needed.
    /// Container operations will trigger VM startup via ensure_vm_ready().
    pub async fn setup_full_environment(&mut self) -> Result<()> {
        self.start_daemon().await?;
        // VM is auto-started by daemon when first container operation is performed.
        // We can optionally wait for it to be ready here by doing a simple operation.
        Ok(())
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        if self.skip_cleanup.load(Ordering::SeqCst) {
            tracing::warn!(
                "Skipping cleanup. Data directory: {}",
                self.data_dir.path().display()
            );
            // Leak the temp directory so it's not deleted
            let _ = std::mem::ManuallyDrop::new(std::mem::replace(
                &mut self.data_dir,
                TempDir::new().unwrap(),
            ));
            return;
        }

        // Stop machine (best effort)
        let _ = std::process::Command::new(&self.config.arcbox_binary)
            .arg("--socket")
            .arg(self.socket_path())
            .arg("machine")
            .arg("stop")
            .arg(&self.machine_name)
            .output();

        // Stop daemon
        let _ = self.stop_daemon();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = TestConfig::default();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 1024);
    }
}
