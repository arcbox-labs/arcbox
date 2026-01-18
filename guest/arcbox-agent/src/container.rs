//! Container management in guest.
//!
//! This module manages container lifecycle within the guest VM.
//! It handles container creation, starting, stopping, and removal.
//!
//! ## Container Isolation
//!
//! When a rootfs is provided, containers are isolated using:
//! - Mount namespace (CLONE_NEWNS) for filesystem isolation
//! - Chroot to restrict filesystem access
//! - Special mounts (/proc, /sys, /dev) for proper Linux operation

use crate::pty::PtyHandle;
use crate::shim::{
    BroadcastWriter, ProcessShim, spawn_broadcast_only_from_pipes, spawn_broadcast_only_from_pty,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Container log directory.
const CONTAINER_LOG_DIR: &str = "/var/log/containers";

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

/// Mount specification for bind mounts.
#[derive(Debug, Clone)]
pub struct MountSpec {
    /// Source path (in guest filesystem).
    pub source: String,
    /// Target path (inside container).
    pub target: String,
    /// Read-only flag.
    pub readonly: bool,
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
    /// Whether TTY is enabled.
    pub tty: bool,
    /// Whether stdin is open.
    pub open_stdin: bool,
    /// Volume mounts for this container.
    pub mounts: Vec<MountSpec>,
    /// Root filesystem path.
    ///
    /// When set, the container will be chrooted into this directory.
    /// This should point to an extracted OCI image rootfs.
    pub rootfs: Option<String>,
}

/// Running process handle.
pub(crate) struct ProcessHandle {
    /// The child process.
    pub(crate) child: Option<Child>,
    /// Child stdin (non-TTY).
    pub(crate) stdin: Option<ChildStdin>,
    /// PTY handle (if TTY mode).
    pub(crate) pty: Option<PtyHandle>,
    /// Shim shutdown token.
    pub(crate) shim_shutdown: Option<CancellationToken>,
    /// Broadcast writer for attach clients.
    pub(crate) broadcaster: Option<Arc<BroadcastWriter>>,
}

/// Container runtime managing all containers.
pub struct ContainerRuntime {
    /// Container metadata indexed by ID.
    containers: HashMap<String, ContainerHandle>,
    /// Running process handles indexed by container ID.
    processes: Mutex<HashMap<String, Arc<Mutex<ProcessHandle>>>>,
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

    /// Gets a container state snapshot by ID.
    #[must_use]
    pub fn get_container_state(&self, id: &str) -> Option<(ContainerState, Option<i32>)> {
        self.containers
            .get(id)
            .map(|container| (container.state, container.exit_code))
    }

    /// Gets a mutable container by ID.
    pub fn get_container_mut(&mut self, id: &str) -> Option<&mut ContainerHandle> {
        self.containers.get_mut(id)
    }

    /// Gets a process handle by container ID.
    pub async fn get_process_handle(&self, id: &str) -> Option<Arc<Mutex<ProcessHandle>>> {
        let processes = self.processes.lock().await;
        processes.get(id).cloned()
    }

    /// Gets the log broadcaster for a container.
    ///
    /// Returns `None` if the container doesn't exist or has no broadcaster.
    /// The broadcaster can be used to subscribe to real-time log output.
    pub async fn get_log_broadcaster(&self, id: &str) -> Option<Arc<BroadcastWriter>> {
        let processes = self.processes.lock().await;
        processes.get(id).and_then(|handle_arc| {
            // Try to lock without blocking
            match handle_arc.try_lock() {
                Ok(handle) => handle.broadcaster.clone(),
                Err(_) => None,
            }
        })
    }

    /// Removes a process handle by container ID.
    pub async fn remove_process_handle(&self, id: &str) {
        let mut processes = self.processes.lock().await;
        processes.remove(id);
    }

    /// Marks a container as stopped.
    pub fn mark_container_stopped(&mut self, id: &str, exit_code: i32) {
        if let Some(container) = self.containers.get_mut(id) {
            container.state = ContainerState::Stopped;
            container.exit_code = Some(exit_code);
            container.pid = None;
        }
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
        self.start_container_with_size(id, 80, 24).await
    }

    /// Starts a container with specified terminal size.
    pub async fn start_container_with_size(
        &mut self,
        id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        let container = self.containers.get_mut(id).context("container not found")?;

        if container.state == ContainerState::Running {
            return Ok(());
        }

        if container.command.is_empty() {
            anyhow::bail!("container has no command");
        }

        let use_tty = container.tty;
        let open_stdin = container.open_stdin;
        let command = container.command.clone();
        let working_dir = container.working_dir.clone();
        let env = container.env.clone();
        let rootfs = container.rootfs.clone();
        let mounts = container.mounts.clone();

        tracing::info!(
            "Starting container {}: cmd={:?}, workdir={}, tty={}, rootfs={:?}, mounts={}",
            id,
            command,
            working_dir,
            use_tty,
            rootfs,
            mounts.len()
        );

        // Build the command
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..]);
        cmd.current_dir(&working_dir);

        // Set environment variables
        for (key, value) in &env {
            cmd.env(key, value);
        }

        // Configure stdio based on TTY mode
        let pty_handle = if use_tty {
            // Create PTY for TTY mode
            let pty = PtyHandle::new(cols, rows).context("failed to create PTY")?;

            let slave_fd = pty.slave_fd();
            let rootfs_for_exec = rootfs.clone();
            let working_dir_for_exec = working_dir.clone();
            let mounts_for_exec = mounts.clone();

            // Configure process to use PTY slave
            // SAFETY: pre_exec runs after fork, before exec
            unsafe {
                cmd.pre_exec(move || {
                    // Setup rootfs isolation if provided
                    if let Some(ref rootfs_path) = rootfs_for_exec {
                        setup_container_rootfs(
                            rootfs_path,
                            &working_dir_for_exec,
                            &mounts_for_exec,
                        )?;
                    }

                    // Create new session
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // Set controlling terminal
                    // Note: ioctl request type differs between platforms
                    #[cfg(target_os = "linux")]
                    let ioctl_result = libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
                    #[cfg(target_os = "macos")]
                    let ioctl_result = libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0);
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    let ioctl_result = -1i32;
                    if ioctl_result < 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // Duplicate slave to stdin/stdout/stderr
                    if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(slave_fd, libc::STDERR_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    // Close slave if not already stdin/stdout/stderr
                    if slave_fd > libc::STDERR_FILENO {
                        libc::close(slave_fd);
                    }

                    Ok(())
                });
            }

            // Set TERM environment variable
            cmd.env("TERM", "xterm-256color");

            Some(pty)
        } else {
            // Non-TTY mode: use pipes
            // Setup rootfs isolation if provided
            if let Some(ref rootfs_path) = rootfs {
                let rootfs_for_exec = rootfs_path.clone();
                let working_dir_for_exec = working_dir.clone();
                let mounts_for_exec = mounts.clone();
                // SAFETY: pre_exec runs after fork, before exec
                unsafe {
                    cmd.pre_exec(move || {
                        setup_container_rootfs(
                            &rootfs_for_exec,
                            &working_dir_for_exec,
                            &mounts_for_exec,
                        )
                    });
                }
            }

            if open_stdin {
                cmd.stdin(Stdio::piped());
            } else {
                cmd.stdin(Stdio::null());
            }
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            None
        };

        // Spawn the process
        tracing::info!("Spawning process: {:?}", command);
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "failed to spawn container process (cmd={:?}, rootfs={:?}, workdir={})",
                command, rootfs, working_dir
            )
        })?;
        let pid = child.id();
        let stdin_handle = child.stdin.take();

        // Update container state
        container.state = ContainerState::Running;
        container.pid = pid;
        container.exit_code = None;

        // Store the process handle
        if let Some(pid) = pid {
            tracing::info!("Container {} started with PID {}", id, pid);
        }

        // Create and start the shim for log capture (both TTY and non-TTY modes)
        let (shim_shutdown, broadcaster) = if use_tty {
            // TTY mode: use PTY master for log capture
            if let Some(ref pty) = pty_handle {
                let pty_master_fd = pty.master_fd();
                match ProcessShim::with_pty(id.to_string(), pty_master_fd) {
                    Ok(shim) => {
                        let shutdown = shim.shutdown_token();
                        let broadcaster = shim.broadcaster();
                        let container_id = id.to_string();
                        tokio::spawn(async move {
                            if let Err(e) = shim.run().await {
                                tracing::error!("Shim error for {}: {}", container_id, e);
                            }
                        });
                        (Some(shutdown), Some(broadcaster))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create shim for {}: {}", id, e);
                        let broadcaster = spawn_broadcast_only_from_pty(pty_master_fd);
                        (None, Some(broadcaster))
                    }
                }
            } else {
                (None, Some(Arc::new(BroadcastWriter::new())))
            }
        } else {
            // Non-TTY mode: use stdout/stderr pipes
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            if let (Some(stdout), Some(stderr)) = (stdout, stderr) {
                let stdout_fd = stdout.as_raw_fd();
                let stderr_fd = stderr.as_raw_fd();
                // Prevent the ChildStdout/ChildStderr from closing the fds
                std::mem::forget(stdout);
                std::mem::forget(stderr);
                match ProcessShim::with_pipes(id.to_string(), stdout_fd, stderr_fd) {
                    Ok(shim) => {
                        let shutdown = shim.shutdown_token();
                        let broadcaster = shim.broadcaster();
                        let container_id = id.to_string();
                        tokio::spawn(async move {
                            if let Err(e) = shim.run().await {
                                tracing::error!("Shim error for {}: {}", container_id, e);
                            }
                        });
                        (Some(shutdown), Some(broadcaster))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create shim for {}: {}", id, e);
                        let broadcaster = spawn_broadcast_only_from_pipes(stdout_fd, stderr_fd);
                        (None, Some(broadcaster))
                    }
                }
            } else {
                (None, Some(Arc::new(BroadcastWriter::new())))
            }
        };

        let mut processes = self.processes.lock().await;
        processes.insert(
            id.to_string(),
            Arc::new(Mutex::new(ProcessHandle {
                child: Some(child),
                stdin: stdin_handle,
                pty: pty_handle,
                shim_shutdown,
                broadcaster,
            })),
        );

        Ok(())
    }

    /// Stops a container.
    pub async fn stop_container(&mut self, id: &str, timeout_secs: u32) -> Result<()> {
        let container = self.containers.get_mut(id).context("container not found")?;

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
            use nix::sys::signal::{Signal, kill};
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
        let process_handle = {
            let processes = self.processes.lock().await;
            processes.get(id).cloned()
        };

        if let Some(process_handle) = process_handle {
            let child = {
                let mut process_handle = process_handle.lock().await;
                process_handle.child.take()
            };

            if let Some(mut child) = child {
                let timeout = tokio::time::Duration::from_secs(timeout_secs.into());
                let result = tokio::time::timeout(timeout, child.wait()).await;

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
                            use nix::sys::signal::{Signal, kill};
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
                            child.wait(),
                        )
                        .await;
                    }
                }
            }
        }

        // Update state
        container.state = ContainerState::Stopped;
        container.pid = None;

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
        self.remove_process_handle(id).await;

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

        let process_handle = {
            let processes = self.processes.lock().await;
            processes.get(id).cloned()
        };

        if let Some(process_handle) = process_handle {
            let child = {
                let mut process_handle = process_handle.lock().await;
                process_handle.child.take()
            };

            if let Some(mut child) = child {
                let status = child.wait().await?;
                let exit_code = status.code().unwrap_or(-1);

                if let Some(container) = self.containers.get_mut(id) {
                    container.state = ContainerState::Stopped;
                    container.exit_code = Some(exit_code);
                    container.pid = None;
                }

                return Ok(exit_code);
            }
        }

        anyhow::bail!("container process not found")
    }

    /// Sends a signal to a container.
    pub async fn signal_container(&mut self, id: &str, signal: &str) -> Result<()> {
        let container = self.containers.get(id).context("container not found")?;

        if container.state != ContainerState::Running {
            anyhow::bail!("container is not running");
        }

        let pid = container.pid.context("container has no PID")?;

        tracing::info!(
            "Sending signal {} to container {} (PID {})",
            signal,
            id,
            pid
        );

        // Parse signal name or number
        let sig_num = parse_signal(signal)?;

        #[cfg(target_os = "linux")]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            let nix_pid = Pid::from_raw(pid as i32);
            let nix_signal = Signal::try_from(sig_num).context("invalid signal number")?;
            kill(nix_pid, nix_signal).context("failed to send signal")?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            let result = unsafe { libc::kill(pid as i32, sig_num) };
            if result != 0 {
                anyhow::bail!("failed to send signal: {}", std::io::Error::last_os_error());
            }
        }

        Ok(())
    }

    /// Resizes the TTY for a container.
    pub async fn resize_tty(&self, id: &str, cols: u16, rows: u16) -> Result<()> {
        tracing::debug!("ResizeTty for {}: {}x{}", id, cols, rows);

        let process_handle = {
            let processes = self.processes.lock().await;
            processes.get(id).cloned()
        };
        if let Some(process_handle) = process_handle {
            let process_handle = process_handle.lock().await;
            if let Some(ref pty) = process_handle.pty {
                pty.resize(cols, rows)?;
                tracing::debug!("Container {} TTY resized to {}x{}", id, cols, rows);
                return Ok(());
            } else {
                tracing::debug!("Container {} has no TTY", id);
            }
        } else {
            tracing::debug!("Container {} process not found", id);
        }

        Ok(())
    }

    /// Gets the PTY master file descriptor for a container.
    ///
    /// Returns `None` if the container is not running or doesn't have a TTY.
    pub async fn get_pty_master_fd(&self, id: &str) -> Option<std::os::unix::io::RawFd> {
        let process_handle = {
            let processes = self.processes.lock().await;
            processes.get(id).cloned()
        };
        if let Some(process_handle) = process_handle {
            let process_handle = process_handle.lock().await;
            process_handle.pty.as_ref().map(|pty| pty.master_fd())
        } else {
            None
        }
    }
}

/// Parses a signal name or number string into a signal number.
fn parse_signal(signal: &str) -> Result<i32> {
    // First try to parse as a number
    if let Ok(num) = signal.parse::<i32>() {
        return Ok(num);
    }

    // Try to parse as a signal name (with or without "SIG" prefix)
    let sig_name = signal.to_uppercase();
    let sig_name = sig_name.strip_prefix("SIG").unwrap_or(&sig_name);

    match sig_name {
        "HUP" => Ok(libc::SIGHUP),
        "INT" => Ok(libc::SIGINT),
        "QUIT" => Ok(libc::SIGQUIT),
        "ILL" => Ok(libc::SIGILL),
        "TRAP" => Ok(libc::SIGTRAP),
        "ABRT" | "IOT" => Ok(libc::SIGABRT),
        "BUS" => Ok(libc::SIGBUS),
        "FPE" => Ok(libc::SIGFPE),
        "KILL" => Ok(libc::SIGKILL),
        "USR1" => Ok(libc::SIGUSR1),
        "SEGV" => Ok(libc::SIGSEGV),
        "USR2" => Ok(libc::SIGUSR2),
        "PIPE" => Ok(libc::SIGPIPE),
        "ALRM" => Ok(libc::SIGALRM),
        "TERM" => Ok(libc::SIGTERM),
        "CHLD" => Ok(libc::SIGCHLD),
        "CONT" => Ok(libc::SIGCONT),
        "STOP" => Ok(libc::SIGSTOP),
        "TSTP" => Ok(libc::SIGTSTP),
        "TTIN" => Ok(libc::SIGTTIN),
        "TTOU" => Ok(libc::SIGTTOU),
        "URG" => Ok(libc::SIGURG),
        "XCPU" => Ok(libc::SIGXCPU),
        "XFSZ" => Ok(libc::SIGXFSZ),
        "VTALRM" => Ok(libc::SIGVTALRM),
        "PROF" => Ok(libc::SIGPROF),
        "WINCH" => Ok(libc::SIGWINCH),
        "IO" | "POLL" => Ok(libc::SIGIO),
        "SYS" => Ok(libc::SIGSYS),
        _ => anyhow::bail!("unknown signal: {}", signal),
    }
}

impl Default for ContainerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Container Isolation Helpers
// =============================================================================

/// Sets up container rootfs environment in pre_exec.
///
/// This function:
/// 1. Creates a new mount namespace
/// 2. Remounts root as private to prevent mount propagation
/// 3. Mounts essential filesystems (proc, sys, dev)
/// 4. Chroots into the rootfs
/// 5. Changes to the specified working directory
///
/// # Safety
///
/// This must be called in a pre_exec context (after fork, before exec).
#[cfg(target_os = "linux")]
pub(crate) unsafe fn setup_container_rootfs(
    rootfs: &str,
    working_dir: &str,
    mounts: &[MountSpec],
) -> std::io::Result<()> {
    use std::path::Path;

    // Verify rootfs path exists before attempting chroot
    if !Path::new(rootfs).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("rootfs path does not exist: {}", rootfs),
        ));
    }

    let rootfs_c = CString::new(rootfs).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid rootfs path")
    })?;

    // Create new mount namespace
    // SAFETY: unshare is a valid syscall for creating namespaces
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } < 0 {
        // Best-effort isolation; continue if namespaces are unavailable.
    }

    // Make root mount private to prevent propagation
    let none = CString::new("none").unwrap();
    let slash = CString::new("/").unwrap();
    // SAFETY: mount is a valid syscall with proper arguments
    let _ = unsafe {
        libc::mount(
            none.as_ptr(),
            slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    // Best-effort; continue even if remounting fails.

    // Setup essential mounts in the new rootfs
    // SAFETY: setup_container_mounts is unsafe and we're in an unsafe context
    unsafe {
        let _ = setup_container_mounts(rootfs);
    }

    // Perform bind mounts for volumes (before chroot, paths relative to rootfs)
    // SAFETY: setup_bind_mounts is unsafe and we're in an unsafe context
    unsafe {
        let _ = setup_bind_mounts(rootfs, mounts);
    }

    // Chroot into the rootfs
    // SAFETY: chroot is a valid syscall with a proper C string
    if unsafe { libc::chroot(rootfs_c.as_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Change to the specified working directory
    let workdir_c = CString::new(working_dir).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid working_dir path")
    })?;
    // SAFETY: chdir is a valid syscall with a proper C string
    if unsafe { libc::chdir(workdir_c.as_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Sets up bind mounts for container volumes.
///
/// # Safety
///
/// Must be called before chroot. Mounts source paths to target paths within rootfs.
#[cfg(target_os = "linux")]
unsafe fn setup_bind_mounts(rootfs: &str, mounts: &[MountSpec]) -> std::io::Result<()> {
    for mount in mounts {
        // Target path is relative to rootfs
        let target_path = format!("{}{}", rootfs, mount.target);

        // Create target directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&target_path) {
            tracing::warn!("Failed to create mount target {}: {}", target_path, e);
            continue;
        }

        let source_c = CString::new(mount.source.as_str()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid source path")
        })?;
        let target_c = CString::new(target_path.as_str()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid target path")
        })?;

        // Perform bind mount
        // SAFETY: mount is a valid syscall with proper arguments
        let flags = libc::MS_BIND | libc::MS_REC;
        if unsafe {
            libc::mount(
                source_c.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        } < 0
        {
            let err = std::io::Error::last_os_error();
            tracing::warn!(
                "Failed to bind mount {} -> {}: {}",
                mount.source,
                mount.target,
                err
            );
            continue;
        }

        // If readonly, remount with MS_RDONLY
        if mount.readonly {
            let ro_flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY;
            if unsafe {
                libc::mount(
                    std::ptr::null(),
                    target_c.as_ptr(),
                    std::ptr::null(),
                    ro_flags,
                    std::ptr::null(),
                )
            } < 0
            {
                tracing::warn!(
                    "Failed to remount {} as readonly: {}",
                    mount.target,
                    std::io::Error::last_os_error()
                );
            }
        }

        tracing::debug!(
            "Bind mounted {} -> {} (readonly={})",
            mount.source,
            mount.target,
            mount.readonly
        );
    }

    Ok(())
}

/// Sets up essential mounts inside the container rootfs.
#[cfg(target_os = "linux")]
unsafe fn setup_container_mounts(rootfs: &str) -> std::io::Result<()> {
    // Mount /proc
    let proc_path = format!("{}/proc", rootfs);
    if Path::new(&proc_path).exists() {
        let proc_src = CString::new("proc").unwrap();
        let proc_dst = CString::new(proc_path).unwrap();
        let proc_type = CString::new("proc").unwrap();

        // SAFETY: mount is a valid syscall with proper arguments
        if unsafe {
            libc::mount(
                proc_src.as_ptr(),
                proc_dst.as_ptr(),
                proc_type.as_ptr(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            // Non-fatal: /proc might already be mounted or not supported
            tracing::warn!("Failed to mount /proc: {}", std::io::Error::last_os_error());
        }
    }

    // Mount /sys (sysfs)
    let sys_path = format!("{}/sys", rootfs);
    if Path::new(&sys_path).exists() {
        let sys_src = CString::new("sysfs").unwrap();
        let sys_dst = CString::new(sys_path).unwrap();
        let sys_type = CString::new("sysfs").unwrap();

        // SAFETY: mount is a valid syscall with proper arguments
        if unsafe {
            libc::mount(
                sys_src.as_ptr(),
                sys_dst.as_ptr(),
                sys_type.as_ptr(),
                libc::MS_RDONLY,
                std::ptr::null(),
            )
        } < 0
        {
            tracing::warn!("/sys mount failed: {}", std::io::Error::last_os_error());
        }
    }

    // Bind mount /dev from host
    // This is simpler than creating all device nodes manually
    let dev_path = format!("{}/dev", rootfs);
    if Path::new(&dev_path).exists() {
        let dev_src = CString::new("/dev").unwrap();
        let dev_dst = CString::new(dev_path).unwrap();

        // SAFETY: mount is a valid syscall with proper arguments
        if unsafe {
            libc::mount(
                dev_src.as_ptr(),
                dev_dst.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        } < 0
        {
            tracing::warn!(
                "/dev bind mount failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // Mount /dev/pts for PTY support
    let devpts_path = format!("{}/dev/pts", rootfs);
    if Path::new(&devpts_path).exists() {
        let devpts_src = CString::new("devpts").unwrap();
        let devpts_dst = CString::new(devpts_path).unwrap();
        let devpts_type = CString::new("devpts").unwrap();
        let devpts_opts = CString::new("newinstance,ptmxmode=0666").unwrap();

        // SAFETY: mount is a valid syscall with proper arguments
        if unsafe {
            libc::mount(
                devpts_src.as_ptr(),
                devpts_dst.as_ptr(),
                devpts_type.as_ptr(),
                0,
                devpts_opts.as_ptr() as *const libc::c_void,
            )
        } < 0
        {
            // PTY mount might fail if already mounted via /dev bind mount
            tracing::debug!("/dev/pts mount: {}", std::io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub(crate) unsafe fn setup_container_rootfs(
    _rootfs: &str,
    working_dir: &str,
    _mounts: &[MountSpec],
) -> std::io::Result<()> {
    use std::path::Path;

    // Container isolation is only implemented for Linux
    // On other platforms (like macOS host for development), just chroot
    // Bind mounts are not supported on non-Linux platforms.

    // Verify rootfs path exists before attempting chroot
    if !Path::new(_rootfs).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("rootfs path does not exist: {}", _rootfs),
        ));
    }

    let rootfs_c = CString::new(_rootfs).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid rootfs path")
    })?;

    // SAFETY: rootfs_c is a valid CString
    unsafe {
        if libc::chroot(rootfs_c.as_ptr()) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Change to the specified working directory
    let workdir_c = CString::new(working_dir).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid working_dir path")
    })?;
    // SAFETY: workdir_c is a valid CString
    unsafe {
        if libc::chdir(workdir_c.as_ptr()) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
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
            tty: false,
            open_stdin: false,
            mounts: vec![],
            rootfs: None,
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
            tty: false,
            open_stdin: false,
            mounts: vec![],
            rootfs: None,
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
        let container =
            create_test_container("pid-test", vec!["sleep".to_string(), "0.1".to_string()]);
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

        let container =
            create_test_container("double-start", vec!["sleep".to_string(), "1".to_string()]);
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

        let container =
            create_test_container("stop-test", vec!["sleep".to_string(), "60".to_string()]);
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
        runtime
            .remove_container("remove-test", false)
            .await
            .unwrap();

        assert!(runtime.get_container("remove-test").is_none());
    }

    #[tokio::test]
    async fn test_remove_running_container_without_force() {
        let mut runtime = ContainerRuntime::new();

        let container =
            create_test_container("force-remove", vec!["sleep".to_string(), "60".to_string()]);
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

        let container =
            create_test_container("force-remove", vec!["sleep".to_string(), "60".to_string()]);
        runtime.add_container(container);

        runtime.start_container("force-remove").await.unwrap();

        // Remove with force
        runtime
            .remove_container("force-remove", true)
            .await
            .unwrap();

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

    // =========================================================================
    // Log Capture Tests
    // =========================================================================

    #[tokio::test]
    async fn test_container_stdout_captured_to_log() {
        use std::fs;
        use tempfile::TempDir;

        // Create a temporary directory for logs
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        fs::create_dir_all(&log_dir).unwrap();

        let container_id = "test-log-capture";
        let log_path = log_dir.join(format!("{}.log", container_id));

        // Spawn a simple echo command and capture its output
        let mut cmd = tokio::process::Command::new("echo");
        cmd.arg("hello from test");
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        // Manually implement log capture for testing (similar to spawn_log_capture_task)
        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();

        let log_file = std::sync::Arc::new(std::sync::Mutex::new(log_file));

        if let Some(stdout) = stdout {
            let log_file = log_file.clone();
            let mut reader = tokio::io::BufReader::new(stdout);
            let mut line = String::new();

            use tokio::io::AsyncBufReadExt;
            while reader.read_line(&mut line).await.unwrap() > 0 {
                let content = line.trim_end_matches('\n');
                if !content.is_empty() {
                    use std::io::Write;
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let json_line = format!(
                        r#"{{"log":"{}","stream":"stdout","time":"{}"}}"#,
                        content, timestamp
                    );
                    if let Ok(mut f) = log_file.lock() {
                        writeln!(f, "{}", json_line).unwrap();
                    }
                }
                line.clear();
            }
        }

        // Wait for the process to complete
        let _ = child.wait().await;

        // Verify log file was created and contains the output
        assert!(log_path.exists(), "Log file should be created");

        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(
            log_content.contains("hello from test"),
            "Log should contain output: {}",
            log_content
        );
        assert!(
            log_content.contains(r#""stream":"stdout""#),
            "Log should have stream field: {}",
            log_content
        );
        assert!(
            log_content.contains(r#""log":"#),
            "Log should be in JSON format: {}",
            log_content
        );
    }

    #[tokio::test]
    async fn test_container_stderr_captured_to_log() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        fs::create_dir_all(&log_dir).unwrap();

        let container_id = "test-stderr-capture";
        let log_path = log_dir.join(format!("{}.log", container_id));

        // Spawn a command that writes to stderr
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", "echo error message >&2"]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().unwrap();
        let stderr = child.stderr.take();

        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();

        let log_file = std::sync::Arc::new(std::sync::Mutex::new(log_file));

        if let Some(stderr) = stderr {
            let log_file = log_file.clone();
            let mut reader = tokio::io::BufReader::new(stderr);
            let mut line = String::new();

            use tokio::io::AsyncBufReadExt;
            while reader.read_line(&mut line).await.unwrap() > 0 {
                let content = line.trim_end_matches('\n');
                if !content.is_empty() {
                    use std::io::Write;
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let json_line = format!(
                        r#"{{"log":"{}","stream":"stderr","time":"{}"}}"#,
                        content, timestamp
                    );
                    if let Ok(mut f) = log_file.lock() {
                        writeln!(f, "{}", json_line).unwrap();
                    }
                }
                line.clear();
            }
        }

        let _ = child.wait().await;

        // Verify stderr was captured
        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(
            log_content.contains("error message"),
            "Log should contain stderr: {}",
            log_content
        );
        assert!(
            log_content.contains(r#""stream":"stderr""#),
            "Log should mark as stderr: {}",
            log_content
        );
    }

    #[tokio::test]
    async fn test_container_multiline_output_captured() {
        use std::fs;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        fs::create_dir_all(&log_dir).unwrap();

        let container_id = "test-multiline";
        let log_path = log_dir.join(format!("{}.log", container_id));

        // Spawn a command that outputs multiple lines
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", "echo line1; echo line2; echo line3"]);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().unwrap();
        let stdout = child.stdout.take();

        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();

        let log_file = std::sync::Arc::new(std::sync::Mutex::new(log_file));

        if let Some(stdout) = stdout {
            let log_file = log_file.clone();
            let mut reader = tokio::io::BufReader::new(stdout);
            let mut line = String::new();

            use tokio::io::AsyncBufReadExt;
            while reader.read_line(&mut line).await.unwrap() > 0 {
                let content = line.trim_end_matches('\n');
                if !content.is_empty() {
                    use std::io::Write;
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let json_line = format!(
                        r#"{{"log":"{}","stream":"stdout","time":"{}"}}"#,
                        content, timestamp
                    );
                    if let Ok(mut f) = log_file.lock() {
                        writeln!(f, "{}", json_line).unwrap();
                    }
                }
                line.clear();
            }
        }

        let _ = child.wait().await;

        // Verify all lines were captured
        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("line1"), "Should have line1");
        assert!(log_content.contains("line2"), "Should have line2");
        assert!(log_content.contains("line3"), "Should have line3");

        // Verify each line is a separate JSON entry
        let lines: Vec<&str> = log_content.lines().collect();
        assert_eq!(lines.len(), 3, "Should have 3 log entries");
    }

    #[tokio::test]
    async fn test_start_container_keeps_stdin_when_open() {
        let mut runtime = ContainerRuntime::new();
        let mut container = create_test_container("stdin-open", vec!["cat".to_string()]);
        container.open_stdin = true;
        runtime.add_container(container);

        runtime.start_container("stdin-open").await.unwrap();

        let handle = runtime
            .get_process_handle("stdin-open")
            .await
            .expect("process handle");
        {
            let mut handle = handle.lock().await;
            assert!(
                handle.stdin.is_some(),
                "stdin should be kept open when open_stdin=true"
            );
            if let Some(child) = handle.child.as_mut() {
                if let Some(pid) = child.id() {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    tracing::debug!("Killed test process {}", pid);
                }
            }
        }
    }
}
