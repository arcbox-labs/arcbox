//! Child process supervisor for PID 1 agent.
//!
//! Manages daemon processes (containerd, dockerd) spawned by the agent.
//! Handles SIGCHLD for zombie reaping when running as PID 1.

#[cfg(target_os = "linux")]
mod platform {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Mutex;

    /// Manages child processes spawned by the agent.
    pub struct Supervisor {
        /// Tracked children: name → PID.
        children: HashMap<String, u32>,
    }

    impl Supervisor {
        pub fn new() -> Self {
            Self {
                children: HashMap::new(),
            }
        }

        /// Spawn a named child process. Returns the PID on success.
        pub fn spawn(&mut self, name: &str, mut cmd: std::process::Command) -> anyhow::Result<u32> {
            let child = cmd.spawn()?;
            let pid = child.id();
            tracing::info!(name, pid, "spawned child process");
            self.children.insert(name.to_string(), pid);
            Ok(pid)
        }

        /// Wait for a Unix socket to become ready, polling at 200ms intervals.
        pub async fn wait_ready(&self, name: &str, socket: &str, timeout: Duration) -> bool {
            let deadline = tokio::time::Instant::now() + timeout;
            while tokio::time::Instant::now() < deadline {
                if probe_unix_socket(socket).await {
                    tracing::info!(name, socket, "socket ready");
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            tracing::warn!(name, socket, "socket not ready after timeout");
            false
        }

        /// Reap zombie children via waitpid(-1, WNOHANG).
        ///
        /// Reaps ALL zombies (including orphaned grandchildren reparented to PID 1),
        /// and removes tracked children from the internal map.
        pub fn reap_children(&mut self) {
            use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
            use nix::unistd::Pid;

            loop {
                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(pid, status)) => {
                        let name = self.remove_by_pid(pid.as_raw() as u32);
                        tracing::info!(
                            pid = pid.as_raw(),
                            status,
                            name = name.as_deref().unwrap_or("untracked"),
                            "reaped child process"
                        );
                    }
                    Ok(WaitStatus::Signaled(pid, sig, _)) => {
                        let name = self.remove_by_pid(pid.as_raw() as u32);
                        tracing::warn!(
                            pid = pid.as_raw(),
                            signal = %sig,
                            name = name.as_deref().unwrap_or("untracked"),
                            "child killed by signal"
                        );
                    }
                    // No more zombies or error (ECHILD = no children).
                    Ok(WaitStatus::StillAlive) | Err(_) => break,
                    _ => continue,
                }
            }
        }

        /// Gracefully stop all tracked children (SIGTERM, wait, reap).
        pub fn shutdown_all(&mut self) {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            for (name, pid) in &self.children {
                tracing::info!(name, pid, "sending SIGTERM to child");
                let _ = kill(Pid::from_raw(*pid as i32), Signal::SIGTERM);
            }
            // Brief grace period, then reap.
            std::thread::sleep(Duration::from_secs(2));
            self.reap_children();
        }

        fn remove_by_pid(&mut self, pid: u32) -> Option<String> {
            let name = self
                .children
                .iter()
                .find(|(_, &p)| p == pid)
                .map(|(n, _)| n.clone());
            if let Some(ref n) = name {
                self.children.remove(n);
            }
            name
        }
    }

    async fn probe_unix_socket(path: &str) -> bool {
        if !std::path::Path::new(path).exists() {
            return false;
        }
        matches!(
            tokio::time::timeout(
                Duration::from_millis(300),
                tokio::net::UnixStream::connect(path),
            )
            .await,
            Ok(Ok(_))
        )
    }

    /// Spawn a background task that reaps zombies on SIGCHLD.
    ///
    /// Must be called from a tokio runtime. Runs until the process exits.
    pub fn spawn_reaper(supervisor: Arc<Mutex<Supervisor>>) {
        tokio::spawn(async move {
            let mut sigchld = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::child(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    // PID 1 must not panic. Degrade gracefully: zombies may
                    // accumulate but the agent keeps running.
                    tracing::error!(error = %e, "failed to register SIGCHLD handler, zombie reaping disabled");
                    return;
                }
            };

            loop {
                sigchld.recv().await;
                supervisor.lock().await.reap_children();
            }
        });
    }
}

#[cfg(target_os = "linux")]
pub use platform::{Supervisor, spawn_reaper};

// Stubs for non-Linux development.
#[cfg(not(target_os = "linux"))]
pub struct Supervisor;

#[cfg(not(target_os = "linux"))]
impl Supervisor {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_reaper(_supervisor: std::sync::Arc<tokio::sync::Mutex<Supervisor>>) {}
