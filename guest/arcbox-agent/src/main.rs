//! ArcBox Guest Agent
//!
//! Runs inside the guest VM to handle host requests.
//!
//! The agent listens on vsock port 1024 and processes RPC requests from the host.
//! It manages container lifecycle and executes commands within the guest VM.

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod agent;
mod init;
mod supervisor;

mod rpc;

// Mount module uses Linux-specific syscalls (mount/umount).
#[cfg(target_os = "linux")]
mod mount;

// VMM config loading and sandbox service are Linux-only (arcbox-vm dep).
#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod sandbox;

// DNS module manages /etc/hosts for container name resolution.
mod dns;

// NFS in-kernel server management (Linux guest only).
#[cfg(target_os = "linux")]
mod nfs;

// k3s lightweight Kubernetes management (Linux guest only).
#[cfg(target_os = "linux")]
mod k3s;

#[tokio::main]
async fn main() -> Result<()> {
    let is_pid1 = std::process::id() == 1;

    // Initialize logging early so init_system() has tracing output.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arcbox_agent=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // PID 1 path: agent was exec'd by busybox trampoline on EROFS rootfs.
    if is_pid1 {
        tracing::info!("Running as PID 1, initializing system");
        init::init_system();

        // Install SIGCHLD handler so orphaned grandchildren (containerd shims,
        // etc.) don't accumulate as zombies.
        let sv = std::sync::Arc::new(tokio::sync::Mutex::new(supervisor::Supervisor::new()));
        supervisor::spawn_reaper(sv);
    }

    tracing::info!("ArcBox agent starting...");

    // Run the agent (vsock listener + RPC handler).
    agent::run().await
}
