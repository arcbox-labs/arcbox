//! ArcBox Guest Agent
//!
//! Runs inside the guest VM to handle host requests.
//!
//! The agent listens on vsock port 1024 and processes RPC requests from the host.
//! It manages container lifecycle and executes commands within the guest VM.

// TODO: Remove these allows once the agent is complete.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod agent;
mod machine_init;

mod rpc;

// Mount module uses Linux-specific syscalls (mount/umount).
#[cfg(target_os = "linux")]
mod mount;

// DNS module manages /etc/hosts for container name resolution.
mod dns;

#[tokio::main]
async fn main() -> Result<()> {
    // Machine provisioning should only run in initramfs as PID 1.
    // After switch_root, distro service managers also start arcbox-agent but
    // those processes must run the RPC server directly.
    if machine_init::is_machine_mode() && std::process::id() == 1 {
        machine_init::run(); // Never returns.
    }

    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arcbox_agent=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("ArcBox agent starting...");

    // Run the agent
    agent::run().await
}
