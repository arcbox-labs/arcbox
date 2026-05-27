//! ArcBox Guest Agent
//!
//! Runs inside the guest VM to handle host requests.
//!
//! The agent listens on vsock port 1024 and processes RPC requests from the host.
//! It manages container lifecycle and executes commands within the guest VM.

use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod agent;
mod init;
mod supervisor;

#[cfg(target_os = "linux")]
mod error;

mod rpc;
mod shutdown;

// Mount module uses Linux-specific syscalls (mount/umount).
#[cfg(target_os = "linux")]
mod mount;

// VMM config loading and sandbox service are Linux-only.
#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod rootfs_builder;
#[cfg(target_os = "linux")]
mod sandbox;

// DNS: legacy /etc/hosts management (being replaced by dns_server).
mod dns;

// Guest-side DNS server and Docker event-driven container registration.
mod dns_server;
mod docker_events;

#[tokio::main]
async fn main() -> Result<()> {
    let is_pid1 = std::process::id() == 1;

    // Initialize logging early so init_system() has tracing output.
    // Write to /arcbox/log/agent.log (VirtioFS, visible from host as
    // ~/.arcbox/log/agent.log) and to the VM console (hvc1 if available,
    // falling back to stderr which goes to hvc0).
    let log_dir = format!("/arcbox/{}", arcbox_constants::paths::guest::LOG);
    let console_writer: Box<dyn std::io::Write + Send> =
        match std::fs::OpenOptions::new().write(true).open("/dev/hvc1") {
            Ok(f) => Box::new(f),
            Err(_) => Box::new(std::io::stderr()),
        };
    let _log_guard = if std::path::Path::new("/arcbox").exists() {
        match std::fs::create_dir_all(&log_dir) {
            Ok(()) => {
                let file_appender = tracing_appender::rolling::never(&log_dir, "agent.log");
                let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
                tracing_subscriber::registry()
                    .with(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "arcbox_agent=info,arcbox_vm=info".into()),
                    )
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(std::sync::Mutex::new(console_writer)),
                    )
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_target(true)
                            .with_writer(non_blocking),
                    )
                    .init();
                Some(guard)
            }
            Err(e) => {
                // VirtioFS log dir not writable — fall back to console only.
                eprintln!("arcbox-agent: failed to create {log_dir}: {e}, falling back to console");
                tracing_subscriber::registry()
                    .with(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "arcbox_agent=info,arcbox_vm=info".into()),
                    )
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(false)
                            .with_writer(std::sync::Mutex::new(console_writer)),
                    )
                    .init();
                None
            }
        }
    } else {
        // No VirtioFS mount — console only (development / testing).
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "arcbox_agent=info,arcbox_vm=info".into()),
            )
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(console_writer)),
            )
            .init();
        None
    };

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

    let cancel = tokio_util::sync::CancellationToken::new();

    // Start the guest DNS server (0.0.0.0:53).
    let dns = std::sync::Arc::new(dns_server::GuestDnsServer::new(cancel.clone()));
    let dns_handle = {
        let dns = Arc::clone(&dns);
        tokio::spawn(async move {
            if let Err(e) = dns.run().await {
                tracing::error!(error = %e, "guest DNS server exited with error");
            }
        })
    };

    // Start Docker event listener for auto-registering container DNS.
    let docker_handle = {
        let dns = Arc::clone(&dns);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            docker_events::reconcile_and_watch(&dns, cancel).await;
        })
    };

    // Run the agent (vsock listener + RPC handler).
    let result = agent::run().await;

    // Shut down background tasks.
    cancel.cancel();
    let _ = tokio::join!(dns_handle, docker_handle);

    result
}
