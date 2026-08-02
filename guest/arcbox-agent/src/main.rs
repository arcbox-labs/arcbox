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

// Consumed by the Linux agent's WatchMemoryPressure handler; the library
// target compiles it everywhere so the logic stays unit-testable on hosts.
#[cfg(target_os = "linux")]
mod memory_pressure;

// Same arrangement for the WatchStats handler's /proc parsers.
#[cfg(target_os = "linux")]
mod stats;

// Same arrangement for the ext4 metadata-volume migration state machine
// (pure std::fs; the mount syscalls live in agent/linux/metadata_volume.rs).
#[cfg(target_os = "linux")]
mod metadata_migrate;

#[cfg(target_os = "linux")]
mod create_registry;
#[cfg(target_os = "linux")]
mod error;

mod rpc;
mod shutdown;

// Mount module uses Linux-specific syscalls (mount/umount).
#[cfg(target_os = "linux")]
mod mount;

// NFSv3 export of the docker data mount + vsock relays (Linux-only: kernel nfsd).
#[cfg(target_os = "linux")]
mod nfs;

// containerd snapshots client for container filesystem-path resolution.
#[cfg(target_os = "linux")]
mod containerd;

// Finder volume-icon files for the NFS export root.
#[cfg(target_os = "linux")]
mod volume_icon;

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

/// Max bytes for `agent.log` before it rotates (matches the daemon's 10 MiB).
const AGENT_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Number of rotated `agent.log.N` files to retain (matches the daemon).
const AGENT_LOG_MAX_FILES: usize = 5;

/// Startup mode selected from the process arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// One-shot system initialization (`arcbox-agent init`), run by busybox init's
    /// sysinit (rcS) before the agent is respawned. Performs `init_system` and exits.
    Init,
    /// One-shot distro machine initialization (`arcbox-agent machine-init`),
    /// run by the machine boot shim inside the overlay root before
    /// `switch_root`. Brings networking up and exits; the distro init owns
    /// everything else.
    MachineInit,
    /// Long-running agent (default / `serve`): vsock RPC listener and background
    /// services. busybox init respawns it if it exits.
    Serve,
}

/// Selects the startup [`Mode`] from `args` (typically `std::env::args()`).
///
/// `arcbox-agent init` runs one-shot system initialization, `arcbox-agent
/// machine-init` the distro-machine variant; anything else — no subcommand or
/// `serve` — runs the long-running agent.
fn parse_mode(args: &[String]) -> Mode {
    match args.get(1).map(String::as_str) {
        Some("init") => Mode::Init,
        Some("machine-init") => Mode::MachineInit,
        _ => Mode::Serve,
    }
}

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
                // Size-based rotation (10 MiB x 5) reusing the daemon's writer:
                // keeps the active file named `agent.log` (so `abctl logs
                // --component agent` still finds it) while bounding growth.
                let log_path = std::path::Path::new(&log_dir).join("agent.log");
                let file_appender = arcbox_logging::SizeRotatingWriter::new(
                    log_path,
                    AGENT_LOG_MAX_BYTES,
                    AGENT_LOG_MAX_FILES,
                );
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

    // `arcbox-agent init` is the one-shot system-init entry that busybox init's
    // sysinit (rcS) runs before respawning the long-running agent: it performs the
    // system initialization and exits without starting the serving stack.
    if parse_mode(&std::env::args().collect::<Vec<_>>()) == Mode::MachineInit {
        tracing::info!("Running one-shot machine initialization");
        // No critical-mount verification: the machine root is the distro's
        // own writable overlay, not the tmpfs-staged EROFS layout.
        init::machine_init();
        return Ok(());
    }

    if parse_mode(&std::env::args().collect::<Vec<_>>()) == Mode::Init {
        tracing::info!("Running one-shot system initialization");
        init::init_system();
        // Fail fast (non-zero exit) if a writable layer the agent depends on did
        // not mount, so rcS can halt/retry instead of respawning an agent that
        // would run on the read-only EROFS rootfs and fail in obscure ways.
        if let Err(e) = init::verify_critical_mounts() {
            tracing::error!("system initialization incomplete: {e}");
            return Err(anyhow::anyhow!("system initialization incomplete: {e}"));
        }
        return Ok(());
    }

    // When the agent is run directly as PID 1 (legacy standalone boot, e.g. the
    // e2e harness) it owns system init itself. Under busybox init the agent is not
    // PID 1 — rcS already ran `arcbox-agent init` — so this block is skipped and
    // PID 1 (busybox init) reaps orphaned grandchildren natively.
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

    // Bridge the guest NFSv4 server (nfsd on 2049) to the host over vsock. The
    // export itself is set up lazily once dockerd's data mount exists (see
    // agent::linux::runtime); the relay just waits for it. NFSv4 needs only
    // this one port — no MOUNT protocol.
    #[cfg(target_os = "linux")]
    let nfs_handle = tokio::spawn(nfs::run_nfs_relay(
        cancel.clone(),
        arcbox_constants::ports::NFS_NFSD_RELAY_PORT,
        nfs::NFSD_PORT,
    ));

    // Run the agent (vsock listener + RPC handler).
    let result = agent::run().await;

    // Shut down background tasks.
    cancel.cancel();
    let _ = tokio::join!(dns_handle, docker_handle);
    #[cfg(target_os = "linux")]
    let _ = nfs_handle.await;

    result
}

#[cfg(test)]
mod tests {
    use super::{Mode, parse_mode};

    fn argv(extra: &[&str]) -> Vec<String> {
        std::iter::once("arcbox-agent")
            .chain(extra.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn init_subcommand_selects_init_mode() {
        assert_eq!(parse_mode(&argv(&["init"])), Mode::Init);
    }

    #[test]
    fn machine_init_subcommand_selects_machine_init_mode() {
        assert_eq!(parse_mode(&argv(&["machine-init"])), Mode::MachineInit);
    }

    #[test]
    fn no_subcommand_defaults_to_serve() {
        assert_eq!(parse_mode(&argv(&[])), Mode::Serve);
    }

    #[test]
    fn explicit_serve_subcommand_selects_serve() {
        assert_eq!(parse_mode(&argv(&["serve"])), Mode::Serve);
    }

    #[test]
    fn unknown_subcommand_defaults_to_serve() {
        assert_eq!(parse_mode(&argv(&["wat"])), Mode::Serve);
    }
}
