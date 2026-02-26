use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};

use vmm_core::{SandboxManager, VmmConfig};

/// firecracker-vmm daemon — Firecracker sandbox manager with gRPC interface.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "/etc/firecracker-vmm/config.toml")]
    config: String,

    /// Override the Unix socket path from config.
    #[arg(long)]
    unix_socket: Option<String>,

    /// Override the TCP address from config (e.g. `127.0.0.1:9090`).
    #[arg(long)]
    tcp_addr: Option<String>,

    /// Override the Firecracker data directory from config.
    #[arg(long)]
    data_dir: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.as_str().into()),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "firecracker-vmm sandbox daemon starting"
    );

    // Load configuration.
    let mut config = if std::path::Path::new(&args.config).exists() {
        VmmConfig::from_file(&args.config)
            .with_context(|| format!("failed to load config from {}", args.config))?
    } else {
        tracing::warn!(path = %args.config, "config file not found, using defaults");
        VmmConfig::default()
    };

    // Apply CLI overrides.
    if let Some(socket) = args.unix_socket {
        config.grpc.unix_socket = socket;
    }
    if let Some(addr) = args.tcp_addr {
        config.grpc.tcp_addr = addr;
    }
    if let Some(dir) = args.data_dir {
        config.firecracker.data_dir = dir;
    }

    let unix_socket = config.grpc.unix_socket.clone();
    let tcp_addr = config.grpc.tcp_addr.clone();

    // Build the sandbox manager.
    let manager = Arc::new(
        SandboxManager::new(config).context("failed to initialise SandboxManager")?,
    );

    // Install signal handlers for graceful shutdown.
    let shutdown = install_signal_handler();

    info!(unix_socket = %unix_socket, "starting gRPC server");

    tokio::select! {
        res = vmm_grpc::serve(manager, &unix_socket, &tcp_addr) => {
            if let Err(e) = res {
                error!(error = %e, "gRPC server error");
            }
        }
        _ = shutdown => {
            info!("received shutdown signal");
        }
    }

    info!("firecracker-vmm sandbox daemon stopped");
    Ok(())
}

/// Returns a future that resolves when SIGTERM or SIGINT is received.
async fn install_signal_handler() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv()  => {}
    }
}
