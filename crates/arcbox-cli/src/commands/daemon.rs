//! Daemon command implementation.
//!
//! Starts the ArcBox daemon which provides:
//! - Docker-compatible REST API on a Unix socket
//! - VM and container lifecycle management
//! - Image management

use anyhow::{Context, Result};
use arcbox_core::{Config, Runtime};
use arcbox_docker::{DockerApiServer, DockerContextManager, ServerConfig};
use clap::Args;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn};

/// Arguments for the daemon command.
#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Unix socket path for Docker API.
    #[arg(long, default_value = "/var/run/arcbox.sock")]
    pub socket: PathBuf,

    /// Data directory for ArcBox.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Run in foreground (don't daemonize).
    #[arg(long, short = 'f', default_value = "true")]
    pub foreground: bool,

    /// Automatically enable Docker CLI integration.
    #[arg(long)]
    pub docker_integration: bool,
}

/// Executes the daemon command.
pub async fn execute(args: DaemonArgs) -> Result<()> {
    info!("Starting ArcBox daemon...");

    // Determine data directory.
    let data_dir = args.data_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".arcbox"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/arcbox"))
    });

    // Create configuration.
    let config = Config {
        data_dir: data_dir.clone(),
        ..Default::default()
    };

    // Initialize runtime.
    let runtime = Arc::new(Runtime::new(config).context("Failed to create runtime")?);
    runtime.init().await.context("Failed to initialize runtime")?;

    info!(data_dir = %data_dir.display(), "Runtime initialized");

    // Configure Docker API server.
    let server_config = ServerConfig {
        socket_path: args.socket.clone(),
    };

    let server = DockerApiServer::new(server_config, Arc::clone(&runtime));

    // Enable Docker CLI integration if requested.
    if args.docker_integration {
        match DockerContextManager::new(args.socket.clone()) {
            Ok(ctx_manager) => {
                if let Err(e) = ctx_manager.enable() {
                    warn!("Failed to enable Docker integration: {}", e);
                } else {
                    info!("Docker CLI integration enabled");
                }
            }
            Err(e) => {
                warn!("Failed to create Docker context manager: {}", e);
            }
        }
    }

    // Print startup info.
    println!("ArcBox daemon started");
    println!("  Socket: {}", args.socket.display());
    println!("  Data:   {}", data_dir.display());
    println!();
    println!("Use 'arcbox docker enable' to configure Docker CLI integration.");
    println!("Press Ctrl+C to stop.");

    // Run server with graceful shutdown.
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
                return Err(e.into());
            }
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received");
        }
    }

    // Cleanup.
    info!("Shutting down...");
    runtime.shutdown().await.context("Failed to shutdown runtime")?;

    // Disable Docker integration if it was enabled.
    if args.docker_integration {
        if let Ok(ctx_manager) = DockerContextManager::new(args.socket) {
            let _ = ctx_manager.disable();
        }
    }

    info!("ArcBox daemon stopped");
    Ok(())
}

/// Waits for a shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
