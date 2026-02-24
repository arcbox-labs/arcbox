//! Docker CLI integration commands.
//!
//! Manages the integration between Docker CLI and ArcBox by controlling
//! Docker contexts.

use anyhow::{Context, Result};
use arcbox_docker::DockerContextManager;
use clap::Subcommand;
use std::path::PathBuf;

/// Docker integration commands.
#[derive(Subcommand)]
pub enum DockerCommands {
    /// Enable Docker CLI integration
    ///
    /// Creates an 'arcbox' Docker context and sets it as the default.
    /// After enabling, all `docker` commands will use ArcBox.
    Enable,

    /// Disable Docker CLI integration
    ///
    /// Restores the previous default Docker context.
    /// The 'arcbox' context is kept but no longer default.
    Disable,

    /// Show Docker integration status
    Status,
}

/// Executes a docker subcommand.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub async fn execute(cmd: DockerCommands) -> Result<()> {
    // Default socket path - same as DockerApiServer default.
    let socket_path = default_socket_path();

    let manager = DockerContextManager::new(socket_path)
        .context("Failed to initialize Docker context manager")?;

    match cmd {
        DockerCommands::Enable => execute_enable(&manager),
        DockerCommands::Disable => execute_disable(&manager),
        DockerCommands::Status => execute_status(&manager),
    }
}

/// Enables Docker CLI integration.
fn execute_enable(manager: &DockerContextManager) -> Result<()> {
    // Check if already enabled.
    if manager.context_exists() && manager.is_default()? {
        println!("Docker integration is already enabled.");
        return Ok(());
    }

    manager
        .enable()
        .context("Failed to enable Docker integration")?;

    println!("Docker integration enabled.");
    println!();
    println!("You can now use the docker CLI with ArcBox:");
    println!("  docker ps");
    println!("  docker run alpine echo hello");
    println!();
    println!("To disable, run: arcbox docker disable");

    // Warn if socket doesn't exist.
    if !manager.socket_path().exists() {
        println!();
        println!(
            "Warning: ArcBox Docker socket not found at {}",
            manager.socket_path().display()
        );
        println!("Make sure the ArcBox daemon is running.");
    }

    Ok(())
}

/// Disables Docker CLI integration.
fn execute_disable(manager: &DockerContextManager) -> Result<()> {
    if !manager.is_default()? {
        println!("Docker integration is not currently enabled.");
        return Ok(());
    }

    manager
        .disable()
        .context("Failed to disable Docker integration")?;

    println!("Docker integration disabled.");
    println!("The previous default Docker context has been restored.");

    Ok(())
}

/// Shows Docker integration status.
fn execute_status(manager: &DockerContextManager) -> Result<()> {
    let status = manager.status();

    println!("Docker Integration Status");
    println!("=========================");
    println!();
    println!(
        "Context exists:  {}",
        if status.context_exists { "yes" } else { "no" }
    );
    println!(
        "Is default:      {}",
        if status.is_default { "yes" } else { "no" }
    );
    println!("Socket path:     {}", status.socket_path.display());
    println!(
        "Socket exists:   {}",
        if status.socket_exists { "yes" } else { "no" }
    );

    println!();
    if status.is_default && status.socket_exists {
        println!("Status: Ready - docker commands will use ArcBox");
    } else if status.is_default && !status.socket_exists {
        println!("Status: Enabled but daemon not running");
        println!("        Start the ArcBox daemon to use docker commands");
    } else if status.context_exists {
        println!("Status: Context exists but not default");
        println!("        Run 'arcbox docker enable' to activate");
    } else {
        println!("Status: Not configured");
        println!("        Run 'arcbox docker enable' to set up");
    }

    Ok(())
}

/// Returns the default socket path for the Docker-compatible API.
fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".arcbox")
        .join("docker.sock")
}
