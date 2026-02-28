//! CLI command implementations.
//!
//! This module contains all the command handlers for the ArcBox CLI.
//! Commands are organized into:
//!
//! - Daemon lifecycle management
//! - Machine management
//! - Boot asset management
//! - Docker CLI integration
//! - DNS resolver management
//! - System information and version output

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

pub mod boot;
pub mod daemon;
pub mod dns;
pub mod docker;
pub mod machine;
pub mod version;

/// ArcBox - High-performance container and VM runtime
#[derive(Parser)]
#[command(name = "arcbox")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Command to execute
    #[command(subcommand)]
    pub command: Commands,

    /// Unix socket path for daemon connection
    ///
    /// Can also be set via ARCBOX_SOCKET or DOCKER_HOST environment variables.
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,

    /// Output format
    #[arg(long, global = true, default_value = "table")]
    pub format: OutputFormat,

    /// Enable debug output
    #[arg(long, global = true)]
    pub debug: bool,
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// Table format (default)
    #[default]
    Table,
    /// JSON format
    Json,
    /// Quiet mode (IDs only)
    Quiet,
}

/// Available commands
#[derive(Subcommand)]
pub enum Commands {
    /// Manage Linux machines
    #[command(subcommand)]
    Machine(machine::MachineCommands),

    /// Manage Docker CLI integration
    #[command(subcommand)]
    Docker(docker::DockerCommands),

    /// Manage boot assets (kernel/rootfs)
    #[command(subcommand)]
    Boot(boot::BootCommands),

    /// Manage DNS resolver for *.arcbox.local
    #[command(subcommand)]
    Dns(dns::DnsCommands),

    /// Manage the ArcBox daemon
    Daemon(daemon::DaemonArgs),

    /// Display system-wide information
    Info,

    /// Show version information
    Version,
}
