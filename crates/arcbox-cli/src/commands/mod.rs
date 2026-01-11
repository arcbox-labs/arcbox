//! CLI command implementations.
//!
//! This module contains all the command handlers for the ArcBox CLI.
//! Commands are organized into:
//!
//! - Container operations (run, start, stop, ps, logs, exec, rm)
//! - Image operations (images, pull, rmi)
//! - Machine operations (machine subcommands)
//! - System operations (version, info)

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

pub mod boot;
pub mod daemon;
pub mod docker;
pub mod exec;
pub mod images;
pub mod logs;
pub mod machine;
pub mod ps;
pub mod pull;
pub mod rm;
pub mod run;
pub mod start;
pub mod stop;
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
    /// Run a command in a new container
    Run(run::RunArgs),

    /// Start one or more stopped containers
    Start(start::StartArgs),

    /// Stop one or more running containers
    Stop(stop::StopArgs),

    /// List containers
    Ps(ps::PsArgs),

    /// Remove one or more containers
    Rm(rm::RmArgs),

    /// Fetch the logs of a container
    Logs(logs::LogsArgs),

    /// Execute a command in a running container
    Exec(exec::ExecArgs),

    /// List images
    Images(images::ImagesArgs),

    /// Pull an image from a registry
    Pull(pull::PullArgs),

    /// Remove one or more images
    Rmi(images::RmiArgs),

    /// Manage Linux machines
    #[command(subcommand)]
    Machine(machine::MachineCommands),

    /// Manage Docker CLI integration
    #[command(subcommand)]
    Docker(docker::DockerCommands),

    /// Manage boot assets (kernel/initramfs)
    #[command(subcommand)]
    Boot(boot::BootCommands),

    /// Start the ArcBox daemon
    Daemon(daemon::DaemonArgs),

    /// Display system-wide information
    Info,

    /// Show version information
    Version,
}
