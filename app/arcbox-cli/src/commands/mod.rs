//! CLI command implementations.
//!
//! This module contains all the command handlers for the ArcBox CLI.
//! Commands are organized into:
//!
//! - Daemon lifecycle management
//! - Machine management
//! - Runtime migration
//! - Boot asset management
//! - Docker CLI integration
//! - DNS resolver management
//! - System information and version output

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Resolves the gRPC socket path from environment or default location.
///
/// Shared by machine, sandbox, and migrate command modules.
pub fn resolve_grpc_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("ARCBOX_GRPC_SOCKET") {
        return PathBuf::from(path);
    }

    if let Ok(path) = std::env::var("ARCBOX_SOCKET") {
        let docker_socket = PathBuf::from(path);
        if let Some(parent) = docker_socket.parent() {
            let preferred = parent.join("arcbox-grpc.sock");
            if preferred.exists() {
                return preferred;
            }

            let legacy = parent.join("arcbox.sock");
            if legacy.exists() {
                return legacy;
            }

            return preferred;
        }
    }

    arcbox_constants::paths::HostLayout::from_env_or_default().grpc_socket
}

/// Resolves the Docker socket from the CLI override or active configuration.
pub fn resolve_docker_socket_path(config: &arcbox_core::Config) -> PathBuf {
    std::env::var_os("ARCBOX_SOCKET")
        .map_or_else(|| config.docker.socket_path.clone(), PathBuf::from)
}

pub mod agent;
pub mod boot;
pub mod cli_plugins;
pub mod daemon;
pub mod disk;
#[cfg(target_os = "macos")]
pub mod dns;
pub mod docker;
pub mod doctor;
#[cfg(target_os = "macos")]
pub mod install;
#[cfg(target_os = "macos")]
pub mod internal;
pub mod kubernetes;
pub mod logs;
pub mod machine;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod migrate;
pub mod sandbox;
pub mod setup;
pub mod symlink;
pub mod system;
pub mod top;
#[cfg(target_os = "macos")]
pub mod uninstall;
pub mod version;

/// ArcBox - High-performance container and VM runtime
#[derive(Parser)]
#[command(name = "abctl")]
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

    /// Runtime profile (production or development).
    #[arg(long, global = true)]
    pub profile: Option<arcbox_constants::paths::ArcboxProfile>,

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

    /// Manage macOS guests (Apple Silicon only)
    #[cfg(target_os = "macos")]
    #[command(subcommand)]
    Macos(macos::MacosCommands),

    /// Import workloads from Docker Desktop or OrbStack
    #[command(subcommand)]
    Migrate(migrate::MigrateCommands),

    /// Manage sandboxes inside a machine
    #[command(subcommand)]
    Sandbox(sandbox::SandboxCommands),

    /// Open Claude Code in a dedicated sandbox
    Claude(agent::AgentArgs),

    /// Manage Docker CLI integration
    #[command(subcommand)]
    Docker(docker::DockerCommands),

    /// Manage native Kubernetes integration
    #[command(subcommand, alias = "k8s")]
    Kubernetes(kubernetes::KubernetesCommands),

    /// Manage the single System VM (hypervisor backend)
    #[command(subcommand)]
    System(system::SystemCommands),

    /// Manage boot assets (kernel/rootfs)
    #[command(subcommand)]
    Boot(boot::BootCommands),

    /// Manage Docker data disk
    #[command(subcommand)]
    Disk(disk::DiskCommands),

    /// Manage DNS resolver for *.arcbox.local
    #[cfg(target_os = "macos")]
    #[command(subcommand)]
    Dns(dns::DnsCommands),

    /// Manage the ArcBox daemon
    Daemon(daemon::DaemonArgs),

    /// View component logs
    Logs(logs::LogsArgs),

    /// Manage CLI shell integration (PATH, completions)
    #[command(subcommand)]
    Setup(setup::SetupCommands),

    /// Run diagnostic checks on the ArcBox runtime
    Doctor,

    /// Live resource monitor for the System VM
    Top(top::TopArgs),

    /// Internal: install helper + register daemon (used by brew/DMG installers)
    #[cfg(target_os = "macos")]
    #[command(name = "_install", hide = true)]
    Install(install::InstallArgs),

    /// Internal: uninstall helper + deregister daemon (used by brew/DMG installers)
    #[cfg(target_os = "macos")]
    #[command(name = "_uninstall", hide = true)]
    Uninstall(uninstall::UninstallArgs),

    /// Internal: package manager hooks (brew postflight/uninstall)
    #[cfg(target_os = "macos")]
    #[command(name = "_internal", hide = true, subcommand)]
    Internal(internal::InternalCommands),

    /// Display system-wide information
    Info,

    /// Show version information
    Version,
}

impl Cli {
    /// Rejects output formats that the selected command does not implement.
    pub fn validate_output_format(&self) -> anyhow::Result<()> {
        let supported = match self.format {
            OutputFormat::Table => true,
            OutputFormat::Json => match &self.command {
                Commands::Boot(
                    boot::BootCommands::Prefetch(_)
                    | boot::BootCommands::Status(_)
                    | boot::BootCommands::Clear
                    | boot::BootCommands::List,
                )
                | Commands::Setup(
                    setup::SetupCommands::Install
                    | setup::SetupCommands::Uninstall
                    | setup::SetupCommands::Status,
                )
                | Commands::Docker(docker::DockerCommands::Setup)
                | Commands::Top(_)
                | Commands::Disk(disk::DiskCommands::Usage)
                | Commands::Machine(machine::MachineCommands::Inspect(_))
                | Commands::Sandbox(sandbox::SandboxCommands::Inspect(_))
                | Commands::Doctor => true,
                #[cfg(target_os = "macos")]
                Commands::Dns(dns::DnsCommands::Status) => true,
                _ => false,
            },
            OutputFormat::Quiet => matches!(
                &self.command,
                Commands::Setup(
                    setup::SetupCommands::Install
                        | setup::SetupCommands::Uninstall
                        | setup::SetupCommands::Status
                )
            ),
        };

        if supported {
            return Ok(());
        }

        let format = match self.format {
            OutputFormat::Json => "json",
            OutputFormat::Quiet => "quiet",
            OutputFormat::Table => unreachable!("table output is always supported"),
        };
        anyhow::bail!("--format {format} is not supported for this command")
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn query_output_format_matrix() {
        let mut cases: Vec<(&[&str], bool, bool)> = vec![
            (&["version"], false, false),
            (&["info"], false, false),
            (&["doctor"], true, false),
            (&["top"], true, false),
            (&["logs"], false, false),
            (&["daemon", "status"], false, false),
            (&["setup", "status"], true, true),
            (&["setup", "completions", "--shell", "zsh"], false, false),
            (&["disk", "usage"], true, false),
            (&["boot", "status"], true, false),
            (&["boot", "list"], true, false),
            (&["system", "backend"], false, false),
            (&["kubernetes", "status"], false, false),
            (&["kubernetes", "kubeconfig"], false, false),
            (&["docker", "status"], false, false),
            (&["machine", "ls"], false, false),
            (&["machine", "status", "default"], false, false),
            (&["machine", "inspect", "default"], true, false),
            (&["machine", "ping", "default"], false, false),
            (&["machine", "info", "default"], false, false),
            (&["sandbox", "ls"], false, false),
            (&["sandbox", "inspect", "sandbox"], true, false),
            (&["sandbox", "events"], false, false),
            (&["sandbox", "snapshots"], false, false),
            (&["sandbox", "templates"], false, false),
            (
                &["migrate", "from", "docker-desktop", "--dry-run"],
                false,
                false,
            ),
            (&["migrate", "from", "orbstack", "--dry-run"], false, false),
        ];

        #[cfg(target_os = "macos")]
        cases.extend([
            (&["dns", "status"][..], true, false),
            (&["macos", "ls"][..], false, false),
            (&["macos", "ip", "guest"][..], false, false),
            (
                &["macos", "image", "resolve", "tahoe-base"][..],
                false,
                false,
            ),
            (&["macos", "image", "ls"][..], false, false),
        ]);

        for (args, json, quiet) in cases {
            assert!(accepts(args, "table"), "table rejected for {args:?}");
            assert_eq!(accepts(args, "json"), json, "JSON mismatch for {args:?}");
            assert_eq!(accepts(args, "quiet"), quiet, "quiet mismatch for {args:?}");
        }
    }

    fn accepts(args: &[&str], format: &str) -> bool {
        let argv: Vec<_> = ["abctl", "--format", format]
            .into_iter()
            .chain(args.iter().copied())
            .collect();
        Cli::try_parse_from(argv)
            .expect("matrix command must parse")
            .validate_output_format()
            .is_ok()
    }
}
