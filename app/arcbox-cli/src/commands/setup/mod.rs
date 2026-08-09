//! Shell integration setup commands.
//!
//! Manages CLI registration in the user's effective login environment.

use std::path::PathBuf;

use anyhow::Result;
use arcbox_constants::paths::HostLayout;
use clap::{Subcommand, ValueEnum};

use super::OutputFormat;

mod completions;
mod install;
mod profile;
mod status;

pub(super) use status::shell_integration_status;

/// Shell integration setup commands.
#[derive(Subcommand)]
pub enum SetupCommands {
    /// Install shell integration (PATH, completions, profile)
    Install,

    /// Remove shell integration
    Uninstall,

    /// Check installation status
    Status,

    /// Print shell completions to stdout
    Completions(CompletionsArgs),
}

/// Arguments for the completions subcommand.
#[derive(clap::Args)]
pub struct CompletionsArgs {
    /// Target shell
    #[arg(long, value_enum)]
    pub shell: ShellKind,
}

/// Supported shells.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellKind {
    Zsh,
    Bash,
    Fish,
}

impl ShellKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Zsh => "zsh",
            Self::Bash => "bash",
            Self::Fish => "fish",
        }
    }
}

/// Execute setup commands.
pub async fn execute(command: SetupCommands, format: OutputFormat) -> Result<()> {
    match command {
        SetupCommands::Install => install::install(format).await,
        SetupCommands::Uninstall => install::uninstall(format).await,
        SetupCommands::Status => status::status(format).await,
        SetupCommands::Completions(args) => {
            completions::print(args.shell);
            Ok(())
        }
    }
}

fn arcbox_home() -> PathBuf {
    HostLayout::from_env_or_default().data_dir
}

fn bin_dir() -> PathBuf {
    arcbox_home().join("bin")
}

fn shell_dir() -> PathBuf {
    arcbox_home().join("shell")
}

fn completions_dir() -> PathBuf {
    arcbox_home().join("completions")
}
