//! Exec command implementation.

use anyhow::Result;
use clap::Args;

/// Arguments for the exec command.
#[derive(Args)]
pub struct ExecArgs {
    /// Container name or ID
    pub container: String,

    /// Command to execute
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,

    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,

    /// Keep STDIN open
    #[arg(short, long)]
    pub interactive: bool,

    /// Run in detached mode
    #[arg(short, long)]
    pub detach: bool,

    /// Environment variables
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Working directory inside the container
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Username or UID
    #[arg(short, long)]
    pub user: Option<String>,

    /// Run in privileged mode
    #[arg(long)]
    pub privileged: bool,
}

/// Executes the exec command.
pub async fn execute(args: ExecArgs) -> Result<()> {
    tracing::info!(
        "Executing command in container: {} {:?}",
        args.container,
        args.command
    );

    // TODO: Connect to daemon and execute command
    println!(
        "arcbox exec {} {}",
        args.container,
        args.command.join(" ")
    );

    Ok(())
}
