//! Runtime migration commands.
//!
//! This module provides a thin CLI wrapper around the daemon-side migration
//! gRPC service for importing local Docker Desktop and OrbStack workloads.

use anyhow::{Context, Result, bail};
use arcbox_connect::v1 as pb;
use arcbox_connect::v1::MigrationServiceClient;
use arcbox_connect::v1::{
    PrepareMigrationRequest, PrepareMigrationResponse, RunMigrationEvent, RunMigrationRequest,
};
use clap::{Args, Subcommand};
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::connect;

/// Runtime migration commands.
#[derive(Subcommand)]
pub enum MigrateCommands {
    /// Import workloads from another local runtime
    #[command(subcommand)]
    From(MigrateFromCommands),
}

/// Supported runtime migration sources.
#[derive(Subcommand)]
pub enum MigrateFromCommands {
    /// Import from Docker Desktop
    DockerDesktop(MigrateSourceArgs),
    /// Import from OrbStack
    Orbstack(MigrateSourceArgs),
}

/// Shared arguments for a runtime migration source.
#[derive(Args, Clone)]
pub struct MigrateSourceArgs {
    /// Override the source Docker-compatible socket path
    #[arg(long = "source-socket")]
    pub source_socket: Option<PathBuf>,
    /// Skip the confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Clone, Copy)]
enum MigrationSourceKind {
    DockerDesktop,
    Orbstack,
}

impl MigrationSourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::DockerDesktop => "docker-desktop",
            Self::Orbstack => "orbstack",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::DockerDesktop => "Docker Desktop",
            Self::Orbstack => "OrbStack",
        }
    }

    fn default_socket_path(self) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        match self {
            Self::DockerDesktop => home.join(".docker").join("run").join("docker.sock"),
            Self::Orbstack => home.join(".orbstack").join("run").join("docker.sock"),
        }
    }
}

fn migration_client() -> MigrationServiceClient<connectrpc::client::SharedHttp2Connection> {
    let (transport, config) = connect::daemon(&super::resolve_grpc_socket_path());
    MigrationServiceClient::new(transport, config)
}

/// Executes a runtime migration subcommand.
pub async fn execute(cmd: MigrateCommands) -> Result<()> {
    match cmd {
        MigrateCommands::From(MigrateFromCommands::DockerDesktop(args)) => {
            execute_source(MigrationSourceKind::DockerDesktop, args).await
        }
        MigrateCommands::From(MigrateFromCommands::Orbstack(args)) => {
            execute_source(MigrationSourceKind::Orbstack, args).await
        }
    }
}

async fn execute_source(source_kind: MigrationSourceKind, args: MigrateSourceArgs) -> Result<()> {
    let source_socket = args
        .source_socket
        .clone()
        .unwrap_or_else(|| source_kind.default_socket_path());
    ensure_source_socket_exists(source_kind, &source_socket)?;

    println!("Preparing migration from {}...", source_kind.display_name());

    let client = migration_client();
    let prepare: PrepareMigrationResponse = client
        .prepare_migration(PrepareMigrationRequest {
            source_kind: source_kind.as_str().to_string(),
            source_socket_path: source_socket.to_string_lossy().into_owned(),
            allow_replacements: true,
            ..Default::default()
        })
        .await
        .context("Failed to prepare migration")?
        .into_owned();

    if prepare.plan_id.is_empty() {
        bail!("Migration prepare response did not include a plan ID");
    }

    print_prepare_summary(source_kind, &prepare);

    if !args.yes && !confirm_migration(&prepare)? {
        println!("Migration cancelled.");
        return Ok(());
    }

    if args.yes {
        println!("Skipping confirmation because --yes was provided.");
    }

    println!();
    println!("Running migration...");

    let mut stream = client
        .run_migration(RunMigrationRequest {
            plan_id: prepare.plan_id.clone(),
            // We only reach this point after the user has explicitly confirmed
            // (either via interactive prompt or --yes), so allow both
            // replacements and stopping blocker containers.
            allow_replacements: true,
            ..Default::default()
        })
        .await
        .context("Failed to start migration")?;

    let mut final_status = None;
    while let Some(item) = stream
        .message::<pb::RunMigrationEvent>()
        .await
        .context("Failed to read migration progress")?
    {
        let event: RunMigrationEvent = item.to_owned_message();
        print_progress_event(&event);
        if event.done {
            final_status = Some(event.success);
            break;
        }
    }

    match final_status {
        Some(true) => {
            println!("Migration completed successfully.");
            Ok(())
        }
        Some(false) => bail!("Migration failed"),
        None => bail!("Migration stream ended without a final status event"),
    }
}

fn ensure_source_socket_exists(source_kind: MigrationSourceKind, path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }

    bail!(
        "{} socket not found at {}. Use --source-socket to override it.",
        source_kind.display_name(),
        path.display()
    )
}

fn print_prepare_summary(source_kind: MigrationSourceKind, prepare: &PrepareMigrationResponse) {
    println!("Migration plan ready");
    println!("  Source:         {}", source_kind.display_name());
    println!("  Source socket:  {}", prepare.source_socket_path);
    println!("  Plan ID:        {}", prepare.plan_id);
    println!("  Images:         {}", prepare.image_count);
    println!("  Volumes:        {}", prepare.volume_count);
    println!("  Networks:       {}", prepare.network_count);
    println!("  Containers:     {}", prepare.container_count);
    println!(
        "  Replacements:   {}",
        if prepare.replacements_required {
            "required"
        } else {
            "none"
        }
    );

    if !prepare.warnings.is_empty() {
        println!();
        println!("Warnings:");
        for warning in &prepare.warnings {
            println!("  - {warning}");
        }
    }
}

fn confirm_migration(prepare: &PrepareMigrationResponse) -> Result<bool> {
    if !io::stdin().is_terminal() {
        bail!("Migration confirmation requires a terminal. Re-run with --yes to continue.");
    }

    println!();
    if prepare.replacements_required {
        println!("This migration will modify existing resources and may stop source containers.");
    }

    print!("Proceed with migration? [y/N]: ");
    io::stdout()
        .flush()
        .context("Failed to flush confirmation prompt")?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("Failed to read confirmation prompt")?;

    Ok(is_confirmation_yes(&answer))
}

fn is_confirmation_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn print_progress_event(event: &RunMigrationEvent) {
    let phase = if event.phase.is_empty() {
        "migration"
    } else {
        event.phase.as_str()
    };

    let mut line = format!("[{phase}]");
    if event.total > 0 {
        let _ = write!(&mut line, " {}/{}", event.completed, event.total);
    } else if event.completed > 0 {
        let _ = write!(&mut line, " {}", event.completed);
    }

    if !event.resource.is_empty() {
        line.push(' ');
        line.push_str(&event.resource);
    }

    if !event.message.is_empty() {
        line.push_str(": ");
        line.push_str(&event.message);
    }

    if event.done {
        line.push_str(if event.success {
            " [done]"
        } else {
            " [failed]"
        });
    }

    println!("{line}");
}

#[cfg(test)]
mod tests {
    use super::{MigrationSourceKind, is_confirmation_yes};

    #[test]
    fn docker_desktop_default_socket_ends_with_expected_path() {
        assert!(
            MigrationSourceKind::DockerDesktop
                .default_socket_path()
                .ends_with(".docker/run/docker.sock")
        );
    }

    #[test]
    fn orbstack_default_socket_ends_with_expected_path() {
        assert!(
            MigrationSourceKind::Orbstack
                .default_socket_path()
                .ends_with(".orbstack/run/docker.sock")
        );
    }

    #[test]
    fn confirmation_parser_accepts_yes_variants() {
        assert!(is_confirmation_yes("y"));
        assert!(is_confirmation_yes("Y"));
        assert!(is_confirmation_yes("yes"));
        assert!(is_confirmation_yes(" YES "));
        assert!(!is_confirmation_yes("n"));
        assert!(!is_confirmation_yes(""));
    }
}
