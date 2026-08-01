//! Runtime migration commands.
//!
//! This module provides a thin CLI wrapper around the daemon-side migration
//! gRPC service for importing local Docker Desktop and OrbStack workloads.

use anyhow::{Context, Result, bail};
use arcbox_grpc::v1::migration_service_client::MigrationServiceClient;
use arcbox_migration::{MigrationPlan, NetworkModeSpec};
use arcbox_protocol::v1::{
    PrepareMigrationRequest, PrepareMigrationResponse, RunMigrationEvent, RunMigrationRequest,
};
use clap::{Args, Subcommand};
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use tonic::transport::{Channel, Endpoint};

use super::machine::UnixConnector;

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
    /// Show what would be migrated and exit without changing anything
    #[arg(long)]
    pub dry_run: bool,
    /// Print the migration plan as JSON
    #[arg(long, requires = "dry_run")]
    pub json: bool,
    /// Recreate containers but leave them stopped
    #[arg(long)]
    pub no_start: bool,
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

async fn migration_client() -> Result<MigrationServiceClient<Channel>> {
    let socket_path = super::resolve_grpc_socket_path();

    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector::new(socket_path.clone()))
        .await
        .with_context(|| {
            format!(
                "Failed to connect to ArcBox gRPC daemon at {}",
                socket_path.display()
            )
        })?;

    Ok(MigrationServiceClient::new(channel))
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

    if !args.json {
        println!("Preparing migration from {}...", source_kind.display_name());
    }

    let mut client = migration_client().await?;
    let prepare = client
        .prepare_migration(tonic::Request::new(PrepareMigrationRequest {
            source_kind: source_kind.as_str().to_string(),
            source_socket_path: source_socket.to_string_lossy().into_owned(),
            allow_replacements: true,
            dry_run: args.dry_run,
        }))
        .await
        .context("Failed to prepare migration")?
        .into_inner();

    if args.dry_run {
        return report_dry_run(source_kind, &prepare, args.json);
    }

    print_prepare_summary(source_kind, &prepare);
    print_blocking_issues(&prepare);
    // Checked before the plan ID: a blocked plan is deliberately not stored, so
    // its empty ID is expected and the blocking issues are the useful message.
    if !prepare.unsupported_resources.is_empty() {
        bail!(
            "Migration cannot run until the blocking issues above are resolved. \
             Re-run with --dry-run to inspect the full plan."
        );
    }
    if prepare.plan_id.is_empty() {
        bail!("Migration prepare response did not include a plan ID");
    }

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
        .run_migration(tonic::Request::new(RunMigrationRequest {
            plan_id: prepare.plan_id.clone(),
            // We only reach this point after the user has explicitly confirmed
            // (either via interactive prompt or --yes), so allow both
            // replacements and stopping blocker containers.
            allow_replacements: true,
            skip_start: args.no_start,
        }))
        .await
        .context("Failed to start migration")?
        .into_inner();

    let mut terminal = None;
    while let Some(event) = stream
        .message()
        .await
        .context("Failed to read migration progress")?
    {
        print_progress_event(&event);
        if event.done {
            terminal = Some(event);
            break;
        }
    }

    let Some(terminal) = terminal else {
        bail!("Migration stream ended without a final status event");
    };
    if !terminal.success {
        bail!("Migration failed");
    }

    // Warnings ride alongside success: everything migrated, but the user needs
    // to see what did not come up before they walk away from the terminal.
    if terminal.warnings.is_empty() {
        println!("Migration completed successfully.");
    } else {
        println!();
        println!("Warnings:");
        for warning in &terminal.warnings {
            println!("  - {warning}");
        }
        println!();
        println!(
            "Migration completed, but {} item(s) need attention (see above).",
            terminal.warnings.len()
        );
    }
    Ok(())
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

/// Renders a dry run and reports whether the plan could actually be executed.
fn report_dry_run(
    source_kind: MigrationSourceKind,
    prepare: &PrepareMigrationResponse,
    as_json: bool,
) -> Result<()> {
    if as_json {
        // The daemon already serialized the plan; reprinting it verbatim keeps
        // the CLI from becoming a second, drifting view of the same model.
        println!("{}", prepare.plan_json);
        return Ok(());
    }

    print_prepare_summary(source_kind, prepare);
    print_plan_details(&prepare.plan_json)?;
    print_blocking_issues(prepare);

    println!();
    if prepare.unsupported_resources.is_empty() {
        println!("Dry run only; nothing was changed. Re-run without --dry-run to migrate.");
    } else {
        println!(
            "Dry run only; nothing was changed. Migration is blocked until the issues above are resolved."
        );
    }
    Ok(())
}

fn print_blocking_issues(prepare: &PrepareMigrationResponse) {
    if prepare.unsupported_resources.is_empty() {
        return;
    }
    println!();
    println!("Blocking issues:");
    for issue in &prepare.unsupported_resources {
        println!("  - {issue}");
    }
}

/// Prints the per-resource breakdown of the plan.
fn print_plan_details(plan_json: &str) -> Result<()> {
    if plan_json.is_empty() {
        return Ok(());
    }
    // Deserialized into the daemon's own plan type rather than picked apart as
    // untyped JSON: `abctl` and `arcbox-daemon` build and ship together, so the
    // type is the contract and a field rename is a compile error here.
    let plan: MigrationPlan =
        serde_json::from_str(plan_json).context("Failed to parse migration plan")?;

    print_section("Images", &plan.images, |image| {
        image.export_references.join(", ")
    });
    print_section("Volumes", &plan.volumes, |volume| {
        format!(
            "{} ({} container(s))",
            volume.name,
            volume.attached_containers.len()
        )
    });
    print_section("Networks", &plan.networks, |network| network.name.clone());
    print_section("Containers", &plan.containers, |container| {
        format!(
            "{} [{}] image={} network={}",
            container.name,
            if container.was_running {
                "will start"
            } else {
                "stopped"
            },
            container.image_reference,
            describe_network_mode(&container.spec.network_mode),
        )
    });
    Ok(())
}

/// Renders a network mode as a short label.
fn describe_network_mode(mode: &NetworkModeSpec) -> String {
    match mode {
        NetworkModeSpec::Default => "default".to_string(),
        NetworkModeSpec::Host => "host".to_string(),
        NetworkModeSpec::None => "none".to_string(),
        NetworkModeSpec::Named(attachment) => attachment.network.clone(),
    }
}

fn print_section<T, F>(title: &str, items: &[T], describe: F)
where
    F: Fn(&T) -> String,
{
    if items.is_empty() {
        return;
    }
    println!();
    println!("{title}:");
    for item in items {
        println!("  - {}", describe(item));
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
    use super::{MigrationSourceKind, NetworkModeSpec, describe_network_mode, is_confirmation_yes};

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
    fn network_modes_render_as_short_labels() {
        assert_eq!(describe_network_mode(&NetworkModeSpec::Host), "host");
        assert_eq!(describe_network_mode(&NetworkModeSpec::Default), "default");
        assert_eq!(
            describe_network_mode(&NetworkModeSpec::Named(
                arcbox_migration::ContainerNetworkAttachment {
                    network: "usernet".into(),
                    aliases: vec!["api".into()],
                }
            )),
            "usernet"
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
