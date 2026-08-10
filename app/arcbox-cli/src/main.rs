//! ArcBox CLI - High-performance container and VM runtime.

use anyhow::{Result, bail};
use clap::Parser;
use std::io::IsTerminal as _;
use std::process::ExitCode;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod commands;
mod connect;
mod error;

use commands::{Cli, Commands};

fn main() -> ExitCode {
    // Sentry must be initialized before the tokio runtime so that spawned
    // threads inherit the Hub from the main thread.
    // When SENTRY_DSN is unset, this is a no-op with zero overhead.
    let _sentry_guard = sentry::init(sentry::ClientOptions {
        dsn: std::env::var("ARCBOX_CLI_SENTRY_DSN")
            .or_else(|_| std::env::var("SENTRY_DSN"))
            .ok()
            .and_then(|s| s.parse().ok()),
        release: Some(env!("CARGO_PKG_VERSION").into()),
        environment: std::env::var("ARCBOX_CLI_SENTRY_ENVIRONMENT")
            .or_else(|_| std::env::var("SENTRY_ENVIRONMENT"))
            .ok()
            .map(Into::into),
        sample_rate: 1.0,
        attach_stacktrace: true,
        ..Default::default()
    });

    let cli = Cli::parse();
    let debug = cli.debug;
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", crate::error::render(&error, debug));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    cli.validate_output_format()?;

    // Set ARCBOX_SOCKET env var if --socket was provided.
    // This makes it available to gRPC socket resolution in machine commands.
    // SAFETY: This is called at the start of main(), before any threads are spawned,
    // and we're the only ones modifying this environment variable.
    if let Some(ref socket) = cli.socket {
        unsafe {
            std::env::set_var("ARCBOX_SOCKET", socket.as_os_str());
        }
        if let Some(data_dir) = arcbox_cli::runtime_selection::data_dir_from_docker_socket(socket) {
            let development_instance =
                arcbox_cli::runtime_selection::is_development_instance(&data_dir);
            let selected_profile = cli.profile.or_else(|| {
                std::env::var(arcbox_constants::env::PROFILE)
                    .ok()
                    .and_then(|value| value.parse().ok())
            });
            if development_instance
                && selected_profile.is_some_and(|profile| {
                    profile != arcbox_constants::paths::ArcboxProfile::Development
                })
            {
                bail!(
                    "--socket selects an isolated development instance, but the selected profile is production"
                );
            }
            if let Some(configured) = std::env::var_os(arcbox_constants::env::DATA_DIR) {
                if std::path::Path::new(&configured) != data_dir {
                    bail!(
                        "--socket selects {}, but {} selects {}",
                        data_dir.display(),
                        arcbox_constants::env::DATA_DIR,
                        std::path::Path::new(&configured).display()
                    );
                }
            } else {
                // SAFETY: startup is still single-threaded.
                unsafe {
                    std::env::set_var(arcbox_constants::env::DATA_DIR, &data_dir);
                }
            }
            if development_instance && selected_profile.is_none() {
                // SAFETY: startup is still single-threaded.
                unsafe {
                    std::env::set_var(
                        arcbox_constants::env::PROFILE,
                        arcbox_constants::paths::ArcboxProfile::Development.as_str(),
                    );
                }
            }
        }
    }
    if let Some(profile) = cli.profile {
        // SAFETY: This is called at the start of main(), before any threads are spawned,
        // and we're the only ones modifying this environment variable.
        unsafe {
            std::env::set_var(arcbox_constants::env::PROFILE, profile.as_str());
        }
    }
    if std::env::var_os(arcbox_constants::env::DOCKER_CONTEXT).is_none() {
        let profile = arcbox_constants::paths::ArcboxProfile::from_env_or_default();
        let data_dir = arcbox_constants::paths::HostLayout::from_env_or_default().data_dir;
        if let Some(context) =
            arcbox_cli::runtime_selection::docker_context_name_for(profile, &data_dir)
        {
            // SAFETY: startup is still single-threaded.
            unsafe {
                std::env::set_var(arcbox_constants::env::DOCKER_CONTEXT, context);
            }
        }
    }

    // Initialize logging based on debug flag
    let filter = if cli.debug {
        "arcbox=debug,arcbox_cli=debug"
    } else {
        "arcbox=info"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(arcbox_cli::terminal::ansi_enabled(
                    std::io::stderr().is_terminal(),
                )),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    let result = runtime.block_on(async {
        match cli.command {
            Commands::Machine(cmd) => commands::machine::execute(cmd).await,
            #[cfg(target_os = "macos")]
            Commands::Macos(cmd) => commands::macos::execute(cmd).await,
            Commands::Migrate(cmd) => commands::migrate::execute(cmd).await,
            Commands::Sandbox(cmd) => commands::sandbox::execute(cmd).await,
            Commands::Claude(args) => {
                commands::agent::execute(&commands::agent::CLAUDE, args).await
            }
            Commands::Docker(cmd) => commands::docker::execute(cmd, cli.format).await,
            Commands::Kubernetes(cmd) => commands::kubernetes::execute(cmd).await,
            Commands::System(cmd) => commands::system::execute(cmd).await,
            Commands::Boot(cmd) => commands::boot::execute(cmd, cli.format).await,
            Commands::Disk(cmd) => commands::disk::execute(cmd, cli.format).await,
            #[cfg(target_os = "macos")]
            Commands::Dns(cmd) => commands::dns::execute(cmd, cli.format).await,
            Commands::Daemon(args) => commands::daemon::execute(args).await,
            Commands::Logs(args) => commands::logs::execute(args).await,
            Commands::Setup(cmd) => commands::setup::execute(cmd, cli.format).await,
            Commands::Doctor => commands::doctor::execute(cli.format).await,
            Commands::Top(args) => commands::top::execute(args, cli.format).await,
            #[cfg(target_os = "macos")]
            Commands::Install(args) => commands::install::execute(args).await,
            #[cfg(target_os = "macos")]
            Commands::Uninstall(args) => commands::uninstall::execute(args).await,
            #[cfg(target_os = "macos")]
            Commands::Internal(cmd) => commands::internal::execute(cmd).await,
            Commands::Info => execute_info().await,
            Commands::Version => commands::version::execute(cli.format).await,
        }
    });

    // Interactive sessions leave a `tokio::io::stdin()` read parked on a
    // blocking thread, and that read cannot be cancelled — dropping the runtime
    // would wait for it, so a clean exit would not return the shell until the
    // user pressed Enter. Detaching those threads lets `main` return normally
    // and still runs the sentry guard's flush on the way out.
    runtime.shutdown_background();

    result
}

/// Display system-wide information.
async fn execute_info() -> Result<()> {
    println!("ArcBox Version: {}", env!("CARGO_PKG_VERSION"));
    println!("OS: {}", std::env::consts::OS);
    println!("Arch: {}", std::env::consts::ARCH);
    println!(
        "CPUs: {}",
        std::thread::available_parallelism().map_or(1, |n| n.get())
    );

    match commands::machine::machine_count().await {
        Ok(machine_count) => println!("Machines: {}", machine_count),
        Err(_) => println!("Machines: (daemon not running)"),
    }

    Ok(())
}
