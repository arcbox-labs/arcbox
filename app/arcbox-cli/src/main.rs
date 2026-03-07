//! ArcBox CLI - High-performance container and VM runtime.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod commands;

use commands::{Cli, Commands};

fn main() -> Result<()> {
    // Sentry must be initialized before the tokio runtime so that spawned
    // threads inherit the Hub from the main thread.
    // When SENTRY_DSN is unset, this is a no-op with zero overhead.
    let _sentry_guard = sentry::init(sentry::ClientOptions {
        dsn: std::env::var("SENTRY_DSN")
            .ok()
            .and_then(|s| s.parse().ok()),
        release: Some(env!("CARGO_PKG_VERSION").into()),
        environment: std::env::var("SENTRY_ENVIRONMENT").ok().map(Into::into),
        sample_rate: 1.0,
        attach_stacktrace: true,
        ..Default::default()
    });

    let cli = Cli::parse();

    // Set ARCBOX_SOCKET env var if --socket was provided.
    // This makes it available to gRPC socket resolution in machine commands.
    // SAFETY: This is called at the start of main(), before any threads are spawned,
    // and we're the only ones modifying this environment variable.
    if let Some(ref socket) = cli.socket {
        unsafe {
            std::env::set_var("ARCBOX_SOCKET", socket.as_os_str());
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
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime")
        .block_on(async {
            match cli.command {
                Commands::Machine(cmd) => commands::machine::execute(cmd).await,
                Commands::Sandbox(cmd) => commands::sandbox::execute(cmd).await,
                Commands::Docker(cmd) => commands::docker::execute(cmd).await,
                Commands::Boot(cmd) => commands::boot::execute(cmd, cli.format).await,
                #[cfg(target_os = "macos")]
                Commands::Dns(cmd) => commands::dns::execute(cmd).await,
                Commands::Daemon(args) => commands::daemon::execute(args).await,
                Commands::Setup(cmd) => commands::setup::execute(cmd, cli.format).await,
                Commands::Info => execute_info().await,
                Commands::Version => commands::version::execute().await,
            }
        })
}

/// Display system-wide information.
async fn execute_info() -> Result<()> {
    println!("ArcBox Version: {}", env!("CARGO_PKG_VERSION"));
    println!("OS: {}", std::env::consts::OS);
    println!("Arch: {}", std::env::consts::ARCH);
    println!(
        "CPUs: {}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );

    match commands::machine::machine_count().await {
        Ok(machine_count) => println!("Machines: {}", machine_count),
        Err(_) => println!("Machines: (daemon not running)"),
    }

    Ok(())
}
