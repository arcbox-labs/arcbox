//! ArcBox CLI - High-performance container and VM runtime.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod commands;

use commands::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set ARCBOX_SOCKET env var if --socket was provided.
    // This makes it available to DaemonClient via its env var lookup.
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

    match cli.command {
        Commands::Machine(cmd) => commands::machine::execute(cmd).await,
        Commands::Docker(cmd) => commands::docker::execute(cmd).await,
        Commands::Boot(cmd) => commands::boot::execute(cmd).await,
        Commands::Dns(cmd) => commands::dns::execute(cmd).await,
        Commands::Daemon(args) => commands::daemon::execute(args).await,
        Commands::Info => execute_info().await,
        Commands::Version => commands::version::execute().await,
    }
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
