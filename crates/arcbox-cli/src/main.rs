//! ArcBox CLI - High-performance container and VM runtime.

use anyhow::Result;
use arcbox_cli::client;
use arcbox_core::{Config, Runtime};
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod commands;

use commands::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on debug flag
    let filter = if cli.debug {
        "arcbox=debug,arcbox_cli=debug"
    } else {
        "arcbox=info"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    match cli.command {
        Commands::Run(args) => commands::run::execute(args).await,
        Commands::Start(args) => commands::start::execute(args).await,
        Commands::Stop(args) => commands::stop::execute(args).await,
        Commands::Ps(args) => commands::ps::execute(args).await,
        Commands::Rm(args) => commands::rm::execute(args).await,
        Commands::Logs(args) => commands::logs::execute(args).await,
        Commands::Exec(args) => commands::exec::execute(args).await,
        Commands::Images(args) => commands::images::execute(args).await,
        Commands::Pull(args) => commands::pull::execute(args).await,
        Commands::Rmi(args) => commands::images::execute_rmi(args).await,
        Commands::Machine(cmd) => commands::machine::execute(cmd).await,
        Commands::Docker(cmd) => commands::docker::execute(cmd).await,
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

    // Try to connect to daemon for runtime info
    let daemon = client::DaemonClient::new();
    if daemon.is_running().await {
        // Get container count
        let containers: Vec<client::ContainerSummary> = daemon
            .get("/v1.43/containers/json?all=true")
            .await
            .unwrap_or_default();
        println!("Containers: {}", containers.len());

        // Get image count
        let images: Vec<client::ImageSummary> = daemon
            .get("/v1.43/images/json")
            .await
            .unwrap_or_default();
        println!("Images: {}", images.len());

        // Get machine count from Runtime
        let machine_count = Config::load()
            .ok()
            .and_then(|config| Runtime::new(config).ok())
            .map(|runtime| runtime.machine_manager().list().len())
            .unwrap_or(0);
        println!("Machines: {}", machine_count);
    } else {
        println!("Containers: (daemon not running)");
        println!("Images: (daemon not running)");
        println!("Machines: (daemon not running)");
    }

    Ok(())
}
