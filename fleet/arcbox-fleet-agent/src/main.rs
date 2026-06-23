//! ArcBox Fleet runner agent.
//!
//! A standalone, cross-platform binary that enrolls a host with the Fleet
//! gateway and, once attached, runs GitHub Actions jobs by invoking the
//! pre-installed runner (`run.sh --jitconfig …`). v1 has no isolation: jobs run
//! directly on the host.
//!
//! Configuration is environment-driven (`ARCBOX_FLEET_*`); the only CLI
//! argument is the one-shot enrollment token.

mod attach;
mod config;
mod credentials;
mod enroll;
mod host;
mod runner;

use anyhow::{Context, Result};
use arcbox_logging::LogConfig;
use clap::{Parser, Subcommand};
use tracing::info;

use crate::config::AgentConfig;
use crate::credentials::CredentialStore;

#[derive(Debug, Parser)]
#[command(name = "arcbox-fleet-agent", author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Exchange an enrollment token for the machine credential and persist it.
    Enroll {
        /// Fleet enrollment token issued by the control plane (a multi-use
        /// join token valid until it expires or is rotated).
        #[arg(long)]
        token: String,
    },
    /// Attach to the gateway and run dispatched jobs until terminated.
    Run,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = AgentConfig::from_env()?;

    let _log_guard = arcbox_logging::init(LogConfig {
        log_dir: config.data_dir.join("log"),
        file_name: "fleet-agent.log".to_string(),
        default_filter: "info".to_string(),
        foreground: true,
        ..LogConfig::default()
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(run(cli.command, config))
}

async fn run(command: Command, config: AgentConfig) -> Result<()> {
    match command {
        Command::Enroll { token } => {
            enroll::enroll(&config, token).await?;
            Ok(())
        }
        Command::Run => {
            let credential = CredentialStore::new(config.credentials_path())
                .load()?
                .context("no credential found — run `arcbox-fleet-agent enroll --token …` first")?;
            info!(machine_id = %credential.machine_id, "starting fleet agent");
            attach::run(config, credential).await
        }
    }
}
