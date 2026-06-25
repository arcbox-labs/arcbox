//! ArcBox Fleet runner agent.
//!
//! A standalone, cross-platform binary that enrolls a host with the Fleet
//! gateway and, once attached, runs GitHub Actions jobs. Linux jobs run in a
//! Docker container for isolation when a Docker-compatible runtime is
//! available; other jobs run via the pre-installed runner
//! (`run.sh --jitconfig …`).
//!
//! Configuration is environment-driven (`ARCBOX_FLEET_*`); the only CLI
//! argument is the one-shot enrollment token.

mod attach;
mod config;
mod credentials;
mod docker;
mod enroll;
mod host;
mod runner;

use anyhow::{Context, Result};
use arcbox_fleet_proto::v1::Capability;
use arcbox_logging::LogConfig;
use clap::{Parser, Subcommand};
use tracing::{info, warn};

use crate::config::{AgentConfig, DockerMode};
use crate::credentials::CredentialStore;
use crate::docker::DockerRunner;

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
            // Enrollment is pure credential exchange — it never needs Docker, so
            // an operator can enroll before the runtime is up. The capabilities
            // sent here are an initial hint, replaced wholesale by the first
            // heartbeat once the agent attaches, so we advertise what we know
            // without probing the runtime.
            let capabilities = capabilities(&config, None);
            enroll::enroll(&config, token, capabilities).await?;
            Ok(())
        }
        Command::Run => {
            let docker = init_docker(&config).await?;
            let capabilities = capabilities(&config, docker.as_ref());
            let credential = CredentialStore::new(config.credentials_path())
                .load()?
                .context("no credential found — run `arcbox-fleet-agent enroll --token …` first")?;
            info!(machine_id = %credential.machine_id, "starting fleet agent");
            attach::run(config, credential, docker, capabilities).await
        }
    }
}

/// Build the capabilities this agent advertises: the native host-runner
/// capability (if a runner directory is set) plus any Docker-served Linux
/// capabilities. Capacity is decided per offer from live telemetry, not here.
fn capabilities(config: &AgentConfig, docker: Option<&DockerRunner>) -> Vec<Capability> {
    let docker_arches = docker.map(DockerRunner::linux_arches).unwrap_or_default();
    host::capabilities(config.runner_dir.is_some(), &docker_arches)
}

/// Probe Docker availability according to the configured [`DockerMode`].
async fn init_docker(config: &AgentConfig) -> Result<Option<DockerRunner>> {
    match config.docker.mode {
        DockerMode::Disabled => Ok(None),
        DockerMode::Enabled => {
            let runner = DockerRunner::new(config.docker.runner_image.clone()).await?;
            Ok(Some(runner))
        }
        DockerMode::Auto => match DockerRunner::new(config.docker.runner_image.clone()).await {
            Ok(runner) => Ok(Some(runner)),
            Err(e) => {
                warn!(error = %e, "docker not available; linux capabilities will not be advertised");
                Ok(None)
            }
        },
    }
}
