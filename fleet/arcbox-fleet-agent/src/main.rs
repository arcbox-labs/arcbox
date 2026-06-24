//! ArcBox Fleet runner agent.
//!
//! A standalone, cross-platform binary that enrolls a host with the Fleet
//! gateway and, once attached, runs GitHub Actions jobs by invoking the
//! pre-installed runner (`run.sh --jitconfig …`). v1 has no isolation: jobs run
//! directly on the host.
//!
//! Configuration is environment-driven (`ARCBOX_FLEET_*`). The `enroll`
//! subcommand reads the fleet join token from a file (`--token-file`) or stdin
//! by default; `--token` is accepted for convenience but discouraged, as it
//! leaks the token through the process argument list and shell history.

mod attach;
mod config;
mod credentials;
mod docker;
mod enroll;
mod host;
mod runner;

use std::path::PathBuf;

use anyhow::{Context, Result};
use arcbox_logging::LogConfig;
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
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
    ///
    /// The token is a multi-use fleet join token (valid until it expires or is
    /// rotated). Provide it via `--token-file`, on stdin, or — discouraged —
    /// `--token`.
    Enroll {
        /// File holding the enrollment token (recommended). Keeps the token out
        /// of the process argument list, shell history, and service logs.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,

        /// Enrollment token passed directly. Convenient but insecure: it leaks
        /// via the process argument list and shell history. Prefer
        /// `--token-file`, or pipe the token on stdin.
        #[arg(long, conflicts_with = "token_file")]
        token: Option<String>,
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
    let docker = init_docker(&config).await?;

    let docker_arches = docker
        .as_ref()
        .map(|d| d.linux_arches())
        .unwrap_or_default();

    match command {
        Command::Enroll { token_file, token } => {
            let token = resolve_enrollment_token(token_file, token)?;
            enroll::enroll(&config, token, &docker_arches).await?;
            Ok(())
        }
        Command::Run => {
            let credential = CredentialStore::new(config.credentials_path())
                .load()?
                .context(
                    "no credential found — run `arcbox-fleet-agent enroll --token-file …` first",
                )?;
            info!(machine_id = %credential.machine_id, "starting fleet agent");

            // Cancelled on the first termination signal; `attach::run` then
            // stops accepting work and tears down in-flight runners.
            let shutdown = CancellationToken::new();
            let signal_token = shutdown.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                info!("termination signal received; draining runners");
                signal_token.cancel();
            });

            attach::run(config, credential, docker, shutdown).await
        }
    }
}

/// Resolve when the process receives a termination signal: Ctrl-C on any
/// platform, or SIGTERM on Unix (e.g. a service-manager stop). If a listener
/// cannot be installed, that signal simply never fires rather than aborting
/// startup.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "failed to listen for Ctrl-C; ignoring");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                warn!(error = %e, "failed to listen for SIGTERM; ignoring");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Resolve the enrollment token from its chosen source: a file, an explicit
/// `--token`, or stdin when neither is given (the two flags are mutually
/// exclusive). Surrounding whitespace — a trailing newline from a file or
/// `echo` — is trimmed.
fn resolve_enrollment_token(token_file: Option<PathBuf>, token: Option<String>) -> Result<String> {
    let raw = match (token_file, token) {
        (Some(path), _) => std::fs::read_to_string(&path)
            .with_context(|| format!("reading enrollment token from {}", path.display()))?,
        (None, Some(token)) => token,
        (None, None) => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading enrollment token from stdin")?;
            buf
        }
    };
    let token = raw.trim().to_owned();
    if token.is_empty() {
        anyhow::bail!("enrollment token is empty");
    }
    Ok(token)
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
                warn!(error = %e, "docker not available; linux pools will not be advertised");
                Ok(None)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_token_is_trimmed() {
        let token = resolve_enrollment_token(None, Some("  flt_join_abc\n".to_owned())).unwrap();
        assert_eq!(token, "flt_join_abc");
    }

    #[test]
    fn blank_token_is_rejected() {
        assert!(resolve_enrollment_token(None, Some("   \n".to_owned())).is_err());
    }

    #[test]
    fn token_file_takes_precedence_and_is_trimmed() {
        let path = std::env::temp_dir().join(format!("fleet-tok-{}", std::process::id()));
        std::fs::write(&path, "flt_from_file\n").unwrap();
        let token =
            resolve_enrollment_token(Some(path.clone()), Some("ignored".to_owned())).unwrap();
        assert_eq!(token, "flt_from_file");
        let _ = std::fs::remove_file(path);
    }
}
