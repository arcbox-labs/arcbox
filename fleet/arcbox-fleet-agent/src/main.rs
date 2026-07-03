//! ArcBox Fleet runner agent.
//!
//! A standalone binary, for macOS and Linux hosts, that enrolls with the
//! Fleet gateway and, once attached, runs GitHub Actions jobs. Linux jobs
//! run in a Docker container for isolation when a Docker-compatible runtime
//! is available; other jobs run via the pre-installed runner
//! (`run.sh --jitconfig …`).
//!
//! Configuration is environment-driven (`ARCBOX_FLEET_*`). The `enroll`
//! subcommand reads the fleet join token from a file (`--token-file`) or stdin
//! by default; `--token` is accepted for convenience but discouraged, as it
//! leaks the token through the process argument list and shell history.
//!
//! Two ways to run: `run` requires a credential from a prior `enroll` (the
//! headless/farm path) and does nothing else. `serve` additionally exposes
//! the local control-plane API on `agent.sock`, and does not require a
//! credential up front — `enroll`/`drain`/`resume`/`disconnect` can drive it
//! from another invocation of this CLI, or from the desktop app, while it
//! runs.

// The local control-plane API (agent.sock) is a Unix domain socket with no
// Windows equivalent implemented, so this crate targets macOS and Linux
// only. A single, clear message here beats a scattered trail of
// "type not found" errors across `control/`.
#[cfg(not(unix))]
compile_error!("arcbox-fleet-agent supports macOS and Linux only");

mod attach;
mod config;
mod control;
mod credentials;
mod docker;
mod enroll;
mod fsutil;
mod host;
mod runner;
mod settings;
mod state;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_fleet_control_proto::v1 as control_proto;
use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_client::FleetLifecycleServiceClient;
use arcbox_fleet_control_proto::v1::fleet_settings_service_client::FleetSettingsServiceClient;
use arcbox_fleet_proto::v1::Capability;
use arcbox_logging::LogConfig;
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::{AgentConfig, DockerMode};
use crate::credentials::CredentialStore;
use crate::docker::DockerRunner;
use crate::settings::{PersistedSettings, SettingsStore};
use crate::state::AgentState;

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
    ///
    /// Requires a credential from a prior `enroll` — the headless/farm path,
    /// unchanged by the local control-plane API. For the desktop-managed
    /// handoff, where enrollment arrives later over `agent.sock`, use `serve`
    /// instead.
    Run,
    /// Start the local control-plane API (`agent.sock`) and, once enrolled,
    /// attach to the gateway and run dispatched jobs until terminated.
    ///
    /// Unlike `run`, a credential is not required at startup: if one is
    /// already persisted this behaves like `run`, but with none it idles
    /// until an `Enroll` call arrives over the socket (the desktop-managed
    /// handoff) or `disconnect`/`enroll` change that from another
    /// invocation. This is what a launchd LaunchAgent should invoke.
    Serve,
    /// Show the running agent's enrollment/attachment status.
    Status,
    /// Stop the running agent from accepting new offers; in-flight jobs
    /// finish normally.
    Drain,
    /// Resume accepting new offers after `drain`.
    Resume,
    /// Remove the running agent's machine credential and stop attaching.
    /// A fresh `enroll` (or the control-plane `Enroll` RPC) is required to
    /// rejoin the fleet.
    Disconnect,
    /// Get or update the running agent's live-settable configuration.
    #[command(subcommand)]
    Settings(SettingsCommand),
}

#[derive(Debug, Subcommand)]
enum SettingsCommand {
    /// Show every setting's current (in-effect) and target (requested) value.
    Get,
    /// Update one or more settings. Only the flags given are changed;
    /// `load_ceiling`/`mem_floor_mib`/`linux_runner_image` apply on the next
    /// offer/job, `gateway` on the next reconnect, and `docker_mode`/
    /// `runner_script` on the next full restart.
    Set {
        #[arg(long)]
        load_ceiling: Option<f64>,
        #[arg(long)]
        mem_floor_mib: Option<u64>,
        #[arg(long)]
        linux_runner_image: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        /// "auto" | "enabled" | "disabled".
        #[arg(long)]
        docker_mode: Option<String>,
        #[arg(long)]
        runner_script: Option<PathBuf>,
    },
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
        Command::Enroll { token_file, token } => {
            let token = resolve_enrollment_token(token_file, token)?;
            let settings_store = SettingsStore::new(config.settings_path());
            let seed = load_or_seed_settings(&settings_store, &config)?;
            // Enrollment is pure credential exchange — it never needs Docker, so
            // an operator can enroll before the runtime is up. The capabilities
            // sent here are an initial hint, replaced wholesale by the first
            // heartbeat once the agent attaches, so we advertise what we know
            // without probing the runtime.
            let capabilities = capabilities(seed.runner_script.is_some(), None);
            let credential = enroll::enroll(&config, token, capabilities, &seed.gateway).await?;
            CredentialStore::new(
                config.credential_store,
                config.credentials_path(),
                &seed.gateway,
            )
            .store(&credential)?;
            Ok(())
        }
        Command::Run => {
            let settings_store = SettingsStore::new(config.settings_path());
            let seed = load_or_seed_settings(&settings_store, &config)?;
            let docker = init_docker(seed.docker_mode, &seed.linux_runner_image).await?;
            let capabilities = capabilities(seed.runner_script.is_some(), docker.as_ref());
            let credential = CredentialStore::new(
                config.credential_store,
                config.credentials_path(),
                &seed.gateway,
            )
            .load()?
            .context(
                "no credential found — run `arcbox-fleet-agent enroll --token-file …` first",
            )?;
            info!(machine_id = %credential.machine_id, "starting fleet agent");

            // `attach::run` stops accepting work and tears down in-flight
            // runners once this fires.
            let shutdown = spawn_shutdown_signal("termination signal received; draining runners");

            // `run` opens no control socket, so nothing ever subscribes to
            // this over `Watch` — but `RunnerSupervisor` still reads
            // admission thresholds live from it, so it's load-bearing.
            let agent_state = AgentState::new(&seed);
            let (supervisor, egress_rx) = attach::spawn_supervisor(
                &config,
                docker,
                capabilities.clone(),
                agent_state.clone(),
            );
            attach::run(
                config,
                credential,
                supervisor,
                egress_rx,
                capabilities,
                shutdown,
                agent_state,
            )
            .await
        }
        Command::Serve => {
            let settings_store = SettingsStore::new(config.settings_path());
            let seed = load_or_seed_settings(&settings_store, &config)?;
            let docker = init_docker(seed.docker_mode, &seed.linux_runner_image).await?;
            let capabilities = capabilities(seed.runner_script.is_some(), docker.as_ref());
            let socket_path = config.control_socket_path();

            // Cascades to every attach task's child token, so runners still
            // drain on SIGTERM even though `Disconnect` can also cancel one
            // independently.
            let shutdown = spawn_shutdown_signal("termination signal received; shutting down");

            let agent_state = AgentState::new(&seed);
            let supervisor = Arc::new(
                control::AgentSupervisor::new(
                    config,
                    docker,
                    capabilities,
                    shutdown.clone(),
                    agent_state.clone(),
                    settings_store.clone(),
                )
                .await?,
            );
            control::serve(
                &socket_path,
                Arc::clone(&supervisor),
                agent_state,
                settings_store,
                shutdown,
            )
            .await?;
            // The control server has stopped accepting connections; give any
            // live attach task its own shutdown grace before the process exits.
            supervisor.join().await;
            Ok(())
        }
        Command::Status => {
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetLifecycleServiceClient::new(channel);
            let response = client
                .get_status(control_proto::GetStatusRequest {})
                .await
                .context("GetStatus RPC failed")?
                .into_inner();
            match control_proto::ConnectionState::try_from(response.state)
                .unwrap_or(control_proto::ConnectionState::Unspecified)
            {
                control_proto::ConnectionState::Unenrolled => println!("unenrolled"),
                control_proto::ConnectionState::Enrolled => {
                    println!("enrolled (machine_id={})", response.machine_id);
                }
                control_proto::ConnectionState::Draining => {
                    println!("draining (machine_id={})", response.machine_id);
                }
                control_proto::ConnectionState::Unspecified => println!("unknown state"),
            }
            Ok(())
        }
        Command::Drain => {
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetLifecycleServiceClient::new(channel);
            client
                .drain(control_proto::DrainRequest {})
                .await
                .context("Drain RPC failed")?;
            println!("draining");
            Ok(())
        }
        Command::Resume => {
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetLifecycleServiceClient::new(channel);
            client
                .resume(control_proto::ResumeRequest {})
                .await
                .context("Resume RPC failed")?;
            println!("resumed");
            Ok(())
        }
        Command::Disconnect => {
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetLifecycleServiceClient::new(channel);
            client
                .disconnect(control_proto::DisconnectRequest {})
                .await
                .context("Disconnect RPC failed")?;
            println!("disconnected");
            Ok(())
        }
        Command::Settings(SettingsCommand::Get) => {
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetSettingsServiceClient::new(channel);
            let response = client
                .get_settings(control_proto::GetSettingsRequest {})
                .await
                .context("GetSettings RPC failed")?
                .into_inner();
            print_settings(
                response
                    .settings
                    .context("GetSettings response missing settings")?,
            );
            Ok(())
        }
        Command::Settings(SettingsCommand::Set {
            load_ceiling,
            mem_floor_mib,
            linux_runner_image,
            gateway,
            docker_mode,
            runner_script,
        }) => {
            let docker_mode = docker_mode
                .as_deref()
                .map(parse_docker_mode)
                .transpose()?
                .map(|m| m as i32);
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetSettingsServiceClient::new(channel);
            let response = client
                .update_settings(control_proto::UpdateSettingsRequest {
                    load_ceiling,
                    mem_floor_mib,
                    linux_runner_image,
                    gateway,
                    docker_mode,
                    runner_script: runner_script.map(|p| p.to_string_lossy().into_owned()),
                })
                .await
                .context("UpdateSettings RPC failed")?
                .into_inner();
            print_settings(
                response
                    .settings
                    .context("UpdateSettings response missing settings")?,
            );
            Ok(())
        }
    }
}

/// Build a `CancellationToken` cancelled on the first termination signal
/// (see [`shutdown_signal`]), logging `message` when it fires. Shared by
/// `run` and `serve`, whose shutdown trigger is otherwise identical.
fn spawn_shutdown_signal(message: &'static str) -> CancellationToken {
    let shutdown = CancellationToken::new();
    let signal_token = shutdown.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("{message}");
        signal_token.cancel();
    });
    shutdown
}

/// Resolve when the process receives a termination signal: Ctrl-C, or
/// SIGTERM (e.g. a service-manager stop) — every supported target (macOS,
/// Linux) is Unix, so SIGTERM handling is unconditional. If a listener
/// cannot be installed, that signal simply never fires rather than aborting
/// startup.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "failed to listen for Ctrl-C; ignoring");
            std::future::pending::<()>().await;
        }
    };

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

/// Build the capabilities this agent advertises: the native host-runner
/// capability (if a runner script is configured) plus any Docker-served
/// Linux capabilities. Capacity is decided per offer from live telemetry,
/// not here.
fn capabilities(runner_script_present: bool, docker: Option<&DockerRunner>) -> Vec<Capability> {
    let docker_arches = docker.map(DockerRunner::linux_arches).unwrap_or_default();
    host::capabilities(runner_script_present, &docker_arches)
}

/// Probe Docker availability according to `mode`.
async fn init_docker(mode: DockerMode, linux_runner_image: &str) -> Result<Option<DockerRunner>> {
    match mode {
        DockerMode::Disabled => Ok(None),
        DockerMode::Enabled => {
            let runner = DockerRunner::new(linux_runner_image).await?;
            Ok(Some(runner))
        }
        DockerMode::Auto => match DockerRunner::new(linux_runner_image).await {
            Ok(runner) => Ok(Some(runner)),
            Err(e) => {
                warn!(error = %e, "docker not available; linux capabilities will not be advertised");
                Ok(None)
            }
        },
    }
}

/// Load persisted settings, seeding from `config`'s env-derived values on
/// first-ever start.
fn load_or_seed_settings(store: &SettingsStore, config: &AgentConfig) -> Result<PersistedSettings> {
    Ok(store
        .load()?
        .unwrap_or_else(|| PersistedSettings::from(config)))
}

fn parse_docker_mode(s: &str) -> Result<control_proto::DockerMode> {
    match s.to_lowercase().as_str() {
        "auto" => Ok(control_proto::DockerMode::Auto),
        "enabled" => Ok(control_proto::DockerMode::Enabled),
        "disabled" => Ok(control_proto::DockerMode::Disabled),
        other => {
            anyhow::bail!("docker_mode must be 'auto', 'enabled', or 'disabled', got '{other}'")
        }
    }
}

fn docker_mode_label(raw: i32) -> &'static str {
    match control_proto::DockerMode::try_from(raw).unwrap_or(control_proto::DockerMode::Unspecified)
    {
        control_proto::DockerMode::Auto => "auto",
        control_proto::DockerMode::Enabled => "enabled",
        control_proto::DockerMode::Disabled => "disabled",
        control_proto::DockerMode::Unspecified => "unspecified",
    }
}

/// Print one setting as `name: <current>`, or `name: <current> (target:
/// <target>)` when the two differ (e.g. `gateway` before the next
/// reconnect, or `docker_mode`/`runner_script` before the next restart).
fn print_setting(name: &str, current: &str, target: &str) {
    if current == target {
        println!("{name}: {current}");
    } else {
        println!("{name}: {current} (target: {target})");
    }
}

fn print_settings(s: control_proto::AgentSettings) {
    if let Some(v) = s.load_ceiling {
        print_setting(
            "load_ceiling",
            &v.current.to_string(),
            &v.target.to_string(),
        );
    }
    if let Some(v) = s.mem_floor_mib {
        print_setting(
            "mem_floor_mib",
            &v.current.to_string(),
            &v.target.to_string(),
        );
    }
    if let Some(v) = s.linux_runner_image {
        print_setting("linux_runner_image", &v.current, &v.target);
    }
    if let Some(v) = s.gateway {
        print_setting("gateway", &v.current, &v.target);
    }
    if let Some(v) = s.docker_mode {
        print_setting(
            "docker_mode",
            docker_mode_label(v.current),
            docker_mode_label(v.target),
        );
    }
    if let Some(v) = s.runner_script {
        let none = "(none)".to_owned();
        let current = if v.current.is_empty() {
            &none
        } else {
            &v.current
        };
        let target = if v.target.is_empty() {
            &none
        } else {
            &v.target
        };
        print_setting("runner_script", current, target);
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
