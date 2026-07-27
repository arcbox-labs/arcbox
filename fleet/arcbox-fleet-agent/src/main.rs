//! ArcBox Fleet runner agent.
//!
//! A standalone binary, for macOS and Linux hosts, that enrolls with the
//! Fleet gateway and, once attached, runs GitHub Actions jobs. Linux jobs
//! run in a Docker container for isolation when a Docker-compatible runtime
//! is available; other jobs run via the pre-installed runner
//! (`run.sh --jitconfig …`).
//!
//! Configuration is environment-driven (`ARCBOX_FLEET_*`). The `enroll` and
//! `quick enroll` subcommands read the fleet join token from a file
//! (`--token-file`) or stdin by default; `--token` is accepted for convenience
//! but discouraged, as it leaks the token through the process argument list
//! and shell history.
//!
//! Two ways to run: `quick run` requires a credential from a prior
//! `quick enroll` (the socketless headless/farm path) and does nothing else.
//! `serve` additionally exposes the local control-plane API on `agent.sock`,
//! and does not require a credential up front — `enroll`/`drain`/`resume`/
//! `unenroll` can drive it from another invocation of this CLI, or from the
//! desktop app, while it runs.

// The local control-plane API (agent.sock) is a Unix domain socket with no
// Windows equivalent implemented, so this crate targets macOS and Linux
// only. A single, clear message here beats a scattered trail of
// "type not found" errors across `control/`.
#[cfg(not(unix))]
compile_error!("arcbox-fleet-agent supports macOS and Linux only");

mod attach;
mod backends;
mod config;
mod control;
mod credentials;
mod docker;
mod enroll;
mod fsutil;
mod host;
mod interop;
#[cfg(test)]
mod mock_daemon;
mod runner;
#[cfg(target_os = "macos")]
mod service;
mod settings;
mod state;
mod update;
mod vm;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_control_proto::v1 as control_proto;
use arcbox_fleet_control_proto::v1::fleet_image_service_client::FleetImageServiceClient;
use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_client::FleetLifecycleServiceClient;
use arcbox_fleet_control_proto::v1::fleet_settings_service_client::FleetSettingsServiceClient;
use arcbox_logging::LogConfig;
use clap::{Args, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::backends::Backends;
use crate::config::{AgentConfig, DockerMode, VmMode};
use crate::docker::DockerRunner;
use crate::interop::InteropRunner;
use crate::settings::{PersistedSettings, SettingsStore};
use crate::state::AgentState;
use crate::vm::VmRunner;

#[derive(Debug, Parser)]
#[command(name = "arcbox-fleet-agent", author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enroll through the running agent's local control socket.
    Enroll(EnrollArgs),
    /// Run socketless actions for headless and farm deployments.
    #[command(subcommand)]
    Quick(QuickCommand),
    /// Start the local control-plane API (`agent.sock`) and, once enrolled,
    /// attach to the gateway and run dispatched jobs until terminated.
    ///
    /// Unlike `quick run`, a credential is not required at startup: if one is
    /// already persisted this behaves like `quick run`, but with none it idles
    /// until an `Enroll` call arrives over the socket (the desktop-managed
    /// handoff) or `unenroll`/`enroll` change that from another
    /// invocation. This is what a launchd LaunchAgent should invoke.
    Serve,
    /// Show the running agent's enrollment/attachment status.
    Status,
    /// Stop the running agent from accepting new offers; in-flight jobs
    /// finish normally.
    Drain,
    /// Resume accepting new offers after `drain`.
    Resume,
    /// Leave the fleet — terminal. Stops attaching and removes the machine
    /// credential; the server keeps the machine record, so a fresh `enroll`
    /// joins as a new machine.
    Unenroll,
    /// Get or update the running agent's live-settable configuration.
    #[command(subcommand)]
    Settings(SettingsCommand),
    /// Converge the running agent's image settings onto their targets:
    /// fetch and verify each target image through the runtime that owns it,
    /// then promote it to current. Also the "update to latest" verb — a
    /// floating target (a moving tag) is re-fetched and re-promoted.
    Prepare {
        /// Image kinds to prepare ("linux-runner-image",
        /// "macos-runner-image"). Empty prepares every kind the agent
        /// supports.
        kinds: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum QuickCommand {
    /// Exchange an enrollment token directly with the Fleet gateway and
    /// persist the resulting machine credential.
    Enroll(EnrollArgs),
    /// Attach directly to the gateway and run dispatched jobs until
    /// terminated.
    ///
    /// Requires a credential from a prior `quick enroll` and does not expose
    /// the local control-plane API.
    Run,
    /// Decommission the machine and remove its persisted credential without
    /// contacting a running control server.
    ///
    /// Does not stop a concurrently running `quick run` process.
    Unenroll,
    /// Install a per-user LaunchAgent so `serve` starts on login (macOS).
    ///
    /// Installs the invoking binary into the managed path
    /// (`<data_dir>/bin/arcbox-fleet-agent`) that self-update owns, renders
    /// the plist against it and the agent's data-dir log path, writes it to
    /// `~/Library/LaunchAgents/`, and `launchctl bootstrap`s it into the
    /// current GUI session.
    InstallService,
    /// Remove the LaunchAgent installed by `quick install-service` (macOS).
    /// Idempotent — safe to run when nothing is installed.
    UninstallService,
    /// Self-update to the latest published fleet-agent build.
    ///
    /// Recovery/bootstrap path: resolves the current version from the
    /// release CDN's `latest.json`, downloads the platform binary, verifies
    /// its pinned sha256, and re-execs on the new build. Gateway pushes
    /// remain the authoritative routine-rollout mechanism; run this only
    /// when the gateway is unreachable, before enrollment, or to escape a
    /// bad pinned version.
    SelfUpdate,
}

#[derive(Debug, Args)]
struct EnrollArgs {
    /// File holding the enrollment token (recommended). Keeps the token out
    /// of the process argument list, shell history, and service logs.
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,

    /// Enrollment token passed directly. Convenient but insecure: it leaks
    /// via the process argument list and shell history. Prefer `--token-file`,
    /// or pipe the token on stdin.
    #[arg(long, conflicts_with = "token_file")]
    token: Option<String>,
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "one value, parsed once at startup and consumed immediately — the Set variant's \
              size is irrelevant, and boxing fights the clap derive"
)]
enum SettingsCommand {
    /// Show every setting's current (in-effect) and target (requested) value.
    Get,
    /// Update one or more settings. Only the flags given are changed;
    /// `load_ceiling`/`mem_floor_mib` apply on the next offer/job,
    /// `linux_runner_image` once `prepare` verifies it, `participate` as
    /// soon as the detach/reattach completes, and `docker_mode`/
    /// `runner_script` on the next full restart. `gateway` is only
    /// settable while unenrolled (it takes effect on the next enroll).
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
        /// "false" detaches from the fleet keeping the credential; "true"
        /// reattaches with the same identity.
        #[arg(long)]
        participate: Option<bool>,
        /// macOS base-image stream darwin VM jobs boot from (e.g.
        /// "tahoe-base" or "tahoe-base@2026.07.03").
        #[arg(long)]
        macos_runner_image: Option<String>,
        /// "auto" | "enabled" | "disabled".
        #[arg(long)]
        vm_mode: Option<String>,
        /// Windows-style path to the Windows runner entry point (e.g.
        /// "C:\actions-runner\run.cmd"), run via WSL interop. Requires a WSL
        /// host; "" clears. Applies on the next full restart.
        #[arg(long)]
        windows_runner_script: Option<String>,
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
        Command::Enroll(EnrollArgs { token_file, token }) => {
            let token = resolve_enrollment_token(token_file, token)?;
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetLifecycleServiceClient::new(channel);
            let request = control_proto::EnrollRequest {
                enrollment_token: token,
                control_plane: String::new(),
            };
            let machine_id = match client.enroll(request.clone()).await {
                Ok(response) => response.into_inner().machine_id,
                // A gateway that pins a different build refuses the
                // enrollment, and the agent self-updates and re-execs on the
                // spot — so a connection that drops mid-call is the expected
                // shape of "it updated", not a failure to report.
                Err(status) if is_connection_lost(&status) => {
                    println!(
                        "agent restarted mid-enroll (a version refusal self-updates in place); \
                         waiting for it to come back"
                    );
                    resume_enroll_after_restart(&config, request).await?
                }
                Err(status) => {
                    return Err(anyhow::Error::new(status).context("Enroll RPC failed"));
                }
            };
            println!("enrolled (machine_id={machine_id})");
            Ok(())
        }
        Command::Quick(QuickCommand::Enroll(EnrollArgs { token_file, token })) => {
            let token = resolve_enrollment_token(token_file, token)?;
            let settings_store = SettingsStore::new(config.settings_path());
            let seed = load_or_seed_settings(&settings_store, &config)?;
            // Enrollment is pure credential exchange — it never needs Docker or
            // the daemon, so an operator can enroll before either runtime is up.
            // The capabilities sent here are an initial hint, replaced wholesale
            // by the first Attach handshake once the agent attaches, so we
            // advertise what we know without probing the runtimes.
            let capabilities = host::capabilities(seed.runner_script.is_some(), &[], false, false);
            let credential = match enroll::enroll(&config, token, capabilities, &seed.gateway).await
            {
                Ok(credential) => credential,
                Err(error) => {
                    // A version-refused enrollment that carries a download
                    // self-updates and re-execs this same `enroll`
                    // invocation on the new build (the join token is
                    // multi-use). Managed-path and probe failures fall
                    // through to the original refusal.
                    if let Some(payload) = enroll::update_payload(&error) {
                        info!(
                            expected = %payload.expected_version,
                            "gateway requires a different build; self-updating before enrolling"
                        );
                        let update_error = update::apply_and_exec(&config, &payload).await;
                        warn!(error = %update_error, "self-update failed");
                    }
                    return Err(error);
                }
            };
            config
                .credential_store_for(&seed.gateway)
                .store(&credential)?;
            Ok(())
        }
        Command::Quick(QuickCommand::Run) => {
            let settings_store = SettingsStore::new(config.settings_path());
            let seed = load_or_seed_settings(&settings_store, &config)?;
            // `quick run` opens no control socket, so nothing ever subscribes to
            // this over `Watch` — but `RunnerSupervisor` still reads
            // admission thresholds live from it, so it's load-bearing.
            let agent_state = AgentState::new(&seed);
            let backends = init_backends(&config, &seed, agent_state.clone()).await?;
            let credential = config.credential_store_for(&seed.gateway).load()?.context(
                "no credential found — run `arcbox-fleet-agent quick enroll --token-file …` first",
            )?;
            info!(machine_id = %credential.machine_id, "starting fleet agent");

            // `attach::run` stops accepting work and tears down in-flight
            // runners once this fires.
            let shutdown = spawn_shutdown_signal("termination signal received; draining runners");
            backends::spawn_vm_reprobe(
                &backends,
                agent_state.clone(),
                seed.vm_mode,
                config.vm.daemon_socket.clone(),
                shutdown.clone(),
            );

            let (supervisor, egress_rx) =
                attach::spawn_supervisor(&config, Arc::clone(&backends), agent_state.clone());
            attach::run(
                config,
                credential,
                supervisor,
                egress_rx,
                backends,
                shutdown,
                agent_state,
            )
            .await
        }
        Command::Quick(QuickCommand::Unenroll) => {
            let settings_store = SettingsStore::new(config.settings_path());
            let seed = load_or_seed_settings(&settings_store, &config)?;
            let credential = config
                .credential_store_for(&seed.gateway)
                .load()?
                .context("not enrolled")?;
            enroll::unenroll_and_clear(&config, &seed.gateway, &credential).await?;
            println!("unenrolled");
            Ok(())
        }
        Command::Serve => {
            let settings_store = SettingsStore::new(config.settings_path());
            let seed = load_or_seed_settings(&settings_store, &config)?;
            let agent_state = AgentState::new(&seed);
            let backends = init_backends(&config, &seed, agent_state.clone()).await?;
            let socket_path = config.control_socket_path();

            // Cascades to every attach task's child token, so runners still
            // drain on SIGTERM even though `Unenroll` can also cancel one
            // independently.
            let shutdown = spawn_shutdown_signal("termination signal received; shutting down");
            backends::spawn_vm_reprobe(
                &backends,
                agent_state.clone(),
                seed.vm_mode,
                config.vm.daemon_socket.clone(),
                shutdown.clone(),
            );

            let supervisor = Arc::new(
                control::AgentSupervisor::new(
                    config,
                    backends,
                    shutdown.clone(),
                    agent_state.clone(),
                    settings_store.clone(),
                )
                .await?,
            );
            let reconciler = supervisor.spawn_participation_reconciler(shutdown.clone());
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
            let _ = reconciler.await;
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
                control_proto::ConnectionState::Detached => {
                    println!(
                        "detached (machine_id={}; participate=false — set participate=true to reattach)",
                        response.machine_id
                    );
                }
                control_proto::ConnectionState::CredentialRejected => {
                    println!(
                        "credential rejected (machine_id={}; the machine was decommissioned \
                         server-side — run `unenroll` to clear it and re-enroll to rejoin)",
                        response.machine_id
                    );
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
        Command::Unenroll => {
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetLifecycleServiceClient::new(channel);
            client
                .unenroll(control_proto::UnenrollRequest {})
                .await
                .context("Unenroll RPC failed")?;
            println!("unenrolled");
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
            participate,
            macos_runner_image,
            vm_mode,
            windows_runner_script,
        }) => {
            let docker_mode = docker_mode
                .as_deref()
                .map(parse_docker_mode)
                .transpose()?
                .map(|m| m as i32);
            let vm_mode = vm_mode
                .as_deref()
                .map(parse_vm_mode)
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
                    participate,
                    macos_runner_image,
                    vm_mode,
                    windows_runner_script,
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
        Command::Prepare { kinds } => {
            let kinds = kinds
                .iter()
                .map(|s| parse_image_kind(s).map(|k| k as i32))
                .collect::<Result<Vec<_>>>()?;
            let channel = control::client::connect_default(&config).await?;
            let mut client = FleetImageServiceClient::new(channel);
            let mut stream = client
                .prepare(control_proto::PrepareRequest { kinds })
                .await
                .context("Prepare RPC failed")?
                .into_inner();
            while let Some(event) = stream.message().await.context("prepare failed")? {
                print_prepare_event(&event);
            }
            Ok(())
        }
        Command::Quick(QuickCommand::InstallService) => install_service(&config),
        Command::Quick(QuickCommand::UninstallService) => uninstall_service(),
        Command::Quick(QuickCommand::SelfUpdate) => self_update(&config).await,
    }
}

/// Manual self-update: resolve `latest.json` on the CDN, compare against
/// `CARGO_PKG_VERSION`, and hand off to [`update::apply_and_exec`] when
/// a newer build exists. Returns `Ok(())` on the already-latest no-op;
/// the update path only returns on failure (success re-execs).
async fn self_update(config: &AgentConfig) -> Result<()> {
    let payload = update::resolve_latest(&host::host_os(), &host::host_arch()).await?;
    if payload.expected_version == env!("CARGO_PKG_VERSION") {
        println!("already at latest ({})", payload.expected_version);
        return Ok(());
    }
    info!(
        current = env!("CARGO_PKG_VERSION"),
        expected = %payload.expected_version,
        "self-updating from CDN's latest"
    );
    Err(update::apply_and_exec(config, &payload).await)
}

/// macOS: install the LaunchAgent via [`service::install`]. Other Unix
/// targets (Linux) bail with a pointer to the planned systemd support;
/// keeping the subcommand in the CLI shape lets docs and tab-completion
/// stay uniform across hosts.
#[cfg(target_os = "macos")]
fn install_service(config: &AgentConfig) -> Result<()> {
    service::install(config)
}

#[cfg(not(target_os = "macos"))]
fn install_service(_config: &AgentConfig) -> Result<()> {
    anyhow::bail!(
        "quick install-service is only implemented for macOS; Linux systemd (user unit) \
         support is planned as a follow-up"
    )
}

#[cfg(target_os = "macos")]
fn uninstall_service() -> Result<()> {
    service::uninstall()
}

#[cfg(not(target_os = "macos"))]
fn uninstall_service() -> Result<()> {
    anyhow::bail!(
        "quick uninstall-service is only implemented for macOS; Linux systemd (user unit) \
         support is planned as a follow-up"
    )
}

/// Build a `CancellationToken` cancelled on the first termination signal
/// (see [`shutdown_signal`]), logging `message` when it fires. Shared by
/// `quick run` and `serve`, whose shutdown trigger is otherwise identical.
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

/// How long `enroll` waits for the agent to come back after it self-updates
/// and re-execs mid-call. The download and its checksum verification both
/// finish before the exec, so this only has to cover process restart and the
/// control socket rebind.
const RESTART_WAIT: Duration = Duration::from_secs(30);
/// Gap between reconnect attempts inside [`RESTART_WAIT`].
const RESTART_POLL: Duration = Duration::from_millis(250);

/// Whether the RPC failed because the connection went away rather than
/// because the agent chose to answer that way. `Enroll`'s own refusals all
/// carry a specific code (`InvalidArgument` for an empty token,
/// `FailedPrecondition` for a state or operator-action refusal, `Internal`
/// for a fault), so only transport-level codes reach the resume path.
fn is_connection_lost(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unknown | tonic::Code::Unavailable | tonic::Code::Cancelled
    )
}

/// What a post-restart `GetStatus` says to do about the enrollment this CLI
/// still owes its caller.
#[derive(Debug, PartialEq, Eq)]
enum PostRestart {
    /// Definitively not enrolled — replay the enrollment.
    Replay,
    /// Enrolled, with the id to report.
    Enrolled(String),
    /// Enrolled-ish but no machine id yet: `AgentSupervisor::enroll`
    /// publishes `Attaching` with an empty id for the whole of its gateway
    /// round-trip, and `status` reports that as `Enrolled`. So this is
    /// somebody else's `Enroll` still in flight — it may yet fail and leave
    /// the agent unenrolled. Neither answer is known; look again.
    InProgress,
    /// A state this build does not model.
    Unknown,
}

/// Classify a post-restart status. Split out as a pure function because it
/// carries the whole double-enroll argument: `Replay` may only be returned
/// when the agent is *definitively* unenrolled, never while an enrollment is
/// merely unresolved.
fn post_restart(state: control_proto::ConnectionState, machine_id: &str) -> PostRestart {
    use control_proto::ConnectionState;
    match state {
        ConnectionState::Unenrolled => PostRestart::Replay,
        ConnectionState::Unspecified => PostRestart::Unknown,
        _ if machine_id.is_empty() => PostRestart::InProgress,
        _ => PostRestart::Enrolled(machine_id.to_owned()),
    }
}

/// One attempt at reading the restarting agent's enrollment. `Err` is a
/// retryable "not back yet": no socket, or a socket whose server is still
/// coming up.
async fn poll_post_restart(
    config: &AgentConfig,
) -> Result<(
    FleetLifecycleServiceClient<tonic::transport::Channel>,
    PostRestart,
)> {
    let mut client =
        FleetLifecycleServiceClient::new(control::client::connect_default(config).await?);
    let status = client
        .get_status(control_proto::GetStatusRequest {})
        .await
        .context("GetStatus RPC failed after the agent restarted")?
        .into_inner();
    let state = control_proto::ConnectionState::try_from(status.state)
        .unwrap_or(control_proto::ConnectionState::Unspecified);
    Ok((client, post_restart(state, &status.machine_id)))
}

/// Finish an `Enroll` whose connection dropped because the agent
/// self-updated and re-exec'd. Polls until the replacement process has
/// rebound the control socket *and* reports a settled enrollment, then
/// replays the enrollment — the join token is multi-use, so replaying it is
/// safe. Guarded by [`post_restart`]: the replay happens only while the
/// agent is definitively unenrolled, so an enrollment that did land — or one
/// another caller is still driving — can never enroll the machine twice.
async fn resume_enroll_after_restart(
    config: &AgentConfig,
    request: control_proto::EnrollRequest,
) -> Result<String> {
    let deadline = tokio::time::Instant::now() + RESTART_WAIT;
    let mut client = loop {
        // Every arm that doesn't resolve the enrollment yields the reason to
        // report if the deadline expires while we keep waiting on it.
        let waiting_on = match poll_post_restart(config).await {
            Ok((client, PostRestart::Replay)) => break client,
            Ok((_, PostRestart::Enrolled(machine_id))) => return Ok(machine_id),
            Ok((_, PostRestart::Unknown)) => {
                anyhow::bail!("agent reported an unknown state after restarting")
            }
            Ok((_, PostRestart::InProgress)) => {
                anyhow::anyhow!("another enrollment is still in progress")
            }
            Err(error) => error,
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(
                waiting_on.context("the agent never came back ready to enroll after restarting")
            );
        }
        tokio::time::sleep(RESTART_POLL).await;
    };

    let info = client
        .get_agent_info(control_proto::GetAgentInfoRequest {})
        .await
        .context("GetAgentInfo RPC failed after the agent restarted")?
        .into_inner();
    println!(
        "agent is back on {}; finishing enrollment",
        info.agent_version
    );
    Ok(client
        .enroll(request)
        .await
        .context("Enroll RPC failed after the agent self-updated")?
        .into_inner()
        .machine_id)
}

/// Run the startup probes and assemble the backend registry: any
/// Docker-served Linux capabilities, windows via WSL interop when that
/// probe passed, plus the native pair — VM-served when the daemon backend
/// is active, else the host runner (if a runner script is configured).
/// Capacity is decided per offer from live telemetry, not here.
async fn init_backends(
    config: &AgentConfig,
    seed: &PersistedSettings,
    agent_state: AgentState,
) -> Result<Arc<Backends>> {
    let docker = init_docker(seed.docker_mode, &seed.linux_runner_image).await?;
    let vm = init_vm(
        seed.vm_mode,
        &seed.macos_runner_image,
        &config.vm.daemon_socket,
    )
    .await?;
    let interop = init_interop(seed.windows_runner_script.as_deref()).await;
    Ok(Backends::new(
        seed.runner_script.is_some(),
        docker,
        vm,
        interop,
        agent_state,
    ))
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

/// Probe the local arcbox-daemon's macOS VM backend according to `mode`
/// (mirrors [`init_docker`]). The backend is macOS-only: on other hosts
/// `Auto` resolves to none and `Enabled` fails startup.
async fn init_vm(
    mode: VmMode,
    macos_runner_image: &str,
    daemon_socket: &std::path::Path,
) -> Result<Option<VmRunner>> {
    if std::env::consts::OS != "macos" {
        anyhow::ensure!(
            mode != VmMode::Enabled,
            "vm_mode=enabled requires a macOS host (the VM backend runs macOS guests via the \
             local arcbox-daemon)"
        );
        return Ok(None);
    }
    match mode {
        VmMode::Disabled => Ok(None),
        VmMode::Enabled => {
            let runner = VmRunner::new(daemon_socket, macos_runner_image).await?;
            Ok(Some(runner))
        }
        VmMode::Auto => match VmRunner::new(daemon_socket, macos_runner_image).await {
            Ok(runner) => Ok(Some(runner)),
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "macOS VM backend not available; darwin jobs fall back to the host runner"
                );
                Ok(None)
            }
        },
    }
}

/// Probe the WSL interop backend for windows jobs, Auto semantics only: an
/// unset `windows_runner_script` means not wanted, and a failed probe (not
/// WSL, interop disabled, script missing) logs and falls through — the
/// windows capability is simply not advertised. There is no Enabled mode:
/// unlike Docker/VM, nothing else can serve windows jobs, so failing
/// startup would only take the host's other capabilities down with it.
async fn init_interop(windows_runner_script: Option<&str>) -> Option<InteropRunner> {
    let script = windows_runner_script?;
    match InteropRunner::new(script).await {
        Ok(runner) => {
            info!(
                script,
                "WSL interop available; advertising the windows capability"
            );
            Some(runner)
        }
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "WSL interop not available; the windows capability will not be advertised"
            );
            None
        }
    }
}

/// Load persisted settings, seeding from `config`'s env-derived values on
/// first-ever start.
fn load_or_seed_settings(store: &SettingsStore, config: &AgentConfig) -> Result<PersistedSettings> {
    Ok(store
        .load()?
        .unwrap_or_else(|| PersistedSettings::from(config)))
}

fn parse_image_kind(s: &str) -> Result<control_proto::ImageKind> {
    match s.to_lowercase().as_str() {
        "linux-runner-image" => Ok(control_proto::ImageKind::LinuxRunnerImage),
        "macos-runner-image" => Ok(control_proto::ImageKind::MacosRunnerImage),
        other => anyhow::bail!(
            "image kind must be 'linux-runner-image' or 'macos-runner-image', got '{other}'"
        ),
    }
}

fn image_kind_label(raw: i32) -> &'static str {
    match control_proto::ImageKind::try_from(raw).unwrap_or(control_proto::ImageKind::Unspecified) {
        control_proto::ImageKind::LinuxRunnerImage => "linux_runner_image",
        control_proto::ImageKind::MacosRunnerImage => "macos_runner_image",
        control_proto::ImageKind::Unspecified => "unknown",
    }
}

/// Print one preparation progress event as `kind: stage [detail] (pct%)`.
fn print_prepare_event(event: &control_proto::PrepareResponse) {
    let label = image_kind_label(event.kind);
    let pct = (event.fraction * 100.0).round();
    if event.detail.is_empty() {
        println!("{label}: {} ({pct:.0}%)", event.stage);
    } else {
        println!("{label}: {} {} ({pct:.0}%)", event.stage, event.detail);
    }
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

fn parse_vm_mode(s: &str) -> Result<control_proto::VmMode> {
    match s.to_lowercase().as_str() {
        "auto" => Ok(control_proto::VmMode::Auto),
        "enabled" => Ok(control_proto::VmMode::Enabled),
        "disabled" => Ok(control_proto::VmMode::Disabled),
        other => {
            anyhow::bail!("vm_mode must be 'auto', 'enabled', or 'disabled', got '{other}'")
        }
    }
}

fn vm_mode_label(raw: i32) -> &'static str {
    match control_proto::VmMode::try_from(raw).unwrap_or(control_proto::VmMode::Unspecified) {
        control_proto::VmMode::Auto => "auto",
        control_proto::VmMode::Enabled => "enabled",
        control_proto::VmMode::Disabled => "disabled",
        control_proto::VmMode::Unspecified => "unspecified",
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
    if let Some(v) = s.participate {
        print_setting("participate", &v.current.to_string(), &v.target.to_string());
    }
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
        print_script_setting("runner_script", &v);
    }
    if let Some(v) = s.macos_runner_image {
        print_setting("macos_runner_image", &v.current, &v.target);
    }
    if let Some(v) = s.vm_mode {
        print_setting("vm_mode", vm_mode_label(v.current), vm_mode_label(v.target));
    }
    if let Some(v) = s.windows_runner_script {
        print_script_setting("windows_runner_script", &v);
    }
}

/// [`print_setting`] for the script settings, whose empty string encodes
/// "unset" and prints as `(none)`.
fn print_script_setting(name: &str, v: &control_proto::StringSetting) {
    let or_none = |s: &str| {
        if s.is_empty() {
            "(none)".to_owned()
        } else {
            s.to_owned()
        }
    };
    print_setting(name, &or_none(&v.current), &or_none(&v.target));
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

    /// Only a lost connection may trigger the resume path. A deliberate
    /// refusal reaching it would replay an enrollment the agent already
    /// answered.
    #[test]
    fn only_transport_failures_count_as_a_lost_connection() {
        for code in [
            tonic::Code::Unknown,
            tonic::Code::Unavailable,
            tonic::Code::Cancelled,
        ] {
            assert!(
                is_connection_lost(&tonic::Status::new(code, "")),
                "{code:?}"
            );
        }
        for code in [
            tonic::Code::FailedPrecondition,
            tonic::Code::InvalidArgument,
            tonic::Code::Internal,
        ] {
            assert!(
                !is_connection_lost(&tonic::Status::new(code, "")),
                "{code:?}"
            );
        }
    }

    /// The double-enroll guard. `Replay` is only ever correct when the agent
    /// is definitively unenrolled — an enrolled state reports its id, and an
    /// enrollment still in flight (`Attaching`, which `status` reports as
    /// `Enrolled` with no id yet) is unresolved, not a licence to replay.
    #[test]
    fn post_restart_replays_only_a_definitely_unenrolled_agent() {
        use control_proto::ConnectionState;

        assert_eq!(
            post_restart(ConnectionState::Unenrolled, ""),
            PostRestart::Replay
        );
        assert_eq!(
            post_restart(ConnectionState::Enrolled, "fltm_test"),
            PostRestart::Enrolled("fltm_test".to_owned())
        );
        // Another caller's Enroll is mid-round-trip: no id published yet.
        assert_eq!(
            post_restart(ConnectionState::Enrolled, ""),
            PostRestart::InProgress
        );
        assert_eq!(
            post_restart(ConnectionState::Unspecified, ""),
            PostRestart::Unknown
        );
        // Every other enrolled-ish state reports its machine, never replays.
        for state in [
            ConnectionState::Draining,
            ConnectionState::Detached,
            ConnectionState::CredentialRejected,
        ] {
            assert_eq!(
                post_restart(state, "fltm_test"),
                PostRestart::Enrolled("fltm_test".to_owned()),
                "{state:?}"
            );
        }
    }
}
