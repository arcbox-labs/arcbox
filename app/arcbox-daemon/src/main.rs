//! ArcBox daemon — orchestrates VM, networking, and API services.

mod context;
mod dns_service;
mod kubernetes_proxy;
mod recovery;
mod self_setup;
mod services;
mod shutdown;
mod startup;

use std::sync::Arc;

use anyhow::Result;
use arcbox_api::SetupState;
use arcbox_constants::paths::ArcboxProfile;
use arcbox_logging::LogConfig;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "arcbox-daemon")]
#[command(author, version, about, long_about = None)]
pub struct DaemonArgs {
    /// Runtime profile (production or development).
    #[arg(long)]
    pub profile: Option<ArcboxProfile>,

    /// Unix socket path for Docker API (default: ~/.arcbox/run/docker.sock).
    #[arg(long)]
    pub socket: Option<std::path::PathBuf>,

    /// Unix socket path for gRPC API (default: ~/.arcbox/run/arcbox.sock).
    #[arg(long)]
    pub grpc_socket: Option<std::path::PathBuf>,

    /// Data directory for ArcBox.
    #[arg(long)]
    pub data_dir: Option<std::path::PathBuf>,

    /// Custom kernel path for VM boot.
    #[arg(long)]
    pub kernel: Option<std::path::PathBuf>,

    /// Automatically enable Docker CLI integration.
    #[arg(long)]
    pub docker_integration: bool,

    /// Run in foreground (also log to stderr in human-readable format).
    #[arg(long)]
    pub foreground: bool,

    /// Guest dockerd API vsock port.
    #[arg(long)]
    pub guest_docker_vsock_port: Option<u32>,
}

fn main() -> Result<()> {
    let args = DaemonArgs::parse();

    let _sentry_guard = sentry::init(sentry::ClientOptions {
        dsn: sentry_dsn().and_then(|s| s.parse().ok()),
        release: Some(env!("CARGO_PKG_VERSION").into()),
        environment: sentry_environment().map(Into::into),
        traces_sample_rate: 0.2,
        sample_rate: 1.0,
        attach_stacktrace: true,
        ..Default::default()
    });

    let profile = args
        .profile
        .unwrap_or_else(ArcboxProfile::from_env_or_default);
    let data_dir = startup::resolve_data_dir(profile, args.data_dir.as_ref());
    let log_guard = arcbox_logging::init_with_sentry(LogConfig {
        log_dir: data_dir.join(arcbox_constants::paths::host::LOG),
        file_name: arcbox_constants::paths::host::DAEMON_LOG.to_string(),
        // `guest_serial` (PL011 earlycon) and `guest_console` (VirtioConsole
        // hvc0) carry the in-VM kernel + agent boot output. Enable them by
        // default so a stuck guest boot is diagnosable without a RUST_LOG
        // override — they fall quiet once userspace is up.
        default_filter: "arcbox=info,arcbox_daemon=info,guest_serial=info,guest_console=info"
            .to_string(),
        foreground: args.foreground,
        ..LogConfig::default()
    });

    // Build identity — match a running daemon to its source revision. The
    // packaged app restores its own daemon, so dev work must confirm this SHA.
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        build = env!("ARCBOX_BUILD_SHA"),
        profile = ?profile,
        "arcbox-daemon starting"
    );

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime")
        .block_on(run(args));
    if let Err(ref e) = result {
        let error: &(dyn std::error::Error + Send + Sync + 'static) = e.as_ref();
        sentry::capture_error(error);
        tracing::error!("Daemon exited with error: {e:?}");
    }

    log_guard.flush();
    result
}

fn sentry_dsn() -> Option<String> {
    std::env::var("ARCBOX_DAEMON_SENTRY_DSN")
        .or_else(|_| std::env::var("SENTRY_DSN"))
        .ok()
}

fn sentry_environment() -> Option<String> {
    std::env::var("ARCBOX_DAEMON_SENTRY_ENVIRONMENT")
        .or_else(|_| std::env::var("SENTRY_ENVIRONMENT"))
        .ok()
}

async fn run(args: DaemonArgs) -> Result<()> {
    let setup_state = Arc::new(SetupState::new());

    let ready = match start(args, Arc::clone(&setup_state)).await {
        Ok(ready) => ready,
        Err(e) => {
            // Publish the failure on the setup stream before exiting so a
            // WatchSetupStatus client (desktop app, e2e harness) learns the
            // cause instead of seeing a bare disconnect. The brief grace
            // period lets already-connected streams flush the final event;
            // with no clients it only delays the error exit.
            setup_state.set_failed(&format!("{e:#}"));
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            return Err(e);
        }
    };

    shutdown::run(ready.ctx, ready.handles).await
}

async fn start(args: DaemonArgs, setup_state: Arc<SetupState>) -> Result<startup::ReadyDaemon> {
    startup::Startup::from_args(args, setup_state)
        .prepare_host()
        .await?
        .acquire_daemon_lease()
        .await?
        .start_control_plane()
        .await?
        .release_stale_resources()
        .await?
        .prepare_assets()
        .await?
        .boot_runtime()
        .await?
        .start_runtime_services()
        .await?
        .mark_ready()
        .await
}
