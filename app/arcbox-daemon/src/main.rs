//! ArcBox daemon — orchestrates VM, networking, and API services.

mod context;
mod dns_service;
mod kubernetes_proxy;
mod recovery;
mod self_setup;
mod services;
mod shutdown;
mod startup;

use anyhow::Result;
use arcbox_logging::LogConfig;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "arcbox-daemon")]
#[command(author, version, about, long_about = None)]
pub struct DaemonArgs {
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

    let data_dir = startup::resolve_data_dir(args.data_dir.as_ref());
    let log_guard = arcbox_logging::init_with_sentry(LogConfig {
        log_dir: data_dir.join(arcbox_constants::paths::host::LOG),
        file_name: arcbox_constants::paths::host::DAEMON_LOG.to_string(),
        default_filter: "arcbox=info,arcbox_daemon=info".to_string(),
        foreground: args.foreground,
        ..LogConfig::default()
    });

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime")
        .block_on(startup::Startup::from_args(args).run());
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
