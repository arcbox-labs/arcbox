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
use arcbox_api::SetupPhase;
use arcbox_logging::LogConfig;
use clap::Parser;
use macos_resolver::FileResolver;
use tracing::info;

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
        .or_else(|| option_env!("ARCBOX_DAEMON_SENTRY_DSN").map(str::to_owned))
        .or_else(|| option_env!("SENTRY_DSN").map(str::to_owned))
}

fn sentry_environment() -> Option<String> {
    std::env::var("ARCBOX_DAEMON_SENTRY_ENVIRONMENT")
        .or_else(|_| std::env::var("SENTRY_ENVIRONMENT"))
        .ok()
        .or_else(|| option_env!("ARCBOX_DAEMON_SENTRY_ENVIRONMENT").map(str::to_owned))
        .or_else(|| option_env!("SENTRY_ENVIRONMENT").map(str::to_owned))
}

async fn run(args: DaemonArgs) -> Result<()> {
    info!("Starting ArcBox daemon...");

    // Phase 1: directories, config, sockets — no runtime yet.
    let early = startup::init_early(args).await?;

    // Acquire exclusive daemon lock. Terminates any stale daemon that
    // still holds the lock (up to ~30 s SIGTERM wait). Must complete
    // before start_grpc because the old daemon may be listening on the
    // same socket paths. Consumes EarlyContext, producing a
    // DaemonContext with a guaranteed lock.
    let ctx = startup::acquire_lock(early).await?;

    // Start gRPC with all services. Machine/Sandbox return UNAVAILABLE
    // until runtime is ready. SystemService works immediately so clients
    // can observe the full startup progression (CLEANING_UP →
    // INITIALIZING → DOWNLOADING_ASSETS → ASSETS_READY → …).
    let shared_runtime = ctx.shared_runtime.clone();
    let grpc = services::start_grpc(&ctx, shared_runtime).await?;

    // Wait for residual resource holders (e.g. orphaned
    // Virtualization.framework XPC helpers holding docker.img).
    // Visible to gRPC clients as the CLEANING_UP phase.
    startup::wait_for_resources(&ctx).await?;

    // Phase 2: seed/download boot assets, build runtime, start VM.
    // Progress is visible to gRPC clients via WatchSetupStatus.
    let runtime = startup::init_runtime(&ctx).await?;

    // Phase 3: start remaining services that require the runtime.
    let handles = services::start_services(&ctx, &runtime, grpc).await?;
    recovery::run(&ctx, &runtime).await;

    check_resolver_installed(&ctx.dns_domain);
    ctx.setup_state.set_phase(SetupPhase::Ready, "Daemon ready");

    println!("ArcBox daemon started");
    println!("  Docker API: {}", ctx.layout.docker_socket.display());
    println!("  gRPC API:   {}", ctx.layout.grpc_socket.display());
    println!("  DNS:        127.0.0.1:{}", ctx.dns_port);
    println!("  Data:       {}", ctx.layout.data_dir.display());
    println!();
    println!("Use 'arcbox docker enable' to configure Docker CLI integration.");
    println!("Press Ctrl+C to stop.");

    shutdown::run(ctx, handles).await
}

fn check_resolver_installed(domain: &str) {
    let resolver = FileResolver::new("arcbox");
    if !resolver.is_registered(domain) {
        println!("Hint: Run 'sudo arcbox dns install' to enable *.{domain} DNS resolution.");
    }
}
