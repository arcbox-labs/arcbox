//! Daemon startup: lock acquisition, config, runtime initialization.

mod assets;
mod cleanup;
mod lock;
mod pipeline;

pub use assets::find_bundle_contents;
pub use lock::DaemonLock;
pub use pipeline::Startup;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::{SetupPhase, SetupState};
use arcbox_constants::paths::HostLayout;
use arcbox_core::{Config, Runtime};
use macos_resolver::to_env_prefix;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::DaemonArgs;
use crate::context::{DaemonContext, EarlyContext, VmArgs};

const DNS_PREFIX: &str = "arcbox";
const DEFAULT_DNS_DOMAIN: &str = "arcbox.local";

/// Phase 1: directories, config, sockets. No runtime, no lock yet.
///
/// Returns an [`EarlyContext`] sufficient to start the gRPC
/// SystemService so clients can observe the full startup progression.
/// Call [`acquire_lock`] next to obtain a [`DaemonContext`].
async fn init_early(args: DaemonArgs) -> Result<EarlyContext> {
    let setup_state = Arc::new(SetupState::new());

    let mut layout = HostLayout::resolve(args.data_dir.as_deref());

    // CLI overrides for socket paths.
    if let Some(socket) = args.socket {
        layout.docker_socket = socket;
    }
    if let Some(grpc) = args.grpc_socket {
        layout.grpc_socket = grpc;
    }

    std::fs::create_dir_all(&layout.data_dir).context("Failed to create data directory")?;
    std::fs::create_dir_all(&layout.run_dir).context("Failed to create run directory")?;
    std::fs::create_dir_all(&layout.log_dir).context("Failed to create log directory")?;
    std::fs::create_dir_all(&layout.data_subdir)
        .context("Failed to create persistent data directory")?;

    let dns_domain = dns_domain();
    let dns_port = dns_port();

    Ok(EarlyContext {
        layout,
        shared_runtime: Arc::new(std::sync::OnceLock::new()),
        setup_state,
        shutdown: CancellationToken::new(),
        dns_domain,
        dns_port,
        docker_integration: args.docker_integration,
        vm_args: VmArgs {
            guest_docker_vsock_port: args.guest_docker_vsock_port,
            kernel: args.kernel,
        },
    })
}

/// Acquire the daemon lock, consuming the [`EarlyContext`].
///
/// Fast when no stale daemon exists. If a stale daemon holds the lock,
/// sends SIGTERM (with 30 s grace period and SIGKILL fallback), then
/// blocks on `flock(LOCK_EX)` until the lock is released. Must run
/// before `start_grpc` because the old daemon may still be listening
/// on the same socket paths.
async fn acquire_lock(early: EarlyContext) -> Result<DaemonContext> {
    let lock_file = early.layout.lock_file.clone();
    let lock = tokio::task::spawn_blocking(move || DaemonLock::acquire(&lock_file))
        .await
        .context("lock task panicked")?
        .context("failed to acquire daemon lock")?;
    Ok(DaemonContext {
        layout: early.layout,
        daemon_lock: lock,
        shared_runtime: early.shared_runtime,
        setup_state: early.setup_state,
        shutdown: early.shutdown,
        dns_domain: early.dns_domain,
        dns_port: early.dns_port,
        docker_integration: early.docker_integration,
        vm_args: early.vm_args,
    })
}

/// Wait for residual resource holders (e.g. docker.img) to release.
///
/// Must complete before [`init_runtime`] — on macOS, orphaned
/// Virtualization.framework XPC helpers of a just-displaced daemon may
/// still hold a previous daemon's disk images. Only runs when lock
/// acquisition actually displaced a stale daemon; clean starts skip the
/// (expensive) scan. Reports the `CleaningUp` phase so gRPC clients can
/// show progress.
///
/// Scans every persistent dockerd image owned by a configured utility
/// VM role (native `docker.img`, rosetta `docker-rosetta.img`) so a
/// stale VZ holder on either side does not block daemon startup.
///
/// On non-macOS this is a no-op (no XPC helpers).
#[cfg(target_os = "macos")]
async fn wait_for_resources(ctx: &DaemonContext) -> Result<()> {
    let candidates = ["docker.img", "docker-rosetta.img"];
    let docker_imgs: Vec<std::path::PathBuf> = candidates
        .iter()
        .map(|name| ctx.layout.data_subdir.join(name))
        .filter(|path| path.exists())
        .collect();

    if docker_imgs.is_empty() {
        return Ok(());
    }

    // Residual holders only exist when an old daemon was displaced during
    // lock acquisition (its XPC helpers may outlive the flock release).
    // On a clean start, skip the scan: `pids_by_path` walks every
    // process's fd table and costs ~100ms. A crashed daemon's helpers can
    // in principle linger past the kernel's flock release, but the scan
    // was always best-effort (10s cap, then proceed with a warning) and
    // VM start reports its own error if the image is still held.
    if !ctx.daemon_lock.displaced_stale_daemon() {
        return Ok(());
    }

    ctx.setup_state
        .set_phase(SetupPhase::CleaningUp, "Waiting for resource release…");

    tokio::task::spawn_blocking(move || {
        for path in docker_imgs {
            cleanup::wait_for_docker_img_holders(&path);
        }
    })
    .await
    .context("resource wait task panicked")?;

    ctx.setup_state.set_phase(
        SetupPhase::Initializing,
        "Finished waiting for resource release (see logs for details)",
    );
    Ok(())
}

/// No-op on non-macOS — no Virtualization.framework XPC helpers.
#[cfg(not(target_os = "macos"))]
async fn wait_for_resources(_ctx: &DaemonContext) -> Result<()> {
    Ok(())
}

/// Reconciles bundle, downloaded, and staged assets for this startup.
///
/// Called after gRPC is already listening so clients can observe download
/// progress and before [`init_runtime`] so the runtime sees coherent artifacts
/// for the launched app version.
async fn prepare_assets(ctx: &DaemonContext) -> Result<assets::PreparedAssets> {
    let prepared = assets::prepare(&ctx.layout.data_dir, &ctx.setup_state).await?;
    ctx.setup_state
        .set_phase(SetupPhase::AssetsReady, "Boot assets ready");
    Ok(prepared)
}

/// Phase 2: seed/download boot assets, build runtime, start VM.
///
/// Called after gRPC SystemService is already listening so clients
/// can observe DOWNLOADING_ASSETS → ASSETS_READY progression.
/// Returns the initialized runtime.
async fn init_runtime(ctx: &DaemonContext) -> Result<Arc<Runtime>> {
    let mut config = Config::load().unwrap_or_else(|err| {
        warn!(error = %err, "Failed to load config file; falling back to defaults");
        Config::default()
    });
    // The daemon's layout (sockets, lock file) was already resolved from
    // --data-dir, so it must win over any data_dir in the config file.
    config.data_dir = ctx.layout.data_dir.clone();
    if let Some(port) = ctx.vm_args.guest_docker_vsock_port {
        config.container.guest_docker_vsock_port = port;
    }
    let selected_guest_docker_port = config.container.guest_docker_vsock_port;

    // The --kernel CLI flag wins over the config file; Runtime::new
    // propagates config.vm.* into the VM lifecycle config.
    if let Some(ref kernel) = ctx.vm_args.kernel {
        config.vm.kernel_path = Some(kernel.clone());
    }

    let runtime = Arc::new(Runtime::new(config).context("Failed to create runtime")?);
    runtime
        .init()
        .await
        .context("Failed to initialize runtime")?;
    info!(
        data_dir = %ctx.layout.data_dir.display(),
        guest_docker_vsock_port = selected_guest_docker_port,
        "Runtime initialized"
    );

    if ctx.dns_domain != DEFAULT_DNS_DOMAIN {
        runtime.network_manager().set_dns_domain(&ctx.dns_domain);
    }

    ctx.shared_runtime
        .set(Arc::clone(&runtime))
        .map_err(|_| anyhow::anyhow!("init_runtime called twice"))?;
    Ok(runtime)
}

/// Resolve the data directory from an optional override.
///
/// Re-exported for use by `main.rs` (logging setup runs before
/// `init_early`, so it needs the path independently).
pub fn resolve_data_dir(data_dir: Option<&PathBuf>) -> PathBuf {
    HostLayout::resolve(data_dir.map(PathBuf::as_path)).data_dir
}

fn dns_port() -> u16 {
    let key = format!("{}_DNS_PORT", to_env_prefix(DNS_PREFIX));
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5553)
}

fn dns_domain() -> String {
    let key = format!("{}_DNS_DOMAIN", to_env_prefix(DNS_PREFIX));
    std::env::var(key).unwrap_or_else(|_| DEFAULT_DNS_DOMAIN.to_string())
}
