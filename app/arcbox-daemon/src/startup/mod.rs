//! Daemon startup: lock acquisition, config, runtime initialization.

mod assets;
mod cleanup;
mod lock;
mod pipeline;
mod resource_cleanup;

pub use assets::find_bundle_contents;
pub use lock::DaemonLock;
pub use pipeline::{ReadyDaemon, Startup};

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::SetupPhase;
use arcbox_constants::paths::{ArcboxProfile, HostLayout};
use arcbox_core::{Config, InitProgress, Runtime};
use macos_resolver::to_env_prefix;
use tracing::{info, warn};

use crate::DaemonArgs;
use crate::context::{DaemonContext, EarlyContext, StartupHandles, VmArgs};

const DNS_PREFIX: &str = "arcbox";
const DEFAULT_DNS_DOMAIN: &str = "arcbox.local";
/// Canonical host DNS port. Only the daemon serving this port owns the
/// `/etc/resolver/<domain>` entry (see `recovery::run`).
pub const DEFAULT_DNS_PORT: u16 = 5553;

/// Phase 1: directories, config, sockets. No runtime, no lock yet.
///
/// Returns an [`EarlyContext`] sufficient to start the gRPC
/// SystemService so clients can observe the full startup progression.
/// Call [`acquire_lock`] next to obtain a [`DaemonContext`].
async fn init_early(args: DaemonArgs, handles: StartupHandles) -> Result<EarlyContext> {
    let profile = args
        .profile
        .unwrap_or_else(ArcboxProfile::from_env_or_default);
    let mut layout = HostLayout::resolve_for_profile_from_env(profile, args.data_dir.as_deref());

    // CLI overrides for socket paths.
    if let Some(socket) = args.socket {
        layout.docker_socket = socket;
    }
    if let Some(grpc) = args.grpc_socket {
        layout.grpc_socket = grpc;
    }

    std::fs::create_dir_all(&layout.data_dir).context("Failed to create data directory")?;
    std::fs::create_dir_all(&layout.run_dir).context("Failed to create run directory")?;
    // The gRPC/Docker sockets live in run_dir and are the daemon's only access
    // control (a connected client gets full sandbox read/write/exec). Restrict
    // the directory to the owner so the posture doesn't depend on the umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&layout.run_dir, std::fs::Permissions::from_mode(0o700))
            .context("Failed to restrict run directory permissions")?;
    }
    std::fs::create_dir_all(&layout.log_dir).context("Failed to create log directory")?;
    std::fs::create_dir_all(&layout.data_subdir)
        .context("Failed to create persistent data directory")?;

    let dns_domain = dns_domain();
    let dns_port = dns_port();

    Ok(EarlyContext {
        profile,
        layout,
        shared_runtime: handles.shared_runtime,
        early_runtime: handles.early_runtime,
        setup_state: handles.setup_state,
        shutdown: handles.shutdown,
        daemon_lock_slot: handles.daemon_lock,
        dns_domain,
        dns_port,
        docker_integration: args.docker_integration,
        mount_nfs: !args.no_mount_nfs,
        vm_args: VmArgs {
            guest_docker_vsock_port: args.guest_docker_vsock_port,
            kernel: args.kernel,
            no_linux_vm: args.no_linux_vm,
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
    let lock = Arc::new(lock);
    // Publish a sibling clone into the pre-pipeline handles: a signal drops
    // this pipeline's context mid-flight, and the flock must outlive that
    // drop for as long as the interrupt path is still tearing down the VM.
    early
        .daemon_lock_slot
        .set(Arc::clone(&lock))
        .map_err(|_| anyhow::anyhow!("acquire_lock called twice"))?;
    Ok(DaemonContext {
        profile: early.profile,
        layout: early.layout,
        daemon_lock: lock,
        shared_runtime: early.shared_runtime,
        early_runtime: early.early_runtime,
        setup_state: early.setup_state,
        shutdown: early.shutdown,
        dns_domain: early.dns_domain,
        dns_port: early.dns_port,
        docker_integration: early.docker_integration,
        mount_nfs: early.mount_nfs,
        vm_args: early.vm_args,
    })
}

/// Wait for residual resource holders (e.g. docker.img) to release.
///
/// Must complete before [`init_runtime`] — on macOS, orphaned
/// Virtualization.framework XPC helpers of a just-displaced or crashed daemon
/// may still hold a previous daemon's disk images. Clean starts skip the
/// expensive scan unless persisted machine state shows the previous daemon was
/// interrupted while a VM was running. Reports the `CleaningUp` phase so gRPC
/// clients can show progress.
///
/// Scans every persistent dockerd image owned by a configured utility
/// VM role (native `docker.img`, rosetta `docker-rosetta.img`) so a
/// stale VZ holder on either side does not block daemon startup.
///
/// On non-macOS this is a no-op (no XPC helpers).
#[cfg(target_os = "macos")]
async fn wait_for_resources(ctx: &DaemonContext) -> Result<()> {
    // Remove a stale Docker socket from a previous session up front. It is
    // otherwise (re)bound only in start_runtime_services, so if a later phase
    // (e.g. VM boot) fails, a leftover socket makes clients hit "connection
    // refused" against a dead listener instead of seeing the daemon as
    // not-yet-ready. Mirrors the gRPC socket's early unlink-then-bind.
    let _ = std::fs::remove_file(&ctx.layout.docker_socket);

    let docker_imgs = resource_cleanup::disk_image_paths(&ctx.layout.data_subdir);
    let decision = resource_cleanup::decide(
        ctx.daemon_lock.displaced_stale_daemon(),
        resource_cleanup::has_interrupted_running_machine(&ctx.layout.data_dir),
        !docker_imgs.is_empty(),
    );

    let resource_cleanup::ResourceCleanupDecision::ScanDiskImageHolders { reason } = decision
    else {
        info!(
            decision = ?decision,
            "Skipping startup resource-holder cleanup"
        );
        return Ok(());
    };

    info!(
        reason = ?reason,
        image_count = docker_imgs.len(),
        "Scanning disk-image holders before runtime startup"
    );

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
/// can observe DOWNLOADING_ASSETS → ASSETS_READY progression, and
/// publishes VM_STARTING → VM_READY around the guest boot itself.
/// Returns the initialized runtime.
async fn init_runtime(ctx: &DaemonContext) -> Result<Arc<Runtime>> {
    let mut config = Config::load_for_profile(ctx.profile).unwrap_or_else(|err| {
        warn!(error = %err, "Failed to load config file; falling back to defaults");
        Config::for_profile(ctx.profile)
    });
    // The daemon's layout (sockets, lock file) was already resolved from
    // --profile/--data-dir/--socket, so it must win over config files.
    config.data_dir = ctx.layout.data_dir.clone();
    config.docker.socket_path = ctx.layout.docker_socket.clone();
    if let Some(port) = ctx.vm_args.guest_docker_vsock_port {
        config.container.guest_docker_vsock_port = port;
    }
    let selected_guest_docker_port = config.container.guest_docker_vsock_port;

    // The --kernel CLI flag wins over the config file; Runtime::new
    // propagates config.vm.* into the VM lifecycle config.
    if let Some(ref kernel) = ctx.vm_args.kernel {
        config.vm.kernel_path = Some(kernel.clone());
    }

    // --no-linux-vm wins over the config file, forcing VM-host-only mode.
    if ctx.vm_args.no_linux_vm {
        config.vm.autostart = false;
    }

    let runtime = Arc::new(Runtime::new(config).context("Failed to create runtime")?);
    // Publish the diagnostics handle before the VM boots: a stuck boot
    // must stay observable via GetVirtioDebug while `shared_runtime`
    // (the general RPC gate) is still empty.
    ctx.early_runtime
        .set(Arc::clone(&runtime))
        .map_err(|_| anyhow::anyhow!("init_runtime called twice"))?;
    // Armed before `init` for the same reason `early_runtime` is published
    // here: the VM reaches its ready state partway through the call below, so
    // a mirror started after it returns would report the VM down across the
    // whole window between the agent answering and dockerd coming up.
    crate::services::spawn_vm_running_mirror(ctx, &runtime);
    // The guest boot is the longest stretch of startup and the only one a
    // client cannot infer from anything else, so the runtime reports its
    // milestones from inside and they are published as they arrive.
    runtime
        .init(|milestone| match milestone {
            InitProgress::SystemVmStarting => ctx
                .setup_state
                .set_phase(SetupPhase::VmStarting, "Starting the Linux VM…"),
            InitProgress::SystemVmReady => ctx.setup_state.set_phase(
                SetupPhase::VmReady,
                "Linux VM ready; waiting for the container runtime…",
            ),
        })
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
pub fn resolve_data_dir(profile: ArcboxProfile, data_dir: Option<&PathBuf>) -> PathBuf {
    HostLayout::resolve_for_profile_from_env(profile, data_dir.map(PathBuf::as_path)).data_dir
}

fn dns_port() -> u16 {
    let key = format!("{}_DNS_PORT", to_env_prefix(DNS_PREFIX));
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_DNS_PORT)
}

fn dns_domain() -> String {
    let key = format!("{}_DNS_DOMAIN", to_env_prefix(DNS_PREFIX));
    std::env::var(key).unwrap_or_else(|_| DEFAULT_DNS_DOMAIN.to_string())
}
