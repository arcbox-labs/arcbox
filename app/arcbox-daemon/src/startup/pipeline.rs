//! Typed daemon startup pipeline.
//!
//! Each step consumes the previous state and returns the next one, so `main.rs`
//! can show the startup order directly while Rust types enforce it.

use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use arcbox_api::SetupPhase;
use arcbox_core::Runtime;
use macos_resolver::FileResolver;
use tracing::{info, warn};

use crate::context::{DaemonContext, EarlyContext, ServiceHandles, StartupHandles};
use crate::{DaemonArgs, recovery, services};

use super::{acquire_lock, assets, init_early, init_runtime, prepare_assets, wait_for_resources};

/// Entry point for the daemon startup lifecycle.
pub struct Startup {
    args: DaemonArgs,
    handles: StartupHandles,
}

pub struct ReadyDaemon {
    pub ctx: DaemonContext,
    pub handles: ServiceHandles,
}

impl Startup {
    /// Creates a startup pipeline from parsed daemon arguments.
    ///
    /// `handles` is created by the caller before the pipeline runs so a
    /// shutdown signal arriving mid-startup can reach the pipeline's
    /// published state (setup stream, cancellation token, runtime).
    pub fn from_args(args: DaemonArgs, handles: StartupHandles) -> Self {
        Self { args, handles }
    }

    /// Prepares host directories and pre-lock context.
    pub async fn prepare_host(self) -> Result<HostPrepared> {
        info!("Starting ArcBox daemon...");
        let early =
            record_startup_phase("prepare_host", init_early(self.args, self.handles)).await?;
        Ok(HostPrepared { early })
    }
}

pub struct HostPrepared {
    early: EarlyContext,
}

impl HostPrepared {
    /// Acquires the exclusive daemon lease.
    pub async fn acquire_daemon_lease(self) -> Result<DaemonLeased> {
        let ctx = record_startup_phase("acquire_daemon_lease", acquire_lock(self.early)).await?;
        Ok(DaemonLeased { ctx })
    }
}

pub struct DaemonLeased {
    ctx: DaemonContext,
}

impl DaemonLeased {
    /// Starts gRPC before slow runtime phases so clients can observe progress.
    pub async fn start_control_plane(self) -> Result<ControlPlaneStarted> {
        let shared_runtime = Arc::clone(&self.ctx.shared_runtime);
        let grpc = record_startup_phase(
            "start_control_plane",
            services::start_grpc(&self.ctx, shared_runtime),
        )
        .await?;
        Ok(ControlPlaneStarted {
            ctx: self.ctx,
            grpc,
        })
    }
}

pub struct ControlPlaneStarted {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
}

impl ControlPlaneStarted {
    /// Waits for stale resource holders from a previous daemon to release.
    pub async fn release_stale_resources(self) -> Result<ResourcesReleased> {
        record_startup_phase("release_stale_resources", wait_for_resources(&self.ctx)).await?;
        Ok(ResourcesReleased {
            ctx: self.ctx,
            grpc: self.grpc,
        })
    }
}

pub struct ResourcesReleased {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
}

impl ResourcesReleased {
    /// Reconciles bundle, downloaded, and staged assets for this app version.
    pub async fn prepare_assets(self) -> Result<AssetsPrepared> {
        let assets = record_startup_phase("prepare_assets", prepare_assets(&self.ctx)).await?;
        info!(agent = ?assets.agent(), "Startup assets prepared");
        Ok(AssetsPrepared {
            ctx: self.ctx,
            grpc: self.grpc,
            _assets: assets,
        })
    }
}

pub struct AssetsPrepared {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
    _assets: assets::PreparedAssets,
}

impl AssetsPrepared {
    /// Builds and initializes the ArcBox runtime.
    pub async fn boot_runtime(self) -> Result<RuntimeBooted> {
        let runtime = record_startup_phase("boot_runtime", init_runtime(&self.ctx)).await?;
        Ok(RuntimeBooted {
            ctx: self.ctx,
            grpc: self.grpc,
            runtime,
        })
    }
}

pub struct RuntimeBooted {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
    runtime: Arc<Runtime>,
}

impl RuntimeBooted {
    /// Starts services that require an initialized runtime.
    pub async fn start_runtime_services(self) -> Result<RuntimeServicesStarted> {
        let linux_vm = self.runtime.config().vm.autostart;
        let handles = record_startup_phase("start_runtime_services", async {
            let handles = services::start_services(&self.ctx, &self.runtime, self.grpc).await?;
            recovery::run(&self.ctx, &self.runtime, handles.dns_port).await?;
            if linux_vm {
                services::enable_docker_integration(&self.ctx);
            }
            crate::nfs_mount::spawn(&self.ctx, &self.runtime);
            Ok(handles)
        })
        .await?;
        // DNS and, with a Linux VM, Docker are bound before `start_services`
        // returns. An explicitly requested Kubernetes endpoint is also required;
        // the canonical best-effort 16443 listener may remain unavailable. An
        // explicitly requested DNS resolver is installed before this phase.
        self.ctx
            .setup_state
            .set_phase(SetupPhase::NetworkReady, "Network services ready");
        Ok(RuntimeServicesStarted {
            ctx: self.ctx,
            handles,
            linux_vm,
        })
    }
}

pub struct RuntimeServicesStarted {
    ctx: DaemonContext,
    handles: ServiceHandles,
    /// Whether the Linux VM (and its Docker/K8s services) is running.
    linux_vm: bool,
}

impl RuntimeServicesStarted {
    /// Marks startup complete and returns handles for the shutdown loop.
    pub async fn mark_ready(self) -> Result<ReadyDaemon> {
        record_startup_phase("mark_ready", async {
            check_resolver_installed(&self.ctx.dns_domain);
            self.ctx
                .setup_state
                .set_phase(SetupPhase::Ready, "Daemon ready");

            println!("ArcBox daemon started");
            if self.linux_vm {
                println!("  Docker API: {}", self.ctx.layout.docker_socket.display());
            }
            println!("  gRPC API:   {}", self.ctx.layout.grpc_socket.display());
            println!("  DNS:        127.0.0.1:{}", self.handles.dns_port);
            println!("  Data:       {}", self.ctx.layout.data_dir.display());
            println!();
            if self.linux_vm {
                println!("Use 'abctl docker enable' to configure Docker CLI integration.");
            } else {
                println!(
                    "Running as a VM host only (--no-linux-vm): Docker and Kubernetes are disabled."
                );
            }
            println!("Press Ctrl+C to stop.");

            Ok(())
        })
        .await?;

        Ok(ReadyDaemon {
            ctx: self.ctx,
            handles: self.handles,
        })
    }
}

fn check_resolver_installed(domain: &str) {
    let resolver = FileResolver::new("arcbox");
    if !resolver.is_registered(domain) {
        println!("Hint: Run 'sudo abctl dns install' to enable *.{domain} DNS resolution.");
    }
}

async fn record_startup_phase<T, F>(phase: &'static str, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let started = Instant::now();
    let result = future.await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match &result {
        Ok(_) => info!(startup_phase = phase, elapsed_ms, "Startup phase complete"),
        Err(error) => warn!(startup_phase = phase, elapsed_ms, %error, "Startup phase failed"),
    }

    result
}
