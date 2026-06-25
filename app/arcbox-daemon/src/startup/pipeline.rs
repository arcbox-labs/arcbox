//! Typed daemon startup pipeline.
//!
//! Each step consumes the previous state and returns the next one, so the
//! load-bearing startup order is represented by Rust types instead of comments
//! in `main.rs`.

use std::sync::Arc;

use anyhow::Result;
use arcbox_api::SetupPhase;
use arcbox_core::Runtime;
use macos_resolver::FileResolver;
use tracing::info;

use crate::context::{DaemonContext, EarlyContext, ServiceHandles};
use crate::{DaemonArgs, recovery, services, shutdown};

use super::{acquire_lock, assets, init_early, init_runtime, prepare_assets, wait_for_resources};

/// Entry point for the daemon startup lifecycle.
pub struct Startup {
    args: DaemonArgs,
}

struct ReadyDaemon {
    ctx: DaemonContext,
    handles: ServiceHandles,
}

impl Startup {
    /// Creates a startup pipeline from parsed daemon arguments.
    pub fn from_args(args: DaemonArgs) -> Self {
        Self { args }
    }

    async fn run_until_ready(self) -> Result<ReadyDaemon> {
        self.prepare_host()
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

    /// Runs startup and then enters the shutdown loop.
    pub async fn run(self) -> Result<()> {
        let ready = self.run_until_ready().await?;
        shutdown::run(ready.ctx, ready.handles).await
    }

    async fn prepare_host(self) -> Result<HostPrepared> {
        info!("Starting ArcBox daemon...");
        let early = init_early(self.args).await?;
        Ok(HostPrepared { early })
    }
}

struct HostPrepared {
    early: EarlyContext,
}

impl HostPrepared {
    async fn acquire_daemon_lease(self) -> Result<DaemonLeased> {
        let ctx = acquire_lock(self.early).await?;
        Ok(DaemonLeased { ctx })
    }
}

struct DaemonLeased {
    ctx: DaemonContext,
}

impl DaemonLeased {
    async fn start_control_plane(self) -> Result<ControlPlaneStarted> {
        let shared_runtime = Arc::clone(&self.ctx.shared_runtime);
        let grpc = services::start_grpc(&self.ctx, shared_runtime).await?;
        Ok(ControlPlaneStarted {
            ctx: self.ctx,
            grpc,
        })
    }
}

struct ControlPlaneStarted {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
}

impl ControlPlaneStarted {
    async fn release_stale_resources(self) -> Result<ResourcesReleased> {
        wait_for_resources(&self.ctx).await?;
        Ok(ResourcesReleased {
            ctx: self.ctx,
            grpc: self.grpc,
        })
    }
}

struct ResourcesReleased {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
}

impl ResourcesReleased {
    async fn prepare_assets(self) -> Result<AssetsPrepared> {
        let assets = prepare_assets(&self.ctx).await?;
        info!(agent = ?assets.agent(), "Startup assets prepared");
        Ok(AssetsPrepared {
            ctx: self.ctx,
            grpc: self.grpc,
            _assets: assets,
        })
    }
}

struct AssetsPrepared {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
    _assets: assets::PreparedAssets,
}

impl AssetsPrepared {
    async fn boot_runtime(self) -> Result<RuntimeBooted> {
        let runtime = init_runtime(&self.ctx).await?;
        Ok(RuntimeBooted {
            ctx: self.ctx,
            grpc: self.grpc,
            runtime,
        })
    }
}

struct RuntimeBooted {
    ctx: DaemonContext,
    grpc: tokio::task::JoinHandle<()>,
    runtime: Arc<Runtime>,
}

impl RuntimeBooted {
    async fn start_runtime_services(self) -> Result<RuntimeServicesStarted> {
        let handles = services::start_services(&self.ctx, &self.runtime, self.grpc).await?;
        recovery::run(&self.ctx, &self.runtime).await;
        Ok(RuntimeServicesStarted {
            ctx: self.ctx,
            handles,
        })
    }
}

struct RuntimeServicesStarted {
    ctx: DaemonContext,
    handles: ServiceHandles,
}

impl RuntimeServicesStarted {
    async fn mark_ready(self) -> Result<ReadyDaemon> {
        check_resolver_installed(&self.ctx.dns_domain);
        self.ctx
            .setup_state
            .set_phase(SetupPhase::Ready, "Daemon ready");

        println!("ArcBox daemon started");
        println!("  Docker API: {}", self.ctx.layout.docker_socket.display());
        println!("  gRPC API:   {}", self.ctx.layout.grpc_socket.display());
        println!("  DNS:        127.0.0.1:{}", self.ctx.dns_port);
        println!("  Data:       {}", self.ctx.layout.data_dir.display());
        println!();
        println!("Use 'arcbox docker enable' to configure Docker CLI integration.");
        println!("Press Ctrl+C to stop.");

        Ok(ReadyDaemon {
            ctx: self.ctx,
            handles: self.handles,
        })
    }
}

fn check_resolver_installed(domain: &str) {
    let resolver = FileResolver::new("arcbox");
    if !resolver.is_registered(domain) {
        println!("Hint: Run 'sudo arcbox dns install' to enable *.{domain} DNS resolution.");
    }
}
