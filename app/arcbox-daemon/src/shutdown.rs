//! Graceful shutdown: signal handling, connection drain, cleanup.
//!
//! First signal triggers graceful shutdown with visible feedback.
//! Second signal force-quits: skips the VM graceful stop but still runs
//! full cleanup (port forwarding, network manager, routes, sockets).
//!
//! Signals arriving before startup completes are handled by
//! [`interrupt_startup`] — `main::run` keeps a signal watcher armed for
//! the whole startup window so a mid-boot SIGTERM cannot fall through to
//! the default disposition and orphan the VM.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arcbox_docker::DockerContextManager;
use tokio::signal;
use tracing::{info, warn};

use crate::context::{DaemonContext, ServiceHandles, StartupHandles};

const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a startup interrupt waits for a graceful runtime stop before
/// force-killing the VM. A boot in flight parks graceful `Stop` behind
/// itself in the VM lifecycle actor, so an unbounded wait could last the
/// whole boot timeout — longer than launchd's own SIGKILL patience.
const STARTUP_ABORT_GRACE: Duration = Duration::from_secs(10);

/// Waits for a shutdown signal, drains services, and cleans up.
pub async fn run(ctx: DaemonContext, mut handles: ServiceHandles) -> Result<()> {
    wait_for_signal().await;
    println!("Shutting down guest VM... (press Ctrl+C again to force quit)");
    info!("Shutdown signal received, draining connections...");
    ctx.shutdown.cancel();

    drain(&mut handles).await;

    // runtime.shutdown() calls graceful_stop() which sends a vsock shutdown
    // RPC and blocks waiting for the VM to stop. It must run in a separate
    // task — otherwise select! can't poll the signal branch while the
    // blocking call holds the current task.
    let forced = if let Some(runtime) = ctx.shared_runtime.get() {
        let runtime = runtime.clone();
        let shutdown_task = tokio::spawn(async move { runtime.shutdown().await });

        tokio::select! {
            result = shutdown_task => {
                match result {
                    Ok(Err(e)) => warn!("Runtime shutdown error: {e}"),
                    Err(e) => warn!("Runtime shutdown task panicked: {e}"),
                    _ => {}
                }
                false
            }
            () = wait_for_signal() => {
                println!("Force shutting down...");
                warn!("Second signal received, forcing shutdown");
                true
            }
        }
    } else {
        false
    };

    // Force path: shutdown_force does everything except the graceful VM
    // stop (port forwarding, force VM kill, other machines, network manager).
    if forced {
        if let Some(runtime) = ctx.shared_runtime.get() {
            let _ = runtime.shutdown_force().await;
        }
    }

    cleanup(&ctx).await;
    info!("ArcBox daemon stopped");

    if forced {
        // The spawned graceful shutdown task may still be blocked waiting
        // for the VM to stop (no locks held, but still occupies a tokio
        // worker thread). process::exit avoids hanging in runtime drop.
        std::process::exit(0);
    }

    Ok(())
}

async fn cleanup(ctx: &DaemonContext) {
    #[cfg(target_os = "macos")]
    {
        arcbox_core::route_reconciler::remove_route().await;
    }

    if ctx.docker_integration {
        if let Ok(ctx_manager) = DockerContextManager::new(ctx.layout.docker_socket.clone()) {
            let _ = ctx_manager.disable();
        }
    }

    crate::nfs_mount::cleanup(ctx);

    remove_sockets(ctx);
}

fn remove_sockets(ctx: &DaemonContext) {
    for path in [&ctx.layout.docker_socket, &ctx.layout.grpc_socket] {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Failed to remove socket {}: {}", path.display(), e);
            }
        }
    }

    // daemon.lock is deliberately kept on disk — the flock is released
    // automatically when the process exits, and the next daemon reuses the
    // file. Removing it would race with a concurrent startup.
}

/// Tears down a daemon whose startup was interrupted by a signal.
///
/// The startup future has been dropped at an await point, but a VM that
/// began booting lives on in its lifecycle tasks — reach it through the
/// pre-pipeline [`StartupHandles`] and stop it so no orphaned VM or
/// Virtualization.framework helper keeps holding disk images.
///
/// Mirrors [`run`]'s two-signal contract: the graceful stop is bounded by
/// [`STARTUP_ABORT_GRACE`] (or cut short by a second signal), then the VM
/// is force-killed.
pub async fn interrupt_startup(handles: &StartupHandles) -> Result<()> {
    println!("Shutting down... (press Ctrl+C again to force quit)");
    info!("Shutdown signal received during startup, aborting");

    // Publish the cause on the setup stream, then give already-connected
    // WatchSetupStatus clients a moment to flush before the gRPC server
    // (which observes the cancellation token) shuts down.
    handles
        .setup_state
        .set_failed("startup interrupted by shutdown signal");
    tokio::time::sleep(Duration::from_millis(200)).await;
    handles.shutdown.cancel();

    // `early_runtime` is filled before the VM boots, so it covers every
    // window in which a VM can exist; empty means nothing to tear down.
    let Some(runtime) = handles.early_runtime.get() else {
        info!("ArcBox daemon stopped");
        return Ok(());
    };
    let runtime = Arc::clone(runtime);

    let graceful = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        async move { runtime.shutdown().await }
    });

    let forced = tokio::select! {
        result = tokio::time::timeout(STARTUP_ABORT_GRACE, graceful) => match result {
            Ok(Ok(Err(e))) => {
                warn!("Runtime shutdown error during startup abort: {e}");
                false
            }
            Ok(Err(e)) => {
                warn!("Runtime shutdown task panicked during startup abort: {e}");
                true
            }
            Err(_) => {
                warn!(
                    "Graceful stop did not finish within {}s during startup abort, forcing",
                    STARTUP_ABORT_GRACE.as_secs()
                );
                true
            }
            Ok(Ok(Ok(()))) => false,
        },
        () = wait_for_signal() => {
            println!("Force shutting down...");
            warn!("Second signal received during startup abort, forcing shutdown");
            true
        }
    };

    if forced {
        let _ = runtime.shutdown_force().await;
    }

    info!("ArcBox daemon stopped");

    if forced {
        // The abandoned graceful-stop task may still be blocked waiting for
        // the VM (it occupies a worker thread); exit directly rather than
        // hanging in runtime drop, mirroring the force path of `run`.
        std::process::exit(0);
    }

    Ok(())
}

pub async fn wait_for_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

async fn drain(handles: &mut ServiceHandles) {
    if tokio::time::timeout(DRAIN_TIMEOUT, async {
        let _ = tokio::join!(&mut handles.dns, &mut handles.grpc);
        if let Some(h) = handles.docker.as_mut() {
            let _ = h.await;
        }
        if let Some(h) = handles.kubernetes_proxy.as_mut() {
            let _ = h.await;
        }
    })
    .await
    .is_err()
    {
        warn!(
            "Server drain timed out after {}s, aborting remaining tasks",
            DRAIN_TIMEOUT.as_secs()
        );
        handles.dns.abort();
        handles.grpc.abort();
        if let Some(h) = handles.docker.as_mut() {
            h.abort();
        }
        if let Some(h) = handles.kubernetes_proxy.as_mut() {
            h.abort();
        }
    }
}
