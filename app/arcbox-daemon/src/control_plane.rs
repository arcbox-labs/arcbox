//! The daemon's control-plane socket: two RPC stacks, one endpoint.
//!
//! The sandbox API is served over Connect (CORE-53) while the rest of the
//! daemon's services stay on tonic. Both are `tower` services over HTTP, so
//! they compose into one axum router and share a single Unix socket: tonic
//! registers a route per service name, and anything it does not claim falls
//! through to the Connect handlers. A client therefore reaches every service
//! at the same address, and no path prefix has to be kept in sync by hand.
//!
//! Connections are served with hyper's protocol-detecting builder rather
//! than tonic's HTTP/2-only server, which is what makes the acceptance
//! criterion reachable: gRPC clients arrive over HTTP/2 while
//! `curl --unix-socket` posting JSON arrives over HTTP/1.1, and the same
//! handlers answer both.

use anyhow::{Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Accepts connections on `listener` until `shutdown` fires, serving `app`.
///
/// Returns once every in-flight connection has finished, so the socket is
/// free before the daemon drops its lock.
pub async fn serve(listener: UnixListener, app: axum::Router, shutdown: CancellationToken) {
    let graceful = GracefulShutdown::new();
    let builder = auto::Builder::new(TokioExecutor::new());

    loop {
        let stream = tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _addr)) => stream,
                Err(e) => {
                    // A single failed accept (EMFILE, a client that vanished
                    // between the SYN and the accept) must not take the
                    // control plane down with it.
                    debug!(error = %e, "control-plane accept failed");
                    continue;
                }
            },
        };

        let service = TowerToHyperService::new(app.clone());
        let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
        let conn = graceful.watch(conn.into_owned());
        drop(tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "control-plane connection ended");
            }
        }));
    }

    info!("control plane draining in-flight connections");
    graceful.shutdown().await;
}

/// Binds the control-plane Unix socket, replacing any stale one.
///
/// Each server owns its socket (remove-before-bind) rather than relying on
/// a central cleanup pass, so a crashed predecessor cannot block startup.
pub fn bind(socket_path: &std::path::Path) -> Result<UnixListener> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
    }
    UnixListener::bind(socket_path).context(format!(
        "Failed to bind gRPC socket: {}",
        socket_path.display()
    ))
}

/// Composes the tonic services and the Connect sandbox services into one
/// router.
///
/// `tonic` claims `/{service}/{method}` for each service registered on it;
/// the Connect router is the fallback, so it receives exactly the paths
/// tonic does not serve. Adding a service to either side needs no change
/// here.
pub fn compose(tonic_routes: tonic::service::Routes, connect: connectrpc::Router) -> axum::Router {
    tonic_routes
        // Lets axum flatten its route table once instead of per request.
        .prepare()
        .into_axum_router()
        .fallback_service(connect.into_axum_service())
}
