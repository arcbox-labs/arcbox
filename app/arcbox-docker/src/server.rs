//! Docker API server.

use crate::api::{ProxyState, router_with_proxy, strip_api_version_prefix};
use crate::error::{DockerError, Result};
use crate::proxy::VsockConnector;
use arcbox_core::Runtime;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tower_http::trace::TraceLayer;

/// Docker API server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Unix socket path.
    pub socket_path: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
        }
    }
}

fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".arcbox")
        .join("docker.sock")
}

/// Docker API server.
pub struct DockerApiServer {
    config: ServerConfig,
    runtime: Arc<Runtime>,
}

impl DockerApiServer {
    /// Creates a new Docker API server.
    #[must_use]
    pub const fn new(config: ServerConfig, runtime: Arc<Runtime>) -> Self {
        Self { config, runtime }
    }

    /// Returns the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// Runs the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        // Remove existing socket
        let _ = std::fs::remove_file(&self.config.socket_path);

        // Create parent directory if needed
        if let Some(parent) = self.config.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.config.socket_path)
            .map_err(|e| crate::error::DockerError::Server(e.to_string()))?;

        tracing::info!(
            "Docker API server listening on {}",
            self.config.socket_path.display()
        );
        tracing::info!("Docker API backend: smart proxy to guest dockerd");

        self.run_native_http(listener, shutdown).await
    }
}

impl DockerApiServer {
    async fn run_native_http(
        &self,
        listener: UnixListener,
        shutdown: CancellationToken,
    ) -> Result<()> {
        let connector = Arc::new(VsockConnector::new(Arc::clone(&self.runtime)));
        let proxy = Arc::new(ProxyState::new(connector));

        // Drop the cached guest-dockerd readiness whenever the System VM
        // restarts (e.g. a backend switch) so the next Docker request
        // re-verifies against the fresh VM instead of failing once on a stale
        // connection and self-healing a request later.
        drop(tokio::spawn(watch_endpoint_invalidation(
            self.runtime.event_bus().subscribe(),
            self.runtime.default_machine_name().to_owned(),
            {
                let proxy = Arc::clone(&proxy);
                move || proxy.invalidate_endpoint()
            },
            shutdown.clone(),
        )));

        // Wrap the Axum Router with a MapRequestLayer that strips API version
        // prefixes *before* route matching. `Router::layer` runs after routing
        // and cannot be used for URI rewriting.
        let version_layer = tower::util::MapRequestLayer::new(strip_api_version_prefix);
        let app = version_layer.layer(
            router_with_proxy(Arc::clone(&self.runtime), proxy).layer(TraceLayer::new_for_http()),
        );

        let mut connections = JoinSet::new();

        loop {
            let stream = tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.map_err(|e| DockerError::Server(e.to_string()))?;
                    stream
                }
                () = shutdown.cancelled() => {
                    tracing::info!("Docker API server shutting down, waiting for {} in-flight connection(s)", connections.len());
                    break;
                }
            };

            let tower_service = app.clone();
            connections.spawn(async move {
                let hyper_service =
                    hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                        tower_service.clone().call(request)
                    });

                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), hyper_service)
                    .with_upgrades()
                    .await
                {
                    let err_str = err.to_string().to_lowercase();
                    if !err_str.contains("shutting down")
                        && !err_str.contains("connection reset")
                        && !err_str.contains("broken pipe")
                        && !err_str.contains("connection closed")
                        && !err_str.contains("incomplete")
                    {
                        tracing::error!("Error serving connection: {}", err);
                    }
                }
            });
        }

        // Drain in-flight connections before returning.
        while connections.join_next().await.is_some() {}

        Ok(())
    }
}

/// Drops the proxy's cached guest-dockerd readiness each time the System VM
/// stops.
///
/// A System VM restart (notably a backend switch) leaves the cached `_ping`
/// verification — and the pooled connections behind it — pointing at the old
/// VM. Reacting to `MachineStopped` makes the next Docker request re-verify
/// against the fresh VM, rather than the first request failing on a stale
/// connection and only the second one self-healing.
///
/// Only the System VM's own `MachineStopped` matters; user machines stop
/// independently of the Docker proxy endpoint.
async fn watch_endpoint_invalidation<F>(
    mut events: tokio::sync::broadcast::Receiver<arcbox_core::event::Event>,
    system_vm_name: String,
    invalidate: F,
    shutdown: CancellationToken,
) where
    F: Fn(),
{
    use arcbox_core::event::Event;
    use tokio::sync::broadcast::error::RecvError;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            event = events.recv() => match event {
                Ok(Event::MachineStopped { name }) if name == system_vm_name => invalidate(),
                Ok(_) => {}
                // Dropped events under load converge via the reactive
                // invalidate-on-transport-failure path in the proxy handlers.
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcbox_core::event::{Event, EventBus};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    async fn wait_for_hits(hits: &AtomicUsize, want: usize) -> bool {
        for _ in 0..200 {
            if hits.load(Ordering::Relaxed) == want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    #[tokio::test]
    async fn invalidates_only_when_system_vm_stops() {
        let bus = EventBus::new();
        let shutdown = CancellationToken::new();
        let hits = Arc::new(AtomicUsize::new(0));

        // Subscribe before publishing so no event is missed.
        let events = bus.subscribe();
        let task = tokio::spawn({
            let hits = Arc::clone(&hits);
            let shutdown = shutdown.clone();
            async move {
                watch_endpoint_invalidation(
                    events,
                    "default".to_owned(),
                    move || {
                        hits.fetch_add(1, Ordering::Relaxed);
                    },
                    shutdown,
                )
                .await;
            }
        });

        // A user machine stopping and unrelated System VM events are ignored.
        bus.publish(Event::MachineStopped {
            name: "user-vm".into(),
        });
        bus.publish(Event::MachineStarted {
            name: "default".into(),
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(hits.load(Ordering::Relaxed), 0);

        // The System VM stopping invalidates exactly once.
        bus.publish(Event::MachineStopped {
            name: "default".into(),
        });
        assert!(wait_for_hits(&hits, 1).await);

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("loop exits on shutdown")
            .expect("task panicked");
    }
}
