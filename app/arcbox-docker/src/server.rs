//! Docker API server.

use crate::api::create_router;
use crate::error::{DockerError, Result};
use arcbox_core::Runtime;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tower::Service;
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
    pub async fn run(&self) -> Result<()> {
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

        self.run_native_http(listener).await
    }
}

impl DockerApiServer {
    async fn run_native_http(&self, listener: UnixListener) -> Result<()> {
        let app = create_router(Arc::clone(&self.runtime)).layer(TraceLayer::new_for_http());

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| DockerError::Server(e.to_string()))?;

            let tower_service = app.clone();
            tokio::spawn(async move {
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
                    {
                        tracing::error!("Error serving connection: {}", err);
                    }
                }
            });
        }
    }
}
