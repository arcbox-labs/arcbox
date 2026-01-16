//! Docker API server.

use crate::api::create_router;
use crate::error::Result;
use arcbox_core::Runtime;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
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
    pub fn new(config: ServerConfig, runtime: Arc<Runtime>) -> Self {
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

        let app = create_router(Arc::clone(&self.runtime)).layer(TraceLayer::new_for_http());

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| crate::error::DockerError::Server(e.to_string()))?;

            let tower_service = app.clone();

            tokio::spawn(async move {
                let hyper_service =
                    hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                        tower_service.clone().call(request)
                    });

                if let Err(err) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(stream), hyper_service)
                    .await
                {
                    // Ignore normal connection shutdown errors (client closed connection)
                    let err_str = err.to_string();
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
