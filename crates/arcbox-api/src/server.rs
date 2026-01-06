//! API server implementation.

use crate::error::Result;
use arcbox_core::{Config, Runtime};
use arcbox_docker::{DockerApiServer, ServerConfig as DockerConfig};
use std::path::PathBuf;
use std::sync::Arc;

/// API server configuration.
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// gRPC listen address.
    pub grpc_addr: String,
    /// Docker API socket path.
    pub docker_socket: PathBuf,
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: "[::1]:50051".to_string(),
            docker_socket: PathBuf::from("/var/run/arcbox-docker.sock"),
        }
    }
}

/// ArcBox API server.
pub struct ApiServer {
    config: ApiServerConfig,
    runtime: Arc<Runtime>,
}

impl ApiServer {
    /// Creates a new API server.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime cannot be created.
    pub fn new(api_config: ApiServerConfig, core_config: Config) -> Result<Self> {
        let runtime = Arc::new(Runtime::new(core_config)?);
        Ok(Self {
            config: api_config,
            runtime,
        })
    }

    /// Returns the runtime.
    #[must_use]
    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    /// Runs the API server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start.
    pub async fn run(&self) -> Result<()> {
        // Initialize runtime
        self.runtime.init().await?;

        // Start Docker API server in background
        let docker_config = DockerConfig {
            socket_path: self.config.docker_socket.clone(),
        };
        let docker_server = DockerApiServer::new(docker_config, Arc::clone(&self.runtime));

        let docker_handle = tokio::spawn(async move {
            if let Err(e) = docker_server.run().await {
                tracing::error!("Docker API server error: {}", e);
            }
        });

        // TODO: Start gRPC server
        tracing::info!("ArcBox API server running");
        tracing::info!("  gRPC: {}", self.config.grpc_addr);
        tracing::info!(
            "  Docker API: {}",
            self.config.docker_socket.display()
        );

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        tracing::info!("Shutting down...");

        docker_handle.abort();
        self.runtime.shutdown().await?;

        Ok(())
    }
}
