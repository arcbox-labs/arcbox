//! API server implementation.

use crate::error::Result;
use crate::generated::{
    container_service_server::ContainerServiceServer,
    image_service_server::ImageServiceServer,
    machine_service_server::MachineServiceServer,
    network_service_server::NetworkServiceServer,
    system_service_server::SystemServiceServer,
};
use crate::grpc::{ContainerServiceImpl, ImageServiceImpl, MachineServiceImpl, NetworkServiceImpl, SystemServiceImpl};
use arcbox_core::{Config, Runtime};
use arcbox_docker::{DockerApiServer, ServerConfig as DockerConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tonic::transport::Server;

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

        // Create gRPC services
        let container_service = ContainerServiceImpl::new(Arc::clone(&self.runtime));
        let machine_service = MachineServiceImpl::new(Arc::clone(&self.runtime));
        let image_service = ImageServiceImpl::new(Arc::clone(&self.runtime));
        let network_service = NetworkServiceImpl::new(Arc::clone(&self.runtime));
        let system_service = SystemServiceImpl::new(Arc::clone(&self.runtime));

        // Parse gRPC address
        let grpc_addr = self
            .config
            .grpc_addr
            .parse()
            .map_err(|e| crate::error::ApiError::Config(format!("invalid gRPC address: {}", e)))?;

        tracing::info!("ArcBox API server starting");
        tracing::info!("  gRPC: {}", self.config.grpc_addr);
        tracing::info!(
            "  Docker API: {}",
            self.config.docker_socket.display()
        );

        // Build gRPC server
        let grpc_server = Server::builder()
            .add_service(ContainerServiceServer::new(container_service))
            .add_service(MachineServiceServer::new(machine_service))
            .add_service(ImageServiceServer::new(image_service))
            .add_service(NetworkServiceServer::new(network_service))
            .add_service(SystemServiceServer::new(system_service))
            .serve_with_shutdown(grpc_addr, async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for ctrl-c");
                tracing::info!("Received shutdown signal");
            });

        tracing::info!("ArcBox API server running");

        // Run gRPC server
        grpc_server.await.map_err(|e| {
            crate::error::ApiError::Transport(format!("gRPC server error: {}", e))
        })?;

        tracing::info!("Shutting down...");

        docker_handle.abort();
        self.runtime.shutdown().await?;

        Ok(())
    }
}
