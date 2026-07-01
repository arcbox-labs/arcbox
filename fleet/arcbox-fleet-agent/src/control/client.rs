//! Unix-socket gRPC client helper for the `status`/`drain`/`resume`/
//! `disconnect` CLI subcommands, connecting to the running agent's
//! `agent.sock`. Mirrors `arcbox-cli`'s `UnixConnector`
//! (`app/arcbox-cli/src/commands/machine.rs`).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_client::FleetLifecycleServiceClient;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::codegen::{Service, http::Uri};
use tonic::transport::{Channel, Endpoint};

use crate::config::AgentConfig;

/// Connect to the running agent's control socket, at `config`'s configured
/// path (see [`AgentConfig::control_socket_path`]).
pub async fn connect_default(config: &AgentConfig) -> Result<FleetLifecycleServiceClient<Channel>> {
    connect(&config.control_socket_path()).await
}

/// Connect to `socket_path` and return a `FleetLifecycleService` client.
pub async fn connect(socket_path: &Path) -> Result<FleetLifecycleServiceClient<Channel>> {
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector::new(socket_path.to_path_buf()))
        .await
        .with_context(|| {
            format!(
                "failed to connect to fleet agent control socket at {}",
                socket_path.display()
            )
        })?;
    Ok(FleetLifecycleServiceClient::new(channel))
}

struct UnixConnector {
    socket_path: PathBuf,
}

impl UnixConnector {
    fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

impl Service<Uri> for UnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let socket_path = self.socket_path.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(socket_path).await?;
            Ok(TokioIo::new(stream))
        })
    }
}
