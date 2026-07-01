//! System VM control commands.

use anyhow::{Context, Result};
use arcbox_grpc::v1::system_service_client::SystemServiceClient;
use arcbox_protocol::v1::{Empty, SetSystemVmBackendRequest, SystemVmBackend};
use clap::{Subcommand, ValueEnum};
use tonic::Request;
use tonic::transport::{Channel, Endpoint};

use super::machine::UnixConnector;

#[derive(Debug, Subcommand)]
pub enum SystemCommands {
    /// Show or switch the System VM hypervisor backend (HV / VZ).
    ///
    /// With no argument, prints the current backend. With `hv` or `vz`,
    /// persists the choice and restarts the System VM so it takes effect —
    /// this stops running containers.
    Backend {
        /// Backend to switch to. Omit to print the current backend.
        #[arg(value_enum)]
        set: Option<BackendArg>,
    },
}

/// CLI spelling of [`SystemVmBackend`].
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BackendArg {
    /// Hypervisor.framework — ArcBox's custom VMM (amd64 via FEX).
    Hv,
    /// Virtualization.framework — Apple-managed execution (default).
    Vz,
}

impl From<BackendArg> for SystemVmBackend {
    fn from(arg: BackendArg) -> Self {
        match arg {
            BackendArg::Hv => Self::Hv,
            BackendArg::Vz => Self::Vz,
        }
    }
}

/// Human label for a wire backend value.
fn label(backend: SystemVmBackend) -> &'static str {
    match backend {
        SystemVmBackend::Hv => "hv (Hypervisor.framework + FEX)",
        SystemVmBackend::Vz => "vz (Virtualization.framework)",
        SystemVmBackend::Unspecified => "unspecified",
    }
}

async fn system_client() -> Result<SystemServiceClient<Channel>> {
    let socket_path = super::resolve_grpc_socket_path();
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(UnixConnector::new(socket_path.clone()))
        .await
        .with_context(|| {
            format!(
                "Failed to connect to ArcBox gRPC daemon at {}",
                socket_path.display()
            )
        })?;
    Ok(SystemServiceClient::new(channel))
}

pub async fn execute(cmd: SystemCommands) -> Result<()> {
    match cmd {
        SystemCommands::Backend { set } => {
            let mut client = system_client().await?;
            let info = if let Some(arg) = set {
                let backend = SystemVmBackend::from(arg);
                println!(
                    "Switching System VM backend to {} — restarting the System VM...",
                    label(backend)
                );
                client
                    .set_system_vm_backend(Request::new(SetSystemVmBackendRequest {
                        backend: backend as i32,
                    }))
                    .await
                    .context("failed to switch System VM backend")?
                    .into_inner()
            } else {
                client
                    .get_system_vm_backend(Request::new(Empty {}))
                    .await
                    .context("failed to query System VM backend")?
                    .into_inner()
            };
            let current =
                SystemVmBackend::try_from(info.backend).unwrap_or(SystemVmBackend::Unspecified);
            println!("System VM backend: {}", label(current));
            Ok(())
        }
    }
}
