use std::path::Path;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;

use vmm_core::VmmManager;

use crate::machine_svc::MachineServiceImpl;
use crate::proto::arcbox::{
    machine_service_server::MachineServiceServer,
    system_service_server::SystemServiceServer,
};
use crate::proto::vmm::vmm_service_server::VmmServiceServer;
use crate::system_svc::SystemServiceImpl;
use crate::vmm_svc::VmmServiceImpl;

/// Start the gRPC server.
///
/// Listens on `unix_socket` (required) and optionally on `tcp_addr` if non-empty.
pub async fn serve(
    manager: Arc<VmmManager>,
    unix_socket: &str,
    tcp_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let machine_svc = MachineServiceServer::new(MachineServiceImpl::new(Arc::clone(&manager)));
    let system_svc = SystemServiceServer::new(SystemServiceImpl::new(Arc::clone(&manager)));
    let vmm_svc = VmmServiceServer::new(VmmServiceImpl::new(Arc::clone(&manager)));

    // Ensure parent directory for the unix socket exists.
    if let Some(parent) = Path::new(unix_socket).parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove stale socket if present.
    if Path::new(unix_socket).exists() {
        std::fs::remove_file(unix_socket)?;
    }

    let uds_path = unix_socket.to_owned();
    let uds_server = {
        let machine_svc = machine_svc.clone();
        let system_svc = system_svc.clone();
        let vmm_svc = vmm_svc.clone();
        async move {
            info!(socket = %uds_path, "gRPC listening on Unix socket");
            let uds = tokio::net::UnixListener::bind(&uds_path)?;
            let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);
            Server::builder()
                .add_service(machine_svc)
                .add_service(system_svc)
                .add_service(vmm_svc)
                .serve_with_incoming(incoming)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        }
    };

    if tcp_addr.is_empty() {
        uds_server.await
    } else {
        let tcp_addr_str = tcp_addr.to_owned();
        let tcp_server = async move {
            let addr = tcp_addr_str
                .parse()
                .map_err(|e: std::net::AddrParseError| Box::new(e) as Box<dyn std::error::Error>)?;
            info!(addr = %tcp_addr_str, "gRPC also listening on TCP");
            Server::builder()
                .add_service(machine_svc)
                .add_service(system_svc)
                .add_service(vmm_svc)
                .serve(addr)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };
        tokio::try_join!(uds_server, tcp_server)?;
        Ok(())
    }
}
