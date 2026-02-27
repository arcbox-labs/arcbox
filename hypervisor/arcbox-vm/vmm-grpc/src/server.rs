use std::path::Path;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;

use vmm_core::SandboxManager;

use crate::proto::sandbox::{
    sandbox_service_server::SandboxServiceServer,
    sandbox_snapshot_service_server::SandboxSnapshotServiceServer,
};
use crate::sandbox_svc::{SandboxServiceImpl, SandboxSnapshotServiceImpl};

/// Start the gRPC server.
///
/// Listens on `unix_socket` (required) and optionally on `tcp_addr` if
/// non-empty.
pub async fn serve(
    manager: Arc<SandboxManager>,
    unix_socket: &str,
    tcp_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sandbox_svc = SandboxServiceServer::new(SandboxServiceImpl::new(Arc::clone(&manager)));
    let snapshot_svc =
        SandboxSnapshotServiceServer::new(SandboxSnapshotServiceImpl::new(Arc::clone(&manager)));

    // Ensure the parent directory for the Unix socket exists.
    if let Some(parent) = Path::new(unix_socket).parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove a stale socket file if present.
    if Path::new(unix_socket).exists() {
        std::fs::remove_file(unix_socket)?;
    }

    let uds_path = unix_socket.to_owned();
    let uds_server = {
        let sandbox_svc = sandbox_svc.clone();
        let snapshot_svc = snapshot_svc.clone();
        async move {
            info!(socket = %uds_path, "gRPC listening on Unix socket");
            let uds = tokio::net::UnixListener::bind(&uds_path)?;
            let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);
            Server::builder()
                .add_service(sandbox_svc)
                .add_service(snapshot_svc)
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
                .add_service(sandbox_svc)
                .add_service(snapshot_svc)
                .serve(addr)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        };
        tokio::try_join!(uds_server, tcp_server)?;
        Ok(())
    }
}
