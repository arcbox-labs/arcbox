//! Shows how to embed the sandbox gRPC services into a tonic server.
//!
//! This replaces the former `vmm-daemon` binary.  The caller (e.g. arcbox-vmm)
//! is expected to own the process lifecycle, signal handling, and tokio runtime.
//!
//! Run:
//!   cargo run --example serve -- --unix-socket /tmp/vmm-test.sock

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tonic::transport::Server;
use vmm_core::{SandboxManager, VmmConfig};
use vmm_grpc::proto::sandbox::{
    sandbox_service_server::SandboxServiceServer,
    sandbox_snapshot_service_server::SandboxSnapshotServiceServer,
};
use vmm_grpc::{SandboxServiceImpl, SandboxSnapshotServiceImpl};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "vmm_core=debug,vmm_grpc=debug,info".into()),
        )
        .init();

    // Parse a minimal --unix-socket argument for the example.
    let unix_socket = std::env::args()
        .skip_while(|a| a != "--unix-socket")
        .nth(1)
        .unwrap_or_else(|| "/run/firecracker-vmm/vmm.sock".to_string());

    // Build the manager from default config (or load from file in real usage).
    let config = VmmConfig::default();
    let manager = Arc::new(SandboxManager::new(config).context("init SandboxManager")?);

    // ── Wire up the two sandbox services ─────────────────────────────────────
    let sandbox_svc =
        SandboxServiceServer::new(SandboxServiceImpl::new(Arc::clone(&manager)));
    let snapshot_svc =
        SandboxSnapshotServiceServer::new(SandboxSnapshotServiceImpl::new(Arc::clone(&manager)));

    // ── Start a Unix-socket listener ─────────────────────────────────────────
    if let Some(parent) = Path::new(&unix_socket).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&unix_socket);

    tracing::info!(socket = %unix_socket, "gRPC server listening");

    let uds = tokio::net::UnixListener::bind(&unix_socket)?;
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);

    // ── In real usage: add other services here and handle shutdown ────────────
    //
    //   Server::builder()
    //       .add_service(sandbox_svc)
    //       .add_service(snapshot_svc)
    //       .add_service(your_other_service)
    //       .serve_with_incoming(incoming)
    //       .await?;
    //
    Server::builder()
        .add_service(sandbox_svc)
        .add_service(snapshot_svc)
        .serve_with_incoming(incoming)
        .await
        .context("gRPC server error")?;

    Ok(())
}
