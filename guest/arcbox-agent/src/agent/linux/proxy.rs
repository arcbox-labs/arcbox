//! Guest-side vsock proxies that bridge host traffic to local Unix / TCP
//! sockets:
//!
//! - **Docker API**: vsock listener → `/var/run/docker.sock` (Unix).
//! - **Kubernetes API**: vsock listener → `127.0.0.1:KUBERNETES_API_GUEST_PORT`
//!   (TCP, k3s API server bound to localhost).

use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result};
use tokio::net::{TcpStream, UnixStream};
use tokio_vsock::VsockStream;

use arcbox_constants::paths::DOCKER_API_UNIX_SOCKET;
use arcbox_constants::ports::KUBERNETES_API_GUEST_PORT;

use super::cmdline::{docker_api_vsock_port, kubernetes_api_vsock_port};
use super::vsock::bind_vsock_listener_with_retry;

pub(super) async fn run_docker_api_proxy() -> Result<()> {
    let port = docker_api_vsock_port();
    let mut listener = bind_vsock_listener_with_retry(port, "docker api proxy").await?;
    tracing::info!("Docker API proxy listening on vsock port {}", port);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                tracing::info!("Docker API proxy accepted connection from {:?}", peer_addr);
                tokio::spawn(async move {
                    if let Err(e) = proxy_docker_api_connection(stream).await {
                        tracing::warn!("Docker API proxy connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Docker API proxy accept failed: {}", e);
            }
        }
    }
}

async fn proxy_docker_api_connection(vsock_stream: VsockStream) -> Result<()> {
    let unix_stream = UnixStream::connect(DOCKER_API_UNIX_SOCKET)
        .await
        .context("failed to connect guest docker unix socket")?;
    tracing::info!("Docker proxy: connected to {}", DOCKER_API_UNIX_SOCKET);

    let (mut vsock_rd, mut vsock_wr) = tokio::io::split(vsock_stream);
    let (mut unix_rd, mut unix_wr) = tokio::io::split(unix_stream);

    // vsock → unix (host HTTP request → dockerd)
    let v2u = tokio::spawn(async move {
        let mut total: u64 = 0;
        let mut buf = [0u8; 8192];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut vsock_rd, &mut buf).await {
                Ok(0) => {
                    tracing::info!("Docker proxy vsock→unix: EOF after {} bytes", total);
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(
                        "Docker proxy vsock→unix: read error after {} bytes: {}",
                        total,
                        e
                    );
                    break;
                }
            };
            if total == 0 {
                tracing::debug!(
                    "Docker proxy vsock→unix: first chunk received ({} bytes, payload redacted)",
                    n
                );
            }
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut unix_wr, &buf[..n]).await {
                tracing::warn!(
                    "Docker proxy vsock→unix: write error after {} bytes: {}",
                    total,
                    e
                );
                break;
            }
            total += n as u64;
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut unix_wr).await;
        total
    });

    // unix → vsock (dockerd response → host)
    let u2v = tokio::spawn(async move {
        let mut total: u64 = 0;
        let mut buf = [0u8; 8192];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut unix_rd, &mut buf).await {
                Ok(0) => {
                    tracing::info!("Docker proxy unix→vsock: EOF after {} bytes", total);
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(
                        "Docker proxy unix→vsock: read error after {} bytes: {}",
                        total,
                        e
                    );
                    break;
                }
            };
            if total == 0 {
                tracing::debug!(
                    "Docker proxy unix→vsock: first chunk received ({} bytes, payload redacted)",
                    n
                );
            }
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut vsock_wr, &buf[..n]).await {
                tracing::warn!(
                    "Docker proxy unix→vsock: write error after {} bytes: {}",
                    total,
                    e
                );
                break;
            }
            total += n as u64;
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut vsock_wr).await;
        total
    });

    let (v2u_result, u2v_result) = tokio::join!(v2u, u2v);
    let v2u_bytes = v2u_result.unwrap_or(0);
    let u2v_bytes = u2v_result.unwrap_or(0);
    tracing::info!(
        "Docker proxy session done: vsock→unix={} bytes, unix→vsock={} bytes",
        v2u_bytes,
        u2v_bytes,
    );
    Ok(())
}

pub(super) async fn run_kubernetes_api_proxy() -> Result<()> {
    let port = kubernetes_api_vsock_port();
    let mut listener = bind_vsock_listener_with_retry(port, "kubernetes api proxy").await?;
    tracing::info!("Kubernetes API proxy listening on vsock port {}", port);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                tracing::debug!(
                    "Kubernetes API proxy accepted connection from {:?}",
                    peer_addr
                );
                tokio::spawn(async move {
                    if let Err(e) = proxy_kubernetes_api_connection(stream).await {
                        tracing::debug!("Kubernetes API proxy connection ended: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Kubernetes API proxy accept failed: {}", e);
            }
        }
    }
}

async fn proxy_kubernetes_api_connection(mut vsock_stream: VsockStream) -> Result<()> {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, KUBERNETES_API_GUEST_PORT);
    let mut tcp_stream = TcpStream::connect(addr)
        .await
        .context("failed to connect guest kubernetes api socket")?;

    let _ = tokio::io::copy_bidirectional(&mut vsock_stream, &mut tcp_stream)
        .await
        .context("kubernetes api proxy copy failed")?;
    Ok(())
}
