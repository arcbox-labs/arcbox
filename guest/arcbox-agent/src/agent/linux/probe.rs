//! Connectivity probes used to check whether services are reachable.

use std::net::SocketAddrV4;
use std::path::Path;
use std::time::Duration;

use tokio::net::{TcpStream, UnixStream};

pub(super) async fn probe_tcp(addr: SocketAddrV4) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

pub(super) async fn probe_first_ready_socket(paths: &[&str]) -> bool {
    for path in paths {
        if probe_unix_socket(path).await {
            return true;
        }
    }
    false
}

/// Checks if a Unix socket is connectable (lightweight probe).
pub(super) async fn probe_unix_socket(path: &str) -> bool {
    if !Path::new(path).exists() {
        return false;
    }
    match tokio::time::timeout(Duration::from_millis(300), UnixStream::connect(path)).await {
        Ok(Ok(_stream)) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

/// Sends a real HTTP `GET /_ping` to the Docker socket and waits for a
/// valid response. This is much stronger than `probe_unix_socket` which
/// only checks if `connect()` succeeds — dockerd may accept connections
/// before its HTTP handler is ready.
pub(super) async fn probe_docker_api_ready(path: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_millis(500), UnixStream::connect(path)).await
    else {
        return false;
    };
    let req = b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(req).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let resp = String::from_utf8_lossy(&buf[..n]);
            // dockerd returns "HTTP/1.1 200 OK" with body "OK".
            resp.starts_with("HTTP/1.1 200")
        }
        _ => false,
    }
}
