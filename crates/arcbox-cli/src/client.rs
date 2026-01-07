//! Daemon client for CLI communication.
//!
//! Provides HTTP client for connecting to the ArcBox daemon via Unix socket.

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;

/// Default socket path for the ArcBox daemon.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/arcbox.sock";

/// Daemon client for Docker-compatible API communication.
pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    /// Creates a new daemon client with the default socket path.
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
        }
    }

    /// Creates a new daemon client with a custom socket path.
    pub fn with_socket(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
        }
    }

    /// Returns the socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Checks if the daemon is running.
    pub async fn is_running(&self) -> bool {
        self.ping().await.is_ok()
    }

    /// Pings the daemon.
    pub async fn ping(&self) -> Result<()> {
        let _: serde_json::Value = self.get("/_ping").await?;
        Ok(())
    }

    /// Performs a GET request.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let body = self.request(Method::GET, path, None::<()>).await?;
        serde_json::from_slice(&body).context("failed to parse response")
    }

    /// Performs a GET request returning raw bytes.
    pub async fn get_raw(&self, path: &str) -> Result<Vec<u8>> {
        let body = self.request(Method::GET, path, None::<()>).await?;
        Ok(body.to_vec())
    }

    /// Performs a POST request with a JSON body.
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let body = self.request(Method::POST, path, body).await?;
        serde_json::from_slice(&body).context("failed to parse response")
    }

    /// Performs a POST request without expecting a response body.
    pub async fn post_empty<B: Serialize>(&self, path: &str, body: Option<B>) -> Result<()> {
        self.request(Method::POST, path, body).await?;
        Ok(())
    }

    /// Performs a POST request returning raw bytes.
    pub async fn post_raw<B: Serialize>(&self, path: &str, body: Option<B>) -> Result<Vec<u8>> {
        let body = self.request(Method::POST, path, body).await?;
        Ok(body.to_vec())
    }

    /// Performs a DELETE request.
    pub async fn delete(&self, path: &str) -> Result<()> {
        self.request(Method::DELETE, path, None::<()>).await?;
        Ok(())
    }

    /// Upgrades HTTP connection for exec interactive mode.
    ///
    /// Returns the underlying stream for bidirectional communication.
    pub async fn upgrade_exec<B: Serialize>(
        &self,
        exec_id: &str,
        body: Option<B>,
    ) -> Result<tokio::io::DuplexStream> {
        let path = format!("/v1.43/exec/{}/start", exec_id);
        self.upgrade_connection(&path, body).await
    }

    /// Upgrades HTTP connection for container attach.
    ///
    /// Returns the underlying stream for bidirectional communication.
    pub async fn upgrade_attach(
        &self,
        container_id: &str,
        stdin: bool,
        tty: bool,
    ) -> Result<tokio::io::DuplexStream> {
        let path = format!(
            "/v1.43/containers/{}/attach?stream=1&stdin={}&stdout=1&stderr={}",
            container_id, stdin, !tty
        );
        self.upgrade_connection::<()>(&path, None).await
    }

    /// Upgrades HTTP connection for bidirectional streaming.
    ///
    /// This sends an HTTP request and then returns a duplex stream that
    /// allows reading/writing directly to the connection.
    async fn upgrade_connection<B: Serialize>(
        &self,
        path: &str,
        body: Option<B>,
    ) -> Result<tokio::io::DuplexStream> {
        // Connect to Unix socket
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to daemon at {}",
                    self.socket_path.display()
                )
            })?;

        let io = TokioIo::new(stream);

        // Create HTTP connection
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("Upgrade connection closed: {}", e);
            }
        });

        // Build request with Upgrade header for streaming
        let request = if let Some(body) = body {
            let body_bytes = serde_json::to_vec(&body).context("failed to serialize body")?;
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://localhost{}", path))
                .header("Host", "localhost")
                .header("Content-Type", "application/json")
                .header("Content-Length", body_bytes.len())
                .header("Connection", "Upgrade")
                .header("Upgrade", "tcp")
                .body(Full::new(Bytes::from(body_bytes)))
                .context("failed to build request")?
        } else {
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://localhost{}", path))
                .header("Host", "localhost")
                .header("Connection", "Upgrade")
                .header("Upgrade", "tcp")
                .body(Full::new(Bytes::new()))
                .context("failed to build request")?
        };

        // Send request
        let response = sender
            .send_request(request)
            .await
            .context("failed to send upgrade request")?;

        let status = response.status();

        // Check for successful upgrade (101 Switching Protocols) or 200 OK
        if !status.is_success() && status != hyper::StatusCode::SWITCHING_PROTOCOLS {
            let body = response
                .into_body()
                .collect()
                .await
                .context("failed to read response")?
                .to_bytes();
            let error_msg = String::from_utf8_lossy(&body);
            anyhow::bail!("daemon returned error {}: {}", status, error_msg);
        }

        // Create a duplex stream for bidirectional communication.
        // We use a pair of channels to bridge between the HTTP body and our stream.
        let (client_duplex, server_duplex) = tokio::io::duplex(4096);

        // Spawn a task to forward data from HTTP response body to client
        let mut body = response.into_body();
        let (mut server_read, mut server_write) = tokio::io::split(server_duplex);

        // Forward response body to client read side
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(f) => {
                        if let Some(data) = f.data_ref() {
                            if server_write.write_all(data).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(client_duplex)
    }

    /// Streams logs from the daemon, calling the callback for each frame.
    pub async fn stream_logs<F>(&self, path: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(&[u8]),
    {
        self.stream_logs_with_cancel(path, &mut callback, tokio_util::sync::CancellationToken::new()).await
    }

    /// Streams logs from the daemon with cancellation support.
    ///
    /// The stream will be cancelled when the cancellation token is triggered.
    pub async fn stream_logs_with_cancel<F>(
        &self,
        path: &str,
        callback: &mut F,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<()>
    where
        F: FnMut(&[u8]),
    {
        use std::io::{stdout, Write};

        // Connect to Unix socket
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to daemon at {}",
                    self.socket_path.display()
                )
            })?;

        let io = TokioIo::new(stream);

        // Create HTTP connection
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("Log stream connection closed: {}", e);
            }
        });

        // Build request
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("http://localhost{}", path))
            .header("Host", "localhost")
            .body(Full::new(Bytes::new()))
            .context("failed to build request")?;

        // Send request
        let response = sender
            .send_request(request)
            .await
            .context("failed to send request")?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("daemon returned error {}", status);
        }

        // Stream response body with cancellation support
        let mut body = response.into_body();
        let mut buffer = Vec::with_capacity(4096);
        let mut frames_processed = 0u64;

        loop {
            tokio::select! {
                biased;

                // Check for cancellation
                _ = cancel_token.cancelled() => {
                    tracing::debug!("Log stream cancelled after {} frames", frames_processed);
                    break;
                }

                // Read next frame
                frame_result = body.frame() => {
                    match frame_result {
                        Some(Ok(frame)) => {
                            if let Some(data) = frame.data_ref() {
                                // Extend buffer with new data
                                buffer.extend_from_slice(data);

                                // Process all complete frames from buffer
                                while let Some((stream_type, content)) = extract_log_frame(&buffer) {
                                    let frame_size = 8 + content.len();

                                    // Call the callback with the log content
                                    // stream_type: 0 = stdin, 1 = stdout, 2 = stderr
                                    let _ = stream_type; // Can be used to route output
                                    callback(content);
                                    frames_processed += 1;

                                    // Remove processed frame from buffer
                                    buffer.drain(..frame_size);
                                }

                                // Flush output periodically
                                if frames_processed % 10 == 0 {
                                    stdout().flush().ok();
                                }
                            }
                        }
                        Some(Err(e)) => {
                            tracing::debug!("Error reading log frame: {}", e);
                            break;
                        }
                        None => {
                            // Stream ended
                            break;
                        }
                    }
                }
            }
        }

        // Process any remaining complete frames in buffer
        while let Some((_, content)) = extract_log_frame(&buffer) {
            let frame_size = 8 + content.len();
            callback(content);
            buffer.drain(..frame_size);
        }

        // If there's incomplete data left, try to print it as-is
        if !buffer.is_empty() {
            // Check if it might be raw (non-multiplexed) output
            if buffer.len() < 8 || buffer[0] > 2 {
                callback(&buffer);
            }
        }

        stdout().flush().ok();
        tracing::debug!("Log stream completed after {} frames", frames_processed);

        Ok(())
    }

    /// Performs an HTTP request to the daemon.
    async fn request<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Result<Bytes> {
        // Connect to Unix socket
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to daemon at {}",
                    self.socket_path.display()
                )
            })?;

        let io = TokioIo::new(stream);

        // Create HTTP connection
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("Connection error: {}", e);
            }
        });

        // Build request
        let request = if let Some(body) = body {
            let body_bytes = serde_json::to_vec(&body).context("failed to serialize body")?;
            Request::builder()
                .method(method)
                .uri(format!("http://localhost{}", path))
                .header("Host", "localhost")
                .header("Content-Type", "application/json")
                .header("Content-Length", body_bytes.len())
                .body(Full::new(Bytes::from(body_bytes)))
                .context("failed to build request")?
        } else {
            Request::builder()
                .method(method)
                .uri(format!("http://localhost{}", path))
                .header("Host", "localhost")
                .body(Full::new(Bytes::new()))
                .context("failed to build request")?
        };

        // Send request
        let response = sender
            .send_request(request)
            .await
            .context("failed to send request")?;

        let status = response.status();

        // Read response body
        let body = response
            .into_body()
            .collect()
            .await
            .context("failed to read response")?
            .to_bytes();

        // Check status
        if !status.is_success() {
            let error_msg = String::from_utf8_lossy(&body);
            anyhow::bail!("daemon returned error {}: {}", status, error_msg);
        }

        Ok(body)
    }
}

impl Default for DaemonClient {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Docker API Types
// =============================================================================

/// Container summary from list containers.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerSummary {
    pub id: String,
    pub names: Vec<String>,
    pub image: String,
    pub image_id: String,
    pub command: String,
    pub created: i64,
    pub state: String,
    pub status: String,
}

/// Create container request.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContainerRequest {
    pub image: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cmd: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub tty: bool,
    pub open_stdin: bool,
    pub attach_stdin: bool,
    pub attach_stdout: bool,
    pub attach_stderr: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_config: Option<HostConfig>,
}

/// Host configuration for container.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub binds: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_bindings: Option<std::collections::HashMap<String, Vec<PortBinding>>>,
    pub auto_remove: bool,
}

/// Port binding configuration.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PortBinding {
    pub host_ip: String,
    pub host_port: String,
}

/// Create container response.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContainerResponse {
    pub id: String,
    pub warnings: Vec<String>,
}

/// Container inspect response (simplified).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInspect {
    pub id: String,
    pub name: String,
    pub state: ContainerState,
    pub config: ContainerConfig,
}

/// Container state.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerState {
    pub status: String,
    pub running: bool,
    pub paused: bool,
    pub exit_code: i32,
}

/// Container config.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    pub image: String,
    pub cmd: Option<Vec<String>>,
    pub tty: bool,
}

/// Exec create request.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCreateRequest {
    pub attach_stdin: bool,
    pub attach_stdout: bool,
    pub attach_stderr: bool,
    pub tty: bool,
    pub cmd: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// Exec create response.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExecCreateResponse {
    pub id: String,
}

/// Container wait response.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerWaitResponse {
    pub status_code: i64,
}

/// Image summary.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageSummary {
    pub id: String,
    pub repo_tags: Vec<String>,
    pub created: i64,
    pub size: i64,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Gets the daemon client, checking if it's running first.
pub async fn get_client() -> Result<DaemonClient> {
    let client = DaemonClient::new();

    if !client.is_running().await {
        anyhow::bail!(
            "Cannot connect to ArcBox daemon at {}\n\
             Is the daemon running? Start it with: arcbox daemon",
            client.socket_path().display()
        );
    }

    Ok(client)
}

/// Truncates a string to the specified length.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Formats a container ID (first 12 characters).
pub fn short_id(id: &str) -> &str {
    if id.len() > 12 {
        &id[..12]
    } else {
        id
    }
}

/// Formats a relative time string.
pub fn relative_time(timestamp: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let diff = now - timestamp;

    if diff < 60 {
        format!("{} seconds ago", diff)
    } else if diff < 3600 {
        format!("{} minutes ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
}

/// Extracts a single log frame from a buffer.
///
/// Docker log format: [stream_type (1 byte)][padding (3 bytes)][size (4 bytes BE)][data]
/// - stream_type: 0 = stdin, 1 = stdout, 2 = stderr
///
/// Returns (stream_type, content) if a complete frame is available, None otherwise.
fn extract_log_frame(buffer: &[u8]) -> Option<(u8, &[u8])> {
    if buffer.len() < 8 {
        return None;
    }

    let stream_type = buffer[0];
    let size = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;

    let frame_end = 8 + size;
    if buffer.len() < frame_end {
        return None;
    }

    Some((stream_type, &buffer[8..frame_end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_id() {
        assert_eq!(short_id("abc123def456789"), "abc123def456");
        assert_eq!(short_id("short"), "short");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello world", 20), "hello world");
        assert_eq!(truncate("hello world this is long", 15), "hello world ...");
    }
}
