//! Unix domain socket transport.

use crate::error::{Result, TransportError};
use crate::{Transport, TransportListener};
use async_trait::async_trait;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Unix socket transport.
pub struct UnixTransport {
    path: PathBuf,
    stream: Option<UnixStream>,
}

impl UnixTransport {
    /// Creates a new Unix transport for the given path.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            stream: None,
        }
    }

    /// Creates a transport from an existing stream.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        Self {
            path: PathBuf::new(),
            stream: Some(stream),
        }
    }
}

#[async_trait]
impl Transport for UnixTransport {
    async fn connect(&mut self) -> Result<()> {
        if self.stream.is_some() {
            return Err(TransportError::AlreadyConnected);
        }

        let stream = UnixStream::connect(&self.path)
            .await
            .map_err(|e| TransportError::ConnectionRefused(e.to_string()))?;

        self.stream = Some(stream);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.stream.take();
        Ok(())
    }

    async fn send(&mut self, data: Bytes) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;

        // Write length prefix (4 bytes)
        let len = data.len() as u32;
        stream.write_all(&len.to_le_bytes()).await?;
        stream.write_all(&data).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn recv(&mut self) -> Result<Bytes> {
        let stream = self.stream.as_mut().ok_or(TransportError::NotConnected)?;

        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;

        // Read message
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        Ok(Bytes::from(buf))
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

/// Unix socket listener.
pub struct UnixSocketListener {
    path: PathBuf,
    listener: Option<UnixListener>,
}

impl UnixSocketListener {
    /// Creates a new Unix socket listener.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            listener: None,
        }
    }
}

#[async_trait]
impl TransportListener for UnixSocketListener {
    type Transport = UnixTransport;

    async fn bind(&mut self) -> Result<()> {
        // Remove existing socket if present
        let _ = std::fs::remove_file(&self.path);

        let listener = UnixListener::bind(&self.path)?;
        self.listener = Some(listener);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Self::Transport> {
        let listener = self
            .listener
            .as_ref()
            .ok_or(TransportError::NotConnected)?;

        let (stream, _) = listener.accept().await?;
        Ok(UnixTransport::from_stream(stream))
    }

    async fn close(&mut self) -> Result<()> {
        self.listener.take();
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
}
