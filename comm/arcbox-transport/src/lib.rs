//! # arcbox-transport
//!
//! Transport layer abstractions for `ArcBox`.
//!
//! This crate provides transport implementations for communication:
//!
//! - [`UnixTransport`]: Unix domain sockets (CLI ↔ Daemon, Docker compatibility)
//! - [`VsockTransport`]: Virtio socket (Host ↔ Guest)
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │            arcbox-transport              │
//! │                                          │
//! │                                          │
//! │ ┌───────────────┐     ┌────────────────┐ │
//! │ │               │     │                │ │
//! │ │ UnixTransport │     │ VsockTransport │ │
//! │ │               │     │                │ │
//! │ └───────┬───────┘     └────────┬───────┘ │
//! │         │                      │         │
//! │         ▼                      ▼         │
//! │ ┌───────────────┐     ┌────────────────┐ │
//! │ │               │     │                │ │
//! │ │  arcbox.sock  │     │ vsock-CID+port │ │
//! │ │               │     │                │ │
//! │ └───────────────┘     └────────────────┘ │
//! │                                          │
//! └──────────────────────────────────────────┘
//! ```

pub mod error;
pub mod unix;
pub mod vsock;

pub use error::{Result, TransportError};
pub use unix::UnixTransport;
pub use vsock::VsockTransport;

use async_trait::async_trait;
use bytes::Bytes;

/// Transport trait for sending and receiving messages.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connects to the remote endpoint.
    async fn connect(&mut self) -> Result<()>;

    /// Disconnects from the remote endpoint.
    async fn disconnect(&mut self) -> Result<()>;

    /// Sends a message.
    async fn send(&mut self, data: Bytes) -> Result<()>;

    /// Receives a message.
    async fn recv(&mut self) -> Result<Bytes>;

    /// Returns whether the transport is connected.
    fn is_connected(&self) -> bool;
}

/// Transport listener for accepting connections.
#[async_trait]
pub trait TransportListener: Send + Sync {
    /// The transport type for accepted connections.
    type Transport: Transport;

    /// Binds to the endpoint.
    async fn bind(&mut self) -> Result<()>;

    /// Accepts a new connection.
    async fn accept(&mut self) -> Result<Self::Transport>;

    /// Closes the listener.
    async fn close(&mut self) -> Result<()>;
}
