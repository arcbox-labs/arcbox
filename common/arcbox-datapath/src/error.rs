//! Error type for the datapath buffer pool.

use thiserror::Error;

/// Result alias for datapath operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by the datapath primitives.
#[derive(Debug, Error)]
pub enum Error {
    /// Packet pool error (buffer too large, or pool exhausted).
    #[error("packet pool error: {0}")]
    PacketPool(String),
}
