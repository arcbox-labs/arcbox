//! Error types for the core layer.

use thiserror::Error;

/// Result type alias for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors that can occur in core operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// VM error.
    #[error("VM error: {0}")]
    Vm(String),

    /// Machine error.
    #[error("machine error: {0}")]
    Machine(String),

    /// Container error.
    #[error("container error: {0}")]
    Container(#[from] arcbox_container::ContainerError),

    /// Image error.
    #[error("image error: {0}")]
    Image(#[from] arcbox_image::ImageError),

    /// Filesystem error.
    #[error("filesystem error: {0}")]
    Fs(#[from] arcbox_fs::FsError),

    /// Network error.
    #[error("network error: {0}")]
    Net(#[from] arcbox_net::NetError),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Already exists.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// Invalid state.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
