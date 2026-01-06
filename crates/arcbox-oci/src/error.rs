//! Error types for OCI operations.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias for OCI operations.
pub type Result<T> = std::result::Result<T, OciError>;

/// Errors that can occur during OCI operations.
#[derive(Debug, Error)]
pub enum OciError {
    /// Invalid OCI version.
    #[error("invalid OCI version: {0}")]
    InvalidVersion(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Bundle not found.
    #[error("bundle not found: {0}")]
    BundleNotFound(PathBuf),

    /// Config file not found in bundle.
    #[error("config.json not found in bundle: {0}")]
    ConfigNotFound(PathBuf),

    /// Invalid bundle structure.
    #[error("invalid bundle structure: {0}")]
    InvalidBundle(String),

    /// Invalid container state.
    #[error("invalid container state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    /// Container not found.
    #[error("container not found: {0}")]
    ContainerNotFound(String),

    /// Hook execution failed.
    #[error("hook execution failed: {path} - {reason}")]
    HookFailed { path: PathBuf, reason: String },

    /// Hook timeout.
    #[error("hook timeout: {path} (timeout: {timeout}s)")]
    HookTimeout { path: PathBuf, timeout: u32 },

    /// Invalid path.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
