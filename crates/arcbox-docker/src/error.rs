//! Error types for Docker API.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

/// Result type alias for Docker API operations.
pub type Result<T> = std::result::Result<T, DockerError>;

/// Errors that can occur in Docker API operations.
#[derive(Debug, Error)]
pub enum DockerError {
    /// Container not found.
    #[error("No such container: {0}")]
    ContainerNotFound(String),

    /// Image not found.
    #[error("No such image: {0}")]
    ImageNotFound(String),

    /// Volume not found.
    #[error("No such volume: {0}")]
    VolumeNotFound(String),

    /// Network not found.
    #[error("No such network: {0}")]
    NetworkNotFound(String),

    /// Invalid parameter.
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Conflict (e.g., container already exists).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Server error.
    #[error("Server error: {0}")]
    Server(String),

    /// Not implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

impl DockerError {
    /// Returns the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::ContainerNotFound(_)
            | Self::ImageNotFound(_)
            | Self::VolumeNotFound(_)
            | Self::NetworkNotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidParameter(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Server(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

/// Docker API error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error message.
    pub message: String,
}

impl IntoResponse for DockerError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = serde_json::json!({
            "message": self.to_string()
        });

        (status, axum::Json(body)).into_response()
    }
}
