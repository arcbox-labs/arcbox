//! Error types for VirtIO devices.

use thiserror::Error;

/// Result type alias for VirtIO operations.
pub type Result<T> = std::result::Result<T, VirtioError>;

/// Errors that can occur during VirtIO operations.
#[derive(Debug, Error)]
pub enum VirtioError {
    /// Device not ready.
    #[error("device not ready: {0}")]
    NotReady(String),

    /// Invalid queue configuration.
    #[error("invalid queue configuration: {0}")]
    InvalidQueue(String),

    /// Invalid descriptor.
    #[error("invalid descriptor: {0}")]
    InvalidDescriptor(String),

    /// Buffer too small.
    #[error("buffer too small: need {needed}, got {got}")]
    BufferTooSmall { needed: usize, got: usize },

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Memory error.
    #[error("memory error: {0}")]
    MemoryError(String),

    /// Device-specific error.
    #[error("{device} error: {message}")]
    DeviceError { device: String, message: String },

    /// Feature not supported.
    #[error("feature not supported: {0}")]
    FeatureNotSupported(String),

    /// Operation not supported.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Invalid operation.
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_ready_error() {
        let err = VirtioError::NotReady("device not initialized".to_string());
        assert!(err.to_string().contains("device not ready"));
        assert!(err.to_string().contains("device not initialized"));
    }

    #[test]
    fn test_invalid_queue_error() {
        let err = VirtioError::InvalidQueue("size must be power of 2".to_string());
        assert!(err.to_string().contains("invalid queue"));
    }

    #[test]
    fn test_invalid_descriptor_error() {
        let err = VirtioError::InvalidDescriptor("out of bounds".to_string());
        assert!(err.to_string().contains("invalid descriptor"));
    }

    #[test]
    fn test_buffer_too_small_error() {
        let err = VirtioError::BufferTooSmall { needed: 1024, got: 512 };
        let msg = err.to_string();
        assert!(msg.contains("1024"));
        assert!(msg.contains("512"));
    }

    #[test]
    fn test_io_error() {
        let err = VirtioError::Io("read failed".to_string());
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_io_error_from_std() {
        let std_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: VirtioError = std_err.into();
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_memory_error() {
        let err = VirtioError::MemoryError("allocation failed".to_string());
        assert!(err.to_string().contains("memory error"));
    }

    #[test]
    fn test_device_error() {
        let err = VirtioError::DeviceError {
            device: "block".to_string(),
            message: "disk full".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("block"));
        assert!(msg.contains("disk full"));
    }

    #[test]
    fn test_feature_not_supported() {
        let err = VirtioError::FeatureNotSupported("multiqueue".to_string());
        assert!(err.to_string().contains("feature not supported"));
    }

    #[test]
    fn test_not_supported_error() {
        let err = VirtioError::NotSupported("flush".to_string());
        assert!(err.to_string().contains("operation not supported"));
    }

    #[test]
    fn test_invalid_operation_error() {
        let err = VirtioError::InvalidOperation("write to read-only".to_string());
        assert!(err.to_string().contains("invalid operation"));
    }

    #[test]
    fn test_error_debug() {
        let err = VirtioError::NotReady("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("NotReady"));
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_ok() -> Result<u32> {
            Ok(42)
        }

        fn returns_err() -> Result<u32> {
            Err(VirtioError::NotReady("test".to_string()))
        }

        assert!(returns_ok().is_ok());
        assert!(returns_err().is_err());
    }
}
