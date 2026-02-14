//! Common error types for `ArcBox`.
//!
//! This crate provides unified error types that are shared across multiple `ArcBox` crates,
//! reducing code duplication and ensuring consistent error handling patterns.
//!
//! # Usage
//!
//! ```rust
//! use arcbox_error::CommonError;
//!
//! fn example() -> Result<(), CommonError> {
//!     // Use CommonError for common error scenarios
//!     Err(CommonError::NotFound("resource".to_string()))
//! }
//! ```
//!
//! # Crate-Specific Errors
//!
//! Each crate can define its own error type that wraps `CommonError`:
//!
//! ```rust,ignore
//! use arcbox_error::CommonError;
//! use thiserror::Error;
//!
//! #[derive(Debug, Error)]
//! pub enum MyError {
//!     #[error(transparent)]
//!     Common(#[from] CommonError),
//!
//!     #[error("my specific error: {0}")]
//!     Specific(String),
//! }
//! ```

mod common;

pub use common::CommonError;

/// Result type alias using `CommonError`.
pub type Result<T> = std::result::Result<T, CommonError>;
