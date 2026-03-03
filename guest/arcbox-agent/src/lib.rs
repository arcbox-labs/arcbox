//! Library exports for integration testing.
//!
//! The production entry point remains `src/main.rs`. This library module only
//! re-exports components needed by Linux integration tests.

#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
pub mod sandbox;
