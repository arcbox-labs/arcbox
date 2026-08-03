//! Library exports for integration testing.
//!
//! The production entry point remains `src/main.rs`. This library module only
//! re-exports components needed by Linux integration tests.

mod rpc;

#[cfg(target_os = "linux")]
pub mod config;
pub mod containerd;
#[cfg(any(target_os = "linux", test))]
mod create_registry;
pub mod dns;
pub mod dns_server;
#[cfg(target_os = "linux")]
pub mod error;
pub mod memory_pressure;
pub mod metadata_migrate;
pub mod rootfs_builder;
#[cfg(target_os = "linux")]
pub mod sandbox;
pub mod stats;
pub mod volume_icon;
