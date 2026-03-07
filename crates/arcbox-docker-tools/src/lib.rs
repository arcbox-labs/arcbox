//! Docker CLI tool download, installation, and management.
//!
//! Reads tool versions and checksums from `assets.lock`, downloads Docker CLI
//! binaries (docker, buildx, compose, credential helpers), verifies SHA-256
//! checksums, and installs them to `~/.arcbox/runtime/bin/`.

pub mod lockfile;
pub mod manager;
pub mod registry;

pub use lockfile::{parse_tools, ToolEntry};
pub use manager::{DockerToolError, DockerToolManager};
