//! Generated protocol buffer types.
//!
//! This module contains Rust types generated from `.proto` files by prost-build.
//! All types are under the `arcbox.v1` protobuf package.

// Allow clippy warnings in generated code.
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

/// All protocol buffer types from the `arcbox.v1` package.
///
/// This module includes types from:
/// - `common.proto` - Shared types (Empty, Timestamp, Mount, etc.)
/// - `machine.proto` - Virtual machine management
/// - `container.proto` - Container lifecycle
/// - `image.proto` - Image management
/// - `agent.proto` - Guest agent operations
/// - `api.proto` - Network, volume, and system services
#[path = "arcbox.v1.rs"]
pub mod arcbox_v1;
