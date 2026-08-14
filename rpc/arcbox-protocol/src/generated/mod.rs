//! Generated protocol buffer types.
//!
//! This module contains Rust types generated from `.proto` files by prost-build.

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
/// - `api.proto` - Network, volume, system, and migration services
/// - `kubernetes.proto` - Native Kubernetes lifecycle
#[path = "arcbox.v1.rs"]
pub mod arcbox_v1;

/// All protocol buffer types from the `arcbox.sandbox.v1` package.
///
/// prost emits one module per package, so the proto files that make up
/// the sandbox API land here together:
/// - `sandbox.proto` - control plane: lifecycle, events, published ports
/// - `process.proto` - data plane: the execution (exec) family
/// - `filesystem.proto` - data plane: file transfer and path verbs
/// - `snapshot.proto` - checkpoint / restore
/// - `template.proto` - the template catalog (CORE-21)
/// - `errors.proto` - the error-code registry (`ErrorInfo` detail)
#[path = "arcbox.sandbox.v1.rs"]
pub mod arcbox_sandbox_v1;
