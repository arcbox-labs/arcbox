//! # arcbox-oci
//!
//! OCI runtime specification support for `ArcBox`.
//!
//! This crate provides parsing and management of OCI (Open Container Initiative)
//! runtime specification structures:
//!
//! - **Configuration**: Parse and validate `config.json` according to OCI runtime-spec
//! - **Bundles**: Load and create OCI bundles (directory containing config + rootfs)
//! - **State**: Container lifecycle state management
//! - **Hooks**: Lifecycle hook definitions and validation
//!
//! ## Example
//!
//! ```no_run
//! use arcbox_oci::{Bundle, BundleBuilder, Spec};
//!
//! // Load an existing bundle
//! let bundle = Bundle::load("/path/to/bundle")?;
//! println!("OCI version: {}", bundle.spec().oci_version);
//!
//! // Create a new bundle with builder
//! let bundle = BundleBuilder::new()
//!     .hostname("my-container")
//!     .args(vec!["nginx".to_string(), "-g".to_string(), "daemon off;".to_string()])
//!     .add_env("NGINX_HOST", "localhost")
//!     .cwd("/")
//!     .build("/path/to/new-bundle")?;
//!
//! // Parse config directly
//! let spec = Spec::load("/path/to/config.json")?;
//! # Ok::<(), arcbox_oci::OciError>(())
//! ```
//!
//! ## OCI Runtime Specification
//!
//! This crate implements the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)
//! which defines:
//!
//! - Container configuration format (`config.json`)
//! - Container lifecycle states (creating, created, running, stopped)
//! - Lifecycle hooks (prestart, poststart, poststop, etc.)
//! - Platform-specific settings (Linux namespaces, cgroups, etc.)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                     arcbox-oci                          │
//! │                                                         │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
//! │  │   config    │  │   bundle    │  │    state    │     │
//! │  │             │  │             │  │             │     │
//! │  │ - Spec      │  │ - Bundle    │  │ - State     │     │
//! │  │ - Process   │  │ - Builder   │  │ - Status    │     │
//! │  │ - Root      │  │ - utils     │  │ - Store     │     │
//! │  │ - Mounts    │  │             │  │             │     │
//! │  │ - Linux     │  │             │  │             │     │
//! │  └─────────────┘  └─────────────┘  └─────────────┘     │
//! │                                                         │
//! │  ┌─────────────┐  ┌─────────────┐                       │
//! │  │   hooks     │  │   error     │                       │
//! │  │             │  │             │                       │
//! │  │ - Hooks     │  │ - OciError  │                       │
//! │  │ - Hook      │  │ - Result    │                       │
//! │  │ - HookType  │  │             │                       │
//! │  └─────────────┘  └─────────────┘                       │
//! └─────────────────────────────────────────────────────────┘
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod bundle;
pub mod config;
pub mod error;
pub mod hooks;
pub mod state;

// Re-export main types for convenience.
pub use bundle::{Bundle, BundleBuilder};
pub use config::{
    Capabilities, ConsoleSize, CpuResources, Device, IdMapping, Linux, MemoryResources, Mount,
    Namespace, NamespaceType, OCI_VERSION, Process, Resources, Rlimit, Root, Seccomp, Spec, User,
};
pub use error::{OciError, Result};
pub use hooks::{Hook, HookContext, HookResult, HookType, Hooks};
pub use state::{ContainerState, State, StateStore, Status};
