//! # arcbox-image
//!
//! Boot-asset and machine-image management for `ArcBox`: the
//! compile-time-pinned boot asset chain (kernel, rootfs, runtime
//! binaries), the distro machine-image index, and the shared
//! remote-image fetch/staging primitives.
//!
//! This is an engine-layer crate: it must stay daemon-free and
//! platform-neutral (no dependency on the daemon, CLI, or any
//! macOS-only crate).

pub mod boot_assets;
pub mod error;
pub mod machine_image;
pub mod remote_image;

pub use error::{ImageError, Result};
