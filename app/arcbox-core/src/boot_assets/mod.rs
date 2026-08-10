//! Boot asset management for VM startup.
//!
//! Thin wrapper around `arcbox_boot::AssetManager`.
//! All downloading, caching, and verification logic lives in the
//! `arcbox-boot` crate; this module provides daemon-specific
//! configuration defaults, error mapping, and the `BootAssets` struct
//! that `vm_lifecycle` consumes.

mod config;
mod lockfile;
mod provider;

#[cfg(test)]
mod tests;

pub use arcbox_boot::download::{PreparePhase, PrepareProgress as DownloadProgress};
pub use arcbox_boot::manifest::Manifest as BootAssetManifest;
pub use config::BootAssetConfig;
pub use lockfile::{boot_asset_cdn, boot_asset_version};
pub use provider::{BootAssetProvider, BootAssets, CachedBinaryReport, ProgressCallback};

pub(crate) const REQUIRED_RUNTIME_BINARIES: [&str; 6] = [
    "dockerd",
    "containerd",
    "containerd-shim-runc-v2",
    "runc",
    "docker-init",
    "k3s",
];
